"""
Host connection limit management for UP Bridge.

Reads known_host_limits.ini to proactively cap concurrent IMAP connections
per host. Implements smart retry suppression for unknown hosts by detecting
"too many connections" patterns at runtime.
"""

import configparser
import logging
import os
import threading
import time
from typing import Dict, List, Optional, Set, Tuple


class HostLimitEntry:
    """Connection limit info for a single IMAP host."""
    def __init__(self, max_concurrent: int, limit_type: str) -> None:
        self.max_concurrent = max_concurrent
        self.limit_type = limit_type  # "per-ip" or "per-account"


class HostLimitManager:
    """Manages per-host connection limits and retry suppression.

    Loads known limits from known_host_limits.ini and tracks runtime
    connection state to enforce limits proactively. For unknown hosts,
    uses heuristic detection to identify per-IP limits.

    Thread-safe via a threading.Lock.

    Attributes:
        known_limits: Dict of hostname -> HostLimitEntry from config file.
        active_connections: Dict of hostname -> set of (email_user, folder) tuples.
        waiting: Dict of hostname -> list of (email_user, folder) tuples waiting for a slot.
        failure_counts: Dict of (hostname, email_user, folder) -> consecutive failure count.
    """

    # Keywords in IMAP BYE responses that suggest a connection limit
    LIMIT_KEYWORDS = ("too many", "rate", "limit", "exceeded", "maximum")

    def __init__(self, config_path: Optional[str] = None) -> None:
        self._lock = threading.Lock()
        self.known_limits: Dict[str, HostLimitEntry] = {}
        self.active_connections: Dict[str, Set[Tuple[str, str]]] = {}
        self.waiting: Dict[str, List[Tuple[str, str]]] = {}
        self.failure_counts: Dict[Tuple[str, str, str], int] = {}
        self._previously_connected: Set[Tuple[str, str, str]] = set()

        if config_path and os.path.exists(config_path):
            self._load_config(config_path)

    def _load_config(self, path: str) -> None:
        """Parse known_host_limits.ini."""
        cfg = configparser.ConfigParser()
        cfg.read(path)
        for section in cfg.sections():
            hostname = section.lower()
            max_concurrent = cfg.getint(section, 'MaxConcurrent', fallback=0)
            limit_type = cfg.get(section, 'LimitType', fallback='per-account').lower()
            if max_concurrent > 0:
                self.known_limits[hostname] = HostLimitEntry(max_concurrent, limit_type)
        logging.info(f"Loaded host limits for {len(self.known_limits)} host(s)")

    def can_connect(self, host: str, email_user: str, folder: str) -> bool:
        """Check if a new connection to this host is allowed.

        For per-ip hosts, checks total active connections against the limit.
        For per-account hosts, always returns True (each account has its own pool).
        For unknown hosts, always returns True.

        Args:
            host: IMAP server hostname.
            email_user: The email account username.
            folder: The IMAP folder being monitored.

        Returns:
            True if the connection should proceed, False if it should wait.
        """
        host_lower = host.lower()
        limit = self.known_limits.get(host_lower)

        if limit is None or limit.limit_type == 'per-account':
            return True

        # per-ip limit: check total connections to this host
        with self._lock:
            active = self.active_connections.get(host_lower, set())
            if len(active) >= limit.max_concurrent:
                # Add to waiting list if not already there
                key = (email_user, folder)
                if host_lower not in self.waiting:
                    self.waiting[host_lower] = []
                if key not in self.waiting[host_lower]:
                    self.waiting[host_lower].append(key)
                return False
            return True

    def record_connected(self, host: str, email_user: str, folder: str) -> None:
        """Record that a connection was successfully established."""
        host_lower = host.lower()
        key = (email_user, folder)
        with self._lock:
            if host_lower not in self.active_connections:
                self.active_connections[host_lower] = set()
            self.active_connections[host_lower].add(key)
            self._previously_connected.add((host_lower, email_user, folder))
            # Clear failure count on success
            self.failure_counts.pop((host_lower, email_user, folder), None)
            # Remove from waiting list
            if host_lower in self.waiting and key in self.waiting[host_lower]:
                self.waiting[host_lower].remove(key)

    def record_disconnected(self, host: str, email_user: str, folder: str) -> None:
        """Record that a connection was closed or lost."""
        host_lower = host.lower()
        key = (email_user, folder)
        with self._lock:
            active = self.active_connections.get(host_lower, set())
            active.discard(key)

    def record_connection_failure(
        self, host: str, email_user: str, folder: str, error_msg: str
    ) -> bool:
        """Record a connection failure and determine if it's a host limit.

        Returns True if this looks like a host-limit issue (smart retry
        suppression should kick in), False for normal transient errors.
        """
        host_lower = host.lower()
        fkey = (host_lower, email_user, folder)

        # Check if error message suggests a connection limit
        is_limit_error = any(kw in error_msg.lower() for kw in self.LIMIT_KEYWORDS)

        with self._lock:
            active = self.active_connections.get(host_lower, set())
            self.failure_counts[fkey] = self.failure_counts.get(fkey, 0) + 1
            count = self.failure_counts[fkey]

            # Smart retry suppression: after 5 consecutive failures while
            # siblings on the same host are connected, treat as host limit
            if count >= 5 and len(active) > 0:
                logging.warning(
                    f"Host {host}: {email_user}/{folder} failed {count} times "
                    f"while {len(active)} sibling(s) connected. Likely host connection limit."
                )
                return True

            if is_limit_error:
                logging.warning(
                    f"Host {host}: connection limit detected for {email_user}/{folder}: {error_msg}"
                )
                return True

        return False

    def get_next_waiting(self, host: str) -> Optional[Tuple[str, str]]:
        """Get the next waiting account for a host, with reconnection priority.

        Previously connected accounts are prioritized over never-connected ones.

        Returns:
            (email_user, folder) tuple, or None if no one is waiting.
        """
        host_lower = host.lower()
        with self._lock:
            waiters = self.waiting.get(host_lower, [])
            if not waiters:
                return None

            # Prioritize previously connected accounts
            for i, key in enumerate(waiters):
                if (host_lower, key[0], key[1]) in self._previously_connected:
                    return waiters.pop(i)

            # Otherwise FIFO
            return waiters.pop(0)

    def get_host_status(self) -> Dict[str, Dict]:
        """Get status info for all tracked hosts (for dashboard display)."""
        with self._lock:
            result = {}
            all_hosts = set(self.active_connections.keys()) | set(self.waiting.keys())
            for host in all_hosts:
                active = self.active_connections.get(host, set())
                waiting = self.waiting.get(host, [])
                limit = self.known_limits.get(host)
                result[host] = {
                    'active': len(active),
                    'waiting': len(waiting),
                    'max_concurrent': limit.max_concurrent if limit else None,
                    'limit_type': limit.limit_type if limit else 'unknown',
                    'at_limit': limit is not None and limit.limit_type == 'per-ip' and len(active) >= limit.max_concurrent,
                }
            return result

    def check_limit_warning(self, host: str, current_count: int) -> Optional[str]:
        """Check if adding an account would exceed a known host limit.

        Used at account creation time to warn the user.

        Returns:
            Warning message string, or None if within limits.
        """
        host_lower = host.lower()
        limit = self.known_limits.get(host_lower)
        if limit is None or limit.limit_type != 'per-ip':
            return None

        with self._lock:
            active = len(self.active_connections.get(host_lower, set()))

        total = active + current_count
        if total >= limit.max_concurrent:
            return (
                f"{host} limits connections to {limit.max_concurrent} per IP. "
                f"You currently have {active} active. This account may be queued."
            )
        return None
