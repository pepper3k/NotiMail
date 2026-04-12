"""
Authentication and authorization for UP Bridge.

Provides bcrypt password hashing, API key generation/validation,
invite management, and tiered brute-force protection.
"""

import datetime
import hashlib
import logging
import secrets
import time
import threading
from typing import Any, Dict, List, Optional, Set, Tuple

import bcrypt

from notimail.crypto import CryptoManager
from notimail.database import DatabaseHandler


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Hash a password using bcrypt.

    Args:
        password: The plaintext password to hash.

    Returns:
        The bcrypt hash string.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def check_password(password: str, password_hash: str) -> bool:
    """Verify a password against its bcrypt hash.

    Args:
        password: The plaintext password to check.
        password_hash: The stored bcrypt hash.

    Returns:
        True if the password matches the hash.
    """
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))


# ---------------------------------------------------------------------------
# API key management
# ---------------------------------------------------------------------------

def generate_api_key() -> Tuple[str, str, str]:
    """Generate a new API key.

    Returns:
        A tuple of (raw_key, key_hash, key_prefix):
        - raw_key: The full API key to show to the user (once).
        - key_hash: SHA-256 hash to store in the database.
        - key_prefix: First 8 characters for display identification.
    """
    raw_key = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_key.encode('utf-8')).hexdigest()
    key_prefix = raw_key[:8]
    return raw_key, key_hash, key_prefix


def validate_api_key(raw_key: str, db: DatabaseHandler) -> Optional[Dict[str, Any]]:
    """Validate an API key against the database.

    Args:
        raw_key: The raw API key from the Authorization header.
        db: The DatabaseHandler instance.

    Returns:
        The API key record dict if valid and not revoked, or None.
    """
    key_hash = hashlib.sha256(raw_key.encode('utf-8')).hexdigest()
    key_record = db.get_api_key_by_hash(key_hash)
    if key_record and not key_record['revoked']:
        db.update_api_key_last_used(key_record['id'])
        return key_record
    return None


# ---------------------------------------------------------------------------
# Invite management
# ---------------------------------------------------------------------------

def create_invite(
    db: DatabaseHandler,
    created_by: int,
    expire_days: int = 7,
) -> str:
    """Create a new invite code.

    Args:
        db: The DatabaseHandler instance.
        created_by: User ID of the person creating the invite.
        expire_days: Number of days until the invite expires.

    Returns:
        The invite code string.
    """
    code = secrets.token_urlsafe(32)
    expires_at = (
        datetime.datetime.now() + datetime.timedelta(days=expire_days)
    ).strftime("%Y-%m-%d %H:%M:%S")
    db.add_invite(code, created_by, expires_at)
    return code


def redeem_invite(
    db: DatabaseHandler,
    crypto: CryptoManager,
    code: str,
    username: str,
    password: str,
) -> Optional[int]:
    """Redeem an invite code and create a new user.

    Validates that the invite exists, has not been redeemed, and has
    not expired. Then creates the user and marks the invite as redeemed.

    Args:
        db: The DatabaseHandler instance.
        crypto: The CryptoManager for encrypting the username.
        code: The invite code to redeem.
        username: The desired username for the new user.
        password: The desired password for the new user.

    Returns:
        The new user's ID, or None if the invite is invalid/expired.
    """
    invite = db.get_invite_by_code(code)
    if invite is None:
        logging.warning(f"Invite code not found: {code[:8]}...")
        return None

    if invite['redeemed_by'] is not None:
        logging.warning(f"Invite already redeemed: {code[:8]}...")
        return None

    if invite['expires_at']:
        expires = datetime.datetime.strptime(invite['expires_at'], "%Y-%m-%d %H:%M:%S")
        if datetime.datetime.now() > expires:
            logging.warning(f"Invite expired: {code[:8]}...")
            return None

    # Create the user
    user_id = db.add_user(
        username_encrypted=crypto.encrypt(username),
        username_lookup=crypto.hmac_hash(username),
        password_hash=hash_password(password),
        role="user",
        invited_by=invite['created_by'],
    )

    # Mark invite as redeemed
    db.redeem_invite(invite['id'], user_id)
    logging.info(f"User created via invite: user_id={user_id}")
    return user_id


# ---------------------------------------------------------------------------
# Tiered brute-force protection
# ---------------------------------------------------------------------------

class RateLimiter:
    """Tiered brute-force protection for login and API authentication.

    Tracks failed authentication attempts per IP and distinguishes
    between user error (wrong password) and active attacks (username
    enumeration, password spraying).

    Thread-safe via a threading.Lock.

    Tiers:
    - Wrong password for a single username: gentle lockout
    - Multiple non-existent usernames from one IP: aggressive lockout
    - Multiple valid usernames with wrong passwords: spray detection

    All thresholds are configurable.
    """

    def __init__(
        self,
        max_attempts: int = 5,
        window_minutes: int = 15,
        lockout_minutes: int = 30,
        enum_threshold: int = 3,
        enum_lockout_minutes: int = 60,
        spray_threshold: int = 3,
        spray_window_minutes: int = 5,
    ) -> None:
        self._lock = threading.Lock()
        self.max_attempts = max_attempts
        self.window_seconds = window_minutes * 60
        self.lockout_seconds = lockout_minutes * 60
        self.enum_threshold = enum_threshold
        self.enum_lockout_seconds = enum_lockout_minutes * 60
        self.spray_threshold = spray_threshold
        self.spray_window_seconds = spray_window_minutes * 60

        # {(ip, username_hmac): [timestamp, ...]}
        self._per_user_failures: Dict[Tuple[str, str], List[float]] = {}
        # {ip: set(non_existent_username_hmacs)}
        self._enum_tracking: Dict[str, Dict[str, float]] = {}
        # {ip: [(valid_username_hmac, timestamp), ...]}
        self._spray_tracking: Dict[str, List[Tuple[str, float]]] = {}
        # {ip: lockout_expiry_timestamp}
        self._ip_lockouts: Dict[str, float] = {}

    def is_locked_out(self, ip: str) -> bool:
        """Check if an IP is currently locked out.

        Also cleans up expired lockouts.
        """
        with self._lock:
            self._cleanup()
            expiry = self._ip_lockouts.get(ip)
            if expiry and time.time() < expiry:
                return True
            if expiry:
                del self._ip_lockouts[ip]
            return False

    def record_failure(
        self,
        ip: str,
        username_hmac: str,
        username_exists: bool,
    ) -> Optional[str]:
        """Record a failed authentication attempt.

        Args:
            ip: The client IP address.
            username_hmac: HMAC hash of the attempted username.
            username_exists: Whether the username exists in the database.

        Returns:
            A string describing the lockout action taken, or None if
            no lockout was triggered.
        """
        now = time.time()

        with self._lock:
            self._cleanup()

            # Track per-username failures (wrong password)
            key = (ip, username_hmac)
            if key not in self._per_user_failures:
                self._per_user_failures[key] = []
            self._per_user_failures[key].append(now)

            # Check for per-user lockout (gentle)
            recent = [t for t in self._per_user_failures[key] if now - t < self.window_seconds]
            self._per_user_failures[key] = recent
            if len(recent) >= self.max_attempts * 2:
                # Hard lockout after 2x threshold
                self._ip_lockouts[ip] = now + self.lockout_seconds
                return f"Too many failed attempts for this account. IP locked for {self.lockout_seconds // 60} minutes."
            elif len(recent) >= self.max_attempts:
                # Soft lockout — delay (handled by caller checking is_locked_out with short expiry)
                self._ip_lockouts[ip] = now + 60  # 60-second delay
                return "Too many attempts. Please wait 60 seconds."

            if not username_exists:
                # Track enumeration (non-existent usernames)
                if ip not in self._enum_tracking:
                    self._enum_tracking[ip] = {}
                self._enum_tracking[ip][username_hmac] = now

                # Prune old entries
                self._enum_tracking[ip] = {
                    h: t for h, t in self._enum_tracking[ip].items()
                    if now - t < self.window_seconds
                }

                if len(self._enum_tracking[ip]) >= self.enum_threshold:
                    self._ip_lockouts[ip] = now + self.enum_lockout_seconds
                    return f"Suspicious activity detected. IP locked for {self.enum_lockout_seconds // 60} minutes."
            else:
                # Track spray (multiple valid usernames failing)
                if ip not in self._spray_tracking:
                    self._spray_tracking[ip] = []
                self._spray_tracking[ip].append((username_hmac, now))

                # Prune old and deduplicate
                self._spray_tracking[ip] = [
                    (h, t) for h, t in self._spray_tracking[ip]
                    if now - t < self.spray_window_seconds
                ]
                distinct_users = set(h for h, t in self._spray_tracking[ip])
                if len(distinct_users) >= self.spray_threshold:
                    self._ip_lockouts[ip] = now + self.enum_lockout_seconds
                    return f"Suspicious activity detected. IP locked for {self.enum_lockout_seconds // 60} minutes."

            return None

    def record_success(self, ip: str, username_hmac: str) -> None:
        """Clear tracking data for a successful login."""
        with self._lock:
            key = (ip, username_hmac)
            self._per_user_failures.pop(key, None)
            # Don't clear enum/spray tracking — those are per-IP

    def _cleanup(self) -> None:
        """Remove stale entries from all tracking dicts."""
        now = time.time()

        # Clean per-user failures
        stale_keys = [
            k for k, timestamps in self._per_user_failures.items()
            if all(now - t > self.window_seconds for t in timestamps)
        ]
        for k in stale_keys:
            del self._per_user_failures[k]

        # Clean enum tracking
        stale_ips = [
            ip for ip, hashes in self._enum_tracking.items()
            if all(now - t > self.window_seconds for t in hashes.values())
        ]
        for ip in stale_ips:
            del self._enum_tracking[ip]

        # Clean spray tracking
        stale_ips = [
            ip for ip, entries in self._spray_tracking.items()
            if all(now - t > self.spray_window_seconds for _, t in entries)
        ]
        for ip in stale_ips:
            del self._spray_tracking[ip]

        # Clean expired lockouts
        expired = [ip for ip, expiry in self._ip_lockouts.items() if now >= expiry]
        for ip in expired:
            del self._ip_lockouts[ip]
