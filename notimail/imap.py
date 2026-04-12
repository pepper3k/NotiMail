"""
IMAP connection handlers for UP Bridge.

Manages IMAP IDLE connections, email processing, multi-account
orchestration, the connection watchdog, and memory-only credential
mode with reauth push notifications.
"""

import datetime
import imaplib
import json
import logging
import select
import socket
import threading
import time
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from threading import Lock
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

import requests

import notimail.config as notimail_config
from notimail.config import (
    shutdown_sock_r, shutdown_sock_w,
    RETRY_DELAY, IDLE_TIMEOUT,
)
from notimail.database import DatabaseHandler
from notimail.notifications import Notifier

# Thread-safe dict for credential handoff from reauth API to waiting handlers.
# Maps account_id -> {"email_user": ..., "email_pass": ..., "host": ...}
pending_reauth: Dict[int, Dict[str, str]] = {}
pending_reauth_lock = threading.Lock()


def _send_reauth_push(notifier: Optional[Notifier], account_name: str, account_id: int) -> None:
    """Send a reauth push notification via the account's notification providers.

    For ntfy UnifiedPush endpoints (?up=1), sends a JSON body with type and account_id.
    For regular ntfy/other endpoints, sends a human-readable message.

    Args:
        notifier: The Notifier instance for this account, or None.
        account_name: Display name of the account.
        account_id: Database ID of the account.
    """
    if not notifier:
        logging.warning(f"Cannot send reauth push for {account_name}: no notifier configured")
        return

    for provider in notifier.providers:
        # Check if this is an ntfy provider with UP endpoints
        if hasattr(provider, 'ntfy_data'):
            for ntfy_url, token in provider.ntfy_data:
                headers: dict = {}
                if token:
                    headers["Authorization"] = f"Bearer {token}"

                parsed = urlparse(ntfy_url)
                params = parse_qs(parsed.query)
                is_up = params.get('up', [''])[0] == '1'

                if is_up:
                    data = json.dumps({"type": "reauth", "account_id": account_id}).encode('utf-8')
                else:
                    headers["Title"] = "UP Bridge Re-authentication Required"
                    data = f"UP Bridge needs re-authentication for account {account_name}".encode('utf-8')

                try:
                    response = requests.post(ntfy_url, data=data, headers=headers)
                    if response.status_code == 200:
                        logging.info(f"Sent reauth push for {account_name} to {ntfy_url}")
                    else:
                        logging.error(f"Failed to send reauth push to {ntfy_url}: {response.status_code}")
                except requests.RequestException as e:
                    logging.error(f"Error sending reauth push to {ntfy_url}: {e}")
                time.sleep(2)
        else:
            # For non-ntfy providers, send as a regular notification
            try:
                provider.send_notification(
                    "UP Bridge Re-authentication",
                    f"Re-authentication needed for account {account_name}")
            except Exception as e:
                logging.error(f"Error sending reauth notification: {e}")


class EmailProcessor:
    """Fetches unseen emails from an IMAP connection and sends notifications.

    Given an authenticated IMAP connection that has already selected a
    folder, this class searches for UNSEEN messages, parses them, fires
    notifications, and records them in the database so they are not
    re-processed.

    Attributes:
        mail: An authenticated imaplib.IMAP4_SSL instance with a folder selected.
        email_account: Identifier for the IMAP account (e.g. user@example.com).
        notifier: The Notifier instance used to dispatch push notifications.
        db_path: Filesystem path to the SQLite database.
        metrics: Dict of Prometheus metric objects (or DummyMetric stubs).
    """

    def __init__(
        self,
        mail: imaplib.IMAP4_SSL,
        email_account: str,
        notifier: Notifier,
        db_path: str,
        metrics: Dict[str, Any],
    ) -> None:
        self.mail = mail
        self.email_account = email_account
        self.notifier = notifier
        self.db_path = db_path
        self.metrics = metrics

    def fetch_unseen_emails(self) -> List[bytes]:
        """Search for UNSEEN emails in the currently selected folder.

        Returns:
            A list of IMAP UID byte-strings (e.g. [b'123', b'456']).
            Returns an empty list on error or if none are found.
        """
        try:
            status, messages = self.mail.uid('search', None, "UNSEEN")
            if status != 'OK':
                logging.warning(f"Search for UNSEEN emails returned status: {status}")
                return []
            return messages[0].split()
        except Exception as e:
            logging.error(f"Error fetching unseen emails: {str(e)}")
            return []

    def parse_email(self, raw_email: bytes) -> EmailMessage:
        """Parse raw email bytes into a structured EmailMessage object.

        Args:
            raw_email: The raw RFC 2822 message bytes.

        Returns:
            A parsed email.message.EmailMessage instance.
        """
        return BytesParser(policy=policy.default).parsebytes(raw_email)

    def process(self) -> None:
        """Fetch all unseen emails, send notifications, and record them.

        For each unseen email that has not already been notified:
        1. Fetch the message body (using BODY.PEEK[] to avoid marking as read).
        2. Parse the From and Subject headers.
        3. Send a push notification via the configured Notifier.
        4. Record the UID in the database with notified=1.

        After processing, old database records are pruned.

        Raises:
            Exception: Re-raises any exception from the outer try block
                      so the caller (IMAPHandler) can detect failures.
        """
        logging.info("Fetching the latest email...")
        try:
            with DatabaseHandler(self.db_path) as db_handler:
                for message in self.fetch_unseen_emails():
                    uid: str = message.decode('utf-8')
                    if db_handler.is_email_notified(self.email_account, uid):
                        logging.info(f"Email UID {uid} already processed and notified, skipping...")
                        continue

                    try:
                        # BODY.PEEK[] fetches the full message without setting \Seen
                        _, msg = self.mail.uid('fetch', message, '(BODY.PEEK[])')
                        if not msg or msg[0] is None:
                            logging.warning(f"Failed to fetch email with UID {uid}")
                            continue

                        for response_part in msg:
                            if isinstance(response_part, tuple):
                                with self.metrics['PROCESSING_TIME'].time():
                                    try:
                                        email_message: EmailMessage = self.parse_email(response_part[1])
                                        sender: Optional[str] = email_message.get('From')
                                        subject: Optional[str] = email_message.get('Subject')
                                        logging.info(f"Processing Email - UID: {uid}, Sender: {sender}, Subject: {subject}")

                                        try:
                                            self.notifier.send_notification(sender, subject)
                                            self.metrics['NOTIFICATIONS_SENT'].inc()
                                        except Exception as e:
                                            logging.error(f"Failed to send notification: {str(e)}")
                                            self.metrics['ERRORS'].inc()

                                        db_handler.add_email(self.email_account, uid, 1)
                                        self.metrics['EMAILS_PROCESSED'].inc()
                                    except Exception as inner_e:
                                        logging.error(f"Error processing email content: {str(inner_e)}")
                                        self.metrics['ERRORS'].inc()
                    except Exception as e:
                        logging.error(f"Error fetching email with UID {uid}: {str(e)}")
                        self.metrics['ERRORS'].inc()

                # Prune old records to keep the database lean
                db_handler.delete_old_emails()
        except Exception as e:
            logging.error(f"Error in process method: {str(e)}")
            self.metrics['ERRORS'].inc()
            raise


class IMAPHandler:
    """Manages a single IMAP IDLE connection for one account/folder pair.

    Handles connecting, entering IMAP IDLE mode, detecting new mail
    via SELECT-based polling, and graceful shutdown via stop_event
    and the global shutdown socket.

    Attributes:
        host: IMAP server hostname.
        email_user: IMAP login username / email address.
        email_pass: IMAP login password (None for memory-only mode when not provided).
        folder: Mailbox folder to monitor (default: "inbox").
        notifier: Notifier instance for dispatching push notifications.
        metrics: Dict of Prometheus metric objects (or DummyMetric stubs).
        mail: The active imaplib.IMAP4_SSL connection, or None if disconnected.
        last_check: Datetime of the last successful IDLE cycle.
        last_error: String description of the most recent error, or None.
        retry_count: Number of consecutive failed connection attempts.
        healthy: False after an unrecoverable error; triggers reconnection.
        stop_event: Threading Event to signal this handler to shut down.
        credential_mode: 0 = stored (default), 1 = memory-only.
        needs_reauth: True when a memory-only handler needs client re-authentication.
        account_id: Database ID of the email account (for reauth handoff).
        account_name: Display name of the account (for logging/reauth pushes).
        reauth_failure_count: Number of consecutive failed auto-reauth attempts.
    """

    def __init__(
        self,
        host: str,
        email_user: str,
        email_pass: Optional[str],
        folder: str = "inbox",
        notifier: Optional[Notifier] = None,
        metrics: Optional[Dict[str, Any]] = None,
        credential_mode: int = 0,
        account_id: Optional[int] = None,
        account_name: Optional[str] = None,
    ) -> None:
        self.host = host
        self.email_user = email_user
        self.email_pass = email_pass
        self.folder = folder
        self.notifier = notifier
        self.metrics: Dict[str, Any] = metrics or {}
        self.mail: Optional[imaplib.IMAP4_SSL] = None
        self.last_check: Optional[datetime.datetime] = None
        self.last_error: Optional[str] = None
        self.retry_count: int = 0
        self.healthy: bool = True
        self.stop_event: threading.Event = threading.Event()
        self.credential_mode: int = credential_mode
        self.needs_reauth: bool = False
        self.account_id: Optional[int] = account_id
        self.account_name: Optional[str] = account_name
        self.reauth_failure_count: int = 0

    def _count_active_connections(self, all_handlers: List["IMAPHandler"]) -> int:
        """Count how many handlers have active IMAP connections.

        Args:
            all_handlers: The full list of IMAPHandler instances.

        Returns:
            The number of handlers whose mail attribute is not None.
        """
        return sum(1 for h in all_handlers if h.mail is not None)

    def connect(self, all_handlers: Optional[List["IMAPHandler"]] = None) -> bool:
        """Establish or verify the IMAP connection.

        If an existing connection is present, sends a NOOP to verify it
        is still alive. If the connection is stale or absent, creates a
        new IMAP4_SSL connection, logs in, and selects the folder.

        For memory-only mode (credential_mode=1), after successful LOGIN
        the password is immediately discarded from memory.

        On the first failure, a notification is sent to alert the user
        about the connection problem.

        Args:
            all_handlers: Optional list of all handlers, used to update
                         the active-connections Prometheus gauge.

        Returns:
            True if the connection is alive and the folder is selected,
            False if the connection attempt failed.
        """
        if notimail_config.shutdown_in_progress or self.stop_event.is_set():
            return False

        # Check if existing connection is still alive via NOOP
        if self.mail is not None:
            try:
                status, _ = self.mail.noop()
                if status == 'OK':
                    logging.info(f"[{self.email_user} - {self.folder}] Connection is still alive")
                    return True
            except Exception as e:
                logging.warning(f"[{self.email_user} - {self.folder}] Connection check failed: {str(e)}")

            # Existing connection is dead; clean it up
            try:
                self.mail.close()
                self.mail.logout()
            except:
                pass
            self.mail = None
            if all_handlers:
                self.metrics.get('CONNECTIONS', _DummyMetric()).set(
                    self._count_active_connections(all_handlers))

        # For memory-only mode, we need a password to connect
        if self.credential_mode == 1 and not self.email_pass:
            # No password available -- need reauth
            if not self.needs_reauth:
                self.needs_reauth = True
                self.last_error = "Waiting for client re-authentication"
                logging.info(f"[{self.email_user} - {self.folder}] Memory-only mode: waiting for reauth")
                _send_reauth_push(self.notifier, self.account_name or self.email_user, self.account_id or 0)
            return False

        # Establish a new connection
        try:
            logging.info(f"[{self.email_user} - {self.folder}] Connecting to IMAP server...")
            self.mail = imaplib.IMAP4_SSL(self.host, 993)
            self.mail.login(self.email_user, self.email_pass)
            self.mail.select(self.folder)
            logging.info(f"[{self.email_user} - {self.folder}] Successfully connected to IMAP server")

            # Memory-only mode: discard password immediately after successful LOGIN
            if self.credential_mode == 1:
                self.email_pass = None
                logging.info(f"[{self.email_user} - {self.folder}] Memory-only mode: password discarded after LOGIN")

            self.last_error = None
            self.retry_count = 0
            self.healthy = True
            self.needs_reauth = False
            self.reauth_failure_count = 0
            if all_handlers:
                self.metrics.get('CONNECTIONS', _DummyMetric()).set(
                    self._count_active_connections(all_handlers))
            return True
        except Exception as e:
            self.last_error = str(e)
            self.mail = None
            self.retry_count += 1
            self.metrics.get('RECONNECTS', _DummyMetric()).inc()
            if all_handlers:
                self.metrics.get('CONNECTIONS', _DummyMetric()).set(
                    self._count_active_connections(all_handlers))
            logging.error(f"[{self.email_user} - {self.folder}] Connection failed (attempt {self.retry_count}): {str(e)}")

            # For memory-only mode, discard the password even on failure
            # and switch to reauth mode
            if self.credential_mode == 1:
                self.email_pass = None
                self.needs_reauth = True
                _send_reauth_push(self.notifier, self.account_name or self.email_user, self.account_id or 0)

            # Notify on first failure only to avoid notification spam
            if self.notifier and self.retry_count == 1 and self.credential_mode == 0:
                try:
                    self.notifier.send_notification(
                        "Connection Error",
                        f"Failed to connect to {self.email_user} - {self.folder}: {str(e)}")
                except:
                    pass
            return False

    def idle(self) -> bool:
        """Enter IMAP IDLE mode and wait for new mail or timeout.

        Sends the IDLE command directly on the socket (imaplib does not
        natively support IDLE). Uses select() to multiplex between the
        IMAP socket and the global shutdown socket, allowing the thread
        to wake up immediately on shutdown.

        The IDLE loop runs for at most IDLE_TIMEOUT seconds (default 600s),
        checking every 30 seconds. This periodic exit allows the caller
        to verify the connection is still healthy.

        Returns:
            True if new mail was detected or the timeout was reached
            (caller should process emails in both cases).
            False if shutdown was signaled or an error occurred.
        """
        if not self.mail or notimail_config.shutdown_in_progress or self.stop_event.is_set():
            return False

        logging.info(f"[{self.email_user} - {self.folder}] IDLE mode started. Waiting for new email...")
        try:
            # Manually send the IDLE command since imaplib has no built-in IDLE support
            tag: str = self.mail._new_tag().decode()
            self.mail.send(f'{tag} IDLE\r\n'.encode('utf-8'))

            end_time: float = time.time() + IDLE_TIMEOUT

            while time.time() < end_time:
                # Poll in 30-second chunks so we can check for shutdown frequently
                timeout: float = min(30, end_time - time.time())
                if timeout <= 0:
                    break

                # Multiplex: wait for data on IMAP socket OR the shutdown signal socket
                rlist, _, _ = select.select([self.mail.sock, shutdown_sock_r], [], [], timeout)

                if self.stop_event.is_set():
                    self.mail.send(b'DONE\r\n')
                    self.mail.readline()
                    return False

                if shutdown_sock_r in rlist:
                    # Drain the shutdown signal byte(s)
                    shutdown_sock_r.recv(1024)
                    logging.info(f"[{self.email_user} - {self.folder}] Shutdown signal received during IDLE")
                    self.mail.send(b'DONE\r\n')
                    self.mail.readline()
                    return False

                if self.mail.sock in rlist:
                    line: str = self.mail.readline().decode('utf-8', errors='ignore')
                    if not line:
                        raise ConnectionAbortedError("Connection closed by server")

                    logging.debug(f"[{self.email_user} - {self.folder}] IDLE response: {line.strip()}")

                    # Server-side errors during IDLE indicate a broken connection
                    if 'BYE' in line or 'NO ' in line or 'BAD ' in line:
                        logging.warning(f"[{self.email_user} - {self.folder}] Received error from server: {line.strip()}")
                        raise ConnectionAbortedError(f"Server sent: {line.strip()}")

                    # EXISTS response means new mail has arrived
                    if 'EXISTS' in line:
                        logging.info(f"[{self.email_user} - {self.folder}] New email detected: {line.strip()}")
                        self.mail.send(b'DONE\r\n')
                        self.mail.readline()
                        self.last_check = datetime.datetime.now()
                        return True

            # IDLE timeout reached without new mail — still return True
            # so the caller can verify the connection and re-enter IDLE
            logging.info(f"[{self.email_user} - {self.folder}] IDLE timeout reached")
            self.metrics.get('IDLE_TIMEOUTS', _DummyMetric()).inc()
            self.mail.send(b'DONE\r\n')
            self.mail.readline()
            self.last_check = datetime.datetime.now()
            return True

        except Exception as e:
            logging.error(f"[{self.email_user} - {self.folder}] Error in IDLE: {str(e)}")
            self.last_error = str(e)
            self.metrics.get('ERRORS', _DummyMetric()).inc()
            self.healthy = False
            return False
        finally:
            logging.info(f"[{self.email_user} - {self.folder}] IDLE mode ended")

    def process_emails(self, db_path: str) -> bool:
        """Process unseen emails on this connection.

        Creates an EmailProcessor and delegates to it. If processing
        fails, marks the handler as unhealthy so the monitor loop
        will reconnect.

        Args:
            db_path: Filesystem path to the SQLite database.

        Returns:
            True if processing succeeded, False on error.
        """
        if not self.mail or not self.healthy:
            return False

        try:
            processor = EmailProcessor(
                self.mail, self.email_user, self.notifier, db_path, self.metrics)
            processor.process()
            return True
        except Exception as e:
            logging.error(f"[{self.email_user} - {self.folder}] Error processing emails: {str(e)}")
            self.last_error = str(e)
            self.metrics.get('ERRORS', _DummyMetric()).inc()
            self.healthy = False
            return False

    def provide_reauth_credentials(self, email_user: str, email_pass: str, host: str) -> None:
        """Provide credentials for re-authentication (memory-only mode).

        Called by the reauth API endpoint to hand credentials to a
        waiting handler. The credentials are stored temporarily and
        will be discarded after the next successful LOGIN.

        Args:
            email_user: IMAP login username.
            email_pass: IMAP login password.
            host: IMAP server hostname.
        """
        self.email_user = email_user
        self.email_pass = email_pass
        self.host = host
        self.needs_reauth = False
        self.healthy = True
        logging.info(f"[{self.email_user} - {self.folder}] Reauth credentials provided")


class MultiIMAPHandler:
    """Orchestrates monitoring of multiple IMAP accounts concurrently.

    Creates one IMAPHandler per account/folder pair and runs each in
    its own daemon thread. The run() method blocks until all threads
    complete (which normally only happens on shutdown).

    Supports dynamic account reload: the connection_watchdog calls
    reload_accounts() every 60 seconds to pick up new/changed/disabled
    accounts from the database without a restart.

    Attributes:
        accounts: List of account configuration dicts.
        metrics: Shared Prometheus metrics dict.
        db_path: Filesystem path to the SQLite database.
        handlers: List of IMAPHandler instances (one per account).
        lock: Threading lock used to serialize email processing.
        threads: List of monitoring threads (one per handler).
        registry: Dict mapping (email_user, folder) to handler index for diffing.
        account_loader: Optional callable that returns fresh account list from DB.
    """

    def __init__(
        self,
        accounts: List[Dict[str, Any]],
        metrics: Optional[Dict[str, Any]] = None,
        db_path: Optional[str] = None,
        account_loader: Optional[Any] = None,
        db: Optional[DatabaseHandler] = None,
        server_url: Optional[str] = None,
    ) -> None:
        self.accounts = accounts
        self.metrics: Dict[str, Any] = metrics or {}
        self.db_path: str = db_path or "processed_emails.db"
        self.account_loader = account_loader  # callable returning List[Dict] or None
        self.db: Optional[DatabaseHandler] = db
        self.server_url: Optional[str] = server_url
        self.handlers: List[IMAPHandler] = [
            IMAPHandler(
                account['Host'], account['EmailUser'], account['EmailPass'],
                account['Folder'], account['Notifier'], metrics=self.metrics,
                credential_mode=account.get('credential_mode', 0),
                account_id=account.get('account_id'),
                account_name=account.get('account_name'),
            )
            for account in accounts
        ]
        self.lock: Lock = Lock()
        self.threads: List[threading.Thread] = []
        # Build registry for diffing: (email_user, folder) -> index
        self._registry: Dict[tuple, int] = {
            (h.email_user, h.folder): i for i, h in enumerate(self.handlers)
        }

    def run(self) -> None:
        """Start monitoring threads and block until shutdown.

        If no accounts are configured, blocks and waits — the watchdog's
        reload_accounts() will spawn threads as accounts are added via API.
        """
        self.threads = []
        for handler in self.handlers:
            thread = threading.Thread(
                target=self.monitor_account, args=(handler,),
                name=f"{handler.email_user}-{handler.folder}")
            thread.daemon = True
            self.threads.append(thread)
            thread.start()

        # Block until shutdown, periodically joining any threads.
        # This keeps main() alive even when there are no accounts yet.
        while not notimail_config.shutdown_in_progress:
            alive_threads = [t for t in self.threads if t.is_alive()]
            if alive_threads:
                for t in alive_threads:
                    t.join(timeout=5)
            else:
                # No threads running — sleep and wait for reload_accounts to add some
                time.sleep(5)

    def reload_accounts(self) -> None:
        """Reload accounts from the database and start/stop handlers as needed.

        Called by connection_watchdog every 60 seconds. Compares the current
        set of running handlers against the latest account list from the DB.

        - New accounts: create handler + thread
        - Removed/disabled accounts: signal handler to stop
        - Changed accounts (updated_at newer): stop old, start new
        """
        if not self.account_loader:
            return

        try:
            fresh_accounts = self.account_loader()
        except Exception as e:
            logging.error(f"Failed to reload accounts from DB: {e}")
            return

        fresh_keys = {(a['EmailUser'], a['Folder']) for a in fresh_accounts}
        current_keys = set(self._registry.keys())

        # Detect new accounts
        new_keys = fresh_keys - current_keys
        for acct in fresh_accounts:
            key = (acct['EmailUser'], acct['Folder'])
            if key not in new_keys:
                continue

            handler = IMAPHandler(
                acct['Host'], acct['EmailUser'], acct['EmailPass'],
                acct['Folder'], acct['Notifier'], metrics=self.metrics,
                credential_mode=acct.get('credential_mode', 0),
                account_id=acct.get('account_id'),
                account_name=acct.get('account_name'),
            )

            with self.lock:
                idx = len(self.handlers)
                self.handlers.append(handler)
                self._registry[key] = idx

                thread = threading.Thread(
                    target=self.monitor_account, args=(handler,),
                    name=f"{handler.email_user}-{handler.folder}")
                thread.daemon = True
                self.threads.append(thread)
                thread.start()

            logging.info(f"Dynamic reload: started monitoring {acct['EmailUser']} - {acct['Folder']}")

        # Detect removed accounts
        removed_keys = current_keys - fresh_keys
        for key in removed_keys:
            idx = self._registry.get(key)
            if idx is None:
                continue
            handler = self.handlers[idx]
            handler.stop_event.set()
            logging.info(f"Dynamic reload: stopping {handler.email_user} - {handler.folder}")
            # Don't remove from registry — thread will exit on its own

    def get_handler_by_account_id(self, account_id: int) -> Optional[IMAPHandler]:
        """Find a handler by its account_id.

        Args:
            account_id: The database ID of the email account.

        Returns:
            The matching IMAPHandler, or None if not found.
        """
        for handler in self.handlers:
            if handler.account_id == account_id:
                return handler
        return None

    def _send_manual_reauth(self, handler: IMAPHandler) -> None:
        """Generate a reauth token and send a manual reauth notification.

        Called when auto-reauth has failed repeatedly (reauth_failure_count >= 3).
        Creates a one-time token and sends a clickable notification link so the
        user can re-enter credentials via the web interface.

        Args:
            handler: The IMAPHandler that needs manual re-authentication.
        """
        import secrets

        if not self.db or not handler.account_id:
            logging.warning(
                f"[{handler.email_user}] Cannot send manual reauth: "
                f"db={'yes' if self.db else 'no'}, account_id={handler.account_id}")
            return

        token = secrets.token_urlsafe(32)
        expires_at = (
            datetime.datetime.now() + datetime.timedelta(hours=24)
        ).strftime("%Y-%m-%d %H:%M:%S")
        self.db.add_reauth_token(handler.account_id, token, expires_at)

        reauth_url = f"{self.server_url}/reauth/{token}" if self.server_url else f"/reauth/{token}"
        logging.info(
            f"[{handler.email_user}] Manual reauth token generated: {reauth_url}")

        if handler.notifier:
            for provider in handler.notifier.providers:
                if hasattr(provider, 'ntfy_data'):
                    for ntfy_url, ntfy_token in provider.ntfy_data:
                        headers: dict = {}
                        if ntfy_token:
                            headers["Authorization"] = f"Bearer {ntfy_token}"
                        headers["Title"] = "UP Bridge: Manual Re-authentication Required"
                        headers["Click"] = reauth_url
                        data = (
                            f"Auto re-authentication failed for "
                            f"{handler.account_name or handler.email_user}. "
                            f"Tap to re-authenticate."
                        ).encode('utf-8')
                        try:
                            requests.post(ntfy_url, data=data, headers=headers)
                            logging.info(
                                f"Sent manual reauth notification for "
                                f"{handler.email_user} to {ntfy_url}")
                        except requests.RequestException as e:
                            logging.error(
                                f"Error sending manual reauth notification to "
                                f"{ntfy_url}: {e}")
                else:
                    try:
                        provider.send_notification(
                            "UP Bridge: Manual Re-authentication Required",
                            f"Auto re-authentication failed for "
                            f"{handler.account_name or handler.email_user}. "
                            f"Use this link to re-authenticate: {reauth_url}")
                    except Exception as e:
                        logging.error(f"Error sending manual reauth notification: {e}")

    def monitor_account(self, handler: IMAPHandler) -> None:
        """Main loop for monitoring a single IMAP account.

        Repeatedly connects, enters IDLE, processes new emails, and
        handles errors with exponential backoff. Runs until the global
        shutdown flag is set or the handler's stop_event is triggered.

        For memory-only accounts (credential_mode=1), if the connection
        drops, the handler enters a waiting state and checks for pending
        reauth credentials instead of retrying with stored credentials.

        Args:
            handler: The IMAPHandler instance to monitor.
        """
        logging.info(f"Monitoring {handler.email_user} - Folder: {handler.folder}")
        backoff_time: int = RETRY_DELAY

        while not notimail_config.shutdown_in_progress and not handler.stop_event.is_set():
            # Track whether this iteration is a reauth attempt
            _was_reauth_attempt = False

            # Check for pending reauth credentials (memory-only mode)
            if handler.needs_reauth and handler.account_id is not None:
                with pending_reauth_lock:
                    creds = pending_reauth.pop(handler.account_id, None)
                if creds:
                    handler.provide_reauth_credentials(
                        creds['email_user'], creds['email_pass'], creds['host'])
                    _was_reauth_attempt = True
                else:
                    # Still waiting -- sleep and check again
                    time.sleep(5)
                    continue

            try:
                if not handler.connect(all_handlers=self.handlers):
                    # If this was a reauth attempt and login failed,
                    # increment the failure counter for auto->manual fallback
                    if _was_reauth_attempt and handler.needs_reauth:
                        handler.reauth_failure_count += 1
                        logging.warning(
                            f"[{handler.email_user}] Reauth attempt failed "
                            f"(count={handler.reauth_failure_count})")
                        if handler.reauth_failure_count >= 3:
                            handler.last_error = (
                                "Auto re-authentication failed. Manual reauth link sent.")
                            self._send_manual_reauth(handler)

                    if handler.needs_reauth:
                        # Memory-only mode: don't retry, wait for reauth
                        continue

                    # Exponential backoff capped at 300 seconds (5 minutes)
                    retry_time: int = min(backoff_time * (handler.retry_count % 5), 300)
                    logging.info(f"[{handler.email_user} - {handler.folder}] Retrying connection in {retry_time} seconds")

                    # Sleep in 1-second increments to respond quickly to shutdown
                    wait_until: float = time.time() + retry_time
                    while time.time() < wait_until and not notimail_config.shutdown_in_progress and not handler.stop_event.is_set():
                        time.sleep(1)

                    continue

                # Reset backoff on successful connection
                backoff_time = RETRY_DELAY

                # Inner loop: IDLE -> process -> verify -> repeat
                while handler.healthy and not notimail_config.shutdown_in_progress and not handler.stop_event.is_set():
                    idle_result: bool = handler.idle()
                    if not idle_result:
                        break

                    # Serialize email processing across all handler threads
                    with self.lock:
                        if not handler.process_emails(self.db_path):
                            break

                    # Verify the connection is still alive after processing
                    try:
                        status, _ = handler.mail.noop()
                        if status != 'OK':
                            logging.warning(f"[{handler.email_user} - {handler.folder}] NOOP check failed after processing")
                            break
                    except Exception as e:
                        logging.warning(f"[{handler.email_user} - {handler.folder}] NOOP check error: {str(e)}")
                        break

            except ConnectionAbortedError as e:
                logging.error(f"[{handler.email_user} - {handler.folder}] Connection aborted: {str(e)}")
                handler.last_error = str(e)
                handler.healthy = False
                self.metrics.get('ERRORS', _DummyMetric()).inc()
            except Exception as e:
                logging.error(f"[{handler.email_user} - {handler.folder}] Unexpected error: {str(e)}")
                handler.last_error = str(e)
                handler.healthy = False
                self.metrics.get('ERRORS', _DummyMetric()).inc()

            # Clean up the dead connection before retrying
            if handler.mail:
                try:
                    handler.mail.close()
                    handler.mail.logout()
                except:
                    pass
                handler.mail = None
                self.metrics.get('CONNECTIONS', _DummyMetric()).set(
                    sum(1 for h in self.handlers if h.mail is not None))

            # For memory-only mode, trigger reauth on connection loss
            if handler.credential_mode == 1 and not handler.needs_reauth:
                handler.email_pass = None
                handler.needs_reauth = True

                if handler.reauth_failure_count >= 3:
                    # Auto-reauth has failed repeatedly -- switch to manual
                    handler.last_error = "Auto re-authentication failed. Manual reauth link sent."
                    self._send_manual_reauth(handler)
                else:
                    handler.last_error = "Connection lost. Waiting for client re-authentication."
                    _send_reauth_push(handler.notifier, handler.account_name or handler.email_user, handler.account_id or 0)

            # Brief pause before reconnection attempt
            if not notimail_config.shutdown_in_progress and not handler.stop_event.is_set():
                time.sleep(5)


def connection_watchdog(multi_handler: MultiIMAPHandler) -> None:
    """Monitor handler threads, restart dead ones, and reload accounts from DB.

    Runs in its own thread, checking every 60 seconds:
    1. Whether each monitoring thread is still alive (restart if dead).
    2. Whether new accounts have been added or existing ones removed/disabled
       in the database (via multi_handler.reload_accounts()).

    Args:
        multi_handler: The MultiIMAPHandler whose threads to watch.
    """
    while not notimail_config.shutdown_in_progress:
        time.sleep(60)

        if notimail_config.shutdown_in_progress:
            break

        # Reload accounts from DB (picks up new/changed/disabled accounts)
        multi_handler.reload_accounts()

        # Cleanup expired reauth tokens
        if multi_handler.db:
            try:
                cleaned = multi_handler.db.cleanup_expired_reauth_tokens()
                if cleaned > 0:
                    logging.info(f"Cleaned up {cleaned} expired/used reauth token(s)")
            except Exception as e:
                logging.error(f"Error cleaning up reauth tokens: {e}")

        for i, thread in enumerate(multi_handler.threads):
            if not thread.is_alive() and not notimail_config.shutdown_in_progress:
                handler: IMAPHandler = multi_handler.handlers[i]
                logging.warning(f"Thread for {handler.email_user} - {handler.folder} has died. Restarting...")

                # Clean up any lingering IMAP connection
                if handler.mail:
                    try:
                        handler.mail.close()
                        handler.mail.logout()
                    except:
                        pass
                    handler.mail = None

                # Reset handler state so it can reconnect cleanly
                handler.healthy = True
                handler.stop_event.clear()

                new_thread = threading.Thread(
                    target=multi_handler.monitor_account,
                    args=(handler,),
                    name=f"{handler.email_user}-{handler.folder}")
                new_thread.daemon = True
                multi_handler.threads[i] = new_thread
                new_thread.start()

                # Notify the user that a thread was automatically restarted
                if handler.notifier:
                    try:
                        handler.notifier.send_notification(
                            "Thread Restarted",
                            f"Monitoring thread for {handler.email_user} - {handler.folder} has been restarted")
                    except:
                        pass


class _DummyMetric:
    """Fallback metric that does nothing, used when metrics dict is incomplete.

    This is a module-internal version used by IMAPHandler when a metric
    key is missing from the dict. The public equivalent lives in
    notimail.config.DummyMetric.
    """

    def inc(self, amount: int = 1) -> None:
        """No-op increment."""
        pass

    def set(self, value: float) -> None:
        """No-op set."""
        pass

    def time(self) -> "_Timer":
        """Return a no-op context manager.

        Returns:
            A context manager that does nothing on enter/exit.
        """
        class _Timer:
            def __enter__(self) -> None:
                pass
            def __exit__(self, *a: Any) -> None:
                pass
        return _Timer()
