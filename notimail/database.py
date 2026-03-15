"""
Database operations for NotiMail.

Handles SQLite connection management, the processed_emails table,
and schema migrations. Thread-safe via connection-per-thread using
threading.local().
"""

import datetime
import logging
import sqlite3
import threading
from typing import Optional


class DatabaseHandler:
    """SQLite database handler with thread-safe connections.

    Uses threading.local() to give each thread its own connection,
    and WAL journal mode for concurrent read access.

    Attributes:
        db_path: Filesystem path to the SQLite database file.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        """Initialize the database handler.

        Opens a connection on the calling thread, creates the schema
        if it does not exist, and applies any pending migrations.

        Args:
            db_path: Path to the SQLite database file.
                     Defaults to "processed_emails.db".
        """
        self.db_path: str = db_path or "processed_emails.db"
        self._local: threading.local = threading.local()
        # Initialize on the creating thread
        conn: sqlite3.Connection = self._get_conn()
        self._create_table(conn)
        self._update_schema_if_needed(conn)

    def _get_conn(self) -> sqlite3.Connection:
        """Get or create a thread-local database connection.

        Each thread gets its own SQLite connection so that concurrent
        IMAP handler threads do not share a single connection (which
        is not safe with SQLite).

        Returns:
            A sqlite3.Connection bound to the current thread.
        """
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path)
            # WAL mode allows concurrent readers while one writer is active
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
        return self._local.conn

    def __enter__(self) -> "DatabaseHandler":
        """Support usage as a context manager."""
        return self

    def __exit__(
        self,
        exc_type: Optional[type],
        exc_value: Optional[BaseException],
        traceback: Optional[object],
    ) -> None:
        """Close the database connection when exiting a with-block."""
        self.close()

    def _create_table(self, conn: sqlite3.Connection) -> None:
        """Create the processed_emails table if it does not already exist.

        Args:
            conn: An active SQLite connection.
        """
        conn.execute('''
        CREATE TABLE IF NOT EXISTS processed_emails (
            email_account TEXT,
            uid TEXT,
            notified INTEGER,
            processed_date TEXT,
            PRIMARY KEY(email_account, uid)
        )''')
        conn.commit()

    def _update_schema_if_needed(self, conn: sqlite3.Connection) -> None:
        """Apply schema migrations for older databases.

        Adds the email_account column and a unique index if they are
        missing. This handles upgrades from the single-account schema
        used in NotiMail < 2.0.

        Args:
            conn: An active SQLite connection.
        """
        cursor: sqlite3.Cursor = conn.execute("PRAGMA table_info(processed_emails)")
        columns = [column[1] for column in cursor.fetchall()]
        if 'email_account' not in columns:
            conn.execute(
                "ALTER TABLE processed_emails ADD COLUMN email_account TEXT DEFAULT 'unknown'")
            conn.execute(
                "CREATE UNIQUE INDEX idx_email_account_uid ON processed_emails(email_account, uid)")
            conn.commit()

    def add_email(self, email_account: str, uid: str, notified: int) -> None:
        """Record a processed email in the database.

        Uses INSERT OR REPLACE so that re-processing the same UID
        updates the existing row rather than raising a constraint error.

        Args:
            email_account: The IMAP account identifier (e.g. user@example.com).
            uid: The IMAP UID of the email message.
            notified: 1 if a notification was sent, 0 otherwise.
        """
        conn: sqlite3.Connection = self._get_conn()
        date_str: str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT OR REPLACE INTO processed_emails "
            "(email_account, uid, notified, processed_date) VALUES (?, ?, ?, ?)",
            (email_account, uid, notified, date_str))
        conn.commit()

    def is_email_notified(self, email_account: str, uid: str) -> bool:
        """Check if an email has already been notified.

        Args:
            email_account: The IMAP account identifier.
            uid: The IMAP UID of the email message.

        Returns:
            True if a row exists with notified=1 for the given account/uid.
        """
        conn: sqlite3.Connection = self._get_conn()
        cursor: sqlite3.Cursor = conn.execute(
            "SELECT 1 FROM processed_emails WHERE email_account = ? AND uid = ? AND notified = 1",
            (email_account, uid))
        return cursor.fetchone() is not None

    def delete_old_emails(self, days: int = 7) -> None:
        """Remove processed email records older than the given number of days.

        This keeps the database from growing indefinitely. Called after
        each email processing cycle.

        Args:
            days: Records older than this many days will be deleted.
                  Defaults to 7.
        """
        conn: sqlite3.Connection = self._get_conn()
        date_limit_str: str = (
            datetime.datetime.now() - datetime.timedelta(days=days)
        ).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "DELETE FROM processed_emails WHERE processed_date < ?",
            (date_limit_str,))
        conn.commit()

    def close(self) -> None:
        """Close the current thread's database connection.

        Safe to call multiple times; subsequent calls are no-ops.
        """
        if hasattr(self._local, 'conn') and self._local.conn is not None:
            self._local.conn.close()
            self._local.conn = None
