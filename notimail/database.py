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


class DatabaseHandler:
    """SQLite database handler with thread-safe connections.

    Uses threading.local() to give each thread its own connection,
    and WAL journal mode for concurrent read access.
    """
    def __init__(self, db_path=None):
        self.db_path = db_path or "processed_emails.db"
        self._local = threading.local()
        # Initialize on the creating thread
        conn = self._get_conn()
        self._create_table(conn)
        self._update_schema_if_needed(conn)

    def _get_conn(self):
        """Get or create a thread-local database connection."""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
        return self._local.conn

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def _create_table(self, conn):
        conn.execute('''
        CREATE TABLE IF NOT EXISTS processed_emails (
            email_account TEXT,
            uid TEXT,
            notified INTEGER,
            processed_date TEXT,
            PRIMARY KEY(email_account, uid)
        )''')
        conn.commit()

    def _update_schema_if_needed(self, conn):
        cursor = conn.execute("PRAGMA table_info(processed_emails)")
        columns = [column[1] for column in cursor.fetchall()]
        if 'email_account' not in columns:
            conn.execute(
                "ALTER TABLE processed_emails ADD COLUMN email_account TEXT DEFAULT 'unknown'")
            conn.execute(
                "CREATE UNIQUE INDEX idx_email_account_uid ON processed_emails(email_account, uid)")
            conn.commit()

    def add_email(self, email_account, uid, notified):
        """Record a processed email in the database."""
        conn = self._get_conn()
        date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT OR REPLACE INTO processed_emails "
            "(email_account, uid, notified, processed_date) VALUES (?, ?, ?, ?)",
            (email_account, uid, notified, date_str))
        conn.commit()

    def is_email_notified(self, email_account, uid):
        """Check if an email has already been notified."""
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT 1 FROM processed_emails WHERE email_account = ? AND uid = ? AND notified = 1",
            (email_account, uid))
        return cursor.fetchone() is not None

    def delete_old_emails(self, days=7):
        """Remove processed email records older than the given number of days."""
        conn = self._get_conn()
        date_limit_str = (
            datetime.datetime.now() - datetime.timedelta(days=days)
        ).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "DELETE FROM processed_emails WHERE processed_date < ?",
            (date_limit_str,))
        conn.commit()

    def close(self):
        """Close the current thread's database connection."""
        if hasattr(self._local, 'conn') and self._local.conn is not None:
            self._local.conn.close()
            self._local.conn = None
