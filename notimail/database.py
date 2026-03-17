"""
Database operations for NotiMail.

Handles SQLite connection management, the processed_emails table,
and schema migrations. Thread-safe via connection-per-thread using
threading.local().
"""

import datetime
import hashlib
import logging
import secrets
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Tuple


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

    # ------------------------------------------------------------------
    # Schema migration framework
    # ------------------------------------------------------------------

    # Ordered list of (version, list_of_sql_statements) tuples.
    # On startup, apply_migrations() runs any that haven't been applied yet.
    MIGRATIONS: List[Tuple[int, List[str]]] = [
        (1, [
            # Schema version tracking
            """CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            )""",
            # Users table
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                username_lookup TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                invited_by INTEGER REFERENCES users(id),
                created_at TEXT NOT NULL,
                last_login TEXT
            )""",
            # API keys
            """CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                key_hash TEXT UNIQUE NOT NULL,
                key_prefix TEXT NOT NULL,
                label TEXT,
                created_at TEXT NOT NULL,
                last_used TEXT,
                revoked INTEGER DEFAULT 0
            )""",
            # Invites
            """CREATE TABLE IF NOT EXISTS invites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE NOT NULL,
                created_by INTEGER NOT NULL REFERENCES users(id),
                redeemed_by INTEGER REFERENCES users(id),
                created_at TEXT NOT NULL,
                redeemed_at TEXT,
                expires_at TEXT
            )""",
            # Email accounts (encrypted credentials)
            """CREATE TABLE IF NOT EXISTS email_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                account_name TEXT NOT NULL,
                email_user_encrypted TEXT NOT NULL,
                email_pass_encrypted TEXT NOT NULL,
                host_encrypted TEXT NOT NULL,
                port INTEGER DEFAULT 993,
                folders TEXT NOT NULL DEFAULT 'inbox',
                enabled INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT,
                UNIQUE(user_id, account_name)
            )""",
            # Notification configs (encrypted JSON blobs)
            """CREATE TABLE IF NOT EXISTS notification_configs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_account_id INTEGER NOT NULL REFERENCES email_accounts(id) ON DELETE CASCADE,
                provider_type TEXT NOT NULL,
                config_encrypted TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT
            )""",
        ]),
        (2, [
            # Audit log for admin actions
            """CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_user_id INTEGER NOT NULL REFERENCES users(id),
                action TEXT NOT NULL,
                target_user_id INTEGER REFERENCES users(id),
                details TEXT,
                timestamp TEXT NOT NULL
            )""",
            # Add enabled column to users (default 1 = enabled)
            """ALTER TABLE users ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1""",
            # Password reset tokens
            """CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token TEXT UNIQUE NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            )""",
        ]),
        (3, [
            # Per-user PBKDF2 salt for deriving per-user encryption keys
            """ALTER TABLE users ADD COLUMN key_salt TEXT""",
            # Flag indicating whether an account's credentials use per-user encryption
            """ALTER TABLE email_accounts ADD COLUMN user_encrypted INTEGER NOT NULL DEFAULT 0""",
        ]),
    ]

    def apply_migrations(self) -> None:
        """Apply any pending schema migrations.

        Checks the schema_version table for the current version,
        then runs all migrations with a higher version number.
        Safe to call multiple times — already-applied migrations
        are skipped.
        """
        conn = self._get_conn()

        # Ensure schema_version table exists (bootstrap for fresh DBs)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
        """)
        conn.commit()

        cursor = conn.execute("SELECT MAX(version) FROM schema_version")
        row = cursor.fetchone()
        current_version: int = row[0] if row[0] is not None else 0

        for version, statements in self.MIGRATIONS:
            if version <= current_version:
                continue
            logging.info(f"Applying database migration v{version}...")
            for sql in statements:
                conn.execute(sql)
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (version, now))
            conn.commit()
            logging.info(f"Migration v{version} applied successfully.")

            # Post-migration hooks
            if version == 3:
                # Backfill key_salt for existing users that don't have one
                rows = conn.execute(
                    "SELECT id FROM users WHERE key_salt IS NULL"
                ).fetchall()
                for (uid,) in rows:
                    salt_hex = secrets.token_hex(16)  # 16 bytes = 32 hex chars
                    conn.execute(
                        "UPDATE users SET key_salt = ? WHERE id = ?",
                        (salt_hex, uid))
                if rows:
                    conn.commit()
                    logging.info(f"Backfilled key_salt for {len(rows)} existing user(s).")

    # ------------------------------------------------------------------
    # User operations
    # ------------------------------------------------------------------

    def add_user(
        self,
        username_encrypted: str,
        username_lookup: str,
        password_hash: str,
        role: str = "user",
        invited_by: Optional[int] = None,
    ) -> int:
        """Create a new user and return their ID.

        A random 16-byte key_salt is generated automatically for PBKDF2
        key derivation (used by per-user encryption).

        Args:
            username_encrypted: Fernet-encrypted username.
            username_lookup: HMAC-SHA256 hash of the username for lookups.
            password_hash: bcrypt hash of the password.
            role: 'admin' or 'user'.
            invited_by: User ID of the inviter, or None for the first admin.

        Returns:
            The new user's ID.
        """
        conn = self._get_conn()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        key_salt = secrets.token_hex(16)
        cursor = conn.execute(
            "INSERT INTO users (username, username_lookup, password_hash, role, invited_by, created_at, key_salt) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (username_encrypted, username_lookup, password_hash, role, invited_by, now, key_salt))
        conn.commit()
        return cursor.lastrowid

    def get_user_by_lookup(self, username_lookup: str) -> Optional[Dict[str, Any]]:
        """Find a user by their HMAC username lookup hash.

        Args:
            username_lookup: HMAC-SHA256 hex digest of the username.

        Returns:
            A dict with user fields, or None if not found.
        """
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT id, username, username_lookup, password_hash, role, invited_by, created_at, last_login, "
            "COALESCE(enabled, 1) as enabled, key_salt FROM users WHERE username_lookup = ?",
            (username_lookup,))
        row = cursor.fetchone()
        if row is None:
            return None
        return {
            'id': row[0], 'username': row[1], 'username_lookup': row[2],
            'password_hash': row[3], 'role': row[4], 'invited_by': row[5],
            'created_at': row[6], 'last_login': row[7], 'enabled': row[8],
            'key_salt': row[9],
        }

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Fetch a user by their ID."""
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT id, username, username_lookup, password_hash, role, invited_by, created_at, last_login, "
            "COALESCE(enabled, 1) as enabled, key_salt FROM users WHERE id = ?",
            (user_id,))
        row = cursor.fetchone()
        if row is None:
            return None
        return {
            'id': row[0], 'username': row[1], 'username_lookup': row[2],
            'password_hash': row[3], 'role': row[4], 'invited_by': row[5],
            'created_at': row[6], 'last_login': row[7], 'enabled': row[8],
            'key_salt': row[9],
        }

    def get_all_users(self) -> List[Dict[str, Any]]:
        """Return all users."""
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT id, username, username_lookup, password_hash, role, invited_by, created_at, last_login, "
            "COALESCE(enabled, 1) as enabled, key_salt FROM users")
        return [
            {'id': r[0], 'username': r[1], 'username_lookup': r[2],
             'password_hash': r[3], 'role': r[4], 'invited_by': r[5],
             'created_at': r[6], 'last_login': r[7], 'enabled': r[8],
             'key_salt': r[9]}
            for r in cursor.fetchall()
        ]

    def update_user_last_login(self, user_id: int) -> None:
        """Update the last_login timestamp for a user."""
        conn = self._get_conn()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (now, user_id))
        conn.commit()

    def update_user_password(self, user_id: int, password_hash: str) -> None:
        """Update a user's password hash."""
        conn = self._get_conn()
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
        conn.commit()

    def count_users(self) -> int:
        """Return the total number of users."""
        conn = self._get_conn()
        cursor = conn.execute("SELECT COUNT(*) FROM users")
        return cursor.fetchone()[0]

    def disable_user(self, user_id: int) -> None:
        """Disable a user account (prevent login)."""
        conn = self._get_conn()
        conn.execute("UPDATE users SET enabled = 0 WHERE id = ?", (user_id,))
        conn.commit()

    def enable_user(self, user_id: int) -> None:
        """Enable a user account."""
        conn = self._get_conn()
        conn.execute("UPDATE users SET enabled = 1 WHERE id = ?", (user_id,))
        conn.commit()

    def delete_user(self, user_id: int) -> None:
        """Delete a user and their associated data (email accounts cascade)."""
        conn = self._get_conn()
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()

    # ------------------------------------------------------------------
    # Audit log operations
    # ------------------------------------------------------------------

    def log_admin_action(
        self,
        admin_user_id: int,
        action: str,
        target_user_id: Optional[int] = None,
        details: Optional[str] = None,
    ) -> None:
        """Record an admin action in the audit log."""
        conn = self._get_conn()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO audit_log (admin_user_id, action, target_user_id, details, timestamp) "
            "VALUES (?, ?, ?, ?, ?)",
            (admin_user_id, action, target_user_id, details, now))
        conn.commit()

    # ------------------------------------------------------------------
    # Password reset token operations
    # ------------------------------------------------------------------

    def add_password_reset_token(
        self,
        user_id: int,
        token: str,
        expires_at: str,
    ) -> int:
        """Create a password reset token. Returns the token ID."""
        conn = self._get_conn()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor = conn.execute(
            "INSERT INTO password_reset_tokens (user_id, token, created_at, expires_at) "
            "VALUES (?, ?, ?, ?)",
            (user_id, token, now, expires_at))
        conn.commit()
        return cursor.lastrowid

    def get_password_reset_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Look up a password reset token."""
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT id, user_id, token, created_at, expires_at, used "
            "FROM password_reset_tokens WHERE token = ?",
            (token,))
        row = cursor.fetchone()
        if row is None:
            return None
        return {
            'id': row[0], 'user_id': row[1], 'token': row[2],
            'created_at': row[3], 'expires_at': row[4], 'used': row[5],
        }

    def mark_reset_token_used(self, token_id: int) -> None:
        """Mark a password reset token as used."""
        conn = self._get_conn()
        conn.execute(
            "UPDATE password_reset_tokens SET used = 1 WHERE id = ?",
            (token_id,))
        conn.commit()

    def count_email_accounts(self) -> int:
        """Return the total number of email accounts."""
        conn = self._get_conn()
        cursor = conn.execute("SELECT COUNT(*) FROM email_accounts")
        return cursor.fetchone()[0]

    def count_user_encrypted_accounts(self, user_id: int) -> int:
        """Return the number of per-user-encrypted accounts for a user."""
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT COUNT(*) FROM email_accounts "
            "WHERE user_id = ? AND COALESCE(user_encrypted, 0) = 1",
            (user_id,))
        return cursor.fetchone()[0]

    # ------------------------------------------------------------------
    # API key operations
    # ------------------------------------------------------------------

    def add_api_key(self, user_id: int, key_hash: str, key_prefix: str, label: Optional[str] = None) -> int:
        """Store a new API key (hashed) and return its ID."""
        conn = self._get_conn()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor = conn.execute(
            "INSERT INTO api_keys (user_id, key_hash, key_prefix, label, created_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, key_hash, key_prefix, label, now))
        conn.commit()
        return cursor.lastrowid

    def get_api_key_by_hash(self, key_hash: str) -> Optional[Dict[str, Any]]:
        """Look up an API key by its SHA-256 hash."""
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT id, user_id, key_hash, key_prefix, label, created_at, last_used, revoked "
            "FROM api_keys WHERE key_hash = ? AND revoked = 0",
            (key_hash,))
        row = cursor.fetchone()
        if row is None:
            return None
        return {
            'id': row[0], 'user_id': row[1], 'key_hash': row[2], 'key_prefix': row[3],
            'label': row[4], 'created_at': row[5], 'last_used': row[6], 'revoked': row[7],
        }

    def get_api_keys_for_user(self, user_id: int) -> List[Dict[str, Any]]:
        """List all API keys for a user (prefix and label only, no hash)."""
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT id, key_prefix, label, created_at, last_used, revoked "
            "FROM api_keys WHERE user_id = ?",
            (user_id,))
        return [
            {'id': r[0], 'key_prefix': r[1], 'label': r[2],
             'created_at': r[3], 'last_used': r[4], 'revoked': r[5]}
            for r in cursor.fetchall()
        ]

    def revoke_api_key(self, key_id: int, user_id: int) -> bool:
        """Revoke an API key. Returns True if the key was found and revoked."""
        conn = self._get_conn()
        cursor = conn.execute(
            "UPDATE api_keys SET revoked = 1 WHERE id = ? AND user_id = ?",
            (key_id, user_id))
        conn.commit()
        return cursor.rowcount > 0

    def update_api_key_last_used(self, key_id: int) -> None:
        """Update the last_used timestamp for an API key."""
        conn = self._get_conn()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("UPDATE api_keys SET last_used = ? WHERE id = ?", (now, key_id))
        conn.commit()

    # ------------------------------------------------------------------
    # Invite operations
    # ------------------------------------------------------------------

    def add_invite(self, code: str, created_by: int, expires_at: Optional[str] = None) -> int:
        """Create an invite code and return its ID."""
        conn = self._get_conn()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if expires_at is None:
            # Default expiry: 7 days
            expires_at = (datetime.datetime.now() + datetime.timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
        cursor = conn.execute(
            "INSERT INTO invites (code, created_by, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (code, created_by, now, expires_at))
        conn.commit()
        return cursor.lastrowid

    def get_invite_by_code(self, code: str) -> Optional[Dict[str, Any]]:
        """Look up an invite by its code."""
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT id, code, created_by, redeemed_by, created_at, redeemed_at, expires_at "
            "FROM invites WHERE code = ?",
            (code,))
        row = cursor.fetchone()
        if row is None:
            return None
        return {
            'id': row[0], 'code': row[1], 'created_by': row[2], 'redeemed_by': row[3],
            'created_at': row[4], 'redeemed_at': row[5], 'expires_at': row[6],
        }

    def redeem_invite(self, invite_id: int, user_id: int) -> None:
        """Mark an invite as redeemed by the given user."""
        conn = self._get_conn()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "UPDATE invites SET redeemed_by = ?, redeemed_at = ? WHERE id = ?",
            (user_id, now, invite_id))
        conn.commit()

    def get_invites_for_user(self, user_id: int) -> List[Dict[str, Any]]:
        """List all invites created by a user."""
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT id, code, created_by, redeemed_by, created_at, redeemed_at, expires_at "
            "FROM invites WHERE created_by = ?",
            (user_id,))
        return [
            {'id': r[0], 'code': r[1], 'created_by': r[2], 'redeemed_by': r[3],
             'created_at': r[4], 'redeemed_at': r[5], 'expires_at': r[6]}
            for r in cursor.fetchall()
        ]

    def cleanup_expired_invites(self) -> int:
        """Delete expired, unredeemed invites. Returns the number deleted."""
        conn = self._get_conn()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor = conn.execute(
            "DELETE FROM invites WHERE redeemed_by IS NULL AND expires_at < ?",
            (now,))
        conn.commit()
        return cursor.rowcount

    # ------------------------------------------------------------------
    # Email account operations
    # ------------------------------------------------------------------

    def add_email_account(
        self,
        user_id: int,
        account_name: str,
        email_user_encrypted: str,
        email_pass_encrypted: str,
        host_encrypted: str,
        port: int = 993,
        folders: str = "inbox",
    ) -> int:
        """Add an email account with encrypted credentials. Returns the account ID."""
        conn = self._get_conn()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor = conn.execute(
            "INSERT INTO email_accounts "
            "(user_id, account_name, email_user_encrypted, email_pass_encrypted, "
            "host_encrypted, port, folders, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (user_id, account_name, email_user_encrypted, email_pass_encrypted,
             host_encrypted, port, folders, now))
        conn.commit()
        return cursor.lastrowid

    def get_email_accounts_for_user(self, user_id: int) -> List[Dict[str, Any]]:
        """List all email accounts owned by a user."""
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT id, user_id, account_name, email_user_encrypted, email_pass_encrypted, "
            "host_encrypted, port, folders, enabled, created_at, updated_at, "
            "COALESCE(user_encrypted, 0) as user_encrypted "
            "FROM email_accounts WHERE user_id = ?",
            (user_id,))
        return [self._row_to_account(r) for r in cursor.fetchall()]

    def get_all_enabled_accounts(self) -> List[Dict[str, Any]]:
        """Get all enabled email accounts (for IMAP monitoring)."""
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT id, user_id, account_name, email_user_encrypted, email_pass_encrypted, "
            "host_encrypted, port, folders, enabled, created_at, updated_at, "
            "COALESCE(user_encrypted, 0) as user_encrypted "
            "FROM email_accounts WHERE enabled = 1")
        return [self._row_to_account(r) for r in cursor.fetchall()]

    def get_email_account_by_id(self, account_id: int) -> Optional[Dict[str, Any]]:
        """Fetch a single email account by ID."""
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT id, user_id, account_name, email_user_encrypted, email_pass_encrypted, "
            "host_encrypted, port, folders, enabled, created_at, updated_at, "
            "COALESCE(user_encrypted, 0) as user_encrypted "
            "FROM email_accounts WHERE id = ?",
            (account_id,))
        row = cursor.fetchone()
        return self._row_to_account(row) if row else None

    def update_email_account(self, account_id: int, **fields: Any) -> None:
        """Update fields on an email account. Accepts any column name as keyword arg."""
        conn = self._get_conn()
        fields['updated_at'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [account_id]
        conn.execute(f"UPDATE email_accounts SET {set_clause} WHERE id = ?", values)
        conn.commit()

    def delete_email_account(self, account_id: int) -> None:
        """Delete an email account and its notification configs (CASCADE)."""
        conn = self._get_conn()
        conn.execute("DELETE FROM email_accounts WHERE id = ?", (account_id,))
        conn.commit()

    def _row_to_account(self, row: tuple) -> Dict[str, Any]:
        """Convert a raw SQL row to an email account dict."""
        return {
            'id': row[0], 'user_id': row[1], 'account_name': row[2],
            'email_user_encrypted': row[3], 'email_pass_encrypted': row[4],
            'host_encrypted': row[5], 'port': row[6], 'folders': row[7],
            'enabled': row[8], 'created_at': row[9], 'updated_at': row[10],
            'user_encrypted': row[11] if len(row) > 11 else 0,
        }

    # ------------------------------------------------------------------
    # Notification config operations
    # ------------------------------------------------------------------

    def add_notification_config(
        self,
        email_account_id: int,
        provider_type: str,
        config_encrypted: str,
    ) -> int:
        """Add a notification config for an email account. Returns the config ID."""
        conn = self._get_conn()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor = conn.execute(
            "INSERT INTO notification_configs (email_account_id, provider_type, config_encrypted, created_at) "
            "VALUES (?, ?, ?, ?)",
            (email_account_id, provider_type, config_encrypted, now))
        conn.commit()
        return cursor.lastrowid

    def get_notification_configs_for_account(self, email_account_id: int) -> List[Dict[str, Any]]:
        """List notification configs for an email account."""
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT id, email_account_id, provider_type, config_encrypted, created_at, updated_at "
            "FROM notification_configs WHERE email_account_id = ?",
            (email_account_id,))
        return [
            {'id': r[0], 'email_account_id': r[1], 'provider_type': r[2],
             'config_encrypted': r[3], 'created_at': r[4], 'updated_at': r[5]}
            for r in cursor.fetchall()
        ]

    def delete_notification_config(self, config_id: int) -> None:
        """Delete a notification config."""
        conn = self._get_conn()
        conn.execute("DELETE FROM notification_configs WHERE id = ?", (config_id,))
        conn.commit()
