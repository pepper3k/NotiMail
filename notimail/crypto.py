"""
Cryptographic utilities for NotiMail.

Provides Fernet-based encryption/decryption for credential storage,
HKDF-based key derivation for HMAC lookups and Flask session keys,
per-user key derivation via PBKDF2, and automatic key file generation.
"""

import base64
import hashlib
import hmac
import logging
import os
import stat
import threading
from typing import Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class CryptoManager:
    """Manages Fernet encryption and HKDF-derived keys for NotiMail.

    On initialization, loads (or generates) a Fernet key from a file,
    then derives sub-keys for HMAC lookups and Flask sessions using HKDF.

    Attributes:
        key_path: Filesystem path to the Fernet key file.
        fernet: Fernet instance for encrypt/decrypt operations.
        hmac_key: Derived key bytes for HMAC-SHA256 lookups.
        flask_secret_key: Derived key bytes for Flask session signing.
    """

    def __init__(self, key_path: str = "/etc/notimail/secret.key") -> None:
        """Initialize the crypto manager.

        Loads the Fernet key from key_path, creating it if it does not
        exist. Derives HMAC and Flask session keys via HKDF.

        Args:
            key_path: Path to the Fernet key file. The file will be
                     created with mode 0600 if it does not exist.
        """
        self.key_path: str = key_path
        self._fernet_key: bytes = self._load_or_generate_key()
        self.fernet: Fernet = Fernet(self._fernet_key)

        # Derive separate sub-keys using HKDF so a compromise of one
        # derived key does not directly expose the master Fernet key.
        self.hmac_key: bytes = self._derive_key(b"hmac-lookup-key")
        self.flask_secret_key: bytes = self._derive_key(b"flask-session-key")

    def _load_or_generate_key(self) -> bytes:
        """Load the Fernet key from disk, or generate and save a new one.

        If the key file does not exist, a new Fernet key is generated,
        written to disk, and its permissions are set to 0600 (owner
        read/write only).

        Returns:
            The raw Fernet key bytes (URL-safe base64).
        """
        if os.path.exists(self.key_path):
            with open(self.key_path, 'rb') as f:
                key = f.read().strip()
            logging.info(f"Loaded encryption key from {self.key_path}")
            return key

        # Generate a new key and ensure the directory exists
        key = Fernet.generate_key()
        key_dir = os.path.dirname(self.key_path)
        if key_dir:
            os.makedirs(key_dir, exist_ok=True)

        with open(self.key_path, 'wb') as f:
            f.write(key)

        # Restrict permissions to owner only (chmod 600)
        os.chmod(self.key_path, stat.S_IRUSR | stat.S_IWUSR)
        logging.info(f"Generated new encryption key at {self.key_path} (mode 0600)")
        return key

    def _derive_key(self, label: bytes, length: int = 32) -> bytes:
        """Derive a sub-key from the master Fernet key using HKDF.

        Args:
            label: Context label for key separation (e.g. b"hmac-lookup-key").
            length: Desired output key length in bytes. Defaults to 32.

        Returns:
            The derived key bytes.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=label,
        )
        # Use the raw Fernet key bytes as the input key material
        return hkdf.derive(self._fernet_key)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a plaintext string using Fernet.

        Args:
            plaintext: The string to encrypt.

        Returns:
            The Fernet token as a UTF-8 string (URL-safe base64).
        """
        return self.fernet.encrypt(plaintext.encode('utf-8')).decode('utf-8')

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a Fernet token back to plaintext.

        Args:
            ciphertext: A Fernet token string (as returned by encrypt()).

        Returns:
            The original plaintext string.

        Raises:
            cryptography.fernet.InvalidToken: If the token is invalid
                or has been tampered with.
        """
        return self.fernet.decrypt(ciphertext.encode('utf-8')).decode('utf-8')

    def hmac_hash(self, value: str) -> str:
        """Compute an HMAC-SHA256 hash for deterministic lookups.

        Used for username_lookup and host_hash columns where we need
        to query encrypted fields without decrypting all rows.

        Args:
            value: The plaintext value to hash.

        Returns:
            Hex-encoded HMAC-SHA256 digest.
        """
        return hmac.new(
            self.hmac_key,
            value.encode('utf-8'),
            hashlib.sha256,
        ).hexdigest()


def derive_user_fernet(password: str, salt: bytes) -> Fernet:
    """Derive a Fernet instance from a user's password and salt using PBKDF2.

    Uses PBKDF2HMAC with SHA256 and 600,000 iterations to derive 32 bytes,
    then base64url-encodes the result to create a valid Fernet key.

    Args:
        password: The user's plaintext password.
        salt: A 16-byte salt (stored per-user in the database).

    Returns:
        A Fernet instance keyed to this user's password.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    derived = kdf.derive(password.encode("utf-8"))
    fernet_key = base64.urlsafe_b64encode(derived)
    return Fernet(fernet_key)


class UserKeyCache:
    """In-memory cache of per-user Fernet keys derived from passwords.

    After a user logs in, their password is used (together with a per-user
    salt) to derive a Fernet key which is cached here.  The IMAP account
    loader reads from this cache to decrypt accounts that have per-user
    encryption enabled.

    Thread-safe: all mutations are protected by a lock.
    """

    def __init__(self) -> None:
        self._keys: dict = {}  # user_id -> Fernet instance
        self._lock: threading.Lock = threading.Lock()

    def store(self, user_id: int, password: str, salt: bytes) -> None:
        """Derive a Fernet key from *password* + *salt* and cache it.

        Args:
            user_id: The user's database ID.
            password: The user's plaintext password (used only for derivation).
            salt: The user's 16-byte PBKDF2 salt.
        """
        fernet = derive_user_fernet(password, salt)
        with self._lock:
            self._keys[user_id] = fernet

    def get(self, user_id: int) -> Optional[Fernet]:
        """Return the cached Fernet for *user_id*, or ``None``."""
        with self._lock:
            return self._keys.get(user_id)

    def remove(self, user_id: int) -> None:
        """Remove a cached key (e.g. on logout)."""
        with self._lock:
            self._keys.pop(user_id, None)
