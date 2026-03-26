"""Tests for notimail.crypto.CryptoManager."""

import os
import stat

import pytest
from cryptography.fernet import InvalidToken

from notimail.crypto import CryptoManager


class TestCryptoManager:

    def test_key_generation(self, tmp_path):
        """Auto-generates key file; verify it exists and has correct permissions."""
        key_path = str(tmp_path / "auto_secret.key")
        assert not os.path.exists(key_path)

        cm = CryptoManager(key_path)

        assert os.path.exists(key_path)
        mode = os.stat(key_path).st_mode
        # Owner read+write only (0600)
        assert mode & 0o777 == stat.S_IRUSR | stat.S_IWUSR

    def test_encrypt_decrypt(self, crypto_manager):
        """Round-trip encryption preserves plaintext."""
        plaintext = "hello world! unicode: \u00e9\u00e8\u00ea"
        ciphertext = crypto_manager.encrypt(plaintext)
        assert ciphertext != plaintext
        assert crypto_manager.decrypt(ciphertext) == plaintext

    def test_decrypt_wrong_key(self, tmp_path):
        """Decrypting with a different key raises InvalidToken."""
        cm1 = CryptoManager(str(tmp_path / "key1.key"))
        cm2 = CryptoManager(str(tmp_path / "key2.key"))

        ciphertext = cm1.encrypt("secret data")
        with pytest.raises(InvalidToken):
            cm2.decrypt(ciphertext)

    def test_hmac_hash(self, crypto_manager):
        """Same input produces same hash; different input produces different hash."""
        h1 = crypto_manager.hmac_hash("alice")
        h2 = crypto_manager.hmac_hash("alice")
        h3 = crypto_manager.hmac_hash("bob")

        assert h1 == h2
        assert h1 != h3
        # Should be hex-encoded SHA256 length
        assert len(h1) == 64

    def test_hkdf_derived_keys(self, crypto_manager):
        """hmac_key and flask_secret_key are different from each other and from the fernet key."""
        assert crypto_manager.hmac_key != crypto_manager.flask_secret_key
        assert crypto_manager.hmac_key != crypto_manager._fernet_key
        assert crypto_manager.flask_secret_key != crypto_manager._fernet_key
