"""Tests for notimail.auth module."""

import datetime
import hashlib
import time

import pytest

from notimail.auth import (
    hash_password,
    check_password,
    generate_api_key,
    validate_api_key,
    create_invite,
    redeem_invite,
    RateLimiter,
)


class TestPasswordHashing:

    def test_hash_check_password(self):
        """Hash and verify succeeds for correct password."""
        pw = "mysecurepassword"
        hashed = hash_password(pw)
        assert check_password(pw, hashed) is True

    def test_wrong_password(self):
        """Verify fails with wrong password."""
        hashed = hash_password("correct")
        assert check_password("wrong", hashed) is False


class TestApiKeyGeneration:

    def test_generate_api_key(self):
        """Returns (raw, hash, prefix); hash is sha256 of raw; prefix is first 8 chars."""
        raw, key_hash, prefix = generate_api_key()

        assert len(raw) > 8
        assert prefix == raw[:8]
        expected_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        assert key_hash == expected_hash

    def test_validate_api_key(self, tmp_db, admin_user, api_key):
        """Store key in DB, validate returns the record."""
        record = validate_api_key(api_key, tmp_db)
        assert record is not None
        assert record["user_id"] == admin_user[0]

    def test_validate_revoked_key(self, tmp_db, admin_user, api_key):
        """Revoked key returns None."""
        # First validate to get the record
        record = validate_api_key(api_key, tmp_db)
        assert record is not None

        # Revoke it
        tmp_db.revoke_api_key(record["id"], admin_user[0])

        # Now validation should return None
        assert validate_api_key(api_key, tmp_db) is None


class TestInvites:

    def test_create_redeem_invite(self, tmp_db, crypto_manager, admin_user):
        """Create invite, redeem it, verify user created."""
        user_id, _, _ = admin_user
        code = create_invite(tmp_db, created_by=user_id, expire_days=7)
        assert code is not None

        new_user_id = redeem_invite(
            tmp_db, crypto_manager, code, "newuser", "password1234"
        )
        assert new_user_id is not None

        # Verify the user exists
        lookup = crypto_manager.hmac_hash("newuser")
        user = tmp_db.get_user_by_lookup(lookup)
        assert user is not None
        assert user["id"] == new_user_id

    def test_expired_invite(self, tmp_db, crypto_manager, admin_user):
        """Create invite with past expiry, redeem returns None."""
        user_id, _, _ = admin_user
        past = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        tmp_db.add_invite("expiredcode", created_by=user_id, expires_at=past)

        result = redeem_invite(
            tmp_db, crypto_manager, "expiredcode", "lateuser", "password1234"
        )
        assert result is None


class TestRateLimiter:

    def test_rate_limiter_gentle(self):
        """Wrong password triggers gentle lockout after threshold."""
        rl = RateLimiter(max_attempts=3, window_minutes=15, lockout_minutes=30)

        # Record failures for the same user up to threshold
        for i in range(3):
            result = rl.record_failure("10.0.0.1", "userhash1", username_exists=True)

        # At max_attempts, should get a lockout message
        assert result is not None
        assert rl.is_locked_out("10.0.0.1") is True

    def test_rate_limiter_enumeration(self):
        """Multiple non-existent usernames trigger aggressive lockout."""
        rl = RateLimiter(
            max_attempts=10,
            enum_threshold=3,
            window_minutes=15,
            enum_lockout_minutes=60,
        )

        # Try 3 different non-existent usernames from same IP
        rl.record_failure("10.0.0.2", "fake1", username_exists=False)
        rl.record_failure("10.0.0.2", "fake2", username_exists=False)
        result = rl.record_failure("10.0.0.2", "fake3", username_exists=False)

        assert result is not None
        assert "Suspicious" in result
        assert rl.is_locked_out("10.0.0.2") is True

    def test_rate_limiter_spray(self):
        """Multiple valid usernames failing trigger aggressive lockout."""
        rl = RateLimiter(
            max_attempts=10,
            spray_threshold=3,
            spray_window_minutes=5,
            enum_lockout_minutes=60,
        )

        # Try wrong password for 3 different valid users from same IP
        rl.record_failure("10.0.0.3", "real1", username_exists=True)
        rl.record_failure("10.0.0.3", "real2", username_exists=True)
        result = rl.record_failure("10.0.0.3", "real3", username_exists=True)

        assert result is not None
        assert "Suspicious" in result
        assert rl.is_locked_out("10.0.0.3") is True
