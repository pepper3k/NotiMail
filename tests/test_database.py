"""Tests for notimail.database.DatabaseHandler."""

import datetime

import pytest

from notimail.database import DatabaseHandler


class TestMigrations:

    def test_migrations_apply(self, tmp_path):
        """Fresh DB gets all migrations applied."""
        db = DatabaseHandler(str(tmp_path / "fresh.db"))
        db.apply_migrations()

        conn = db._get_conn()
        cursor = conn.execute("SELECT MAX(version) FROM schema_version")
        max_version = cursor.fetchone()[0]
        assert max_version == max(v for v, _ in DatabaseHandler.MIGRATIONS)
        db.close()

    def test_migrations_idempotent(self, tmp_path):
        """Running apply_migrations twice does not fail."""
        db = DatabaseHandler(str(tmp_path / "idem.db"))
        db.apply_migrations()
        db.apply_migrations()  # Should not raise

        conn = db._get_conn()
        cursor = conn.execute("SELECT COUNT(*) FROM schema_version")
        count = cursor.fetchone()[0]
        assert count == len(DatabaseHandler.MIGRATIONS)
        db.close()


class TestUserOperations:

    def test_add_get_user(self, tmp_db, crypto_manager):
        """Create user, retrieve by lookup."""
        lookup = crypto_manager.hmac_hash("alice")
        user_id = tmp_db.add_user(
            username_encrypted=crypto_manager.encrypt("alice"),
            username_lookup=lookup,
            password_hash="fakehash",
            role="user",
        )
        assert user_id is not None

        user = tmp_db.get_user_by_lookup(lookup)
        assert user is not None
        assert user["id"] == user_id
        assert user["role"] == "user"
        assert user["enabled"] == 1

    def test_user_enabled_disabled(self, tmp_db, crypto_manager):
        """Disable user, verify get returns enabled=0."""
        lookup = crypto_manager.hmac_hash("bob")
        user_id = tmp_db.add_user(
            username_encrypted=crypto_manager.encrypt("bob"),
            username_lookup=lookup,
            password_hash="fakehash",
        )
        tmp_db.disable_user(user_id)

        user = tmp_db.get_user_by_lookup(lookup)
        assert user["enabled"] == 0

        tmp_db.enable_user(user_id)
        user = tmp_db.get_user_by_lookup(lookup)
        assert user["enabled"] == 1

    def test_delete_user_cascades(self, tmp_db, crypto_manager):
        """Delete user with accounts, invites, audit log entries -- no FK errors."""
        lookup = crypto_manager.hmac_hash("charlie")
        user_id = tmp_db.add_user(
            username_encrypted=crypto_manager.encrypt("charlie"),
            username_lookup=lookup,
            password_hash="fakehash",
            role="admin",
        )

        # Create related data
        account_id = tmp_db.add_email_account(
            user_id=user_id,
            account_name="test_acct",
            email_user_encrypted="enc_user",
            email_pass_encrypted="enc_pass",
            host_encrypted="enc_host",
        )
        tmp_db.add_invite("invite123", created_by=user_id)
        tmp_db.log_admin_action(user_id, "test_action", target_user_id=user_id)

        # Should not raise
        tmp_db.delete_user(user_id)

        assert tmp_db.get_user_by_lookup(lookup) is None


class TestEmailAccountOperations:

    def test_add_get_email_account(self, tmp_db, crypto_manager):
        """Create account, retrieve by user_id."""
        user_id = tmp_db.add_user(
            username_encrypted=crypto_manager.encrypt("dave"),
            username_lookup=crypto_manager.hmac_hash("dave"),
            password_hash="fakehash",
        )
        account_id = tmp_db.add_email_account(
            user_id=user_id,
            account_name="my_mail",
            email_user_encrypted="enc_user",
            email_pass_encrypted="enc_pass",
            host_encrypted="enc_host",
            port=993,
            folders="inbox,sent",
        )

        accounts = tmp_db.get_email_accounts_for_user(user_id)
        assert len(accounts) == 1
        assert accounts[0]["id"] == account_id
        assert accounts[0]["account_name"] == "my_mail"
        assert accounts[0]["folders"] == "inbox,sent"

    def test_credential_mode(self, tmp_db, crypto_manager):
        """Create account with credential_mode=1, verify it persists."""
        user_id = tmp_db.add_user(
            username_encrypted=crypto_manager.encrypt("eve"),
            username_lookup=crypto_manager.hmac_hash("eve"),
            password_hash="fakehash",
        )
        account_id = tmp_db.add_email_account(
            user_id=user_id,
            account_name="mem_acct",
            email_user_encrypted="enc_user",
            email_pass_encrypted="",
            host_encrypted="enc_host",
        )
        tmp_db.update_email_account(account_id, credential_mode=1)

        acct = tmp_db.get_email_account_by_id(account_id)
        assert acct["credential_mode"] == 1


class TestNotificationConfigOperations:

    def test_notification_config_crud(self, tmp_db, crypto_manager):
        """Add, get, delete notification configs."""
        user_id = tmp_db.add_user(
            username_encrypted=crypto_manager.encrypt("frank"),
            username_lookup=crypto_manager.hmac_hash("frank"),
            password_hash="fakehash",
        )
        account_id = tmp_db.add_email_account(
            user_id=user_id,
            account_name="frank_mail",
            email_user_encrypted="enc_user",
            email_pass_encrypted="enc_pass",
            host_encrypted="enc_host",
        )

        config_id = tmp_db.add_notification_config(
            email_account_id=account_id,
            provider_type="ntfy",
            config_encrypted="encrypted_json_blob",
        )
        assert config_id is not None

        configs = tmp_db.get_notification_configs_for_account(account_id)
        assert len(configs) == 1
        assert configs[0]["provider_type"] == "ntfy"

        tmp_db.delete_notification_config(config_id)
        configs = tmp_db.get_notification_configs_for_account(account_id)
        assert len(configs) == 0


class TestApiKeyOperations:

    def test_api_key_crud(self, tmp_db, crypto_manager):
        """Add, lookup by hash, revoke."""
        user_id = tmp_db.add_user(
            username_encrypted=crypto_manager.encrypt("grace"),
            username_lookup=crypto_manager.hmac_hash("grace"),
            password_hash="fakehash",
        )

        key_hash = "abc123hash"
        key_prefix = "abc12345"
        key_id = tmp_db.add_api_key(user_id, key_hash, key_prefix, label="my key")

        record = tmp_db.get_api_key_by_hash(key_hash)
        assert record is not None
        assert record["user_id"] == user_id
        assert record["key_prefix"] == key_prefix

        tmp_db.revoke_api_key(key_id, user_id)
        record = tmp_db.get_api_key_by_hash(key_hash)
        assert record is None  # Revoked keys are excluded


class TestInviteOperations:

    def test_invite_crud(self, tmp_db, crypto_manager):
        """Add, get by code, redeem."""
        user_id = tmp_db.add_user(
            username_encrypted=crypto_manager.encrypt("heidi"),
            username_lookup=crypto_manager.hmac_hash("heidi"),
            password_hash="fakehash",
        )

        invite_id = tmp_db.add_invite("invitecode42", created_by=user_id)
        invite = tmp_db.get_invite_by_code("invitecode42")
        assert invite is not None
        assert invite["created_by"] == user_id
        assert invite["redeemed_by"] is None

        tmp_db.redeem_invite(invite_id, user_id=999)
        invite = tmp_db.get_invite_by_code("invitecode42")
        assert invite["redeemed_by"] == 999


class TestProcessedEmails:

    def test_processed_emails(self, tmp_db):
        """Add email, check notified, delete old."""
        tmp_db.add_email("acct@test.com", "UID123", notified=1)
        assert tmp_db.is_email_notified("acct@test.com", "UID123") is True
        assert tmp_db.is_email_notified("acct@test.com", "UID999") is False

        # delete_old_emails with 0 days should delete everything
        tmp_db.delete_old_emails(days=0)
        assert tmp_db.is_email_notified("acct@test.com", "UID123") is False
