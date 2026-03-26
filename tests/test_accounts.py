"""Tests for notimail.accounts module."""

import json

import pytest

from notimail.accounts import load_accounts_from_db, _build_notifier_for_account
from notimail.notifications import NTFYNotificationProvider


class TestLoadAccountsFromDb:

    def test_load_accounts_from_db(self, tmp_db, crypto_manager):
        """Create account in DB, load via load_accounts_from_db, verify decrypted fields."""
        user_id = tmp_db.add_user(
            username_encrypted=crypto_manager.encrypt("testuser"),
            username_lookup=crypto_manager.hmac_hash("testuser"),
            password_hash="fakehash",
        )
        tmp_db.add_email_account(
            user_id=user_id,
            account_name="acct1",
            email_user_encrypted=crypto_manager.encrypt("user@example.com"),
            email_pass_encrypted=crypto_manager.encrypt("secret123"),
            host_encrypted=crypto_manager.encrypt("imap.example.com"),
            port=993,
            folders="inbox",
        )

        accounts = load_accounts_from_db(tmp_db, crypto_manager)
        assert len(accounts) == 1
        acct = accounts[0]
        assert acct["EmailUser"] == "user@example.com"
        assert acct["EmailPass"] == "secret123"
        assert acct["Host"] == "imap.example.com"
        assert acct["Port"] == 993
        assert acct["Folder"] == "inbox"
        assert acct["credential_mode"] == 0

    def test_load_memory_only_account(self, tmp_db, crypto_manager):
        """credential_mode=1 account has None password."""
        user_id = tmp_db.add_user(
            username_encrypted=crypto_manager.encrypt("memuser"),
            username_lookup=crypto_manager.hmac_hash("memuser"),
            password_hash="fakehash",
        )
        account_id = tmp_db.add_email_account(
            user_id=user_id,
            account_name="mem_acct",
            email_user_encrypted=crypto_manager.encrypt("mem@example.com"),
            email_pass_encrypted="",
            host_encrypted=crypto_manager.encrypt("imap.example.com"),
            folders="inbox",
        )
        tmp_db.update_email_account(account_id, credential_mode=1)

        accounts = load_accounts_from_db(tmp_db, crypto_manager)
        assert len(accounts) == 1
        assert accounts[0]["EmailPass"] is None
        assert accounts[0]["credential_mode"] == 1


class TestBuildNotifier:

    def test_build_notifier_for_account(self, tmp_db, crypto_manager):
        """Create notification config, build notifier, verify provider type."""
        user_id = tmp_db.add_user(
            username_encrypted=crypto_manager.encrypt("notifuser"),
            username_lookup=crypto_manager.hmac_hash("notifuser"),
            password_hash="fakehash",
        )
        account_id = tmp_db.add_email_account(
            user_id=user_id,
            account_name="notif_acct",
            email_user_encrypted=crypto_manager.encrypt("user@test.com"),
            email_pass_encrypted=crypto_manager.encrypt("pass"),
            host_encrypted=crypto_manager.encrypt("imap.test.com"),
        )

        config_json = json.dumps({
            "urls": [{"url": "https://ntfy.sh/testtopic", "token": None}]
        })
        tmp_db.add_notification_config(
            email_account_id=account_id,
            provider_type="ntfy",
            config_encrypted=crypto_manager.encrypt(config_json),
        )

        notifier = _build_notifier_for_account(tmp_db, crypto_manager, account_id)
        assert notifier is not None
        assert len(notifier.providers) == 1
        assert isinstance(notifier.providers[0], NTFYNotificationProvider)
