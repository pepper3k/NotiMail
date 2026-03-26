"""Tests for reauth flow: token CRUD, reauth page, reauth API, push notifications."""

import datetime
import json
import threading

import pytest
from unittest.mock import patch, MagicMock

from notimail.imap import (
    IMAPHandler,
    _send_reauth_push,
    pending_reauth,
    pending_reauth_lock,
)


class TestReauthTokenCrud:

    def test_reauth_token_crud(self, tmp_db, crypto_manager, admin_user):
        """Create reauth token in DB, retrieve it, mark used, verify."""
        user_id, _, _ = admin_user
        account_id = tmp_db.add_email_account(
            user_id=user_id,
            account_name="reauth_acct",
            email_user_encrypted=crypto_manager.encrypt("user@example.com"),
            email_pass_encrypted="",
            host_encrypted=crypto_manager.encrypt("imap.example.com"),
        )

        expires_at = (
            datetime.datetime.now() + datetime.timedelta(hours=24)
        ).strftime("%Y-%m-%d %H:%M:%S")
        token_id = tmp_db.add_reauth_token(account_id, "test-token-abc", expires_at)
        assert token_id > 0

        record = tmp_db.get_reauth_token("test-token-abc")
        assert record is not None
        assert record["email_account_id"] == account_id
        assert record["used"] == 0

        tmp_db.mark_reauth_token_used(record["id"])
        updated = tmp_db.get_reauth_token("test-token-abc")
        assert updated["used"] == 1

    def test_reauth_token_expired(self, client, app, tmp_db, crypto_manager, admin_user):
        """Create token with past expiry, verify reauth page rejects it."""
        user_id, _, _ = admin_user
        account_id = tmp_db.add_email_account(
            user_id=user_id,
            account_name="expired_reauth",
            email_user_encrypted=crypto_manager.encrypt("user@example.com"),
            email_pass_encrypted="",
            host_encrypted=crypto_manager.encrypt("imap.example.com"),
        )

        past = (
            datetime.datetime.now() - datetime.timedelta(hours=1)
        ).strftime("%Y-%m-%d %H:%M:%S")
        tmp_db.add_reauth_token(account_id, "expired-token", past)

        resp = client.get("/reauth/expired-token")
        assert resp.status_code == 400

    def test_reauth_token_already_used(self, client, tmp_db, crypto_manager, admin_user):
        """Mark token used, verify reauth page rejects it."""
        user_id, _, _ = admin_user
        account_id = tmp_db.add_email_account(
            user_id=user_id,
            account_name="used_reauth",
            email_user_encrypted=crypto_manager.encrypt("user@example.com"),
            email_pass_encrypted="",
            host_encrypted=crypto_manager.encrypt("imap.example.com"),
        )

        expires_at = (
            datetime.datetime.now() + datetime.timedelta(hours=24)
        ).strftime("%Y-%m-%d %H:%M:%S")
        token_id = tmp_db.add_reauth_token(account_id, "used-token", expires_at)
        tmp_db.mark_reauth_token_used(token_id)

        resp = client.get("/reauth/used-token")
        assert resp.status_code == 400


class TestReauthPage:

    def _make_token(self, tmp_db, crypto_manager, admin_user):
        """Helper to create an account and valid reauth token."""
        user_id, _, _ = admin_user
        account_id = tmp_db.add_email_account(
            user_id=user_id,
            account_name="reauth_page_acct",
            email_user_encrypted=crypto_manager.encrypt("test@example.com"),
            email_pass_encrypted="",
            host_encrypted=crypto_manager.encrypt("imap.example.com"),
        )
        expires_at = (
            datetime.datetime.now() + datetime.timedelta(hours=24)
        ).strftime("%Y-%m-%d %H:%M:%S")
        tmp_db.add_reauth_token(account_id, "valid-page-token", expires_at)
        return account_id

    def test_reauth_page_loads(self, client, tmp_db, crypto_manager, admin_user):
        """Create valid token, GET /reauth/<token> shows form with email/host."""
        self._make_token(tmp_db, crypto_manager, admin_user)
        resp = client.get("/reauth/valid-page-token")
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "test@example.com" in html or "imap.example.com" in html

    def test_reauth_page_submits(self, client, tmp_db, crypto_manager, admin_user):
        """POST /reauth/<token> with password, verify token marked used."""
        self._make_token(tmp_db, crypto_manager, admin_user)

        resp = client.post(
            "/reauth/valid-page-token",
            data={"email_pass": "newpassword123"},
        )
        assert resp.status_code == 200

        record = tmp_db.get_reauth_token("valid-page-token")
        assert record["used"] == 1


class TestReauthApi:

    def test_reauth_api_endpoint(self, client, api_key, tmp_db, crypto_manager, admin_user):
        """POST /api/accounts/<id>/reauth with Bearer key and creds, verify 200."""
        user_id, _, _ = admin_user

        # Create a memory-only account
        account_id = tmp_db.add_email_account(
            user_id=user_id,
            account_name="api_reauth_acct",
            email_user_encrypted=crypto_manager.encrypt("api@example.com"),
            email_pass_encrypted="",
            host_encrypted=crypto_manager.encrypt("imap.example.com"),
        )
        tmp_db.update_email_account(account_id, credential_mode=1)

        resp = client.post(
            f"/api/accounts/{account_id}/reauth",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "email_user": "api@example.com",
                "email_pass": "reauth_pass",
                "host": "imap.example.com",
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "credentials_queued"

    def test_reauth_api_wrong_mode(self, client, api_key, tmp_db, crypto_manager, admin_user):
        """POST /api/accounts/<id>/reauth on stored-mode account returns 400."""
        user_id, _, _ = admin_user

        account_id = tmp_db.add_email_account(
            user_id=user_id,
            account_name="stored_acct",
            email_user_encrypted=crypto_manager.encrypt("stored@example.com"),
            email_pass_encrypted=crypto_manager.encrypt("pass"),
            host_encrypted=crypto_manager.encrypt("imap.example.com"),
        )
        # credential_mode defaults to 0 (stored)

        resp = client.post(
            f"/api/accounts/{account_id}/reauth",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "email_user": "stored@example.com",
                "email_pass": "pass",
                "host": "imap.example.com",
            },
        )
        assert resp.status_code == 400
        assert "not in memory-only mode" in resp.get_json()["error"]


class TestReauthPush:

    def test_send_reauth_push_calls_ntfy(self):
        """Mock requests.post, call _send_reauth_push with a mock ntfy notifier."""
        mock_provider = MagicMock()
        mock_provider.ntfy_data = [
            ("https://ntfy.sh/testtopic?up=1", "test-token"),
        ]

        mock_notifier = MagicMock()
        mock_notifier.providers = [mock_provider]

        with patch("notimail.imap.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            _send_reauth_push(mock_notifier, "test_account", 42)

            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert "ntfy.sh" in call_args[0][0]
            body = json.loads(call_args[1]["data"])
            assert body["type"] == "reauth"
            assert body["account_id"] == 42


class TestProvideReauthCredentials:

    def test_provide_reauth_credentials(self):
        """Create IMAPHandler, call provide_reauth_credentials, verify state."""
        handler = IMAPHandler(
            host="imap.example.com",
            email_user="user@example.com",
            email_pass=None,
            credential_mode=1,
            account_id=1,
        )
        handler.needs_reauth = True
        handler.healthy = False

        handler.provide_reauth_credentials(
            "user@example.com", "newpass", "imap.example.com"
        )

        assert handler.email_pass == "newpass"
        assert handler.email_user == "user@example.com"
        assert handler.host == "imap.example.com"
        assert handler.needs_reauth is False
        assert handler.healthy is True


class TestPendingReauthDict:

    def test_pending_reauth_dict(self):
        """Put creds in pending_reauth, verify they can be popped with the lock."""
        creds = {
            "email_user": "test@example.com",
            "email_pass": "secret",
            "host": "imap.example.com",
        }

        with pending_reauth_lock:
            pending_reauth[999] = creds

        with pending_reauth_lock:
            popped = pending_reauth.pop(999, None)

        assert popped is not None
        assert popped["email_user"] == "test@example.com"
        assert popped["email_pass"] == "secret"

        # Verify it's gone
        with pending_reauth_lock:
            assert 999 not in pending_reauth
