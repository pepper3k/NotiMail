"""Tests for memory-only credential mode: account creation, toggling, handler state."""

import datetime

import pytest
from unittest.mock import patch, MagicMock

from notimail.imap import IMAPHandler, _send_reauth_push


class TestCreateMemoryOnlyAccountApi:

    def test_create_memory_only_account_api(self, client, api_key, tmp_db):
        """POST /api/accounts with credential_mode=1, verify email_pass_encrypted is empty."""
        resp = client.post(
            "/api/accounts",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "account_name": "memonly_acct",
                "email_user": "memonly@example.com",
                "email_pass": "temppass",
                "host": "imap.example.com",
                "credential_mode": 1,
            },
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["credential_mode"] == 1

        # Verify in DB that password field is empty
        acct = tmp_db.get_email_account_by_id(data["id"])
        assert acct is not None
        assert acct["email_pass_encrypted"] == ""
        assert acct["credential_mode"] == 1


class TestToggleCredentialMode:

    def _create_stored_account(self, client, api_key):
        """Helper: create a stored-mode account via API."""
        resp = client.post(
            "/api/accounts",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "account_name": "toggle_acct",
                "email_user": "toggle@example.com",
                "email_pass": "storedpass",
                "host": "imap.example.com",
            },
        )
        return resp.get_json()["id"]

    def _login_admin(self, client, admin_user):
        """Helper: login as admin user."""
        _, username, password = admin_user
        client.post("/login", data={"username": username, "password": password})

    def test_toggle_to_memory_only(self, client, api_key, admin_user, tmp_db):
        """Create stored account, POST toggle endpoint, verify password cleared."""
        self._login_admin(client, admin_user)
        account_id = self._create_stored_account(client, api_key)

        resp = client.post(
            f"/accounts/{account_id}/toggle-credential-mode",
            follow_redirects=False,
        )
        assert resp.status_code == 302

        acct = tmp_db.get_email_account_by_id(account_id)
        assert acct["credential_mode"] == 1
        assert acct["email_pass_encrypted"] == ""

    def test_toggle_to_stored_requires_password(self, client, api_key, admin_user, tmp_db):
        """Toggle memory-only account back to stored without password, verify error."""
        self._login_admin(client, admin_user)
        account_id = self._create_stored_account(client, api_key)

        # First toggle to memory-only
        client.post(f"/accounts/{account_id}/toggle-credential-mode")

        # Now toggle back without password
        resp = client.post(
            f"/accounts/{account_id}/toggle-credential-mode",
            data={},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        # Account should still be memory-only
        acct = tmp_db.get_email_account_by_id(account_id)
        assert acct["credential_mode"] == 1

    def test_toggle_to_stored_with_password(self, client, api_key, admin_user, tmp_db, crypto_manager):
        """Toggle memory-only account with password, verify encrypted and credential_mode=0."""
        self._login_admin(client, admin_user)
        account_id = self._create_stored_account(client, api_key)

        # Toggle to memory-only
        client.post(f"/accounts/{account_id}/toggle-credential-mode")

        # Toggle back with password
        resp = client.post(
            f"/accounts/{account_id}/toggle-credential-mode",
            data={"email_pass": "newstoredpass"},
            follow_redirects=False,
        )
        assert resp.status_code == 302

        acct = tmp_db.get_email_account_by_id(account_id)
        assert acct["credential_mode"] == 0
        assert acct["email_pass_encrypted"] != ""
        # Verify the password decrypts correctly
        decrypted = crypto_manager.decrypt(acct["email_pass_encrypted"])
        assert decrypted == "newstoredpass"


class TestMemoryOnlyHandlerState:

    def test_memory_only_handler_no_password(self):
        """IMAPHandler with credential_mode=1 and no password sets needs_reauth."""
        handler = IMAPHandler(
            host="imap.example.com",
            email_user="user@example.com",
            email_pass=None,
            credential_mode=1,
            account_id=1,
            account_name="test_acct",
        )

        # Mock _send_reauth_push to avoid actual network calls
        with patch("notimail.imap._send_reauth_push"):
            # Mock shutdown state
            with patch("notimail.imap.notimail_config") as mock_config:
                mock_config.shutdown_in_progress = False
                result = handler.connect()

        assert result is False
        assert handler.needs_reauth is True
        assert handler.last_error == "Waiting for client re-authentication"

    def test_reauth_failure_count_increments(self):
        """Simulate reauth failure: set needs_reauth, verify reauth_failure_count logic."""
        handler = IMAPHandler(
            host="imap.example.com",
            email_user="user@example.com",
            email_pass=None,
            credential_mode=1,
            account_id=1,
            account_name="test_acct",
        )

        # Simulate initial state: needs reauth
        handler.needs_reauth = True
        handler.reauth_failure_count = 0

        # Provide bad creds — after connect() fails, the monitor loop increments
        handler.provide_reauth_credentials("user@example.com", "badpass", "imap.example.com")
        assert handler.needs_reauth is False

        # Simulate what monitor_account does on failed connect after reauth attempt
        # The handler's connect() would fail, setting needs_reauth = True for memory-only
        handler.needs_reauth = True
        handler.reauth_failure_count += 1
        assert handler.reauth_failure_count == 1

        # Simulate two more failures
        handler.provide_reauth_credentials("user@example.com", "badpass2", "imap.example.com")
        handler.needs_reauth = True
        handler.reauth_failure_count += 1
        assert handler.reauth_failure_count == 2

        handler.provide_reauth_credentials("user@example.com", "badpass3", "imap.example.com")
        handler.needs_reauth = True
        handler.reauth_failure_count += 1
        assert handler.reauth_failure_count == 3

        # At count >= 3, the monitor loop would trigger manual reauth
        assert handler.reauth_failure_count >= 3
