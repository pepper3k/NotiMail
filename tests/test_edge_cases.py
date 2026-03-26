"""Tests for edge cases and error handling: duplicates, validation, auth, concurrency."""

import datetime
import threading

import pytest

from notimail.auth import hash_password, create_invite


def _login(client, username, password):
    """Helper to log in via the test client."""
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )


class TestDuplicateRegistration:

    def test_duplicate_username_registration(self, client, admin_user, tmp_db, crypto_manager):
        """Try to register two users with same username via invite, verify second fails."""
        admin_id, _, _ = admin_user
        code1 = create_invite(tmp_db, created_by=admin_id)
        code2 = create_invite(tmp_db, created_by=admin_id)

        # Register first user
        resp = client.post(
            f"/register/{code1}",
            data={
                "username": "dupeuser",
                "password": "password1234",
                "password_confirm": "password1234",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302  # success redirect to login

        # Register second user with same username
        resp = client.post(
            f"/register/{code2}",
            data={
                "username": "dupeuser",
                "password": "password5678",
                "password_confirm": "password5678",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "already taken" in html.lower()


class TestApiValidation:

    def test_api_missing_fields(self, client, api_key):
        """POST /api/accounts with missing required fields, verify 400."""
        resp = client.post(
            "/api/accounts",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"account_name": "incomplete"},
        )
        assert resp.status_code == 400
        assert "Missing required field" in resp.get_json()["error"]

    def test_api_invalid_json(self, client, api_key):
        """POST /api/accounts with non-JSON content type, verify 400 or 415."""
        resp = client.post(
            "/api/accounts",
            headers={"Authorization": f"Bearer {api_key}"},
            data="this is not json",
            content_type="text/plain",
        )
        assert resp.status_code in (400, 415)

    def test_api_empty_json_body(self, client, api_key):
        """POST /api/accounts with empty JSON object, verify 400."""
        resp = client.post(
            "/api/accounts",
            headers={"Authorization": f"Bearer {api_key}"},
            json={},
        )
        assert resp.status_code == 400

    def test_api_wrong_bearer_token(self, client):
        """Use invalid token, verify 401."""
        resp = client.get(
            "/api/accounts",
            headers={"Authorization": "Bearer totally-invalid-key-12345"},
        )
        assert resp.status_code == 401
        assert "Invalid API key" in resp.get_json()["error"]


class TestExpiredAndUsedInvites:

    def test_expired_invite_registration(self, client, admin_user, tmp_db):
        """Try to register with expired invite, verify rejection."""
        admin_id, _, _ = admin_user
        past = (
            datetime.datetime.now() - datetime.timedelta(days=1)
        ).strftime("%Y-%m-%d %H:%M:%S")
        tmp_db.add_invite("expired-inv", created_by=admin_id, expires_at=past)

        resp = client.post(
            "/register/expired-inv",
            data={
                "username": "lateuser",
                "password": "password1234",
                "password_confirm": "password1234",
            },
        )
        # GET and POST both should reject with 400
        assert resp.status_code == 400

    def test_used_invite_registration(self, client, admin_user, tmp_db, crypto_manager):
        """Redeem invite then try again with same code, verify rejection."""
        admin_id, _, _ = admin_user
        code = create_invite(tmp_db, created_by=admin_id)

        # Redeem the invite
        resp = client.post(
            f"/register/{code}",
            data={
                "username": "firstuser",
                "password": "password1234",
                "password_confirm": "password1234",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        # Try again with same code
        resp = client.get(f"/register/{code}")
        assert resp.status_code == 400


class TestLoginEdgeCases:

    def test_login_nonexistent_user(self, client):
        """Login with username that doesn't exist, verify generic error message."""
        resp = client.post(
            "/login",
            data={"username": "nonexistent_user_xyz", "password": "anypassword"},
        )
        assert resp.status_code == 401
        html = resp.data.decode()
        # Should show generic error, NOT "user not found"
        assert "invalid credentials" in html.lower()
        assert "not found" not in html.lower()

    def test_empty_password_rejected(self, client, admin_user, tmp_db):
        """Try to register with short password, verify rejection."""
        admin_id, _, _ = admin_user
        code = create_invite(tmp_db, created_by=admin_id)

        resp = client.post(
            f"/register/{code}",
            data={
                "username": "shortpwuser",
                "password": "short",
                "password_confirm": "short",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "at least 8" in html.lower()


class TestAccountOwnership:

    def test_api_account_ownership(self, client, api_key, admin_user, tmp_db, crypto_manager):
        """User A creates account, User B tries to access it, verify 404."""
        # Create account as admin (via API key)
        resp = client.post(
            "/api/accounts",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "account_name": "owned_acct",
                "email_user": "owner@example.com",
                "email_pass": "pass",
                "host": "imap.example.com",
            },
        )
        account_id = resp.get_json()["id"]

        # Create a second user with their own API key
        from notimail.auth import generate_api_key
        admin_id, _, _ = admin_user
        user_b_id = tmp_db.add_user(
            username_encrypted=crypto_manager.encrypt("userb"),
            username_lookup=crypto_manager.hmac_hash("userb"),
            password_hash=hash_password("password1234"),
            role="user",
            invited_by=admin_id,
        )
        raw_key_b, key_hash_b, key_prefix_b = generate_api_key()
        tmp_db.add_api_key(user_b_id, key_hash_b, key_prefix_b, label="userb key")

        # User B tries to access User A's account
        resp = client.get(
            f"/api/accounts/{account_id}",
            headers={"Authorization": f"Bearer {raw_key_b}"},
        )
        assert resp.status_code == 404


class TestConcurrentDbOperations:

    def test_concurrent_db_operations(self, tmp_db, crypto_manager):
        """Create multiple threads doing DB writes simultaneously, verify no crashes."""
        errors = []

        def worker(thread_id):
            try:
                user_id = tmp_db.add_user(
                    username_encrypted=crypto_manager.encrypt(f"concurrent_{thread_id}"),
                    username_lookup=crypto_manager.hmac_hash(f"concurrent_{thread_id}"),
                    password_hash=hash_password("password1234"),
                )
                tmp_db.add_email_account(
                    user_id=user_id,
                    account_name=f"acct_{thread_id}",
                    email_user_encrypted=crypto_manager.encrypt(f"user{thread_id}@test.com"),
                    email_pass_encrypted=crypto_manager.encrypt("pass"),
                    host_encrypted=crypto_manager.encrypt("imap.test.com"),
                )
            except Exception as e:
                errors.append(str(e))

        threads = []
        for i in range(10):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=10)

        assert len(errors) == 0, f"DB errors: {errors}"

        # Verify all users were created
        all_users = tmp_db.get_all_users()
        concurrent_users = [u for u in all_users if "concurrent_" in crypto_manager.decrypt(u["username"])]
        assert len(concurrent_users) == 10
