"""Tests for admin actions: user management, reset links, audit log."""

import datetime

import pytest

from notimail.auth import hash_password


def _login(client, username, password):
    """Helper to log in via the test client."""
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )


def _create_regular_user(tmp_db, crypto_manager, invited_by):
    """Helper to create a non-admin user and return (user_id, username, password)."""
    username = "regularuser"
    password = "regularpass123"
    user_id = tmp_db.add_user(
        username_encrypted=crypto_manager.encrypt(username),
        username_lookup=crypto_manager.hmac_hash(username),
        password_hash=hash_password(password),
        role="user",
        invited_by=invited_by,
    )
    return user_id, username, password


class TestAdminPageAccess:

    def test_admin_page_loads(self, client, admin_user):
        """GET /admin as admin returns 200."""
        _, username, password = admin_user
        _login(client, username, password)
        resp = client.get("/admin")
        assert resp.status_code == 200

    def test_admin_page_requires_admin(self, client, admin_user, tmp_db, crypto_manager):
        """Create regular user, login, GET /admin returns redirect (not admin)."""
        admin_id, _, _ = admin_user
        _, reg_username, reg_password = _create_regular_user(
            tmp_db, crypto_manager, admin_id
        )
        _login(client, reg_username, reg_password)
        resp = client.get("/admin", follow_redirects=False)
        assert resp.status_code == 302


class TestUserManagement:

    def test_disable_user(self, client, admin_user, tmp_db, crypto_manager):
        """POST /admin/users/<id>/disable, verify user disabled in DB."""
        admin_id, admin_username, admin_password = admin_user
        reg_id, _, _ = _create_regular_user(tmp_db, crypto_manager, admin_id)

        _login(client, admin_username, admin_password)
        resp = client.post(f"/admin/users/{reg_id}/disable", follow_redirects=False)
        assert resp.status_code == 302

        user = tmp_db.get_user_by_id(reg_id)
        assert user["enabled"] == 0

    def test_enable_user(self, client, admin_user, tmp_db, crypto_manager):
        """Disable then enable, verify enabled in DB."""
        admin_id, admin_username, admin_password = admin_user
        reg_id, _, _ = _create_regular_user(tmp_db, crypto_manager, admin_id)

        _login(client, admin_username, admin_password)
        client.post(f"/admin/users/{reg_id}/disable")

        user = tmp_db.get_user_by_id(reg_id)
        assert user["enabled"] == 0

        client.post(f"/admin/users/{reg_id}/enable")
        user = tmp_db.get_user_by_id(reg_id)
        assert user["enabled"] == 1

    def test_delete_user_from_admin(self, client, admin_user, tmp_db, crypto_manager):
        """Create user with account, POST delete, verify user and account gone."""
        admin_id, admin_username, admin_password = admin_user
        reg_id, _, _ = _create_regular_user(tmp_db, crypto_manager, admin_id)

        # Add an email account for the regular user
        account_id = tmp_db.add_email_account(
            user_id=reg_id,
            account_name="del_test",
            email_user_encrypted=crypto_manager.encrypt("del@example.com"),
            email_pass_encrypted=crypto_manager.encrypt("pass"),
            host_encrypted=crypto_manager.encrypt("imap.example.com"),
        )

        _login(client, admin_username, admin_password)
        resp = client.post(f"/admin/users/{reg_id}/delete", follow_redirects=False)
        assert resp.status_code == 302

        assert tmp_db.get_user_by_id(reg_id) is None
        assert tmp_db.get_email_account_by_id(account_id) is None

    def test_cannot_delete_self(self, client, admin_user):
        """POST /admin/users/<own_id>/delete, verify error."""
        admin_id, admin_username, admin_password = admin_user
        _login(client, admin_username, admin_password)

        resp = client.post(
            f"/admin/users/{admin_id}/delete",
            follow_redirects=True,
        )
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "cannot delete your own" in html.lower() or "cannot delete" in html.lower()


class TestResetLink:

    def test_generate_reset_link(self, client, admin_user, tmp_db, crypto_manager):
        """POST generate-reset-link, verify token created in DB."""
        admin_id, admin_username, admin_password = admin_user
        reg_id, _, _ = _create_regular_user(tmp_db, crypto_manager, admin_id)

        _login(client, admin_username, admin_password)
        resp = client.post(
            f"/admin/users/{reg_id}/generate-reset-link",
            follow_redirects=True,
        )
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "reset" in html.lower()

    def test_reset_password_via_token(self, client, admin_user, tmp_db, crypto_manager):
        """Generate token, GET shows form, POST sets new password."""
        admin_id, admin_username, admin_password = admin_user
        reg_id, reg_username, _ = _create_regular_user(tmp_db, crypto_manager, admin_id)

        import secrets
        token = secrets.token_urlsafe(32)
        expires_at = (
            datetime.datetime.now() + datetime.timedelta(hours=24)
        ).strftime("%Y-%m-%d %H:%M:%S")
        tmp_db.add_password_reset_token(reg_id, token, expires_at)

        # GET shows form
        resp = client.get(f"/reset-password/{token}")
        assert resp.status_code == 200

        # POST resets password
        new_password = "newresetpass123"
        resp = client.post(
            f"/reset-password/{token}",
            data={"new_password": new_password, "confirm_password": new_password},
            follow_redirects=False,
        )
        assert resp.status_code == 302

        # Verify token is marked used
        record = tmp_db.get_password_reset_token(token)
        assert record["used"] == 1

        # Verify new password works
        resp = _login(client, reg_username, new_password)
        assert resp.status_code == 302

    def test_reset_password_expired_token(self, client, tmp_db, admin_user, crypto_manager):
        """Create token with past expiry, verify rejection."""
        admin_id, _, _ = admin_user
        reg_id, _, _ = _create_regular_user(tmp_db, crypto_manager, admin_id)

        import secrets
        token = secrets.token_urlsafe(32)
        past = (
            datetime.datetime.now() - datetime.timedelta(hours=1)
        ).strftime("%Y-%m-%d %H:%M:%S")
        tmp_db.add_password_reset_token(reg_id, token, past)

        resp = client.get(f"/reset-password/{token}")
        assert resp.status_code == 400


class TestChangePassword:

    def test_change_password_success(self, client, admin_user):
        """Login, POST /change-password with correct current + new, verify works."""
        _, username, password = admin_user
        _login(client, username, password)

        new_pass = "changedpass456"
        resp = client.post(
            "/change-password",
            data={
                "current_password": password,
                "new_password": new_pass,
                "confirm_password": new_pass,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        # Verify new password works
        client.get("/logout")
        resp = _login(client, username, new_pass)
        assert resp.status_code == 302

    def test_change_password_wrong_current(self, client, admin_user):
        """POST with wrong current password, verify error."""
        _, username, password = admin_user
        _login(client, username, password)

        resp = client.post(
            "/change-password",
            data={
                "current_password": "wrongpassword",
                "new_password": "newpass12345",
                "confirm_password": "newpass12345",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "incorrect" in html.lower() or "error" in html.lower()


class TestAuditLog:

    def test_audit_log_recorded(self, client, admin_user, tmp_db, crypto_manager):
        """After admin actions, verify audit_log table has entries."""
        admin_id, admin_username, admin_password = admin_user
        reg_id, _, _ = _create_regular_user(tmp_db, crypto_manager, admin_id)

        _login(client, admin_username, admin_password)

        # Viewing admin page logs 'view_users'
        client.get("/admin")

        # Disable user logs 'disable_user'
        client.post(f"/admin/users/{reg_id}/disable")

        conn = tmp_db._get_conn()
        cursor = conn.execute("SELECT action FROM audit_log ORDER BY id")
        actions = [row[0] for row in cursor.fetchall()]

        assert "view_users" in actions
        assert "disable_user" in actions
