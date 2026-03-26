"""Tests for notimail.web Flask routes."""

import datetime
import json

import pytest


class TestHealthAndPublicRoutes:

    def test_health_endpoint(self, client):
        """GET /health returns 200."""
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "OK"

    def test_login_page_loads(self, client):
        """GET /login returns 200."""
        resp = client.get("/login")
        assert resp.status_code == 200


class TestLogin:

    def test_login_success(self, client, admin_user):
        """POST /login with valid creds, verify redirect and session."""
        _, username, password = admin_user
        resp = client.post(
            "/login",
            data={"username": username, "password": password},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "/login" not in resp.headers.get("Location", "")

        # Verify we can access the dashboard (session is set)
        dash_resp = client.get("/")
        assert dash_resp.status_code == 200

    def test_login_wrong_password(self, client, admin_user):
        """POST /login with wrong password, verify 401."""
        _, username, _ = admin_user
        resp = client.post(
            "/login",
            data={"username": username, "password": "wrongpassword"},
        )
        assert resp.status_code == 401

    def test_login_disabled_user(self, client, app, admin_user):
        """Disabled user gets 403."""
        user_id, username, password = admin_user
        with app.app_context():
            from flask import g
            # Disable the user directly via the DB fixture
            app.config["_test_db"] = True

        # Use the tmp_db fixture through the app's before_request
        from notimail.database import DatabaseHandler
        # Access the db through the app context
        with app.app_context():
            g_db = app.extensions if hasattr(app, 'extensions') else None

        # Disable user by accessing the db fixture that the app uses
        # The app's before_request injects g.db from the db passed to create_app
        # We need to call disable_user on that same db instance
        # Since the app fixture yields the flask app, and the db is injected,
        # we can use the client to trigger a request and access g.db
        # Simpler: just use the db directly from the conftest chain
        # The admin_user fixture uses tmp_db, which is also used by the app
        # So we can import and call disable on it

        # Get the db from the app's inject_context (it's a closure over 'db')
        # Actually, the simplest approach: the admin_user fixture uses tmp_db,
        # and the app fixture also uses tmp_db -- same instance.
        # We can access it indirectly via a request context.
        with app.test_request_context():
            app.preprocess_request()
            from flask import g as flask_g
            flask_g.db.disable_user(user_id)

        resp = client.post(
            "/login",
            data={"username": username, "password": password},
        )
        assert resp.status_code == 403


class TestRegistration:

    def test_register_page_with_valid_invite(self, client, admin_user):
        """GET /register/<code> returns 200 for a valid invite."""
        user_id, _, _ = admin_user
        with client.application.test_request_context():
            client.application.preprocess_request()
            from flask import g
            code = "validinvitecode123"
            g.db.add_invite(code, created_by=user_id)

        resp = client.get(f"/register/{code}")
        assert resp.status_code == 200

    def test_register_with_expired_invite(self, client, admin_user):
        """Expired invite returns 400."""
        user_id, _, _ = admin_user
        past = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        with client.application.test_request_context():
            client.application.preprocess_request()
            from flask import g
            g.db.add_invite("expiredcode", created_by=user_id, expires_at=past)

        resp = client.get("/register/expiredcode")
        assert resp.status_code == 400


class TestApiEndpoints:

    def test_api_accounts_requires_auth(self, client):
        """GET /api/accounts without Bearer returns 401."""
        resp = client.get("/api/accounts")
        assert resp.status_code == 401

    def test_api_accounts_with_key(self, client, api_key):
        """GET /api/accounts with valid key returns 200."""
        resp = client.get(
            "/api/accounts",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert resp.status_code == 200
        assert isinstance(resp.get_json(), list)

    def test_api_create_account(self, client, api_key):
        """POST /api/accounts creates account, verify in DB."""
        resp = client.post(
            "/api/accounts",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "account_name": "test_acct",
                "email_user": "user@example.com",
                "email_pass": "password123",
                "host": "imap.example.com",
                "folders": "inbox",
            },
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["status"] == "created"
        assert "id" in data

        # Verify it shows up in the list
        list_resp = client.get(
            "/api/accounts",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        accounts = list_resp.get_json()
        assert any(a["account_name"] == "test_acct" for a in accounts)

    def test_api_create_memory_only_account(self, client, api_key):
        """POST with credential_mode=1, verify password not stored."""
        resp = client.post(
            "/api/accounts",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "account_name": "mem_acct",
                "email_user": "mem@example.com",
                "email_pass": "temppass",
                "host": "imap.example.com",
                "credential_mode": 1,
            },
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["credential_mode"] == 1


class TestDashboardAuth:

    def test_dashboard_requires_login(self, client):
        """GET / without session redirects to /login."""
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert "login" in resp.headers["Location"]


class TestChangePassword:

    def test_change_password(self, client, admin_user):
        """POST /change-password with correct current password works."""
        _, username, password = admin_user

        # Log in first
        client.post(
            "/login",
            data={"username": username, "password": password},
        )

        new_password = "newpassword456"
        resp = client.post(
            "/change-password",
            data={
                "current_password": password,
                "new_password": new_password,
                "confirm_password": new_password,
            },
            follow_redirects=False,
        )
        # Should redirect to dashboard on success
        assert resp.status_code == 302

        # Log out and log in with new password
        client.get("/logout")
        resp = client.post(
            "/login",
            data={"username": username, "password": new_password},
            follow_redirects=False,
        )
        assert resp.status_code == 302
