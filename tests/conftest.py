"""Shared fixtures for the NotiMail test suite."""

import hashlib
import os
import tempfile

import pytest

from notimail.crypto import CryptoManager
from notimail.database import DatabaseHandler
from notimail.auth import hash_password, generate_api_key


@pytest.fixture()
def tmp_db(tmp_path):
    """Create a temporary SQLite database with all migrations applied."""
    db_path = str(tmp_path / "test.db")
    db = DatabaseHandler(db_path)
    db.apply_migrations()
    yield db
    db.close()


@pytest.fixture()
def crypto_manager(tmp_path):
    """Create a CryptoManager backed by a temporary key file."""
    key_path = str(tmp_path / "test_secret.key")
    return CryptoManager(key_path)


@pytest.fixture()
def app(tmp_path, tmp_db, crypto_manager):
    """Create a Flask test application with test configuration."""
    from notimail.web import create_app
    from notimail.auth import RateLimiter
    import configparser

    config = configparser.ConfigParser()
    config.add_section("GENERAL")
    config.set("GENERAL", "FlaskSecretKey", "test-secret-key-for-testing")
    config.set("GENERAL", "SessionLifetimeHours", "1")

    rate_limiter = RateLimiter(
        max_attempts=5,
        window_minutes=15,
        lockout_minutes=30,
    )

    flask_app = create_app(
        db=tmp_db,
        crypto=crypto_manager,
        config=config,
        rate_limiter=rate_limiter,
    )
    flask_app.config["TESTING"] = True
    flask_app.config["WTF_CSRF_ENABLED"] = False

    yield flask_app


@pytest.fixture()
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture()
def admin_user(tmp_db, crypto_manager):
    """Create an admin user and return (user_id, username, password)."""
    username = "testadmin"
    password = "testpassword123"
    user_id = tmp_db.add_user(
        username_encrypted=crypto_manager.encrypt(username),
        username_lookup=crypto_manager.hmac_hash(username),
        password_hash=hash_password(password),
        role="admin",
    )
    return user_id, username, password


@pytest.fixture()
def api_key(tmp_db, admin_user):
    """Create an API key for the admin user and return the raw key string."""
    user_id, _, _ = admin_user
    raw_key, key_hash, key_prefix = generate_api_key()
    tmp_db.add_api_key(user_id, key_hash, key_prefix, label="test key")
    return raw_key
