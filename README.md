# UP Bridge

IMAP IDLE to UnifiedPush notification bridge.

[![CI](https://github.com/pepper3k/up-bridge/actions/workflows/ci.yml/badge.svg)](https://github.com/pepper3k/up-bridge/actions/workflows/ci.yml)
[![Docker](https://github.com/pepper3k/up-bridge/actions/workflows/docker.yml/badge.svg)](https://github.com/pepper3k/up-bridge/actions/workflows/docker.yml)
[![GHCR](https://img.shields.io/badge/ghcr.io-pepper3k%2Fup--bridge-blue)](https://ghcr.io/pepper3k/up-bridge)

## What is UP Bridge?

UP Bridge is a fork of [NotiMail](https://github.com/draga79/NotiMail) by Stefano Marinelli, extended with major v3 additions. It monitors email inboxes via IMAP IDLE and sends push notifications through UnifiedPush-compatible endpoints (ntfy, Gotify, Pushover, Apprise). Designed for use with mail clients like FairEmail that support UnifiedPush.

## Features

- **Encrypted credential storage** -- Fernet encryption at rest with HKDF-derived sub-keys for HMAC lookups and session signing
- **Memory-only credential mode** -- IMAP password used once for LOGIN, then immediately discarded from memory; never written to disk
- **Multi-user management** -- invite-based registration with configurable expiry, role-based access (admin/user)
- **Web dashboard** -- login, account management, connection status, system metrics, API key management, invite generation
- **REST API** -- full CRUD for accounts, notifications, keys, and invites; Bearer token authentication for mail client integration
- **UnifiedPush signal-only mode** -- empty-body push for UP endpoints (`?up=1`), no email content leaked
- **Tiered brute-force protection** -- gentle lockout for wrong passwords, aggressive lockout for username enumeration and password spraying
- **Auto-to-manual reauth fallback** -- on connection loss, sends reauth push to client; after 3 failed auto attempts, generates a one-time token link for manual re-entry
- **Host connection limits** -- proactive per-provider caps for Yahoo, Gmail, Outlook, and others via `known_host_limits.ini`
- **Audit logging** -- all admin actions logged with timestamps
- **Docker-first deployment** -- pre-built images on GHCR, auto-generated config on first run

## Quick Start (Docker)

```bash
git clone https://github.com/pepper3k/up-bridge
cd up-bridge
docker compose up -d

# Create admin user
docker compose run --rm --entrypoint python up-bridge NotiMail.py -c /app/config/config.ini --setup-admin

docker compose restart
```

Then visit `http://localhost:8080`.

The container auto-generates `config/config.ini` and `secrets/secret.key` on first run.

## Configuration

The config file is at `config/config.ini`. Key settings in the `[GENERAL]` section:

| Setting | Default | Description |
|---|---|---|
| `FlaskHost` | `0.0.0.0` | Web interface bind address |
| `FlaskPort` | `8080` | Web interface port |
| `SecretKeyLocation` | `/app/secrets/secret.key` | Fernet encryption key path (auto-generated) |
| `DataBaseLocation` | `/app/data/notimail.db` | SQLite database path |
| `SessionLifetimeHours` | `24` | Web session duration in hours |
| `InviteExpiryDays` | `7` | Invite code expiry in days |
| `RateLimitMaxAttempts` | `5` | Failed login attempts before lockout |
| `RateLimitWindowMinutes` | `15` | Sliding window for attempt tracking |
| `RateLimitLockoutMinutes` | `30` | Lockout duration after threshold |
| `TrustedProxies` | `0` | Set to `1` if behind a reverse proxy |

Email accounts are managed through the web dashboard or REST API and stored encrypted in the database. Legacy `[EMAIL:*]` config sections from NotiMail v2 are auto-imported on first run.

## REST API

All API endpoints require `Authorization: Bearer <api_key>` unless noted otherwise.

| Method | Endpoint | Description |
|---|---|---|
| `GET/POST` | `/api/accounts` | List or create email accounts |
| `GET/PUT/DELETE` | `/api/accounts/<id>` | Read, update, or delete an account |
| `POST` | `/api/accounts/<id>/reauth` | Re-authenticate a memory-only account |
| `GET/POST/DELETE` | `/api/accounts/<id>/notifications` | Manage notification endpoints |
| `POST/GET` | `/api/keys` | Generate or list API keys |
| `DELETE` | `/api/keys/<id>` | Revoke an API key |
| `POST/GET` | `/api/invites` | Generate or list invite codes |
| `GET` | `/api/status` | Connection status for all accounts |
| `GET` | `/health` | Health check (unauthenticated) |

## Memory-Only Credential Mode

When an account has `credential_mode: 1`, the security model works as follows:

1. The IMAP password is submitted via the REST API (e.g., by FairEmail)
2. UP Bridge uses it once for IMAP LOGIN
3. The password is immediately discarded from memory -- it is never written to disk or stored in the database
4. The IMAP IDLE connection is maintained for as long as possible

If the connection drops (server restart, network issue, IDLE timeout):

- UP Bridge sends a reauth push notification to the client
- **Auto mode**: the mail client receives the push and automatically re-sends credentials via `POST /api/accounts/<id>/reauth`
- **Manual fallback**: after 3 consecutive failed auto-reauth attempts, UP Bridge generates a one-time token and sends a clickable link via ntfy for the user to manually re-enter credentials in the browser

For comparison, the default stored mode (`credential_mode: 0`) encrypts credentials on disk with Fernet and reconnects automatically without client involvement.

## Notification Providers

- **ntfy** -- with UnifiedPush signal-only mode (`?up=1`)
- **Pushover**
- **Gotify**
- **Apprise** (100+ services)

## Security

- **Encryption at rest** -- Fernet with auto-generated key file (mode 0600)
- **Key derivation** -- HKDF-SHA256 derives separate sub-keys for HMAC lookups and Flask sessions from the master key
- **Password hashing** -- bcrypt for user and admin passwords
- **CSRF protection** -- flask-wtf on all web forms
- **Tiered rate limiting** -- separate detection for wrong passwords, username enumeration, and password spraying with configurable thresholds and lockout durations
- **Audit logging** -- admin actions (invite creation, user management, password resets) logged with timestamps
- **Per-host connection limits** -- prevents account lockouts from providers that cap concurrent IMAP connections

## Development

Run the test suite:

```bash
pip install -r requirements.txt
pip install pytest
pytest tests/ -v
```

CI runs on every push to `main` and `v3.0` via GitHub Actions. Docker images are built and pushed to GHCR on push and tagged releases.

## License

BSD 3-Clause License (same as the original NotiMail).

## Credits

- Original [NotiMail](https://github.com/draga79/NotiMail) by [Stefano Marinelli](https://github.com/draga79)
- Fork maintained by [pepper3k](https://github.com/pepper3k)
