# UP Bridge v3 Architecture

## Overview

UP Bridge is a fork of [NotiMail](https://github.com/draga79/NotiMail) by Stefano Marinelli. It monitors email inboxes via IMAP IDLE and sends push notifications via UnifiedPush/ntfy when new mail arrives.

v3 adds: encrypted credential storage, memory-only credential mode, multi-user management with invites, a web dashboard, REST API, tiered brute-force protection, audit logging, and automatic reauth via push notifications.

## Architecture

11 Python modules + entry point. Internal package name is `notimail/` (preserved for upstream mergeability).

| Module | Lines | Responsibility |
|---|---|---|
| `NotiMail.py` | 406 | Entry point: arg parsing, initialization, main loop |
| `notimail/config.py` | 245 | Config loading, logging, Prometheus, conditional imports |
| `notimail/crypto.py` | 145 | Fernet encryption, HKDF key derivation, HMAC hashing |
| `notimail/database.py` | 870 | SQLite with WAL, schema migrations (v1-v5), all CRUD ops |
| `notimail/auth.py` | 341 | bcrypt hashing, API keys, invites, tiered RateLimiter |
| `notimail/notifications.py` | 375 | NTFY/Pushover/Gotify/Apprise providers, UP signal mode |
| `notimail/imap.py` | 958 | IMAPHandler, MultiIMAPHandler, watchdog, reauth push |
| `notimail/web.py` | 1123 | Flask app factory, all routes (web + REST API), auth decorators |
| `notimail/accounts.py` | 146 | Load accounts from DB with runtime decryption |
| `notimail/migrate.py` | 200 | Auto-migrate config.ini EMAIL sections to encrypted DB |
| `notimail/host_limits.py` | 221 | Per-host connection limits, smart retry suppression |

Templates: `base.html`, `login.html`, `register.html`, `dashboard.html`, `accounts.html`, `api_keys.html`, `invites.html`, `admin.html`, `reauth.html`, `reset_password.html`, `change_password.html`

## Database Schema

SQLite with WAL mode, thread-local connections, 10s busy timeout. 5 versioned migrations applied automatically on startup.

### Migration v1: Core tables
- **schema_version** (version, applied_at)
- **users** (id, username [encrypted], username_lookup [HMAC], password_hash [bcrypt], role, invited_by, created_at, last_login)
- **api_keys** (id, user_id, key_hash [SHA-256], key_prefix, label, created_at, last_used, revoked)
- **invites** (id, code, created_by, redeemed_by, created_at, redeemed_at, expires_at)
- **email_accounts** (id, user_id, account_name, email_user_encrypted, email_pass_encrypted, host_encrypted, port, folders, enabled, created_at, updated_at)
- **notification_configs** (id, email_account_id, provider_type, config_encrypted [JSON], created_at, updated_at)
- **processed_emails** (email_account [text], uid, notified, processed_date) — unchanged from upstream

### Migration v2: Admin features
- **audit_log** (id, admin_user_id, action, target_user_id, details, timestamp)
- **password_reset_tokens** (id, user_id, token, created_at, expires_at, used)
- `users.enabled` column (default 1)

### Migration v3: Per-user encryption (now superseded by memory-only mode)
- `users.key_salt` column
- `email_accounts.user_encrypted` column

### Migration v4: Memory-only credential mode
- `email_accounts.credential_mode` column (0=stored, 1=memory_only)

### Migration v5: Reauth tokens
- **reauth_tokens** (id, email_account_id, token, created_at, expires_at, used)

## Encryption

### At-rest (stored mode, credential_mode=0)
- **Fernet** (AES-128-CBC + HMAC-SHA256) via `cryptography` library
- Key auto-generated on first run, stored at configurable path (chmod 600)
- Encrypted fields: username, email_user, email_pass, host, notification configs
- HMAC-SHA256 lookup column for username (derived via HKDF from Fernet key)
- Flask session key derived via HKDF (label: `b"flask-session-key"`)

### Memory-only mode (credential_mode=1)
- Email password is **never stored on disk**
- Used once for IMAP LOGIN, then set to `None` in memory
- DB stores email_user and host (encrypted with global Fernet for display), but email_pass_encrypted is empty
- See "Memory-Only Credential Mode" section below

## Authentication

| Mechanism | Where | Details |
|---|---|---|
| **bcrypt** | Web login | Password hashed with gensalt, verified on login |
| **Flask sessions** | Web UI | Cookie-based, configurable lifetime (default 24h) |
| **API keys** | REST API | SHA-256 hash stored, raw key shown once at creation. `Authorization: Bearer <key>` |
| **Invites** | Registration | One-time codes, 7-day default expiry, cascading (users can invite users) |
| **CSRF** | Web forms | flask-wtf, API blueprint exempt (Bearer auth) |

### Tiered brute-force protection (RateLimiter)

| Pattern | Detection | Response |
|---|---|---|
| Wrong password (same username) | 5 failures in 15 min | 60s delay, then 30 min lockout at 10 |
| Multiple non-existent usernames | 3 distinct unknown usernames | 1 hour IP lockout |
| Password spray | 3 different valid usernames failing in 5 min | 1 hour IP lockout |
| API key failures | 10 failures in 15 min | 30 min IP lockout |

Login responses never reveal whether a username exists.

## Memory-Only Credential Mode

### Flow
```
Client sends creds via API
  -> UP Bridge does IMAP LOGIN
  -> Password immediately set to None
  -> IMAP IDLE runs on authenticated TCP connection
  -> Connection drops
  -> UP Bridge sends reauth push to client's ntfy endpoint
  -> Client re-sends creds via POST /api/accounts/<id>/reauth
  -> Repeat
```

### Auto-reauth (default)
- Push message: `{"type": "reauth", "account_id": N}` (UP mode, empty-body signal)
- Client (e.g. FairEmail) detects `type=reauth` and POSTs creds back
- Password used for LOGIN, discarded, monitoring resumes

### Manual fallback (after 3 failed auto-reauths)
- Generates single-use reauth token (24h expiry)
- Sends ntfy notification with clickable link: `https://host/reauth/TOKEN`
- User taps link, enters password, token consumed
- Handles password changes gracefully (stale client creds fail -> manual link lets user enter new password)

### Security properties
- Password exists in process memory for ~1-2 seconds during IMAP LOGIN
- Nothing stored on disk — DB theft yields no credentials
- Attack window: memory dump during LOGIN (near-impossible to target)
- Stronger than ProtonMail for credential exposure (they store encrypted private key permanently)

## Notification Model

### UnifiedPush signal-only (ntfy with ?up=1)
- Detected via `urllib.parse` (proper URL parsing, not string matching)
- POST with **empty body** — no email content (from/subject) touches push infrastructure
- Client receives ping and syncs via its own IMAP connection

### Legacy mode (ntfy without ?up=1)
- POST with from/subject in headers/body (original NotiMail behavior)

### Other providers
Pushover, Gotify, Apprise: send from/subject (unchanged from upstream)

## Connection Management

### Dynamic account reload
- Watchdog thread runs every 60s
- Queries DB for all enabled accounts, diffs against running handlers
- New accounts: spawn handler thread
- Removed/disabled: set handler's stop_event
- Dead threads: restart immediately

### Host connection limits
- `known_host_limits.ini`: bundled defaults for Gmail (15/per-account), Yahoo (5/per-ip), Outlook (8/per-account), AOL (5/per-ip)
- Smart retry suppression: 5 consecutive failures while siblings connected -> stop retrying, wait for slot
- Reconnection priority: previously-connected accounts get first retry

## Web Interface

Flask app factory (`create_app`) with two blueprints:

### Web routes (session auth, CSRF)
`/login`, `/logout`, `/`, `/register/<code>`, `/accounts`, `/accounts/add`, `/accounts/<id>/delete`, `/accounts/<id>/toggle-credential-mode`, `/keys`, `/keys/create`, `/keys/<id>/revoke`, `/invites`, `/invites/create`, `/admin`, `/admin/users/<id>/disable`, `/admin/users/<id>/enable`, `/admin/users/<id>/delete`, `/admin/users/<id>/generate-reset-link`, `/change-password`, `/reset-password/<token>`, `/reauth/<token>`, `/health`

### Dashboard metrics
RAM usage, CPU time, active IMAP connections, total users, email account count, accounts awaiting reauth

## REST API

All endpoints require `Authorization: Bearer <api_key>`.

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Unauthenticated health check |
| GET/POST | `/api/accounts` | List or create email accounts |
| GET/PUT/DELETE | `/api/accounts/<id>` | Manage specific account |
| POST | `/api/accounts/<id>/reauth` | Re-authenticate memory-only account |
| GET/POST | `/api/accounts/<id>/notifications` | Notification config CRUD |
| DELETE | `/api/accounts/<id>/notifications/<nid>` | Delete notification config |
| POST/GET | `/api/keys` | Generate or list API keys |
| DELETE | `/api/keys/<id>` | Revoke API key |
| POST/GET | `/api/invites` | Generate or list invite codes |
| GET | `/api/status` | Connection status for user's accounts |

## Admin and Audit

### Admin capabilities
- View all users (encrypted usernames decrypted for display)
- Enable/disable user accounts (disabled users can't log in)
- Delete users (cascades to all related data)
- Generate password reset links (one-time tokens, 24h expiry)

### Audit log
Every admin action is recorded: `view_users`, `disable_user`, `enable_user`, `delete_user`, `generate_reset_link`. Stored with admin_user_id, target_user_id, details, timestamp.

## Security Summary

| Layer | Implementation |
|---|---|
| Credentials at rest | Fernet (AES-128-CBC + HMAC-SHA256) or not stored (memory-only mode) |
| Passwords | bcrypt with random salt |
| API keys | SHA-256 hash stored, raw shown once |
| Sessions | Flask server-side, HKDF-derived secret key |
| CSRF | flask-wtf on all web forms, API exempt |
| Rate limiting | Tiered in-memory, per-IP, per-username |
| Reverse proxy | ProxyFix middleware, configurable trusted proxies |
| Admin accountability | Audit log for all admin actions |
| Host limits | Proactive caps from known_host_limits.ini + runtime detection |

## Roadmap

- **OAuth2 XOAUTH2**: For Gmail/Outlook, use OAuth tokens instead of passwords. Scoped, revocable, doesn't expose user's actual password.
- **JMAP Web Push (RFC 8620)**: When mail servers support JMAP, they can push directly to UP endpoints — no middleware needed.
- **Sieve enotify HTTP**: Custom Sieve notify plugin for Dovecot to send webhooks on new mail — server-side, no credentials needed.

## Testing

98 tests across 11 files. CI via GitHub Actions on push to `v3.0` and `main`.

| Test file | Tests | Coverage |
|---|---|---|
| test_crypto.py | 5 | Key generation, encrypt/decrypt, HMAC, HKDF |
| test_database.py | 11 | Migrations, user/account/key/invite CRUD, cascading delete |
| test_auth.py | 10 | Password hashing, API keys, invites, rate limiter tiers |
| test_notifications.py | 5 | UP detection, empty body, legacy mode, fan-out, parsing |
| test_web.py | 13 | Health, login, register, API auth, account CRUD, dashboard |
| test_accounts.py | 3 | DB loading, memory-only, notifier building |
| test_reauth.py | 10 | Token CRUD, expiry, page flow, API endpoint, push mock |
| test_memory_only.py | 6 | API creation, mode toggle, handler state, failure counting |
| test_admin.py | 12 | Page access, disable/enable/delete, reset links, audit log |
| test_host_limits.py | 12 | Config parsing, per-ip/per-account limits, retry suppression |
| test_edge_cases.py | 11 | Duplicate users, bad input, ownership, concurrency |
