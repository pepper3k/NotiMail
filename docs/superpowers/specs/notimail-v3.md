# NotiMail v3: Encrypted Credentials & User Management

## Context

NotiMail stores email account credentials (IMAP passwords, notification tokens) in plaintext in `config.ini`. This is a security risk — anyone with read access to the config file gets full email account credentials. Additionally, NotiMail has no user management: a single shared API key gates all web endpoints, and there's no way for mail clients to dynamically register accounts.

This design adds:
1. Encrypted credential storage with Fernet (app-level encryption)
2. User management with invite-based registration
3. Web dashboard with login
4. REST API for mail client account registration
5. UnifiedPush signal-only mode for ntfy endpoints

## Architecture: Hybrid Module Split

Split the current 1048-line monolith into 7 focused modules. With all new features (auth, crypto, REST API, templates), the single-file approach would grow to ~3000+ lines — unworkable. Each module maps to one responsibility. No nested packages.

```
NotiMail.py                    # Thin entry point (~50 lines)
notimail/
  __init__.py
  config.py                    # Load config.ini GENERAL section
  crypto.py                    # Fernet key management, encrypt/decrypt
  database.py                  # All tables, schema migrations, DB operations
  auth.py                      # bcrypt hashing, sessions, API keys, invites, rate limiting
  notifications.py             # Provider classes (moved from NotiMail.py)
  imap.py                      # IMAPHandler, MultiIMAPHandler, EmailProcessor
  web.py                       # Flask app factory, login, dashboard, REST API
  migrate.py                   # config.ini -> DB migration
  templates/                   # Jinja2 HTML templates
    base.html
    login.html
    dashboard.html
    accounts.html
    invites.html
    api_keys.html
    register.html
config.ini                     # GENERAL settings only (after migration)
```

### Why This Over Alternatives

- **Single file at 3000+ lines**: Unworkable with auth, crypto, REST API, templates added to existing 1048 lines.
- **Full package split (15+ files, nested db/, auth/, api/)**: Over-engineered for a self-hosted daemon.
- **7 flat modules**: Each fits in one screen. No circular imports. A new contributor understands the structure in 5 minutes.

### Shared State & Cross-Module Communication

To avoid circular dependencies between `web.py` (needs handler status) and `imap.py` (needs DB for accounts), use a **registry object** created at startup and passed to both:

```python
# In NotiMail.py (entry point):
class AppContext:
    """Shared state passed to all modules. Avoids globals and circular imports."""
    def __init__(self):
        self.db = None              # database.Database instance
        self.crypto = None          # crypto.CryptoManager instance
        self.multi_handler = None   # imap.MultiIMAPHandler instance
        self.config = None          # configparser instance

ctx = AppContext()
ctx.db = Database(...)
ctx.crypto = CryptoManager(...)
# Flask app gets ctx, imap.py gets ctx, etc.
```

`web.py` reads `ctx.multi_handler` for status. `imap.py` reads `ctx.db` for accounts. No module imports another module's runtime state.

## Database Schema

All tables live in one SQLite database (configurable via `[GENERAL] DataBaseLocation`).

### SQLite Thread Safety

SQLite connections are not thread-safe in Python. `database.py` uses **connection-per-thread** via `threading.local()`:

```python
class Database:
    def __init__(self, db_path):
        self.db_path = db_path
        self._local = threading.local()

    def _get_conn(self):
        if not hasattr(self._local, 'conn'):
            self._local.conn = sqlite3.connect(self.db_path)
            self._local.conn.execute("PRAGMA journal_mode=WAL")  # WAL for concurrent reads
            self._local.conn.execute("PRAGMA foreign_keys=ON")
        return self._local.conn
```

WAL mode allows concurrent reads from Flask threads and IMAP threads. Writes are serialized by SQLite automatically.

### Schema Versioning

```sql
CREATE TABLE schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
```

Migrations are defined inline in `database.py` as an ordered list of `(version, sql_statements)` tuples. On startup: check current version, apply pending migrations in order. For 7 tables this is manageable inline; no separate migration files needed.

### Users

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,               -- encrypted (Fernet)
    username_lookup TEXT UNIQUE NOT NULL,  -- HMAC-SHA256 for WHERE clauses
    password_hash TEXT NOT NULL,           -- bcrypt (not Fernet-encrypted, already hashed)
    role TEXT NOT NULL DEFAULT 'user',     -- 'admin' or 'user'
    invited_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL,
    last_login TEXT
);
```

### API Keys

```sql
CREATE TABLE api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash TEXT UNIQUE NOT NULL,        -- SHA-256 of the key
    key_prefix TEXT NOT NULL,             -- first 8 chars for display
    label TEXT,                           -- user-chosen name ("my-phone")
    created_at TEXT NOT NULL,
    last_used TEXT,
    revoked INTEGER DEFAULT 0
);
```

### Invites

```sql
CREATE TABLE invites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,            -- secrets.token_urlsafe(32)
    created_by INTEGER NOT NULL REFERENCES users(id),
    redeemed_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL,
    redeemed_at TEXT,
    expires_at TEXT                       -- default: 7 days from creation
);
```

Expiration enforced at redemption time: `redeem_invite()` checks `expires_at` before accepting. Expired unredeemed invites cleaned up by a periodic task in the watchdog (alongside `delete_old_emails()`). Default expiry: 7 days (configurable in config.ini via `InviteExpiryDays`).

### Email Accounts

```sql
CREATE TABLE email_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    account_name TEXT NOT NULL,            -- internal label
    email_user_encrypted TEXT NOT NULL,    -- Fernet
    email_pass_encrypted TEXT NOT NULL,    -- Fernet
    host_encrypted TEXT NOT NULL,          -- Fernet
    port INTEGER DEFAULT 993,
    folders TEXT NOT NULL DEFAULT 'inbox',
    enabled INTEGER DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT,
    UNIQUE(user_id, account_name)
);
```

### Notification Configs

```sql
CREATE TABLE notification_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_account_id INTEGER NOT NULL REFERENCES email_accounts(id) ON DELETE CASCADE,
    provider_type TEXT NOT NULL,           -- 'ntfy', 'pushover', 'gotify', 'apprise'
    config_encrypted TEXT NOT NULL,        -- Fernet-encrypted JSON blob
    created_at TEXT NOT NULL,
    updated_at TEXT
);
```

### Processed Emails (unchanged)

```sql
CREATE TABLE processed_emails (
    email_account TEXT,                   -- stays as text (email address string)
    uid TEXT,
    notified INTEGER,
    processed_date TEXT,
    PRIMARY KEY(email_account, uid)
);
```

**Migration note**: `processed_emails.email_account` remains a text field containing the email address string (e.g., `user@example.com`). It is NOT migrated to use integer account IDs. The `EmailProcessor` continues to use the decrypted email address as the lookup key for this table. This avoids a complex data migration and keeps dedup logic simple — the 7-day auto-cleanup means old records cycle out naturally.

## Encryption Strategy

### Fernet (app-level encryption)

- Library: `cryptography.fernet.Fernet`
- Key: auto-generated on first run, stored in a file (path configurable in `[GENERAL] SecretKeyLocation`, default `/etc/notimail/secret.key`, chmod 600)
- All sensitive fields encrypted before DB write, decrypted on read

### Key rotation

Out of scope for v3. If the key is compromised, the admin must:
1. Stop NotiMail
2. Use a future `--rotate-key <old_key_file> <new_key_file>` CLI command (to be implemented in a later version)
3. Or re-create all accounts

This will be documented as a known limitation.

### Encrypted fields

| Table | Field | Why |
|---|---|---|
| `users` | `username` | PII |
| `email_accounts` | `email_user_encrypted` | Email address — PII |
| `email_accounts` | `email_pass_encrypted` | Password |
| `email_accounts` | `host_encrypted` | Reveals mail provider |
| `notification_configs` | `config_encrypted` | Contains URLs + tokens |

### Runtime decryption model

All encrypted data is decrypted into memory at startup and after writes. In-memory cache kept in sync with DB via write-through methods. This avoids the need for HMAC lookup columns on most fields.

**Exception: `users.username`** — needs a lookup column for login queries. Uses `username_lookup` which is an HMAC-SHA256 of the plaintext username (derived from the Fernet key via HKDF with label `b"hmac-lookup-key"`). This allows `WHERE username_lookup = HMAC(input)` without decrypting all users.

### What is NOT encrypted

- `password_hash`: Already bcrypt-hashed. Encrypting a hash adds no security.
- `key_hash`: Already SHA-256 hashed.
- `invite.code`: One-time token, useless once redeemed.
- IDs, timestamps, roles, flags, port numbers, folder names: Not PII.

## Authentication & User Management

### First Run Setup

```bash
python3 NotiMail.py --setup-admin
# Prompts for username + password
# Creates admin user (role='admin') in DB
```

If no admin exists and `--setup-admin` not passed, NotiMail prints a message and exits.

### Web Login

- `GET /login` — renders login form
- `POST /login` — validates username/password, sets Flask session cookie
- `GET /logout` — clears session
- Session: `session['user_id']`, `session['role']`
- `PERMANENT_SESSION_LIFETIME`: 24 hours (configurable in config.ini)
- `app.secret_key`: derived from the Fernet key using HKDF with label `b"flask-session-key"`. Can be overridden explicitly via `[GENERAL] FlaskSecretKey`.

### CSRF Protection

All state-changing web forms (login, registration, account management, invite generation) use CSRF tokens. Implementation: `flask-wtf` for form-based CSRF protection. This adds one dependency but is the standard Flask approach and handles token generation, injection, and validation automatically. REST API endpoints are exempt (they use Bearer token auth, not cookies).

Add `flask-wtf>=1.2.0` to requirements.txt.

### Brute-Force Protection

Tiered in-memory rate limiting with zero additional dependencies. The system distinguishes between user error and active attacks by analyzing failure patterns.

**Two tracking dimensions per IP:**

1. **Per-IP, per-username failures** (wrong password for valid/invalid username):
   - Track `{(ip, username_hmac): [timestamp, ...]}`
   - After 5 failures in 15 minutes → soft lockout: 60-second delay between attempts for that IP+username pair
   - After 10 failures → hard lockout: block that IP+username for 30 minutes
   - **Likely cause**: user forgot password. Response is gentle.

2. **Per-IP, distinct username failures** (multiple different non-existent usernames):
   - Track `{ip: set(distinct_failed_username_hmacs)}` within a 15-minute window
   - After 3 distinct non-existent usernames → aggressive lockout: block IP entirely for 1 hour
   - **Likely cause**: credential stuffing / username enumeration. Response is severe.

**Important**: Login responses never reveal whether a username exists. Always return "Invalid credentials" regardless. The distinction is internal to the rate limiter only.

**Password spray detection**: Multiple existing usernames with wrong passwords from the same IP (e.g., 3+ different valid usernames fail within 5 minutes) → block IP for 1 hour. Same severity as enumeration.

**Implementation**: In-memory dicts with periodic cleanup (prune entries older than window on each login attempt). All thresholds configurable in config.ini.

**Reverse proxy support**: Configure `ProxyFix` middleware via `[GENERAL] TrustedProxies` setting. When set, `request.remote_addr` reflects the real client IP from `X-Forwarded-For`. Documentation will warn about the security implications of misconfiguring this (IP spoofing).

**API key rate limiting**: Also applies to API key authentication failures (defense in depth). Per-IP tracking: 10 failed API key attempts in 15 minutes → block IP for 30 minutes.

### Invite Flow

1. Admin or user generates invite from dashboard → one-time code (`secrets.token_urlsafe(32)`)
2. Share code/link however you want (chat, email, in person)
3. New user visits `/register/<code>` → picks username + password
4. Invite expiration checked at redemption time (default 7 days, configurable)
5. Account created, `invited_by` set, invite marked redeemed
6. Regular users can generate invites (cascading)

### API Key Authentication

- Users generate API keys from dashboard
- Key shown once at creation, stored as SHA-256 hash in DB
- REST API uses `Authorization: Bearer <key>` header
- `@api_key_required` decorator validates against `api_keys` table
- Keys can be labeled ("my-phone"), revoked, viewed (prefix only)

### Roles

| Capability | User | Admin |
|---|---|---|
| Manage own email accounts | Yes | Yes |
| Generate own API keys | Yes | Yes |
| Invite other users | Yes | Yes |
| View own status/logs | Yes | Yes |
| Manage all users | No | Yes |
| Reset other users' passwords | No | Yes |
| View all accounts/status | No | Yes |

## Notification Model

### UnifiedPush Signal-Only Mode (ntfy)

The ntfy provider auto-detects UP mode by parsing the URL with `urllib.parse.parse_qs()` and checking for the `up` query parameter:

- **URL with `up=1` parameter** (e.g., `https://ntfy.sh/topic?up=1` or `https://ntfy.sh/topic?up=1&priority=high`) → UP mode: POST with **empty body**. No email content (from/subject) touches the push infrastructure. Client app receives the ping and syncs via its own IMAP connection.
- **URL without `up` parameter** → Legacy mode: POST with from/subject in headers (current behavior).

Detection uses proper URL parsing (`urllib.parse.urlparse` + `parse_qs`), not string matching.

### Other Providers (unchanged)

Pushover, Gotify, Apprise continue sending from/subject as before.

### Provider Configuration Storage

Provider configs move from config.ini sections (`[NTFY:account1]`) to the `notification_configs` DB table. Stored as Fernet-encrypted JSON blobs:

```json
// ntfy example
{"urls": [{"url": "https://ntfy.sh/topic?up=1", "token": "optional"}]}

// pushover example
{"api_token": "...", "user_key": "..."}

// gotify example
{"url": "https://gotify.example.com/message", "token": "..."}

// apprise example
{"urls": ["pover://user@token", "discord://webhook_id/webhook_token"]}
```

## REST API

All API endpoints require `Authorization: Bearer <api_key>` header.

### Account Management

```
POST   /api/accounts                  # Create email account + notification config
GET    /api/accounts                  # List user's accounts
GET    /api/accounts/<id>             # Get account details
PUT    /api/accounts/<id>             # Update account
DELETE /api/accounts/<id>             # Delete account
```

### Notification Configs

```
GET    /api/accounts/<id>/notifications      # List notification configs
POST   /api/accounts/<id>/notifications      # Add notification config
PUT    /api/accounts/<id>/notifications/<nid> # Update
DELETE /api/accounts/<id>/notifications/<nid> # Delete
```

### API Key Management

```
POST   /api/keys                      # Generate new API key
GET    /api/keys                      # List user's keys (prefix + label only)
DELETE /api/keys/<id>                  # Revoke key
```

### Invites

```
POST   /api/invites                   # Generate invite code
GET    /api/invites                   # List user's invites
```

### Status & Health

```
GET    /health                        # Unauthenticated. Returns 200 OK if process running.
                                      # For container/systemd health checks.
GET    /api/status                    # Authenticated. Account connection status (user's own).
GET    /api/status/all                # Admin only. All accounts' status.
GET    /api/logs                      # Admin only. Recent log lines.
GET    /api/config                    # Admin only. Redacted config view.
POST   /api/accounts/<id>/reset       # Reset IMAP connection for an account.
```

The old `/status`, `/logs`, `/config`, `/reset/<email>/<folder>` endpoints are removed. The new `/api/*` equivalents replace them. `/health` is the only unauthenticated endpoint (for container health checks).

### Mail Client Registration Flow

A mail client (e.g. FairEmail) registers an account via API:

```
POST /api/accounts
Authorization: Bearer <user_api_key>
Content-Type: application/json

{
    "account_name": "work",
    "email_user": "user@example.com",
    "email_pass": "password",
    "host": "imap.example.com",
    "folders": "inbox",
    "notifications": [
        {
            "provider_type": "ntfy",
            "config": {
                "urls": [{"url": "https://ntfy.sh/my-topic?up=1"}]
            }
        }
    ]
}
```

NotiMail encrypts credentials, stores in DB. The connection watchdog picks up the new account within 60 seconds and starts IMAP IDLE monitoring.

## Dynamic Account Loading

The existing `connection_watchdog` (runs every 60s) is extended to own the full handler lifecycle.

### Handler Registry

Replace the current parallel lists (`self.handlers[]`, `self.threads[]`) with a **dict keyed by `(account_id, folder)`**:

```python
class MultiIMAPHandler:
    def __init__(self, ctx):
        self.ctx = ctx
        self.registry = {}      # {(account_id, folder): {"handler": IMAPHandler, "thread": Thread}}
        self.registry_lock = threading.Lock()
```

All mutations to `self.registry` are protected by `self.registry_lock`.

### Connection Startup & Host Limits

All connections start immediately in parallel. Per-host concurrency is managed by a **known host limits system** and **runtime heuristic detection**.

#### Known Host Limits File

Ship a bundled `known_host_limits.ini` (user-editable) with defaults for major providers:

```ini
# known_host_limits.ini — shipped with NotiMail, user can edit/extend
[imap.mail.yahoo.com]
MaxConcurrent = 5
LimitType = per-ip

[imap.aol.com]
MaxConcurrent = 5
LimitType = per-ip

[imap.gmail.com]
MaxConcurrent = 15
LimitType = per-account

[imap.googlemail.com]
MaxConcurrent = 15
LimitType = per-account

[outlook.office365.com]
MaxConcurrent = 8
LimitType = per-account

[imap-mail.outlook.com]
MaxConcurrent = 8
LimitType = per-account

[imap.outlook.com]
MaxConcurrent = 8
LimitType = per-account

# Users can add their own servers:
# [mail.mycompany.com]
# MaxConcurrent = 20
# LimitType = per-ip
```

- **`per-ip`**: Total connections from NotiMail's IP to that host are capped (e.g., Yahoo). NotiMail proactively limits how many accounts it connects to that host.
- **`per-account`**: Each account has its own pool (e.g., Gmail). No cross-account limit needed — NotiMail only opens 1 connection per (account, folder).

At account creation time, if the host is known and the limit would be exceeded, show a warning: "Yahoo allows max 5 accounts from one IP. You currently have 4."

#### Smart Retry Suppression

For unknown hosts (or when limits are hit unexpectedly):

1. All connections attempt to start immediately.
2. If a connection fails with "too many connections" (IMAP `BYE` with keywords: "too many", "rate", "limit", "exceeded"; or TCP connection refused while siblings are connected):
   - After **5 consecutive failures** while other accounts on the same host are successfully connected → mark account as **"waiting for slot"**
   - Stop retrying. Log once: `"Account X waiting for connection slot on host Y (host limit detected)"`
   - Retry only when a sibling account on the same host disconnects (slot freed)
3. Regular auth failures (wrong password) and transient errors (server down) use the existing exponential backoff — these are NOT treated as host-limit issues.

#### Reconnection Priority

When a connection slot frees up on a rate-limited host, previously-connected accounts get priority over never-connected ones. This prevents "musical chairs" where accounts constantly rotate and none gets stable IDLE monitoring.

Priority order: (1) was connected, lost connection → (2) was waiting, longest wait time → (3) new account.

#### Alerting

- **CLI/Docker logs**: When a host limit is detected, log a clear message: `"Host imap.mail.yahoo.com: concurrent connection limit reached (5). Accounts X, Y, Z waiting for available slots."`
- **Web dashboard**: Show an alert banner for affected accounts with explanation: "This account is waiting for a connection slot. Yahoo limits connections to 5 per IP address."
- **Account creation**: If a known host limit would be exceeded, warn before creating: "Adding this account would exceed Yahoo's 5-connection limit. The account will be queued."

### Lifecycle

1. `MultiIMAPHandler.run()` does initial account load from DB, checks known host limits, starts all connections (respecting per-IP caps for known hosts, queuing excess)
2. Startup progress logged: `"Starting IMAP connections: 50 accounts across 5 hosts..."`
3. `connection_watchdog()` runs every 60s and calls `reload_accounts()`:
   - Query all enabled `email_accounts` + `notification_configs` from DB
   - Diff against `self.registry` keys
   - **New accounts**: start immediately (or queue if host limit reached)
   - **Removed/disabled accounts**: set handler's `stop_event`, remove from registry (under lock). Thread exits on next IDLE cycle. If host was at limit, retry a waiting account.
   - **Changed accounts** (password/host/folder changed via `updated_at` timestamp): stop old handler, start new
   - **Dead threads**: restart with reconnection priority (bypass waiting queue)
   - **Waiting accounts**: check if slots have freed up, start if possible
4. Each `IMAPHandler` gains a `stop_event` (`threading.Event`) checked in the IDLE loop alongside `shutdown_in_progress`

### Config Validation

The existing `validate_config()` check requiring at least one `EMAIL:*` section is replaced: on startup, check that either (a) config.ini has EMAIL sections, or (b) the DB has email accounts. If neither, log a warning but don't crash — the user may be about to add accounts via the API.

## Migration from config.ini

### Automatic migration on startup

`migrate.py` runs if `email_accounts` table is empty but config.ini has `EMAIL:*` sections:

1. Read all `EMAIL:*` sections → create `email_accounts` rows (encrypt credentials)
2. Read matching `NTFY:*/PUSHOVER:*/GOTIFY:*/APPRISE:*` sections → create `notification_configs` rows
3. Assign all migrated accounts to admin user (user_id=1)
4. Migrate old `[GENERAL] APIKey` as an API key for admin
5. Log: "Migrated N accounts from config.ini. You may remove EMAIL/notification sections from config.ini."
6. Does NOT auto-delete config.ini sections — user does that manually

### config.ini after migration

```ini
[GENERAL]
LogFileLocation = /var/log/notimail/notimail.log
DataBaseLocation = /var/cache/notimail/notimail.db
LogRotationType = size
LogRotationSize = 10485760
LogRotationInterval = 7
LogBackupCount = 5
SecretKeyLocation = /etc/notimail/secret.key
FlaskHost = 0.0.0.0
FlaskPort = 8080
FlaskSecretKey = <auto-generated>
PrometheusHost = 0.0.0.0
PrometheusPort = 8000
SessionLifetimeHours = 24
InviteExpiryDays = 7
RateLimitMaxAttempts = 5
RateLimitWindowMinutes = 15
RateLimitLockoutMinutes = 30
TrustedProxies =
```

All existing `[GENERAL]` keys (including `LogRotationInterval`, `LogRotationType`) are preserved.

## New Dependencies

```
# requirements.txt (all now required)
requests>=2.28.0
cryptography>=41.0.0
bcrypt>=4.0.0
flask>=3.0.0
flask-wtf>=1.2.0

# requirements-optional.txt
prometheus_client>=0.19.0
apprise>=1.6.0
```

Flask and flask-wtf are promoted from optional to required (needed for login, CSRF, dashboard, API).

## Code Commenting

The entire codebase (existing + new) will be comprehensively commented:
- Module-level docstrings explaining purpose and responsibility
- Class docstrings with usage examples where helpful
- Function/method docstrings for all public interfaces
- Inline comments for non-obvious logic (crypto operations, IMAP IDLE mechanics, thread synchronization)
- Type hints on function signatures

## Implementation Phases

### Phase 1: Foundation (no user-facing changes)
- Create `notimail/` package structure
- Create `AppContext` shared state object
- Extract existing code into modules (`config.py`, `notifications.py`, `imap.py`, `database.py`)
- Replace parallel handler/thread lists with dict registry + lock in `MultiIMAPHandler`
- Replace `validate_config()` with flexible check (config.ini OR DB accounts)
- `NotiMail.py` becomes thin entry point
- **Verify**: existing functionality works identically with new module structure

### Phase 2: Encrypted Credentials + Migration
- `crypto.py`: Fernet key management, HKDF key derivation for HMAC + Flask secret
- `database.py`: new tables + schema migration framework + thread-local connections + WAL mode
- `migrate.py`: config.ini → DB migration
- Update `imap.py` to load accounts from DB (decrypt at runtime)
- Dynamic account reload in watchdog via `reload_accounts()`
- **Verify**: existing config.ini users upgrade seamlessly. Accounts load from DB.

### Phase 3: Auth + User Management
- `auth.py`: bcrypt, sessions, rate limiting (with reverse proxy support), invites (with expiry)
- `--setup-admin` CLI command
- `web.py`: Flask app factory with CSRF (flask-wtf), login form, session management, `@login_required`
- `/health` endpoint (unauthenticated)
- **Verify**: admin login, invite generation, user registration, brute-force lockout

### Phase 4: Web Dashboard + REST API
- Dashboard pages (accounts, notifications, invites, API keys)
- REST API endpoints with `@api_key_required` (with rate limiting on auth failures)
- UnifiedPush signal-only mode in ntfy provider (proper URL parsing)
- HTML templates
- Remove old `/status`, `/logs`, `/config`, `/reset` endpoints
- **Verify**: end-to-end flow — register → add account via API → IMAP handler picks it up → UP ping sent

## Verification Plan

1. **Unit tests**: Each module tested independently (crypto round-trip, DB operations, auth flows, rate limiting)
2. **Migration test**: Start with existing config.ini, verify accounts migrate correctly and IMAP monitoring continues
3. **Auth flow test**: Setup admin → generate invite → register user → login → generate API key
4. **API test**: Use API key to create account via REST → verify watchdog picks it up within 60s → verify IMAP IDLE starts
5. **UP mode test**: Configure ntfy URL with `?up=1` → trigger new email → verify empty POST sent (no from/subject)
6. **Rate limiting test**: Submit 6 bad logins in sequence → verify lockout → wait → verify unlock
7. **Encryption verification**: Open DB with sqlite3 CLI → verify encrypted fields are unreadable ciphertext
8. **CSRF test**: Verify forms include CSRF tokens and reject requests without them
9. **Thread safety test**: Concurrent API requests + IMAP threads accessing DB simultaneously
10. **Health check test**: `GET /health` returns 200 without authentication
11. **Brute-force tiered test**: Verify wrong-password lockout (gentle), username-enumeration lockout (aggressive), password-spray detection
12. **Host limit test**: Add 6 accounts to a Yahoo host (known limit: 5) → verify 5 connect, 6th marked "waiting for slot." Disconnect one → verify waiting account connects. Verify warning at account creation.
13. **Smart retry suppression test**: Simulate "too many connections" for unknown host → verify detection after 5 failures while siblings connected → verify retry stops and resumes when slot frees.

## Known Limitations (v3)

- **Key rotation**: No built-in key rotation. If Fernet key is compromised, all data must be re-encrypted manually. A `--rotate-key` command is planned for a future version.
- **No outbound email**: Invites are shared manually (link/code). No email sending capability.
- **SQLite scale ceiling**: Designed for self-hosted use (<1000 users). For larger deployments, a future version may support PostgreSQL.

## Critical Files to Modify

- `/root/NotiMail/NotiMail.py` — refactor into thin entry point
- `/root/NotiMail/config.ini.sample` — update to GENERAL-only format (preserve all existing GENERAL keys)
- `/root/NotiMail/requirements.txt` — add cryptography, bcrypt, flask, flask-wtf
- `/root/NotiMail/requirements-all.txt` — update

## New Files to Create

- `/root/NotiMail/notimail/__init__.py`
- `/root/NotiMail/notimail/config.py`
- `/root/NotiMail/notimail/crypto.py`
- `/root/NotiMail/notimail/database.py`
- `/root/NotiMail/notimail/auth.py`
- `/root/NotiMail/notimail/notifications.py`
- `/root/NotiMail/notimail/imap.py`
- `/root/NotiMail/notimail/web.py`
- `/root/NotiMail/notimail/migrate.py`
- `/root/NotiMail/notimail/templates/*.html`
- `/root/NotiMail/known_host_limits.ini`
