# UP Bridge

IMAP IDLE to UnifiedPush bridge with encrypted credentials, multi-user management, and memory-only credential mode.

UP Bridge is a fork of [NotiMail](https://github.com/draga79/NotiMail) by Stefano Marinelli, rebranded and extended with v3 features.

## Features

- **IMAP IDLE monitoring** — push notifications for new email without polling
- **UnifiedPush support** — signal-only mode sends empty push (no email content leaked)
- **Encrypted credential storage** — Fernet encryption at rest, HMAC lookups
- **Memory-only credential mode** — passwords never stored on disk, discarded after IMAP LOGIN
- **Multi-user management** — invite-based registration, API keys, role-based access
- **Web dashboard** — account management, connection status, system metrics
- **REST API** — full CRUD for accounts, notifications, keys, invites
- **Tiered brute-force protection** — gentle lockout for wrong passwords, aggressive for enumeration/spray
- **Audit logging** — all admin actions logged with timestamps
- **Host connection limits** — proactive per-IP caps for Yahoo, Gmail, Outlook etc.
- **Auto-reauth** — push notification to re-authenticate after connection loss or restart
- **Docker-ready** — pre-built images on GHCR, auto-generated config

## Quick Start (Docker)

```bash
# Create directory structure
mkdir -p config data logs secrets

# Start the container
docker compose up -d

# Create admin user
docker compose run --rm --entrypoint python up-bridge NotiMail.py -c /app/config/config.ini --setup-admin

# Restart to apply
docker compose restart
```

Access the web dashboard at `http://your-server:8080/login`.

## docker-compose.yml

```yaml
services:
  up-bridge:
    image: ghcr.io/pepper3k/up-bridge:v3.0
    container_name: up-bridge
    restart: unless-stopped
    volumes:
      - ./config:/app/config
      - ./data:/app/data
      - ./logs:/app/logs
      - ./secrets:/app/secrets
    ports:
      - "8080:8080"
```

## Configuration

On first run, a default `config.ini` is generated automatically. Key settings:

| Setting | Default | Description |
|---|---|---|
| `FlaskHost` | `0.0.0.0` | Web interface bind address |
| `FlaskPort` | `8080` | Web interface port |
| `SecretKeyLocation` | `/app/secrets/secret.key` | Fernet encryption key (auto-generated) |
| `DataBaseLocation` | `/app/data/notimail.db` | SQLite database path |
| `SessionLifetimeHours` | `24` | Web session duration |
| `InviteExpiryDays` | `7` | Invite code expiry |

## REST API

All API endpoints require `Authorization: Bearer <api_key>`.

| Method | Endpoint | Description |
|---|---|---|
| `GET/POST` | `/api/accounts` | List or create email accounts |
| `GET/PUT/DELETE` | `/api/accounts/<id>` | Manage a specific account |
| `POST` | `/api/accounts/<id>/reauth` | Re-authenticate (memory-only mode) |
| `GET/POST/DELETE` | `/api/accounts/<id>/notifications` | Notification configs |
| `POST/GET` | `/api/keys` | Generate or list API keys |
| `DELETE` | `/api/keys/<id>` | Revoke an API key |
| `POST/GET` | `/api/invites` | Generate or list invite codes |
| `GET` | `/api/status` | Connection status |
| `GET` | `/health` | Health check (unauthenticated) |

## Memory-Only Credential Mode

When `credential_mode: 1` is set on an account, the IMAP password is:
1. Used once for IMAP LOGIN
2. Immediately discarded from memory
3. Never stored on disk

If the connection drops, UP Bridge sends a push notification to the client to re-authenticate. After 3 failed auto-reauth attempts, a manual reauth link is sent via ntfy.

## Notification Providers

- **ntfy** — with UnifiedPush signal-only mode (`?up=1`)
- **Pushover**
- **Gotify**
- **Apprise** (100+ services)

## Credits

- Original [NotiMail](https://github.com/draga79/NotiMail) by [Stefano Marinelli](https://github.com/draga79)
- Licensed under BSD 3-Clause License
