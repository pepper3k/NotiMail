"""
NotiMail - Email notification service via IMAP IDLE.

This package contains the modular components of NotiMail:
- config: Configuration loading and validation
- crypto: Fernet encryption for credential storage
- database: SQLite database operations and schema management
- auth: Authentication, sessions, API keys, and invites
- notifications: Push notification providers (ntfy, Pushover, Gotify, Apprise)
- imap: IMAP IDLE connection handlers and email processing
- web: Flask web interface, dashboard, and REST API
- migrate: Config.ini to database migration
"""

__version__: str = "3.0.0"
