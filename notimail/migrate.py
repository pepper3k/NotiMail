"""
Migration of email accounts from config.ini to the encrypted database.

Reads EMAIL:*, NTFY:*, PUSHOVER:*, GOTIFY:*, and APPRISE:* sections
from config.ini, encrypts credentials, and stores them in the database.
Runs automatically on startup if the email_accounts table is empty but
config.ini has EMAIL sections.
"""

import configparser
import hashlib
import json
import logging
import secrets
from typing import Any, Dict, List, Optional

from notimail.crypto import CryptoManager
from notimail.database import DatabaseHandler


def should_migrate(config: configparser.ConfigParser, db: DatabaseHandler) -> bool:
    """Check if migration from config.ini is needed.

    Migration runs if the email_accounts table is empty AND config.ini
    has at least one EMAIL:* section.

    Args:
        config: The loaded ConfigParser.
        db: The DatabaseHandler instance.

    Returns:
        True if migration should run.
    """
    has_email_sections = any(s.startswith("EMAIL:") for s in config.sections())
    if not has_email_sections:
        return False

    existing_accounts = db.get_all_enabled_accounts()
    # Also check disabled accounts — if ANY accounts exist in DB, skip migration
    conn = db._get_conn()
    cursor = conn.execute("SELECT COUNT(*) FROM email_accounts")
    count = cursor.fetchone()[0]
    return count == 0


def migrate_from_config(
    config: configparser.ConfigParser,
    db: DatabaseHandler,
    crypto: CryptoManager,
    admin_user_id: int,
) -> int:
    """Migrate email accounts and notification configs from config.ini to the database.

    For each EMAIL:* section:
    - Creates an email_accounts row with encrypted credentials.
    - Reads matching NTFY:*/PUSHOVER:*/GOTIFY:*/APPRISE:* sections and
      creates notification_configs rows with encrypted JSON blobs.

    Also migrates the [GENERAL] APIKey as an API key for the admin user.

    Args:
        config: The loaded ConfigParser with EMAIL/notification sections.
        db: The DatabaseHandler instance (with tables already created).
        crypto: The CryptoManager for encrypting credentials.
        admin_user_id: The user ID to assign all migrated accounts to.

    Returns:
        The number of email accounts migrated.
    """
    migrated = 0

    for section in config.sections():
        if not section.startswith("EMAIL:"):
            continue

        account_name = section.split(":", 1)[1]
        email_user = config[section].get('EmailUser', '')
        email_pass = config[section].get('EmailPass', '')
        host = config[section].get('Host', '')
        folders = config[section].get('Folders', 'inbox')

        if not email_user or not host:
            logging.warning(f"Skipping {section}: missing EmailUser or Host")
            continue

        # Encrypt credentials
        account_id = db.add_email_account(
            user_id=admin_user_id,
            account_name=account_name,
            email_user_encrypted=crypto.encrypt(email_user),
            email_pass_encrypted=crypto.encrypt(email_pass),
            host_encrypted=crypto.encrypt(host),
            port=993,
            folders=folders,
        )

        # Migrate notification providers for this account
        _migrate_notification_providers(config, db, crypto, account_id, account_name)

        # Also check for global providers (sections without ':') if no
        # account-specific providers were found
        configs = db.get_notification_configs_for_account(account_id)
        if not configs:
            _migrate_notification_providers(config, db, crypto, account_id, None)

        migrated += 1
        logging.info(f"Migrated account: {email_user} ({account_name})")

    # Migrate the global API key if present
    api_key_value = config.get('GENERAL', 'APIKey', fallback=None)
    if api_key_value:
        key_hash = hashlib.sha256(api_key_value.encode('utf-8')).hexdigest()
        key_prefix = api_key_value[:8] if len(api_key_value) >= 8 else api_key_value
        db.add_api_key(
            user_id=admin_user_id,
            key_hash=key_hash,
            key_prefix=key_prefix,
            label="Migrated from config.ini",
        )
        logging.info("Migrated API key from [GENERAL] APIKey")

    if migrated > 0:
        logging.info(
            f"Migration complete: {migrated} account(s) imported from config.ini. "
            "You may now remove EMAIL/NTFY/PUSHOVER/GOTIFY/APPRISE sections from config.ini."
        )
    return migrated


def _migrate_notification_providers(
    config: configparser.ConfigParser,
    db: DatabaseHandler,
    crypto: CryptoManager,
    email_account_id: int,
    account_name: Optional[str],
) -> None:
    """Migrate notification provider sections for a given account.

    Args:
        config: The loaded ConfigParser.
        db: The DatabaseHandler instance.
        crypto: The CryptoManager for encrypting config blobs.
        email_account_id: The email_accounts.id to attach configs to.
        account_name: Account suffix (e.g. "account1") for per-account
                     sections, or None for global sections.
    """
    if account_name:
        sections = [s for s in config.sections() if s.endswith(f":{account_name}")]
    else:
        sections = [s for s in config.sections() if ':' not in s]

    # NTFY
    for section in sections:
        if not section.startswith('NTFY'):
            continue
        urls = []
        for key in config[section]:
            if key.lower().startswith("url"):
                url = config[section][key]
                index = key[3:]
                token_key = f"Token{index}"
                token = config[section].get(token_key, None)
                urls.append({"url": url, "token": token})
        if urls:
            config_json = json.dumps({"urls": urls})
            db.add_notification_config(email_account_id, "ntfy", crypto.encrypt(config_json))

    # Pushover
    for section in sections:
        if not section.startswith('PUSHOVER'):
            continue
        if 'ApiToken' in config[section] and 'UserKey' in config[section]:
            config_json = json.dumps({
                "api_token": config[section]['ApiToken'],
                "user_key": config[section]['UserKey'],
            })
            db.add_notification_config(email_account_id, "pushover", crypto.encrypt(config_json))
            break

    # Gotify
    for section in sections:
        if not section.startswith('GOTIFY'):
            continue
        if 'Url' in config[section] and 'Token' in config[section]:
            config_json = json.dumps({
                "url": config[section]['Url'],
                "token": config[section]['Token'],
            })
            db.add_notification_config(email_account_id, "gotify", crypto.encrypt(config_json))
            break

    # Apprise
    for section in sections:
        if not section.startswith('APPRISE'):
            continue
        if 'urls' in config[section]:
            urls_list = [u.strip() for u in config[section]['urls'].split(',')]
            config_json = json.dumps({"urls": urls_list})
            db.add_notification_config(email_account_id, "apprise", crypto.encrypt(config_json))
            break
