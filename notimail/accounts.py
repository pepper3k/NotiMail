"""
Account loading utilities for NotiMail.

Provides functions to load email accounts and their notification
providers from the database, decrypting credentials at runtime.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from notimail.crypto import CryptoManager
from notimail.database import DatabaseHandler
from notimail.notifications import (
    Notifier, NotificationProvider,
    NTFYNotificationProvider, PushoverNotificationProvider,
    GotifyNotificationProvider,
)
from notimail.config import apprise_available

if apprise_available:
    from notimail.notifications import AppriseNotificationProvider


def load_accounts_from_db(
    db: DatabaseHandler,
    crypto: CryptoManager,
    errors_metric: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    """Load all enabled email accounts from the database.

    Decrypts credentials and builds Notifier instances from the
    associated notification_configs.  For memory-only accounts
    (credential_mode=1), email_pass is set to None since the
    password is never stored.

    Args:
        db: The DatabaseHandler instance.
        crypto: The CryptoManager for decrypting credentials.
        errors_metric: Prometheus error counter passed to notification providers.

    Returns:
        A list of account dicts with keys: EmailUser, EmailPass, Host,
        Port, Folder, Notifier, account_id, account_name, credential_mode.
        One entry per (account, folder) combination.
    """
    accounts: List[Dict[str, Any]] = []
    raw_accounts = db.get_all_enabled_accounts()

    for acct in raw_accounts:
        credential_mode = acct.get('credential_mode', 0)

        # Decrypt credentials
        try:
            email_user = crypto.decrypt(acct['email_user_encrypted'])
            host = crypto.decrypt(acct['host_encrypted'])

            if credential_mode == 1:
                # Memory-only: password is never stored (empty string in DB)
                email_pass = None
            else:
                email_pass = crypto.decrypt(acct['email_pass_encrypted'])
        except Exception as e:
            logging.error(f"Failed to decrypt account {acct['account_name']}: {e}")
            continue

        # Build notifier from notification configs
        notifier = _build_notifier_for_account(db, crypto, acct['id'], errors_metric)

        # Split folders and create one entry per folder
        folders = [f.strip() for f in acct['folders'].split(',')]
        for folder in folders:
            accounts.append({
                'EmailUser': email_user,
                'EmailPass': email_pass,
                'Host': host,
                'Port': acct['port'],
                'Folder': folder,
                'Notifier': notifier,
                'account_id': acct['id'],
                'account_name': acct['account_name'],
                'credential_mode': credential_mode,
            })

    return accounts


def _build_notifier_for_account(
    db: DatabaseHandler,
    crypto: CryptoManager,
    email_account_id: int,
    errors_metric: Optional[Any] = None,
) -> Optional[Notifier]:
    """Build a Notifier from the notification_configs for an email account.

    Args:
        db: The DatabaseHandler instance.
        crypto: The CryptoManager for decrypting config blobs.
        email_account_id: The email_accounts.id to load configs for.
        errors_metric: Prometheus error counter passed to providers.

    Returns:
        A Notifier instance, or None if no configs are found.
    """
    configs = db.get_notification_configs_for_account(email_account_id)
    if not configs:
        return None

    providers: List[NotificationProvider] = []

    for cfg in configs:
        try:
            config_json = json.loads(crypto.decrypt(cfg['config_encrypted']))
        except Exception as e:
            logging.error(f"Failed to decrypt notification config {cfg['id']}: {e}")
            continue

        provider_type = cfg['provider_type']

        if provider_type == 'ntfy':
            urls = config_json.get('urls', [])
            ntfy_data = [(u['url'], u.get('token')) for u in urls]
            if ntfy_data:
                providers.append(NTFYNotificationProvider(ntfy_data, errors_metric))

        elif provider_type == 'pushover':
            api_token = config_json.get('api_token', '')
            user_key = config_json.get('user_key', '')
            if api_token and user_key:
                providers.append(PushoverNotificationProvider(api_token, user_key, errors_metric))

        elif provider_type == 'gotify':
            url = config_json.get('url', '')
            token = config_json.get('token', '')
            if url and token:
                providers.append(GotifyNotificationProvider(url, token, errors_metric))

        elif provider_type == 'apprise' and apprise_available:
            urls = config_json.get('urls', [])
            if urls:
                providers.append(AppriseNotificationProvider(urls))

        else:
            logging.warning(f"Unknown notification provider type: {provider_type}")

    return Notifier(providers) if providers else None
