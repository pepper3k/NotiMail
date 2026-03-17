#!/usr/bin/env python3
"""
NotiMail
Version: 3.0.0
Author: Stefano Marinelli <stefano@dragas.it>
License: BSD 3-Clause License

NotiMail monitors email inboxes via IMAP IDLE and sends push notifications
when new mail arrives. v3 adds encrypted credential storage, user management,
a web dashboard with login, and a REST API for mail client registration.
"""

import datetime
import logging
import os
import signal
import socket
import sys
import threading
import time

import notimail.config as notimail_config
from notimail.config import (
    parse_args, load_config, validate_config, setup_logging, setup_prometheus,
    shutdown_sock_r, shutdown_sock_w,
    apprise_available, flask_available,
)
from notimail.database import DatabaseHandler
from notimail.notifications import Notifier, parse_notification_providers
from notimail.imap import IMAPHandler, MultiIMAPHandler, connection_watchdog

# Parse arguments and load configuration
args = parse_args()
config = load_config(args.config)
validate_config(config)

# Core paths from config — ensure parent directories exist
db_path = config.get('GENERAL', 'DataBaseLocation', fallback="processed_emails.db")
key_path = config.get('GENERAL', 'SecretKeyLocation', fallback='/etc/notimail/secret.key')
for _path in (db_path, key_path):
    _dir = os.path.dirname(_path)
    if _dir:
        os.makedirs(_dir, exist_ok=True)

# Setup logging and Prometheus metrics
log_file_location = setup_logging(config)
metrics = setup_prometheus(config)

# Global reference for shutdown handler
multi_handler = None


def shutdown_handler(signum, frame):
    """Handle SIGTERM/SIGINT for graceful shutdown."""
    logging.info("Shutdown signal received. Cleaning up...")
    notimail_config.shutdown_in_progress = True
    try:
        shutdown_sock_w.send(b'\x00')
        time.sleep(1)
        if multi_handler:
            for handler in multi_handler.handlers:
                if handler.mail is not None:
                    try:
                        handler.mail.sock.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass
                    try:
                        handler.mail.logout()
                    except Exception:
                        pass
    except Exception as e:
        logging.error(f"Error during shutdown: {str(e)}")
    logging.info("Cleanup complete. Exiting.")
    sys.exit(0)


def reload_config_handler(signum, frame):
    """Handle SIGHUP for configuration reload."""
    logging.info("Received SIGHUP signal. Reloading configuration...")
    global config
    config.read(args.config)
    logging.info("Configuration reloaded.")


def main():
    """Main entry point: initialize crypto, DB, migration, web app, and IMAP handlers."""
    global multi_handler

    from notimail.crypto import CryptoManager
    from notimail.migrate import should_migrate, migrate_from_config
    from notimail.accounts import load_accounts_from_db
    from notimail.host_limits import HostLimitManager
    from notimail.web import create_app

    # Initialize encryption
    crypto = CryptoManager(key_path)

    # Initialize database and run migrations
    db = DatabaseHandler(db_path)
    db.apply_migrations()

    # Check if admin user exists
    if db.count_users() == 0:
        # Check if there are legacy EMAIL sections to migrate
        has_legacy = any(s.startswith("EMAIL:") for s in config.sections())
        if not has_legacy:
            print("No admin user found. Run: python3 NotiMail.py --setup-admin")
            sys.exit(1)
        else:
            print("No admin user found but legacy EMAIL sections detected.")
            print("Run --setup-admin first, then restart to migrate accounts.")
            sys.exit(1)

    # Auto-migrate from config.ini if needed
    if should_migrate(config, db):
        admin = next(
            (u for u in db.get_all_users() if u['role'] == 'admin'), None)
        if admin:
            migrate_from_config(config, db, crypto, admin['id'])
        else:
            logging.warning("No admin user found for migration. Skipping config.ini import.")

    # Load accounts from database
    accounts = load_accounts_from_db(db, crypto, errors_metric=metrics['ERRORS'])

    # Also load any remaining config.ini accounts (backward compat during transition)
    config_accounts = _load_legacy_accounts()
    accounts.extend(config_accounts)

    if not accounts:
        logging.warning("No email accounts configured. Add accounts via the API or web dashboard.")

    # Set socket timeout
    socket.setdefaulttimeout(480)

    # Signal handlers
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGHUP, reload_config_handler)

    # Initialize host limit manager
    limits_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'known_host_limits.ini')
    host_limits = HostLimitManager(limits_path)

    logging.info("NotiMail v3 starting...")

    # Create and start Flask web app
    flask_host = config.get('GENERAL', 'FlaskHost', fallback=None)
    flask_port_str = config.get('GENERAL', 'FlaskPort', fallback=None)

    # account_loader is called by the watchdog every 60s to detect new/removed accounts
    def _account_loader():
        return load_accounts_from_db(db, crypto, errors_metric=metrics['ERRORS'])

    multi_handler = MultiIMAPHandler(
        accounts, metrics=metrics, db_path=db_path, account_loader=_account_loader)

    if flask_host and flask_port_str:
        flask_port = int(flask_port_str)
        app = create_app(db, crypto, config, multi_handler=multi_handler, host_limits=host_limits)
        flask_thread = threading.Thread(
            target=lambda: app.run(host=flask_host, port=flask_port, use_reloader=False),
            name="flask",
        )
        flask_thread.daemon = True
        flask_thread.start()
        logging.info(f"Web interface started on {flask_host}:{flask_port}")
    else:
        logging.info("FlaskHost or FlaskPort not specified. Web interface disabled.")

    # Start watchdog
    watchdog_thread = threading.Thread(
        target=connection_watchdog, args=(multi_handler,), name="watchdog")
    watchdog_thread.daemon = True
    watchdog_thread.start()

    # Start IMAP monitoring (blocks until shutdown)
    multi_handler.run()

    logging.info("Logging out and closing connections...")
    try:
        for handler in multi_handler.handlers:
            if handler.mail:
                handler.mail.logout()
    except:
        pass


def _load_legacy_accounts():
    """Load accounts from config.ini EMAIL sections (backward compatibility).

    These are accounts that haven't been migrated to the DB yet.
    Returns a list of account dicts compatible with MultiIMAPHandler.
    """
    accounts = []
    global_providers = parse_notification_providers(config, errors_metric=metrics['ERRORS'])
    global_notifier = Notifier(global_providers) if global_providers else None

    for section in config.sections():
        if not section.startswith("EMAIL:"):
            continue
        account_name = section.split(":", 1)[1]
        folders = config[section].get('Folders', 'inbox').split(', ')
        for folder in folders:
            account_providers = parse_notification_providers(
                config, account_name, errors_metric=metrics['ERRORS'])
            notifier = Notifier(account_providers) if account_providers else global_notifier

            if not notifier:
                logging.error(f"No notification providers for {section}. Skipping.")
                continue

            accounts.append({
                'EmailUser': config[section]['EmailUser'],
                'EmailPass': config[section]['EmailPass'],
                'Host': config[section]['Host'],
                'Folder': folder,
                'Notifier': notifier,
            })
    return accounts


def print_config():
    for section in config.sections():
        print(f"[{section}]")
        for key, value in config[section].items():
            print(f"{key} = {value}")
        print()


def test_config():
    logging.info("Testing notification providers...")
    global_providers = parse_notification_providers(config, errors_metric=metrics['ERRORS'])
    if global_providers:
        Notifier(global_providers).send_notification("Test Sender", "Test Notification from NotiMail")
        logging.info("Test notification sent successfully!")
    else:
        logging.info("No global notification providers configured.")

    for section in config.sections():
        if section.startswith("EMAIL:"):
            account_name = section.split(":", 1)[1]
            logging.info(f"Testing {section}...")
            handler = IMAPHandler(config[section]['Host'], config[section]['EmailUser'], config[section]['EmailPass'])
            try:
                handler.connect()
                logging.info(f"Connection successful for {section}")
                handler.mail.logout()
            except Exception as e:
                logging.error(f"Connection failed for {section}: {str(e)}")
    logging.info("Testing completed!")


def list_imap_folders():
    for section in config.sections():
        if section.startswith("EMAIL:"):
            logging.info(f"Listing folders for {section}...")
            handler = IMAPHandler(config[section]['Host'], config[section]['EmailUser'], config[section]['EmailPass'])
            try:
                handler.connect()
                typ, folders = handler.mail.list()
                for folder in folders:
                    print(folder.decode())
                handler.mail.logout()
            except Exception as e:
                logging.error(f"Failed to list folders for {section}: {str(e)}")


def setup_admin():
    """Interactive setup of the initial admin user."""
    import getpass
    from notimail.crypto import CryptoManager
    from notimail.auth import hash_password

    crypto = CryptoManager(key_path)
    db = DatabaseHandler(db_path)
    db.apply_migrations()

    if db.count_users() > 0:
        print("Admin user already exists. Use the web dashboard to manage users.")
        sys.exit(0)

    print("=== NotiMail Admin Setup ===")
    username = input("Admin username: ").strip()
    if not username:
        print("Error: username cannot be empty.")
        sys.exit(1)

    password = getpass.getpass("Admin password: ")
    password_confirm = getpass.getpass("Confirm password: ")
    if password != password_confirm:
        print("Error: passwords do not match.")
        sys.exit(1)
    if len(password) < 8:
        print("Error: password must be at least 8 characters.")
        sys.exit(1)

    user_id = db.add_user(
        username_encrypted=crypto.encrypt(username),
        username_lookup=crypto.hmac_hash(username),
        password_hash=hash_password(password),
        role="admin",
    )
    print(f"Admin user '{username}' created successfully (id={user_id}).")
    db.close()


def create_invite_cli():
    """Generate an invite code from the command line."""
    from notimail.crypto import CryptoManager
    from notimail.auth import create_invite

    crypto = CryptoManager(key_path)
    db = DatabaseHandler(db_path)
    db.apply_migrations()

    if db.count_users() == 0:
        print("Error: no admin user exists. Run --setup-admin first.")
        sys.exit(1)

    admin = next((u for u in db.get_all_users() if u['role'] == 'admin'), None)
    if not admin:
        print("Error: no admin user found.")
        sys.exit(1)

    expire_days = config.getint('GENERAL', 'InviteExpiryDays', fallback=7)
    code = create_invite(db, admin['id'], expire_days)
    flask_port = config.get('GENERAL', 'FlaskPort', fallback='8080')
    print(f"Invite code: {code}")
    print(f"Registration URL: http://<your-host>:{flask_port}/register/{code}")
    print(f"Expires in {expire_days} days.")
    db.close()


if __name__ == "__main__":
    if args.print_config:
        print_config()
    elif args.test_config:
        test_config()
    elif args.list_folders:
        list_imap_folders()
    elif args.setup_admin:
        setup_admin()
    elif args.create_invite:
        create_invite_cli()
    else:
        main()
