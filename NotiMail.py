#!/usr/bin/env python3
"""
NotiMail
Version: 3.0.0
Author: Stefano Marinelli <stefano@dragas.it>
License: BSD 3-Clause License

NotiMail is a script designed to monitor one or more email inboxes using the IMAP IDLE feature
and send notifications via HTTP POST requests when a new email arrives. This version includes
additional features to store processed email UIDs in a SQLite3 database and ensure they are not
processed repeatedly.
"""

import datetime
import logging
import signal
import socket
import sys
import threading
import time

import notimail.config as notimail_config
from notimail.config import (
    parse_args, load_config, validate_config, setup_logging, setup_prometheus,
    shutdown_sock_r, shutdown_sock_w,
    MAX_RETRY_ATTEMPTS, RETRY_DELAY, IDLE_TIMEOUT,
    apprise_available, flask_available, prometheus_available,
)

# Conditional import of Flask (re-imported here for route definitions)
if flask_available:
    from flask import Flask, jsonify, request

# Parse arguments and load configuration
args = parse_args()
config = load_config(args.config)
validate_config(config)

# Database location from config
db_path = config.get('GENERAL', 'DataBaseLocation', fallback="processed_emails.db")

# Setup logging and Prometheus metrics
log_file_location = setup_logging(config)
metrics = setup_prometheus(config)
EMAILS_PROCESSED = metrics['EMAILS_PROCESSED']
NOTIFICATIONS_SENT = metrics['NOTIFICATIONS_SENT']
PROCESSING_TIME = metrics['PROCESSING_TIME']
ERRORS = metrics['ERRORS']
CONNECTIONS = metrics['CONNECTIONS']
RECONNECTS = metrics['RECONNECTS']
IDLE_TIMEOUTS = metrics['IDLE_TIMEOUTS']

# Flask web interface setup
flask_host = config.get('GENERAL', 'FlaskHost', fallback=None)
flask_port = config.getint('GENERAL', 'FlaskPort', fallback=None)

if flask_available and flask_host and flask_port:
    app = Flask(__name__)

    @app.route('/status')
    def status():
        api_key = request.args.get('api_key')
        configured_api_key = config.get('GENERAL', 'APIKey', fallback=None)
        if api_key == configured_api_key and api_key is not None:
            status_info = {'accounts': []}
            for handler in multi_handler.handlers:
                account_status = {
                    'email_user': handler.email_user,
                    'folder': handler.folder,
                    'connected': handler.mail is not None,
                    'last_check': handler.last_check.strftime("%Y-%m-%d %H:%M:%S") if handler.last_check else None,
                    'last_error': handler.last_error,
                    'retry_count': handler.retry_count
                }
                status_info['accounts'].append(account_status)
            return jsonify(status_info)
        else:
            all_connected = all(handler.mail is not None for handler in multi_handler.handlers)
            if all_connected:
                return jsonify({'status': 'OK'}), 200
            else:
                return jsonify({'status': 'ERROR'}), 500

    @app.route('/logs')
    def logs():
        api_key = request.args.get('api_key')
        configured_api_key = config.get('GENERAL', 'APIKey', fallback=None)
        if api_key == configured_api_key and api_key is not None:
            try:
                with open(log_file_location, 'r') as f:
                    logs = f.readlines()
                    last_n_lines = logs[-100:]
                return ''.join(last_n_lines), 200, {'Content-Type': 'text/plain; charset=utf-8'}
            except Exception as e:
                return f"Failed to read log file: {str(e)}", 500
        else:
            return "Unauthorized", 401

    @app.route('/config', methods=['GET'])
    def get_config():
        api_key = request.args.get('api_key')
        configured_api_key = config.get('GENERAL', 'APIKey', fallback=None)
        if api_key == configured_api_key and api_key is not None:
            config_dict = {}
            # Sensitive keys that should be redacted (emailpass remains hidden)
            sensitive_keys = ['emailpass', 'apitoken', 'userkey', 'token', 'urls']
            for section in config.sections():
                config_dict[section] = {}
                for key, value in config[section].items():
                    if key.lower() in sensitive_keys:
                        config_dict[section][key] = 'REDACTED'
                    else:
                        config_dict[section][key] = value
            return jsonify(config_dict)
        else:
            return "Unauthorized", 401

    # Add a new endpoint to reset a specific connection
    @app.route('/reset/<email_user>/<folder>', methods=['POST'])
    def reset_connection(email_user, folder):
        api_key = request.args.get('api_key')
        configured_api_key = config.get('GENERAL', 'APIKey', fallback=None)
        if api_key == configured_api_key and api_key is not None:
            for handler in multi_handler.handlers:
                if handler.email_user == email_user and handler.folder == folder:
                    logging.info(f"Manual reset of connection for {email_user} - {folder}")
                    try:
                        if handler.mail:
                            handler.mail.close()
                            handler.mail.logout()
                    except:
                        pass
                    handler.mail = None
                    handler.retry_count = 0
                    return jsonify({'status': 'Connection reset initiated'}), 200
            return jsonify({'error': 'Account not found'}), 404
        else:
            return "Unauthorized", 401
else:
    if not flask_available:
        logging.info("Flask is not available. Web interface is disabled.")
    else:
        logging.info("FlaskHost or FlaskPort not specified. Web interface will not be started.")
    app = None

from notimail.database import DatabaseHandler
from notimail.notifications import (
    Notifier, parse_notification_providers,
)
from notimail.imap import (
    EmailProcessor, IMAPHandler, MultiIMAPHandler, connection_watchdog,
)

def shutdown_handler(signum, frame):
    logging.info("Shutdown signal received. Cleaning up...")
    notimail_config.shutdown_in_progress = True
    
    try:
        # Send a byte through the socket pair to unblock any select operations
        shutdown_sock_w.send(b'\x00')
        
        # Give threads a moment to notice the shutdown flag
        time.sleep(1)
        
        # Force close any IMAP connections
        for handler in multi_handler.handlers:
            if handler.mail is not None:
                try:
                    # Force close the socket to interrupt any blocking operations
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
    logging.info("Received SIGHUP signal. Reloading configuration...")
    reload_configuration()

def reload_configuration():
    global config
    config.read(args.config)
    logging.info("Configuration reloaded.")
    # Implement logic to update handlers and notifiers if necessary

def multi_account_main():
    accounts = []
    # Parse global notification providers
    global_providers = parse_notification_providers(config, errors_metric=ERRORS)
    if global_providers:
        global_notifier = Notifier(global_providers)
    else:
        global_notifier = None

    for section in config.sections():
        if section.startswith("EMAIL:"):
            account_name = section.split(":", 1)[1]
            folders = config[section].get('Folders', 'inbox').split(', ')
            for folder in folders:
                account = {
                    'EmailUser': config[section]['EmailUser'],
                    'EmailPass': config[section]['EmailPass'],
                    'Host': config[section]['Host'],
                    'Folder': folder,
                    'Notifier': None
                }
                # Parse account-specific notification providers
                account_providers = parse_notification_providers(config, account_name, errors_metric=ERRORS)
                if account_providers:
                    account['Notifier'] = Notifier(account_providers)
                else:
                    # Use global notifier if available
                    if global_notifier:
                        account['Notifier'] = global_notifier
                    else:
                        logging.error(f"No notification providers specified for account {section} and no global notification providers are available.")
                        print(f"Error: No notification providers specified for account {section} and no global notification providers are available.")
                        sys.exit(1)
                accounts.append(account)

    # Set socket timeout
    socket.setdefaulttimeout(480)

    # Signal handlers for graceful shutdown and config reload
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGHUP, reload_config_handler)  # For dynamic config reload

    logging.info("Script started. Press Ctrl+C to stop it at any time.")

    # Start Flask app in a separate thread if available and configured
    if flask_available and app:
        flask_thread = threading.Thread(target=run_flask_app)
        flask_thread.daemon = True
        flask_thread.start()
    else:
        if not flask_available:
            logging.info("Flask is not available. Skipping web interface.")
        else:
            logging.info("FlaskHost or FlaskPort not specified. Web interface will not be started.")

    global multi_handler
    multi_handler = MultiIMAPHandler(accounts, metrics=metrics, db_path=db_path)

    # Start a watchdog thread to monitor handler threads
    watchdog_thread = threading.Thread(target=connection_watchdog, args=(multi_handler,), name="watchdog")
    watchdog_thread.daemon = True
    watchdog_thread.start()

    multi_handler.run()

    logging.info("Logging out and closing connections...")
    try:
        for handler in multi_handler.handlers:
            if handler.mail:
                handler.mail.logout()
    except:
        pass

def print_config():
    for section in config.sections():
        print(f"[{section}]")
        for key, value in config[section].items():
            print(f"{key} = {value}")
        print()

def test_config():
    logging.info("Testing global notification providers...")
    global_providers = parse_notification_providers(config, errors_metric=ERRORS)
    if global_providers:
        global_notifier = Notifier(global_providers)
        try:
            global_notifier.send_notification("Test Sender", "Test Notification from NotiMail")
            logging.info("Test notification sent successfully via global notification providers!")
        except Exception as e:
            logging.error(f"Failed to send test notification via global providers. Reason: {str(e)}")
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
                logging.error(f"Connection failed for {section}. Reason: {str(e)}")
            account_providers = parse_notification_providers(config, account_name, errors_metric=ERRORS)
            if account_providers:
                account_notifier = Notifier(account_providers)
                try:
                    account_notifier.send_notification("Test Sender", f"Test Notification from NotiMail - {section}")
                    logging.info(f"Test notification sent successfully via account-specific providers for {section}!")
                except Exception as e:
                    logging.error(f"Failed to send test notification via account-specific providers for {section}. Reason: {str(e)}")
            else:
                logging.info(f"No account-specific notification providers configured for {section}.")
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
                logging.error(f"Failed to list folders for {section}. Reason: {str(e)}")

def run_flask_app():
    app.run(host=flask_host, port=flask_port)

def initial_checks():
    logging.info("Performing initial tests...")
    # Test log file write
    try:
        with open(log_file_location, 'a') as f:
            test_message = f"{datetime.datetime.now()} - Test log write from NotiMail startup.\n"
            f.write(test_message)
    except Exception as e:
        print("Error: unable to write to log file:", e)
        logging.error("Error: unable to write to log file: " + str(e))
        sys.exit(1)
    
    # Test database operations
    try:
        with DatabaseHandler(db_path) as db:
            db.add_email("test", "test", 0)
            db.cursor.execute("DELETE FROM processed_emails WHERE email_account=? AND uid=?", ("test", "test"))
            db.connection.commit()
    except Exception as e:
        print("Error: unable to write to database:", e)
        logging.error("Error: unable to write to database: " + str(e))
        sys.exit(1)
    
    # Test sending a test notification via global providers
    try:
        global_providers = parse_notification_providers(config, errors_metric=ERRORS)
        if not global_providers:
            print("Warning: no global notification providers configured for the test.")
            logging.warning("Warning: no global notification providers configured for the test.")
        else:
            test_notifier = Notifier(global_providers)
            test_notifier.send_notification("Test Notification", "Test notification from NotiMail startup")
    except Exception as e:
        print("Warning: unable to send test notification:", e)
        logging.warning("Warning: unable to send test notification: " + str(e))
    
    logging.info("Initial tests completed successfully.")

if __name__ == "__main__":
    if args.print_config:
        print_config()
    elif args.test_config:
        test_config()
    elif args.list_folders:
        list_imap_folders()
    else:
        initial_checks()
        multi_account_main()
