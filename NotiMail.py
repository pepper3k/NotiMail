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

import imaplib
import email
import time
import socket
import datetime
import signal
import sys
import logging
import threading
import os
import select
from email import policy
from email.parser import BytesParser
from threading import Lock

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

class EmailProcessor:
    def __init__(self, mail, email_account, notifier):
        self.mail = mail
        self.email_account = email_account
        self.notifier = notifier

    def fetch_unseen_emails(self):
        try:
            status, messages = self.mail.uid('search', None, "UNSEEN")
            if status != 'OK':
                logging.warning(f"Search for UNSEEN emails returned status: {status}")
                return []
            return messages[0].split()
        except Exception as e:
            logging.error(f"Error fetching unseen emails: {str(e)}")
            return []

    def parse_email(self, raw_email):
        return BytesParser(policy=policy.default).parsebytes(raw_email)

    def process(self):
        logging.info("Fetching the latest email...")
        try:
            with DatabaseHandler(db_path) as db_handler:
                for message in self.fetch_unseen_emails():
                    uid = message.decode('utf-8')
                    if db_handler.is_email_notified(self.email_account, uid):
                        logging.info(f"Email UID {uid} already processed and notified, skipping...")
                        continue

                    try:
                        _, msg = self.mail.uid('fetch', message, '(BODY.PEEK[])')
                        if not msg or msg[0] is None:
                            logging.warning(f"Failed to fetch email with UID {uid}")
                            continue
                        
                        for response_part in msg:
                            if isinstance(response_part, tuple):
                                with PROCESSING_TIME.time():
                                    try:
                                        email_message = self.parse_email(response_part[1])
                                        sender = email_message.get('From')
                                        subject = email_message.get('Subject')
                                        logging.info(f"Processing Email - UID: {uid}, Sender: {sender}, Subject: {subject}")
                                        
                                        try:
                                            self.notifier.send_notification(sender, subject)
                                            NOTIFICATIONS_SENT.inc()
                                        except Exception as e:
                                            logging.error(f"Failed to send notification: {str(e)}")
                                            ERRORS.inc()
                                        
                                        db_handler.add_email(self.email_account, uid, 1)
                                        EMAILS_PROCESSED.inc()
                                    except Exception as inner_e:
                                        logging.error(f"Error processing email content: {str(inner_e)}")
                                        ERRORS.inc()
                    except Exception as e:
                        logging.error(f"Error fetching email with UID {uid}: {str(e)}")
                        ERRORS.inc()

                db_handler.delete_old_emails()
        except Exception as e:
            logging.error(f"Error in process method: {str(e)}")
            ERRORS.inc()
            raise  # Re-raise to trigger reconnection

from notimail.notifications import (
    NotificationProvider, NTFYNotificationProvider, PushoverNotificationProvider,
    GotifyNotificationProvider, Notifier, parse_notification_providers,
)
if apprise_available:
    from notimail.notifications import AppriseNotificationProvider

class IMAPHandler:
    def __init__(self, host, email_user, email_pass, folder="inbox", notifier=None):
        self.host = host
        self.email_user = email_user
        self.email_pass = email_pass
        self.folder = folder
        self.notifier = notifier
        self.mail = None
        self.last_check = None
        self.last_error = None
        self.retry_count = 0
        self.healthy = True  # Track if this connection is healthy

    def connect(self):
        if notimail_config.shutdown_in_progress:
            return False
            
        if self.mail is not None:
            # Try to check if the connection is still alive
            try:
                status, _ = self.mail.noop()
                if status == 'OK':
                    logging.info(f"[{self.email_user} - {self.folder}] Connection is still alive")
                    return True
            except Exception as e:
                logging.warning(f"[{self.email_user} - {self.folder}] Connection check failed: {str(e)}")
            
            # If we get here, the connection is not healthy; try to clean it up
            try:
                self.mail.close()
                self.mail.logout()
            except:
                pass
            self.mail = None
            CONNECTIONS.set(sum(1 for handler in multi_handler.handlers if handler.mail is not None))
        
        # Attempt to establish a new connection
        try:
            logging.info(f"[{self.email_user} - {self.folder}] Connecting to IMAP server...")
            self.mail = imaplib.IMAP4_SSL(self.host, 993)
            self.mail.login(self.email_user, self.email_pass)
            self.mail.select(self.folder)
            logging.info(f"[{self.email_user} - {self.folder}] Successfully connected to IMAP server")
            self.last_error = None
            self.retry_count = 0
            self.healthy = True
            CONNECTIONS.set(sum(1 for handler in multi_handler.handlers if handler.mail is not None))
            return True
        except Exception as e:
            self.last_error = str(e)
            self.mail = None
            self.retry_count += 1
            RECONNECTS.inc()
            CONNECTIONS.set(sum(1 for handler in multi_handler.handlers if handler.mail is not None))
            logging.error(f"[{self.email_user} - {self.folder}] Connection failed (attempt {self.retry_count}): {str(e)}")
            if self.notifier and self.retry_count == 1:  # Only notify on first failure
                try:
                    self.notifier.send_notification("Connection Error", 
                                                   f"Failed to connect to {self.email_user} - {self.folder}: {str(e)}")
                except:
                    pass
            return False

    def idle(self):
        if not self.mail or notimail_config.shutdown_in_progress:
            return False
            
        logging.info(f"[{self.email_user} - {self.folder}] IDLE mode started. Waiting for new email...")
        try:
            tag = self.mail._new_tag().decode()
            self.mail.send(f'{tag} IDLE\r\n'.encode('utf-8'))
            
            # Set a timeout to periodically check connection health
            end_time = time.time() + IDLE_TIMEOUT
            
            while time.time() < end_time:
                # Wait with a small timeout to allow periodic checks
                timeout = min(30, end_time - time.time())
                if timeout <= 0:
                    break
                    
                # Wait for activity on the IMAP socket or the shutdown socket
                rlist, _, _ = select.select([self.mail.sock, shutdown_sock_r], [], [], timeout)
                
                if shutdown_sock_r in rlist:
                    # Received "wake-up" data, exit the loop
                    shutdown_sock_r.recv(1024)
                    logging.info(f"[{self.email_user} - {self.folder}] Shutdown signal received during IDLE")
                    self.mail.send(b'DONE\r\n')
                    self.mail.readline()
                    return False
                    
                if self.mail.sock in rlist:
                    line = self.mail.readline().decode('utf-8', errors='ignore')
                    if not line:
                        raise ConnectionAbortedError("Connection closed by server")
                        
                    logging.debug(f"[{self.email_user} - {self.folder}] IDLE response: {line.strip()}")
                    
                    if 'BYE' in line or 'NO ' in line or 'BAD ' in line:
                        logging.warning(f"[{self.email_user} - {self.folder}] Received error from server: {line.strip()}")
                        raise ConnectionAbortedError(f"Server sent: {line.strip()}")
                        
                    if 'EXISTS' in line:
                        logging.info(f"[{self.email_user} - {self.folder}] New email detected: {line.strip()}")
                        # Exit IDLE mode to process the email
                        self.mail.send(b'DONE\r\n')
                        self.mail.readline()
                        self.last_check = datetime.datetime.now()
                        return True
            
            # If we reach here, the IDLE timeout expired
            logging.info(f"[{self.email_user} - {self.folder}] IDLE timeout reached")
            IDLE_TIMEOUTS.inc()
            self.mail.send(b'DONE\r\n')
            self.mail.readline()
            self.last_check = datetime.datetime.now()
            return True
            
        except Exception as e:
            logging.error(f"[{self.email_user} - {self.folder}] Error in IDLE: {str(e)}")
            self.last_error = str(e)
            ERRORS.inc()
            # Mark this connection as unhealthy so we'll reconnect
            self.healthy = False
            return False
        finally:
            logging.info(f"[{self.email_user} - {self.folder}] IDLE mode ended")

    def process_emails(self):
        if not self.mail or not self.healthy:
            return False
            
        try:
            processor = EmailProcessor(self.mail, self.email_user, self.notifier)
            processor.process()
            return True
        except Exception as e:
            logging.error(f"[{self.email_user} - {self.folder}] Error processing emails: {str(e)}")
            self.last_error = str(e)
            ERRORS.inc()
            self.healthy = False
            return False

class MultiIMAPHandler:
    def __init__(self, accounts):
        self.accounts = accounts
        self.handlers = [IMAPHandler(account['Host'], account['EmailUser'], account['EmailPass'], account['Folder'], account['Notifier']) for account in accounts]
        self.lock = Lock()
        self.threads = []

    def run(self):
        self.threads = []
        for handler in self.handlers:
            thread = threading.Thread(target=self.monitor_account, args=(handler,), name=f"{handler.email_user}-{handler.folder}")
            thread.daemon = True
            self.threads.append(thread)
            thread.start()
        for thread in self.threads:
            thread.join()

    def monitor_account(self, handler):
        logging.info(f"Monitoring {handler.email_user} - Folder: {handler.folder}")
        backoff_time = RETRY_DELAY
        
        while not notimail_config.shutdown_in_progress:
            try:
                # Attempt to connect
                if not handler.connect():
                    # If connection failed, implement backoff retry
                    retry_time = min(backoff_time * (handler.retry_count % 5), 300)  # Cap at 5 minutes
                    logging.info(f"[{handler.email_user} - {handler.folder}] Retrying connection in {retry_time} seconds")
                    
                    # Check for shutdown while waiting
                    wait_until = time.time() + retry_time
                    while time.time() < wait_until and not notimail_config.shutdown_in_progress:
                        time.sleep(1)
                        
                    continue  # Skip to next iteration to try connecting again
                
                # Reset backoff time on successful connection
                backoff_time = RETRY_DELAY
                
                # Monitor mailbox until an error occurs
                while handler.healthy and not notimail_config.shutdown_in_progress:
                    idle_result = handler.idle()
                    if not idle_result:
                        break  # IDLE failed, so we need to reconnect
                        
                    # Process any new emails after IDLE returns
                    with self.lock:
                        if not handler.process_emails():
                            break  # Processing failed, so we need to reconnect
                            
                    # Quick check if the connection is still alive
                    try:
                        status, _ = handler.mail.noop()
                        if status != 'OK':
                            logging.warning(f"[{handler.email_user} - {handler.folder}] NOOP check failed after processing")
                            break
                    except Exception as e:
                        logging.warning(f"[{handler.email_user} - {handler.folder}] NOOP check error: {str(e)}")
                        break
                
            except ConnectionAbortedError as e:
                logging.error(f"[{handler.email_user} - {handler.folder}] Connection aborted: {str(e)}")
                handler.last_error = str(e)
                handler.healthy = False
                ERRORS.inc()
            except Exception as e:
                logging.error(f"[{handler.email_user} - {handler.folder}] Unexpected error: {str(e)}")
                handler.last_error = str(e)
                handler.healthy = False
                ERRORS.inc()
            
            # Clean up connection before retrying
            if handler.mail:
                try:
                    handler.mail.close()
                    handler.mail.logout()
                except:
                    pass
                handler.mail = None
                CONNECTIONS.set(sum(1 for h in self.handlers if h.mail is not None))
            
            # Prevent tight retry loops
            if not notimail_config.shutdown_in_progress:
                time.sleep(5)

def shutdown_handler(signum, frame):
    logging.info("Shutdown signal received. Cleaning up...")
    notimail_config.notimail_config.shutdown_in_progress = True
    
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

    # Start a watchdog thread to monitor handler threads
    watchdog_thread = threading.Thread(target=connection_watchdog, name="watchdog")
    watchdog_thread.daemon = True
    watchdog_thread.start()

    global multi_handler
    multi_handler = MultiIMAPHandler(accounts)
    multi_handler.run()

    logging.info("Logging out and closing connections...")
    try:
        for handler in multi_handler.handlers:
            if handler.mail:
                handler.mail.logout()
    except:
        pass

def connection_watchdog():
    """Monitor all handlers and restart threads if needed"""
    while not notimail_config.shutdown_in_progress:
        time.sleep(60)  # Check every minute
        
        if notimail_config.shutdown_in_progress:
            break
            
        # Check if all threads are alive
        for i, thread in enumerate(multi_handler.threads):
            if not thread.is_alive() and not notimail_config.shutdown_in_progress:
                handler = multi_handler.handlers[i]
                logging.warning(f"Thread for {handler.email_user} - {handler.folder} has died. Restarting...")
                
                # Clean up old connection if any
                if handler.mail:
                    try:
                        handler.mail.close()
                        handler.mail.logout()
                    except:
                        pass
                    handler.mail = None
                
                # Reset handler state
                handler.healthy = True
                
                # Start a new thread
                new_thread = threading.Thread(target=multi_handler.monitor_account, 
                                             args=(handler,), 
                                             name=f"{handler.email_user}-{handler.folder}")
                new_thread.daemon = True
                multi_handler.threads[i] = new_thread
                new_thread.start()
                
                # Send notification about thread restart
                if handler.notifier:
                    try:
                        handler.notifier.send_notification("Thread Restarted", 
                                                         f"Monitoring thread for {handler.email_user} - {handler.folder} has been restarted")
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
