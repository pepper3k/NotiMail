"""
IMAP connection handlers for NotiMail.

Manages IMAP IDLE connections, email processing, multi-account
orchestration, and the connection watchdog.
"""

import datetime
import imaplib
import logging
import select
import socket
import threading
import time
from email import policy
from email.parser import BytesParser
from threading import Lock

import notimail.config as notimail_config
from notimail.config import (
    shutdown_sock_r, shutdown_sock_w,
    RETRY_DELAY, IDLE_TIMEOUT,
)
from notimail.database import DatabaseHandler


class EmailProcessor:
    """Fetches unseen emails from an IMAP connection and sends notifications."""
    def __init__(self, mail, email_account, notifier, db_path, metrics):
        self.mail = mail
        self.email_account = email_account
        self.notifier = notifier
        self.db_path = db_path
        self.metrics = metrics

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
            with DatabaseHandler(self.db_path) as db_handler:
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
                                with self.metrics['PROCESSING_TIME'].time():
                                    try:
                                        email_message = self.parse_email(response_part[1])
                                        sender = email_message.get('From')
                                        subject = email_message.get('Subject')
                                        logging.info(f"Processing Email - UID: {uid}, Sender: {sender}, Subject: {subject}")

                                        try:
                                            self.notifier.send_notification(sender, subject)
                                            self.metrics['NOTIFICATIONS_SENT'].inc()
                                        except Exception as e:
                                            logging.error(f"Failed to send notification: {str(e)}")
                                            self.metrics['ERRORS'].inc()

                                        db_handler.add_email(self.email_account, uid, 1)
                                        self.metrics['EMAILS_PROCESSED'].inc()
                                    except Exception as inner_e:
                                        logging.error(f"Error processing email content: {str(inner_e)}")
                                        self.metrics['ERRORS'].inc()
                    except Exception as e:
                        logging.error(f"Error fetching email with UID {uid}: {str(e)}")
                        self.metrics['ERRORS'].inc()

                db_handler.delete_old_emails()
        except Exception as e:
            logging.error(f"Error in process method: {str(e)}")
            self.metrics['ERRORS'].inc()
            raise


class IMAPHandler:
    """Manages a single IMAP IDLE connection for one account/folder pair."""
    def __init__(self, host, email_user, email_pass, folder="inbox", notifier=None, metrics=None):
        self.host = host
        self.email_user = email_user
        self.email_pass = email_pass
        self.folder = folder
        self.notifier = notifier
        self.metrics = metrics or {}
        self.mail = None
        self.last_check = None
        self.last_error = None
        self.retry_count = 0
        self.healthy = True
        self.stop_event = threading.Event()

    def _count_active_connections(self, all_handlers):
        """Count how many handlers have active IMAP connections."""
        return sum(1 for h in all_handlers if h.mail is not None)

    def connect(self, all_handlers=None):
        if notimail_config.shutdown_in_progress or self.stop_event.is_set():
            return False

        if self.mail is not None:
            try:
                status, _ = self.mail.noop()
                if status == 'OK':
                    logging.info(f"[{self.email_user} - {self.folder}] Connection is still alive")
                    return True
            except Exception as e:
                logging.warning(f"[{self.email_user} - {self.folder}] Connection check failed: {str(e)}")

            try:
                self.mail.close()
                self.mail.logout()
            except:
                pass
            self.mail = None
            if all_handlers:
                self.metrics.get('CONNECTIONS', _DummyMetric()).set(
                    self._count_active_connections(all_handlers))

        try:
            logging.info(f"[{self.email_user} - {self.folder}] Connecting to IMAP server...")
            self.mail = imaplib.IMAP4_SSL(self.host, 993)
            self.mail.login(self.email_user, self.email_pass)
            self.mail.select(self.folder)
            logging.info(f"[{self.email_user} - {self.folder}] Successfully connected to IMAP server")
            self.last_error = None
            self.retry_count = 0
            self.healthy = True
            if all_handlers:
                self.metrics.get('CONNECTIONS', _DummyMetric()).set(
                    self._count_active_connections(all_handlers))
            return True
        except Exception as e:
            self.last_error = str(e)
            self.mail = None
            self.retry_count += 1
            self.metrics.get('RECONNECTS', _DummyMetric()).inc()
            if all_handlers:
                self.metrics.get('CONNECTIONS', _DummyMetric()).set(
                    self._count_active_connections(all_handlers))
            logging.error(f"[{self.email_user} - {self.folder}] Connection failed (attempt {self.retry_count}): {str(e)}")
            if self.notifier and self.retry_count == 1:
                try:
                    self.notifier.send_notification(
                        "Connection Error",
                        f"Failed to connect to {self.email_user} - {self.folder}: {str(e)}")
                except:
                    pass
            return False

    def idle(self):
        if not self.mail or notimail_config.shutdown_in_progress or self.stop_event.is_set():
            return False

        logging.info(f"[{self.email_user} - {self.folder}] IDLE mode started. Waiting for new email...")
        try:
            tag = self.mail._new_tag().decode()
            self.mail.send(f'{tag} IDLE\r\n'.encode('utf-8'))

            end_time = time.time() + IDLE_TIMEOUT

            while time.time() < end_time:
                timeout = min(30, end_time - time.time())
                if timeout <= 0:
                    break

                rlist, _, _ = select.select([self.mail.sock, shutdown_sock_r], [], [], timeout)

                if self.stop_event.is_set():
                    self.mail.send(b'DONE\r\n')
                    self.mail.readline()
                    return False

                if shutdown_sock_r in rlist:
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
                        self.mail.send(b'DONE\r\n')
                        self.mail.readline()
                        self.last_check = datetime.datetime.now()
                        return True

            logging.info(f"[{self.email_user} - {self.folder}] IDLE timeout reached")
            self.metrics.get('IDLE_TIMEOUTS', _DummyMetric()).inc()
            self.mail.send(b'DONE\r\n')
            self.mail.readline()
            self.last_check = datetime.datetime.now()
            return True

        except Exception as e:
            logging.error(f"[{self.email_user} - {self.folder}] Error in IDLE: {str(e)}")
            self.last_error = str(e)
            self.metrics.get('ERRORS', _DummyMetric()).inc()
            self.healthy = False
            return False
        finally:
            logging.info(f"[{self.email_user} - {self.folder}] IDLE mode ended")

    def process_emails(self, db_path):
        if not self.mail or not self.healthy:
            return False

        try:
            processor = EmailProcessor(self.mail, self.email_user, self.notifier, db_path, self.metrics)
            processor.process()
            return True
        except Exception as e:
            logging.error(f"[{self.email_user} - {self.folder}] Error processing emails: {str(e)}")
            self.last_error = str(e)
            self.metrics.get('ERRORS', _DummyMetric()).inc()
            self.healthy = False
            return False


class MultiIMAPHandler:
    """Orchestrates monitoring of multiple IMAP accounts concurrently."""
    def __init__(self, accounts, metrics=None, db_path=None):
        self.accounts = accounts
        self.metrics = metrics or {}
        self.db_path = db_path or "processed_emails.db"
        self.handlers = [
            IMAPHandler(
                account['Host'], account['EmailUser'], account['EmailPass'],
                account['Folder'], account['Notifier'], metrics=self.metrics
            )
            for account in accounts
        ]
        self.lock = Lock()
        self.threads = []

    def run(self):
        self.threads = []
        for handler in self.handlers:
            thread = threading.Thread(
                target=self.monitor_account, args=(handler,),
                name=f"{handler.email_user}-{handler.folder}")
            thread.daemon = True
            self.threads.append(thread)
            thread.start()
        for thread in self.threads:
            thread.join()

    def monitor_account(self, handler):
        logging.info(f"Monitoring {handler.email_user} - Folder: {handler.folder}")
        backoff_time = RETRY_DELAY

        while not notimail_config.shutdown_in_progress and not handler.stop_event.is_set():
            try:
                if not handler.connect(all_handlers=self.handlers):
                    retry_time = min(backoff_time * (handler.retry_count % 5), 300)
                    logging.info(f"[{handler.email_user} - {handler.folder}] Retrying connection in {retry_time} seconds")

                    wait_until = time.time() + retry_time
                    while time.time() < wait_until and not notimail_config.shutdown_in_progress and not handler.stop_event.is_set():
                        time.sleep(1)

                    continue

                backoff_time = RETRY_DELAY

                while handler.healthy and not notimail_config.shutdown_in_progress and not handler.stop_event.is_set():
                    idle_result = handler.idle()
                    if not idle_result:
                        break

                    with self.lock:
                        if not handler.process_emails(self.db_path):
                            break

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
                self.metrics.get('ERRORS', _DummyMetric()).inc()
            except Exception as e:
                logging.error(f"[{handler.email_user} - {handler.folder}] Unexpected error: {str(e)}")
                handler.last_error = str(e)
                handler.healthy = False
                self.metrics.get('ERRORS', _DummyMetric()).inc()

            if handler.mail:
                try:
                    handler.mail.close()
                    handler.mail.logout()
                except:
                    pass
                handler.mail = None
                self.metrics.get('CONNECTIONS', _DummyMetric()).set(
                    sum(1 for h in self.handlers if h.mail is not None))

            if not notimail_config.shutdown_in_progress and not handler.stop_event.is_set():
                time.sleep(5)


def connection_watchdog(multi_handler):
    """Monitor all handler threads and restart any that have died."""
    while not notimail_config.shutdown_in_progress:
        time.sleep(60)

        if notimail_config.shutdown_in_progress:
            break

        for i, thread in enumerate(multi_handler.threads):
            if not thread.is_alive() and not notimail_config.shutdown_in_progress:
                handler = multi_handler.handlers[i]
                logging.warning(f"Thread for {handler.email_user} - {handler.folder} has died. Restarting...")

                if handler.mail:
                    try:
                        handler.mail.close()
                        handler.mail.logout()
                    except:
                        pass
                    handler.mail = None

                handler.healthy = True
                handler.stop_event.clear()

                new_thread = threading.Thread(
                    target=multi_handler.monitor_account,
                    args=(handler,),
                    name=f"{handler.email_user}-{handler.folder}")
                new_thread.daemon = True
                multi_handler.threads[i] = new_thread
                new_thread.start()

                if handler.notifier:
                    try:
                        handler.notifier.send_notification(
                            "Thread Restarted",
                            f"Monitoring thread for {handler.email_user} - {handler.folder} has been restarted")
                    except:
                        pass


class _DummyMetric:
    """Fallback metric that does nothing, used when metrics dict is incomplete."""
    def inc(self, amount=1):
        pass
    def set(self, value):
        pass
    def time(self):
        class _Timer:
            def __enter__(self): pass
            def __exit__(self, *a): pass
        return _Timer()
