"""
Configuration loading and validation for NotiMail.

Handles reading config.ini, argument parsing, logging setup,
and conditional imports of optional dependencies (Apprise, Flask, Prometheus).
"""

import argparse
import configparser
import logging
import socket
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler

# Global socket pair for coordinating shutdown across threads
shutdown_sock_r, shutdown_sock_w = socket.socketpair()
shutdown_sock_r.setblocking(0)
shutdown_sock_w.setblocking(0)

# Global flag checked by all threads to initiate graceful shutdown
shutdown_in_progress = False

# Connection retry constants
MAX_RETRY_ATTEMPTS = 5
RETRY_DELAY = 30       # seconds between retry attempts
IDLE_TIMEOUT = 600     # 10 minutes — exit IDLE periodically to verify connection

# Conditional import of Apprise
try:
    import apprise
    apprise_available = True
except ImportError:
    apprise_available = False

# Conditional import of Flask
try:
    from flask import Flask, jsonify, request
    flask_available = True
except ImportError:
    flask_available = False

# Conditional import of Prometheus client
try:
    from prometheus_client import start_http_server, Counter, Histogram
    from prometheus_client import Gauge, Summary
    prometheus_available = True
except ImportError:
    prometheus_available = False


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description='NotiMail Notification Service.')
    parser.add_argument('-c', '--config', type=str, default='config.ini',
                        help='Path to the configuration file.')
    parser.add_argument('--print-config', action='store_true',
                        help='Print the configuration options from config.ini')
    parser.add_argument('--test-config', action='store_true',
                        help='Test the configuration options to ensure they work properly')
    parser.add_argument('--list-folders', action='store_true',
                        help='List all IMAP folders of the configured mailboxes')
    return parser.parse_args()


def load_config(config_path):
    """Read and return the configuration from the given file path."""
    config = configparser.ConfigParser()
    config.read(config_path)
    return config


def validate_config(config):
    """Validate that required configuration sections exist."""
    if 'GENERAL' not in config.sections():
        raise ValueError("The [GENERAL] section is required in config.ini.")
    if not any(section.startswith('EMAIL') for section in config.sections()):
        raise ValueError("At least one EMAIL section is required.")


def setup_logging(config):
    """Configure logging based on config.ini settings. Returns the log file path."""
    log_file_location = config.get('GENERAL', 'LogFileLocation', fallback='notimail.log')
    log_rotation_type = config.get('GENERAL', 'LogRotationType', fallback='size')
    log_rotation_size = config.getint('GENERAL', 'LogRotationSize', fallback=10485760)
    log_rotation_interval = config.getint('GENERAL', 'LogRotationInterval', fallback=1)
    log_backup_count = config.getint('GENERAL', 'LogBackupCount', fallback=5)

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    if log_rotation_type == 'size':
        handler = RotatingFileHandler(
            log_file_location, maxBytes=log_rotation_size, backupCount=log_backup_count)
    elif log_rotation_type == 'time':
        handler = TimedRotatingFileHandler(
            log_file_location, when='midnight', interval=log_rotation_interval,
            backupCount=log_backup_count)
    else:
        raise ValueError(f"Invalid LogRotationType: {log_rotation_type}")

    formatter = logging.Formatter('%(asctime)s - %(threadName)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Console handler for Docker/terminal output
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    logging.info("Module availability:")
    logging.info(f" - Apprise available: {apprise_available}")
    logging.info(f" - Flask available: {flask_available}")
    logging.info(f" - Prometheus client available: {prometheus_available}")

    return log_file_location


class DummyMetric:
    """No-op metric placeholder when Prometheus is not available."""
    def inc(self, amount=1):
        pass

    def set(self, value):
        pass

    def time(self):
        class DummyTimer:
            def __enter__(self):
                pass
            def __exit__(self, exc_type, exc_val, exc_tb):
                pass
        return DummyTimer()


def setup_prometheus(config):
    """Initialize Prometheus metrics if available and configured.

    Returns a dict of metric objects (real or dummy).
    """
    prometheus_host = config.get('GENERAL', 'PrometheusHost', fallback=None)
    prometheus_port = config.getint('GENERAL', 'PrometheusPort', fallback=None)

    if prometheus_available and prometheus_host and prometheus_port:
        try:
            start_http_server(prometheus_port, addr=prometheus_host)
            logging.info(f"Prometheus metrics server started on {prometheus_host}:{prometheus_port}")
            return {
                'EMAILS_PROCESSED': Counter('emails_processed_total', 'Total number of emails processed'),
                'NOTIFICATIONS_SENT': Counter('notifications_sent_total', 'Total number of notifications sent'),
                'PROCESSING_TIME': Histogram('email_processing_seconds', 'Time spent processing emails'),
                'ERRORS': Counter('errors_total', 'Total number of errors encountered'),
                'CONNECTIONS': Gauge('active_connections', 'Number of active IMAP connections'),
                'RECONNECTS': Counter('reconnect_attempts_total', 'Total number of reconnection attempts'),
                'IDLE_TIMEOUTS': Counter('idle_timeouts_total', 'Total number of IDLE timeouts'),
            }
        except Exception as e:
            logging.error(f"Failed to start Prometheus metrics server: {str(e)}")
    else:
        if not prometheus_available:
            logging.info("Prometheus client library is not available. Metrics will not be exposed.")
        else:
            logging.info("PrometheusHost or PrometheusPort not specified. Metrics will not be exposed.")

    # Return dummy metrics that do nothing
    dummy = DummyMetric()
    return {
        'EMAILS_PROCESSED': dummy,
        'NOTIFICATIONS_SENT': dummy,
        'PROCESSING_TIME': dummy,
        'ERRORS': dummy,
        'CONNECTIONS': dummy,
        'RECONNECTS': dummy,
        'IDLE_TIMEOUTS': dummy,
    }
