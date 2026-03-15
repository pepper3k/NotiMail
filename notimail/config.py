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
from typing import Any, Dict, Optional, Union

# Global socket pair for coordinating shutdown across threads.
# A byte written to shutdown_sock_w is readable on shutdown_sock_r,
# allowing select()-based loops in IDLE to wake up immediately.
shutdown_sock_r: socket.socket
shutdown_sock_w: socket.socket
shutdown_sock_r, shutdown_sock_w = socket.socketpair()
shutdown_sock_r.setblocking(0)
shutdown_sock_w.setblocking(0)

# Global flag checked by all threads to initiate graceful shutdown
shutdown_in_progress: bool = False

# Connection retry constants
MAX_RETRY_ATTEMPTS: int = 5
RETRY_DELAY: int = 30       # seconds between retry attempts
IDLE_TIMEOUT: int = 600     # 10 minutes — exit IDLE periodically to verify connection

# Conditional import of Apprise
try:
    import apprise
    apprise_available: bool = True
except ImportError:
    apprise_available = False

# Conditional import of Flask
try:
    from flask import Flask, jsonify, request
    flask_available: bool = True
except ImportError:
    flask_available = False

# Conditional import of Prometheus client
try:
    from prometheus_client import start_http_server, Counter, Histogram
    from prometheus_client import Gauge, Summary
    prometheus_available: bool = True
except ImportError:
    prometheus_available = False


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        An argparse.Namespace with the following attributes:
        - config (str): Path to the configuration file (default: 'config.ini').
        - print_config (bool): Whether to print the loaded configuration.
        - test_config (bool): Whether to run a configuration test.
        - list_folders (bool): Whether to list IMAP folders and exit.
    """
    parser = argparse.ArgumentParser(description='NotiMail Notification Service.')
    parser.add_argument('-c', '--config', type=str, default='config.ini',
                        help='Path to the configuration file.')
    parser.add_argument('--print-config', action='store_true',
                        help='Print the configuration options from config.ini')
    parser.add_argument('--test-config', action='store_true',
                        help='Test the configuration options to ensure they work properly')
    parser.add_argument('--list-folders', action='store_true',
                        help='List all IMAP folders of the configured mailboxes')
    parser.add_argument('--setup-admin', action='store_true',
                        help='Create the initial admin user (interactive)')
    parser.add_argument('--create-invite', action='store_true',
                        help='Generate an invite code for a new user')
    return parser.parse_args()


def load_config(config_path: str) -> configparser.ConfigParser:
    """Read and return the configuration from the given file path.

    Args:
        config_path: Filesystem path to the config.ini file.

    Returns:
        A populated ConfigParser instance.
    """
    config = configparser.ConfigParser()
    config.read(config_path)
    return config


def validate_config(config: configparser.ConfigParser) -> None:
    """Validate that required configuration sections exist.

    In v3, EMAIL sections are optional (accounts can be in the database).
    Only [GENERAL] is required.

    Args:
        config: The loaded ConfigParser to validate.

    Raises:
        ValueError: If [GENERAL] is missing.
    """
    if 'GENERAL' not in config.sections():
        raise ValueError("The [GENERAL] section is required in config.ini.")


def setup_logging(config: configparser.ConfigParser) -> str:
    """Configure logging based on config.ini settings.

    Sets up a file handler (with rotation) and a console handler so that
    log output is available both on disk and in stdout (useful for Docker).

    Args:
        config: The loaded ConfigParser containing [GENERAL] logging options.

    Returns:
        The resolved log file path.

    Raises:
        ValueError: If LogRotationType is neither 'size' nor 'time'.
    """
    log_file_location: str = config.get('GENERAL', 'LogFileLocation', fallback='notimail.log')
    log_rotation_type: str = config.get('GENERAL', 'LogRotationType', fallback='size')
    log_rotation_size: int = config.getint('GENERAL', 'LogRotationSize', fallback=10485760)
    log_rotation_interval: int = config.getint('GENERAL', 'LogRotationInterval', fallback=1)
    log_backup_count: int = config.getint('GENERAL', 'LogBackupCount', fallback=5)

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    handler: Union[RotatingFileHandler, TimedRotatingFileHandler]
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
    """No-op metric placeholder when Prometheus is not available.

    Implements the same interface as Prometheus Counter/Gauge/Histogram
    so callers can use metrics unconditionally without None-checks.
    """

    def inc(self, amount: int = 1) -> None:
        """No-op increment (matches prometheus_client Counter.inc)."""
        pass

    def set(self, value: float) -> None:
        """No-op set (matches prometheus_client Gauge.set)."""
        pass

    def time(self) -> "DummyTimer":
        """Return a no-op context manager (matches prometheus_client Histogram.time).

        Returns:
            A context manager that does nothing on enter/exit.
        """
        class DummyTimer:
            def __enter__(self) -> None:
                pass
            def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
                pass
        return DummyTimer()


def setup_prometheus(config: configparser.ConfigParser) -> Dict[str, Any]:
    """Initialize Prometheus metrics if available and configured.

    Starts a Prometheus HTTP metrics server if the prometheus_client library
    is installed and PrometheusHost/PrometheusPort are set in [GENERAL].

    Args:
        config: The loaded ConfigParser containing optional Prometheus settings.

    Returns:
        A dict mapping metric names (e.g. 'EMAILS_PROCESSED') to either
        real Prometheus metric objects or DummyMetric instances.
    """
    prometheus_host: Optional[str] = config.get('GENERAL', 'PrometheusHost', fallback=None)
    prometheus_port: Optional[int] = config.getint('GENERAL', 'PrometheusPort', fallback=None)

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
