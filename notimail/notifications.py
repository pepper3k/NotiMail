"""
Notification providers for NotiMail.

Implements the strategy pattern for sending push notifications via
multiple services: ntfy, Pushover, Gotify, and Apprise.
"""

import configparser
import logging
import time
from typing import Any, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

import requests

from notimail.config import apprise_available

# Conditionally import apprise
if apprise_available:
    import apprise as apprise_lib


class NotificationProvider:
    """Base class (interface) for all notification providers.

    Subclasses must override send_notification() to deliver a push
    notification for an incoming email.
    """

    def send_notification(self, mail_from: str, mail_subject: str) -> None:
        """Send a notification for a new email.

        Args:
            mail_from: The sender address (From header).
            mail_subject: The email subject line.

        Raises:
            NotImplementedError: Always; subclasses must override.
        """
        raise NotImplementedError("Subclasses must implement this method")


class NTFYNotificationProvider(NotificationProvider):
    """Send notifications via ntfy (https://ntfy.sh).

    Supports multiple ntfy endpoints, each with an optional bearer token.
    A 2-second delay is inserted between requests to avoid rate limiting.

    UnifiedPush mode: If the URL contains a `up=1` query parameter
    (e.g. https://ntfy.sh/topic?up=1), the notification is sent as an
    empty POST body — no email content (from/subject) is transmitted.
    The client app receives the push as a "sync now" signal.
    """

    def __init__(
        self,
        ntfy_data: List[Tuple[str, Optional[str]]],
        errors_metric: Optional[Any] = None,
    ) -> None:
        """Initialize the ntfy provider.

        Args:
            ntfy_data: List of (url, token) tuples. Token may be None
                       if the ntfy topic does not require authentication.
            errors_metric: Prometheus Counter (or DummyMetric) for error tracking.
        """
        self.ntfy_data = ntfy_data
        self.errors_metric = errors_metric

    @staticmethod
    def _is_unified_push(url: str) -> bool:
        """Check if a ntfy URL is a UnifiedPush endpoint.

        Detects the `up` query parameter using proper URL parsing,
        not string matching.

        Args:
            url: The ntfy endpoint URL.

        Returns:
            True if the URL contains up=1 (UnifiedPush mode).
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return params.get('up', [''])[0] == '1'

    def send_notification(self, mail_from: str, mail_subject: str) -> None:
        """POST the notification to each configured ntfy endpoint.

        For UnifiedPush endpoints (?up=1), sends an empty body.
        For regular endpoints, sends from/subject in headers/body.

        Args:
            mail_from: The sender address (From header).
            mail_subject: The email subject line.
        """
        mail_subject = mail_subject if mail_subject is not None else "No Subject"
        mail_from = mail_from if mail_from is not None else "Unknown Sender"

        for ntfy_url, token in self.ntfy_data:
            is_up = self._is_unified_push(ntfy_url)
            headers: dict = {}

            if token:
                headers["Authorization"] = f"Bearer {token}"

            if is_up:
                # UnifiedPush: empty body, no email content
                data = b''
                logging.debug(f"Sending UP signal to {ntfy_url} (no content)")
            else:
                # Legacy mode: include from/subject
                headers["Title"] = mail_subject.encode('utf-8')
                data = mail_from.encode('utf-8')

            try:
                response: requests.Response = requests.post(
                    ntfy_url, data=data, headers=headers)
                if response.status_code == 200:
                    mode = "UP signal" if is_up else "notification"
                    logging.info(f"Sent {mode} to {ntfy_url} via ntfy")
                else:
                    logging.error(f"Failed to send to {ntfy_url} via NTFY. Status Code: {response.status_code}")
                    if self.errors_metric:
                        self.errors_metric.inc()
            except requests.RequestException as e:
                logging.error(f"Error sending to {ntfy_url} via NTFY: {str(e)}")
                if self.errors_metric:
                    self.errors_metric.inc()
            finally:
                # Rate-limit delay between ntfy endpoint requests
                time.sleep(2)


class PushoverNotificationProvider(NotificationProvider):
    """Send notifications via Pushover (https://pushover.net)."""

    def __init__(
        self,
        api_token: str,
        user_key: str,
        errors_metric: Optional[Any] = None,
    ) -> None:
        """Initialize the Pushover provider.

        Args:
            api_token: Pushover application API token.
            user_key: Pushover user/group key.
            errors_metric: Prometheus Counter (or DummyMetric) for error tracking.
        """
        self.api_token = api_token
        self.user_key = user_key
        self.pushover_url: str = "https://api.pushover.net/1/messages.json"
        self.errors_metric = errors_metric

    def send_notification(self, mail_from: str, mail_subject: str) -> None:
        """POST the notification to the Pushover API.

        Args:
            mail_from: The sender address (From header).
            mail_subject: The email subject line.
        """
        mail_subject = mail_subject if mail_subject is not None else "No Subject"
        mail_from = mail_from if mail_from is not None else "Unknown Sender"
        message: str = f"From: {mail_from}\nSubject: {mail_subject}"

        data = {
            "token": self.api_token,
            "user": self.user_key,
            "message": message
        }

        try:
            response: requests.Response = requests.post(self.pushover_url, data=data)
            if response.status_code == 200:
                logging.info("Notification sent successfully via Pushover")
            else:
                logging.error(f"Failed to send notification via Pushover. Status Code: {response.status_code}")
                if self.errors_metric:
                    self.errors_metric.inc()
        except requests.RequestException as e:
            logging.error(f"An error occurred while sending notification via Pushover: {str(e)}")
            if self.errors_metric:
                self.errors_metric.inc()


class GotifyNotificationProvider(NotificationProvider):
    """Send notifications via Gotify (https://gotify.net)."""

    def __init__(
        self,
        gotify_url: str,
        gotify_token: str,
        errors_metric: Optional[Any] = None,
    ) -> None:
        """Initialize the Gotify provider.

        Args:
            gotify_url: Base URL of the Gotify server message endpoint.
            gotify_token: Application token for authentication.
            errors_metric: Prometheus Counter (or DummyMetric) for error tracking.
        """
        self.gotify_url = gotify_url
        self.gotify_token = gotify_token
        self.errors_metric = errors_metric

    def send_notification(self, mail_from: str, mail_subject: str) -> None:
        """POST the notification as JSON to the Gotify server.

        Args:
            mail_from: The sender address (From header).
            mail_subject: The email subject line.
        """
        mail_subject = mail_subject if mail_subject is not None else "No Subject"
        mail_from = mail_from if mail_from is not None else "Unknown Sender"
        message: str = f"From: {mail_from}\nSubject: {mail_subject}"
        # Append the token as a query parameter for Gotify authentication
        url_with_token: str = f"{self.gotify_url}?token={self.gotify_token}"
        payload = {
            "title": mail_subject,
            "message": message,
            "priority": 5
        }
        try:
            response: requests.Response = requests.post(url_with_token, json=payload)
            if response.status_code == 200:
                logging.info("Notification sent successfully via Gotify")
            else:
                logging.error(f"Failed to send notification via Gotify. Status Code: {response.status_code}")
                if self.errors_metric:
                    self.errors_metric.inc()
        except requests.RequestException as e:
            logging.error(f"An error occurred while sending notification via Gotify: {str(e)}")
            if self.errors_metric:
                self.errors_metric.inc()


if apprise_available:
    class AppriseNotificationProvider(NotificationProvider):
        """Send notifications via Apprise (supports 100+ services).

        Apprise is a universal notification library that can deliver to
        Slack, Telegram, Discord, email, and many other services via URLs.
        """

        def __init__(self, apprise_config: List[str]) -> None:
            """Initialize the Apprise provider.

            Args:
                apprise_config: List of Apprise service URL strings
                                (e.g. ["slack://token", "tgram://bot_token/chat_id"]).
            """
            self.apprise = apprise_lib.Apprise()
            for service_url in apprise_config:
                self.apprise.add(service_url.strip())

        def send_notification(self, mail_from: str, mail_subject: str) -> None:
            """Dispatch the notification through all configured Apprise services.

            Args:
                mail_from: The sender address (From header).
                mail_subject: The email subject line.
            """
            mail_subject = mail_subject if mail_subject is not None else "No Subject"
            mail_from = mail_from if mail_from is not None else "Unknown Sender"
            message: str = f"{mail_from}"
            if not self.apprise.notify(title=mail_subject, body=message):
                logging.error("Failed to send notification via Apprise.")


class Notifier:
    """Aggregates multiple notification providers and sends to all of them.

    Acts as a fan-out dispatcher: when send_notification() is called,
    every registered provider is invoked in sequence.
    """

    def __init__(self, providers: List[NotificationProvider]) -> None:
        """Initialize the notifier.

        Args:
            providers: List of NotificationProvider instances to dispatch to.
        """
        self.providers = providers

    def send_notification(self, mail_from: str, mail_subject: str) -> None:
        """Send a notification via all registered providers.

        Args:
            mail_from: The sender address (From header).
            mail_subject: The email subject line.
        """
        for provider in self.providers:
            provider.send_notification(mail_from, mail_subject)


def parse_notification_providers(
    config: configparser.ConfigParser,
    account_name: Optional[str] = None,
    errors_metric: Optional[Any] = None,
) -> List[NotificationProvider]:
    """Build a list of notification providers from config.ini sections.

    Scans the config for NTFY, PUSHOVER, GOTIFY, and APPRISE sections
    and instantiates the corresponding provider classes.

    Provider sections can be global (e.g. [NTFY]) or per-account
    (e.g. [NTFY:account1]). When account_name is set, only sections
    suffixed with that account are loaded; otherwise only global
    (un-suffixed) sections are used.

    Args:
        config: ConfigParser instance with the full config.ini contents.
        account_name: If set, only load providers for this account
                     (e.g. "account1"). If None, load global providers
                     (sections without ':').
        errors_metric: Prometheus error counter (or DummyMetric) passed
                      to providers for error tracking.

    Returns:
        List of NotificationProvider instances ready to send notifications.
    """
    providers: List[NotificationProvider] = []

    # Filter sections to either per-account or global, depending on account_name
    if account_name:
        sections_to_check = [s for s in config.sections() if s.endswith(f":{account_name}")]
    else:
        sections_to_check = [s for s in config.sections() if ':' not in s]

    # --- NTFY providers ---
    # Each NTFY section can contain multiple URL/Token pairs (Url1, Token1, Url2, Token2, etc.)
    ntfy_sections = [s for s in sections_to_check if s.startswith('NTFY')]
    ntfy_data: List[Tuple[str, Optional[str]]] = []
    for section in ntfy_sections:
        for key in config[section]:
            if key.lower().startswith("url"):
                url: str = config[section][key]
                # Extract the numeric suffix to find the matching Token key
                # e.g. "Url1" -> suffix "1" -> look for "Token1"
                index: str = key[3:]
                token_key: str = f"Token{index}"
                token: Optional[str] = config[section].get(token_key, None)
                ntfy_data.append((url, token))
    if ntfy_data:
        providers.append(NTFYNotificationProvider(ntfy_data, errors_metric))

    # --- Pushover provider (at most one) ---
    pushover_sections = [s for s in sections_to_check if s.startswith('PUSHOVER')]
    for section in pushover_sections:
        if 'ApiToken' in config[section] and 'UserKey' in config[section]:
            api_token: str = config[section]['ApiToken']
            user_key: str = config[section]['UserKey']
            providers.append(PushoverNotificationProvider(api_token, user_key, errors_metric))
            break  # Only one Pushover provider is supported

    # --- Gotify provider (at most one) ---
    gotify_sections = [s for s in sections_to_check if s.startswith('GOTIFY')]
    for section in gotify_sections:
        if 'Url' in config[section] and 'Token' in config[section]:
            gotify_url: str = config[section]['Url']
            gotify_token: str = config[section]['Token']
            providers.append(GotifyNotificationProvider(gotify_url, gotify_token, errors_metric))
            break  # Only one Gotify provider is supported

    # --- Apprise providers (at most one) ---
    if apprise_available:
        apprise_sections = [s for s in sections_to_check if s.startswith('APPRISE')]
        for section in apprise_sections:
            if 'urls' in config[section]:
                apprise_urls: List[str] = config[section]['urls'].split(',')
                providers.append(AppriseNotificationProvider(apprise_urls))
                break  # Only one Apprise provider is supported

    return providers
