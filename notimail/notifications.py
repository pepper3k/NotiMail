"""
Notification providers for NotiMail.

Implements the strategy pattern for sending push notifications via
multiple services: ntfy, Pushover, Gotify, and Apprise.
"""

import logging
import time

import requests

from notimail.config import apprise_available

# Conditionally import apprise
if apprise_available:
    import apprise as apprise_lib


class NotificationProvider:
    """Base class for all notification providers."""
    def send_notification(self, mail_from, mail_subject):
        raise NotImplementedError("Subclasses must implement this method")


class NTFYNotificationProvider(NotificationProvider):
    """Send notifications via ntfy (https://ntfy.sh)."""
    def __init__(self, ntfy_data, errors_metric=None):
        self.ntfy_data = ntfy_data  # list of (url, token) tuples
        self.errors_metric = errors_metric

    def send_notification(self, mail_from, mail_subject):
        mail_subject = mail_subject if mail_subject is not None else "No Subject"
        mail_from = mail_from if mail_from is not None else "Unknown Sender"
        encoded_from = mail_from.encode('utf-8')
        encoded_subject = mail_subject.encode('utf-8')

        for ntfy_url, token in self.ntfy_data:
            headers = {"Title": encoded_subject}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            try:
                response = requests.post(ntfy_url, data=encoded_from, headers=headers)
                if response.status_code == 200:
                    logging.info(f"Notification sent successfully to {ntfy_url} via ntfy")
                else:
                    logging.error(f"Failed to send notification to {ntfy_url} via NTFY. Status Code: {response.status_code}")
                    if self.errors_metric:
                        self.errors_metric.inc()
            except requests.RequestException as e:
                logging.error(f"An error occurred while sending notification to {ntfy_url} via NTFY: {str(e)}")
                if self.errors_metric:
                    self.errors_metric.inc()
            finally:
                time.sleep(2)


class PushoverNotificationProvider(NotificationProvider):
    """Send notifications via Pushover (https://pushover.net)."""
    def __init__(self, api_token, user_key, errors_metric=None):
        self.api_token = api_token
        self.user_key = user_key
        self.pushover_url = "https://api.pushover.net/1/messages.json"
        self.errors_metric = errors_metric

    def send_notification(self, mail_from, mail_subject):
        mail_subject = mail_subject if mail_subject is not None else "No Subject"
        mail_from = mail_from if mail_from is not None else "Unknown Sender"
        message = f"From: {mail_from}\nSubject: {mail_subject}"

        data = {
            "token": self.api_token,
            "user": self.user_key,
            "message": message
        }

        try:
            response = requests.post(self.pushover_url, data=data)
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
    def __init__(self, gotify_url, gotify_token, errors_metric=None):
        self.gotify_url = gotify_url
        self.gotify_token = gotify_token
        self.errors_metric = errors_metric

    def send_notification(self, mail_from, mail_subject):
        mail_subject = mail_subject if mail_subject is not None else "No Subject"
        mail_from = mail_from if mail_from is not None else "Unknown Sender"
        message = f"From: {mail_from}\nSubject: {mail_subject}"
        url_with_token = f"{self.gotify_url}?token={self.gotify_token}"
        payload = {
            "title": mail_subject,
            "message": message,
            "priority": 5
        }
        try:
            response = requests.post(url_with_token, json=payload)
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
        """Send notifications via Apprise (supports 100+ services)."""
        def __init__(self, apprise_config):
            self.apprise = apprise_lib.Apprise()
            for service_url in apprise_config:
                self.apprise.add(service_url.strip())

        def send_notification(self, mail_from, mail_subject):
            mail_subject = mail_subject if mail_subject is not None else "No Subject"
            mail_from = mail_from if mail_from is not None else "Unknown Sender"
            message = f"{mail_from}"
            if not self.apprise.notify(title=mail_subject, body=message):
                logging.error("Failed to send notification via Apprise.")


class Notifier:
    """Aggregates multiple notification providers and sends to all of them."""
    def __init__(self, providers):
        self.providers = providers

    def send_notification(self, mail_from, mail_subject):
        for provider in self.providers:
            provider.send_notification(mail_from, mail_subject)


def parse_notification_providers(config, account_name=None, errors_metric=None):
    """Build a list of notification providers from config.ini sections.

    Args:
        config: ConfigParser instance
        account_name: If set, only load providers for this account (e.g. "account1").
                     If None, load global providers (sections without ':').
        errors_metric: Prometheus error counter (or DummyMetric) passed to providers.

    Returns:
        List of NotificationProvider instances.
    """
    providers = []

    if account_name:
        sections_to_check = [s for s in config.sections() if s.endswith(f":{account_name}")]
    else:
        sections_to_check = [s for s in config.sections() if ':' not in s]

    # NTFY providers
    ntfy_sections = [s for s in sections_to_check if s.startswith('NTFY')]
    ntfy_data = []
    for section in ntfy_sections:
        for key in config[section]:
            if key.lower().startswith("url"):
                url = config[section][key]
                index = key[3:]
                token_key = f"Token{index}"
                token = config[section].get(token_key, None)
                ntfy_data.append((url, token))
    if ntfy_data:
        providers.append(NTFYNotificationProvider(ntfy_data, errors_metric))

    # Pushover provider
    pushover_sections = [s for s in sections_to_check if s.startswith('PUSHOVER')]
    for section in pushover_sections:
        if 'ApiToken' in config[section] and 'UserKey' in config[section]:
            api_token = config[section]['ApiToken']
            user_key = config[section]['UserKey']
            providers.append(PushoverNotificationProvider(api_token, user_key, errors_metric))
            break

    # Gotify provider
    gotify_sections = [s for s in sections_to_check if s.startswith('GOTIFY')]
    for section in gotify_sections:
        if 'Url' in config[section] and 'Token' in config[section]:
            gotify_url = config[section]['Url']
            gotify_token = config[section]['Token']
            providers.append(GotifyNotificationProvider(gotify_url, gotify_token, errors_metric))
            break

    # Apprise providers
    if apprise_available:
        apprise_sections = [s for s in sections_to_check if s.startswith('APPRISE')]
        for section in apprise_sections:
            if 'urls' in config[section]:
                apprise_urls = config[section]['urls'].split(',')
                providers.append(AppriseNotificationProvider(apprise_urls))
                break

    return providers
