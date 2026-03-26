"""Tests for notimail.notifications module."""

import configparser
from unittest.mock import patch, MagicMock

import pytest

from notimail.notifications import (
    NTFYNotificationProvider,
    Notifier,
    NotificationProvider,
    parse_notification_providers,
)


class TestNTFYUnifiedPush:

    def test_ntfy_unified_push_detection(self):
        """URL with ?up=1 detected correctly, without is not."""
        assert NTFYNotificationProvider._is_unified_push("https://ntfy.sh/topic?up=1") is True
        assert NTFYNotificationProvider._is_unified_push("https://ntfy.sh/topic") is False
        assert NTFYNotificationProvider._is_unified_push("https://ntfy.sh/topic?foo=bar") is False
        assert NTFYNotificationProvider._is_unified_push("https://ntfy.sh/topic?up=0") is False
        assert NTFYNotificationProvider._is_unified_push("https://ntfy.sh/topic?up=1&extra=yes") is True

    @patch("notimail.notifications.requests.post")
    @patch("notimail.notifications.time.sleep")
    def test_ntfy_up_mode_empty_body(self, mock_sleep, mock_post):
        """UP mode sends empty body with no email content."""
        mock_post.return_value = MagicMock(status_code=200)

        provider = NTFYNotificationProvider(
            [("https://ntfy.sh/topic?up=1", None)]
        )
        provider.send_notification("sender@test.com", "Test Subject")

        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        # data should be empty bytes
        assert call_kwargs.kwargs.get("data", call_kwargs[1].get("data", b"")) == b""
        # Headers should NOT contain Title (no email content in UP mode)
        headers = call_kwargs.kwargs.get("headers", call_kwargs[1].get("headers", {}))
        assert "Title" not in headers

    @patch("notimail.notifications.requests.post")
    @patch("notimail.notifications.time.sleep")
    def test_ntfy_legacy_mode_has_content(self, mock_sleep, mock_post):
        """Legacy mode sends from/subject in request."""
        mock_post.return_value = MagicMock(status_code=200)

        provider = NTFYNotificationProvider(
            [("https://ntfy.sh/topic", "mytoken")]
        )
        provider.send_notification("sender@test.com", "Test Subject")

        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        # data should contain the sender
        data = call_kwargs.kwargs.get("data", call_kwargs[1].get("data", b""))
        assert b"sender@test.com" in data
        # Headers should contain Title and Authorization
        headers = call_kwargs.kwargs.get("headers", call_kwargs[1].get("headers", {}))
        assert "Title" in headers
        assert headers["Authorization"] == "Bearer mytoken"


class TestNotifier:

    def test_notifier_dispatches_all(self):
        """Notifier with multiple mock providers calls all of them."""
        provider1 = MagicMock(spec=NotificationProvider)
        provider2 = MagicMock(spec=NotificationProvider)

        notifier = Notifier([provider1, provider2])
        notifier.send_notification("sender@test.com", "Hello")

        provider1.send_notification.assert_called_once_with("sender@test.com", "Hello")
        provider2.send_notification.assert_called_once_with("sender@test.com", "Hello")


class TestParseNotificationProviders:

    def test_parse_notification_providers(self):
        """Parse from a ConfigParser with NTFY/Pushover sections."""
        config = configparser.ConfigParser()
        config.add_section("NTFY")
        config.set("NTFY", "Url1", "https://ntfy.sh/topic1")
        config.set("NTFY", "Token1", "tok1")
        config.set("NTFY", "Url2", "https://ntfy.sh/topic2?up=1")

        config.add_section("PUSHOVER")
        config.set("PUSHOVER", "ApiToken", "po_token")
        config.set("PUSHOVER", "UserKey", "po_user")

        providers = parse_notification_providers(config)

        # Should have one NTFY provider and one Pushover provider
        assert len(providers) == 2
        provider_types = [type(p).__name__ for p in providers]
        assert "NTFYNotificationProvider" in provider_types
        assert "PushoverNotificationProvider" in provider_types
