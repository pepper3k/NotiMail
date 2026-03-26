"""Tests for HostLimitManager: config loading, connection control, retry suppression."""

import configparser
import os

import pytest

from notimail.host_limits import HostLimitManager


def _write_ini(tmp_path, content):
    """Helper to write an INI file and return the path."""
    ini_path = str(tmp_path / "host_limits.ini")
    with open(ini_path, "w") as f:
        f.write(content)
    return ini_path


class TestLoadKnownLimits:

    def test_load_known_limits(self, tmp_path):
        """Create temp ini file with limits, load, verify parsed correctly."""
        ini_path = _write_ini(tmp_path, """\
[imap.example.com]
MaxConcurrent = 3
LimitType = per-ip

[imap.other.com]
MaxConcurrent = 10
LimitType = per-account
""")
        mgr = HostLimitManager(config_path=ini_path)

        assert "imap.example.com" in mgr.known_limits
        assert mgr.known_limits["imap.example.com"].max_concurrent == 3
        assert mgr.known_limits["imap.example.com"].limit_type == "per-ip"

        assert "imap.other.com" in mgr.known_limits
        assert mgr.known_limits["imap.other.com"].max_concurrent == 10
        assert mgr.known_limits["imap.other.com"].limit_type == "per-account"


class TestCanConnect:

    def test_can_connect_per_account(self, tmp_path):
        """per-account host always returns True."""
        ini_path = _write_ini(tmp_path, """\
[imap.example.com]
MaxConcurrent = 1
LimitType = per-account
""")
        mgr = HostLimitManager(config_path=ini_path)

        # Even with many accounts, per-account always allows
        for i in range(10):
            assert mgr.can_connect("imap.example.com", f"user{i}@example.com", "inbox") is True

    def test_can_connect_per_ip_under_limit(self, tmp_path):
        """per-ip host with fewer active than max returns True."""
        ini_path = _write_ini(tmp_path, """\
[imap.example.com]
MaxConcurrent = 3
LimitType = per-ip
""")
        mgr = HostLimitManager(config_path=ini_path)

        # Record 2 active connections (under limit of 3)
        mgr.record_connected("imap.example.com", "user1@example.com", "inbox")
        mgr.record_connected("imap.example.com", "user2@example.com", "inbox")

        assert mgr.can_connect("imap.example.com", "user3@example.com", "inbox") is True

    def test_can_connect_per_ip_at_limit(self, tmp_path):
        """Fill up active connections to max, verify returns False and adds to waiting."""
        ini_path = _write_ini(tmp_path, """\
[imap.example.com]
MaxConcurrent = 2
LimitType = per-ip
""")
        mgr = HostLimitManager(config_path=ini_path)

        mgr.record_connected("imap.example.com", "user1@example.com", "inbox")
        mgr.record_connected("imap.example.com", "user2@example.com", "inbox")

        # Third connection should be blocked
        assert mgr.can_connect("imap.example.com", "user3@example.com", "inbox") is False
        assert ("user3@example.com", "inbox") in mgr.waiting.get("imap.example.com", [])

    def test_unknown_host_always_allows(self):
        """Host not in config, can_connect returns True."""
        mgr = HostLimitManager()
        assert mgr.can_connect("unknown.host.com", "user@example.com", "inbox") is True


class TestRecordConnectedDisconnected:

    def test_record_connected_disconnected(self, tmp_path):
        """Connect then disconnect, verify active count changes."""
        ini_path = _write_ini(tmp_path, """\
[imap.example.com]
MaxConcurrent = 5
LimitType = per-ip
""")
        mgr = HostLimitManager(config_path=ini_path)

        mgr.record_connected("imap.example.com", "user@example.com", "inbox")
        assert len(mgr.active_connections.get("imap.example.com", set())) == 1

        mgr.record_disconnected("imap.example.com", "user@example.com", "inbox")
        assert len(mgr.active_connections.get("imap.example.com", set())) == 0


class TestSmartRetrySuppression:

    def test_smart_retry_suppression(self, tmp_path):
        """Record 5 failures while siblings connected, verify returns True."""
        ini_path = _write_ini(tmp_path, """\
[imap.example.com]
MaxConcurrent = 2
LimitType = per-ip
""")
        mgr = HostLimitManager(config_path=ini_path)

        # One sibling is connected
        mgr.record_connected("imap.example.com", "sibling@example.com", "inbox")

        # Record 5 consecutive failures for another account
        for i in range(4):
            result = mgr.record_connection_failure(
                "imap.example.com", "failing@example.com", "inbox", "Connection refused"
            )
            assert result is False

        # 5th failure should trigger suppression
        result = mgr.record_connection_failure(
            "imap.example.com", "failing@example.com", "inbox", "Connection refused"
        )
        assert result is True

    def test_no_suppression_without_siblings(self, tmp_path):
        """Record failures with no siblings connected, verify returns False."""
        ini_path = _write_ini(tmp_path, """\
[imap.example.com]
MaxConcurrent = 2
LimitType = per-ip
""")
        mgr = HostLimitManager(config_path=ini_path)

        # No siblings connected -- 5 failures should NOT trigger suppression
        for i in range(6):
            result = mgr.record_connection_failure(
                "imap.example.com", "lonely@example.com", "inbox", "Connection refused"
            )
        assert result is False


class TestReconnectionPriority:

    def test_reconnection_priority(self, tmp_path):
        """Previously-connected accounts get priority over new ones."""
        ini_path = _write_ini(tmp_path, """\
[imap.example.com]
MaxConcurrent = 1
LimitType = per-ip
""")
        mgr = HostLimitManager(config_path=ini_path)

        # Simulate a previously connected account
        mgr.record_connected("imap.example.com", "old@example.com", "inbox")
        mgr.record_disconnected("imap.example.com", "old@example.com", "inbox")

        # Fill the slot with another connection
        mgr.record_connected("imap.example.com", "active@example.com", "inbox")

        # Both try to connect -- new one first, then old one
        mgr.can_connect("imap.example.com", "new@example.com", "inbox")
        mgr.can_connect("imap.example.com", "old@example.com", "inbox")

        # Previously connected should have priority
        next_acct = mgr.get_next_waiting("imap.example.com")
        assert next_acct is not None
        assert next_acct[0] == "old@example.com"


class TestGetHostStatus:

    def test_get_host_status(self, tmp_path):
        """Connect some, wait some, verify status dict correct."""
        ini_path = _write_ini(tmp_path, """\
[imap.example.com]
MaxConcurrent = 2
LimitType = per-ip
""")
        mgr = HostLimitManager(config_path=ini_path)

        mgr.record_connected("imap.example.com", "user1@example.com", "inbox")
        mgr.record_connected("imap.example.com", "user2@example.com", "inbox")
        # This will be added to waiting
        mgr.can_connect("imap.example.com", "user3@example.com", "inbox")

        status = mgr.get_host_status()
        assert "imap.example.com" in status
        s = status["imap.example.com"]
        assert s["active"] == 2
        assert s["waiting"] == 1
        assert s["max_concurrent"] == 2
        assert s["limit_type"] == "per-ip"
        assert s["at_limit"] is True


class TestCheckLimitWarning:

    def test_check_limit_warning(self, tmp_path):
        """At per-ip limit, check_limit_warning returns warning message."""
        ini_path = _write_ini(tmp_path, """\
[imap.example.com]
MaxConcurrent = 2
LimitType = per-ip
""")
        mgr = HostLimitManager(config_path=ini_path)

        mgr.record_connected("imap.example.com", "user1@example.com", "inbox")
        mgr.record_connected("imap.example.com", "user2@example.com", "inbox")

        warning = mgr.check_limit_warning("imap.example.com", 1)
        assert warning is not None
        assert "limits connections" in warning

    def test_check_limit_warning_none_when_ok(self, tmp_path):
        """Under limit, check_limit_warning returns None."""
        ini_path = _write_ini(tmp_path, """\
[imap.example.com]
MaxConcurrent = 10
LimitType = per-ip
""")
        mgr = HostLimitManager(config_path=ini_path)

        warning = mgr.check_limit_warning("imap.example.com", 1)
        assert warning is None
