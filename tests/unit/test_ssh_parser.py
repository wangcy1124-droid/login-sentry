from datetime import datetime, timedelta, timezone, tzinfo

import pytest

from app.models.event import LoginResult, SourceType
from app.parsers.base import ParseError
from app.parsers.ssh import parse_ssh_line


def line(message, prefix="Oct  5 13:42:12 example-host sshd[1001]: "):
    return prefix + message


@pytest.mark.parametrize("message, username, ip, result", [
    ("Accepted password for alice from 192.0.2.10 port 52111 ssh2", "alice", "192.0.2.10", LoginResult.SUCCESS),
    ("Accepted publickey for bob from 198.51.100.8 port 49201 ssh2", "bob", "198.51.100.8", LoginResult.SUCCESS),
    ("Accepted publickey for bob from 198.51.100.8 port 49201 ssh2: ED25519 SHA256:example", "bob", "198.51.100.8", LoginResult.SUCCESS),
    ("Failed password for root from 203.0.113.99 port 44552 ssh2", "root", "203.0.113.99", LoginResult.FAILURE),
    ("Failed password for invalid user admin from 203.0.113.99 port 44553 ssh2", "admin", "203.0.113.99", LoginResult.FAILURE),
    ("Failed password for user_01 from 2001:0DB8:0:0:0:0:0:10 port 44553 ssh2", "user_01", "2001:db8::10", LoginResult.FAILURE),
])
def test_login_results(message, username, ip, result):
    raw = line(message)
    event = parse_ssh_line(raw, year=2026, tzinfo=timezone.utc)
    assert event is not None
    assert event.source_type is SourceType.SSH
    assert (event.username, event.source_ip, event.result) == (username, ip, result)
    assert event.timestamp == datetime(2026, 10, 5, 13, 42, 12, tzinfo=timezone.utc)
    assert event.timestamp.utcoffset() == timedelta(0)
    assert event.raw_log == raw


@pytest.mark.parametrize("day, year, tz", [(" 5", 2026, timezone.utc), ("15", 2024, timezone(timedelta(hours=8)))])
def test_explicit_time_context(day, year, tz):
    raw = line("Accepted password for alice from 192.0.2.10 port 52111 ssh2", f"Oct {day} 13:42:12 other-host sshd[98765]: ")
    event = parse_ssh_line(raw, year=year, tzinfo=tz)
    assert event.timestamp == datetime(year, 10, int(day), 13, 42, 12, tzinfo=tz)
    assert event.timestamp.tzinfo is tz


@pytest.mark.parametrize("raw", [
    line("Connection closed by 192.0.2.20 port 60123"),
    "Oct  5 13:42:12 host cron[12]: daily job completed",
    "Oct  5 13:42:12 host app[12]: Failed password for root from 192.0.2.1 port 22 ssh2",
    line("Failed publickey for root from 192.0.2.1 port 22 ssh2"),
    "", "unrelated text",
])
def test_irrelevant(raw):
    assert parse_ssh_line(raw, year=2026, tzinfo=timezone.utc) is None


@pytest.mark.parametrize("message, error", [
    ("Failed password for root from 999.999.999.999 port 44552 ssh2", "invalid source IP"),
    ("Failed password for root from 2001:db8::zz port 44552 ssh2", "invalid source IP"),
    ("Failed password for root port 44552 ssh2", "invalid SSH login fields"),
    ("Failed password for invalid user from 192.0.2.10 port 44552 ssh2", "invalid SSH login fields"),
    ("Accepted password for  from 192.0.2.10 port 44552 ssh2", "invalid SSH login fields"),
    ("Accepted publickey", "invalid SSH login fields"),
    ("Failed password for root from 192.0.2.10 port abc ssh2", "invalid SSH login fields"),
    ("Failed password for root from 192.0.2.10 port 65536 ssh2", "invalid SSH source port"),
    ("Failed password for root from 192.0.2.10 port 0 ssh2", "invalid SSH source port"),
    ("Accepted password for root from 192.0.2.10 port 22 ssh2 secret=example", "unexpected SSH password login fields"),
])
def test_malformed_messages(message, error):
    with pytest.raises(ParseError, match=error):
        parse_ssh_line(line(message), year=2026, tzinfo=timezone.utc)


@pytest.mark.parametrize("prefix", [
    "Oct 32 13:42:12 host sshd[1]: ",
    "Feb 29 13:42:12 host sshd[1]: ",
    "Bad  5 13:42:12 host sshd[1]: ",
    "Oct  5 25:42:12 host sshd[1]: ",
    "bad timestamp host sshd[1]: ",
    "Oct  5 13:42:12 host sshd[bad]: ",
    "Oct  5 13:42:12 host sshd[1001: ",
    "Oct  5 13:42:12 host sshd[1] ",
])
def test_malformed_prefix_and_timestamp(prefix):
    with pytest.raises(ParseError, match="SSH (syslog prefix|timestamp)"):
        parse_ssh_line(line("Failed password for root from 192.0.2.10 port 22 ssh2", prefix), year=2026, tzinfo=timezone.utc)


class NoOffset(tzinfo):
    def utcoffset(self, dt):
        return None


@pytest.mark.parametrize("year, tz", [(0, timezone.utc), (2026, None), (2026, NoOffset()), (2026, "UTC")])
def test_invalid_time_context(year, tz):
    with pytest.raises(ParseError, match="timestamp"):
        parse_ssh_line(line("Failed password for root from 192.0.2.10 port 22 ssh2"), year=year, tzinfo=tz)


def test_context_is_required():
    with pytest.raises(TypeError):
        parse_ssh_line("irrelevant")


@pytest.mark.parametrize("ending", ["", "\n", "\r\n"])
def test_raw_log_preserves_trailing_spaces(ending):
    raw = line("Failed password for root from 192.0.2.10 port 22 ssh2  ")
    event = parse_ssh_line(raw + ending, year=2026, tzinfo=timezone.utc)
    assert event.raw_log == raw


def test_error_does_not_echo_potential_secret():
    with pytest.raises(ParseError) as caught:
        parse_ssh_line(line("Failed password for root from secret-example port 22 ssh2"), year=2026, tzinfo=timezone.utc)
    assert "secret-example" not in str(caught.value)
    assert caught.value.__suppress_context__


def test_embedded_newline_is_malformed():
    raw = line("Failed password for root from 192.0.2.10 port 22 ssh2")
    with pytest.raises(ParseError, match="invalid SSH syslog prefix"):
        parse_ssh_line(raw + "\nsecond line", year=2026, tzinfo=timezone.utc)
