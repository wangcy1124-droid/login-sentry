from datetime import datetime, timedelta, timezone

import pytest

from app.models.event import LoginResult, SourceType
from app.parsers.base import ParseError
from app.parsers.web import parse_web_line


def line(timestamp="2026-10-05T13:42:12+08:00", username="alice", ip="192.0.2.10", result="SUCCESS"):
    return f"{timestamp} LOGIN username={username} ip={ip} result={result}"


@pytest.mark.parametrize("result, expected", [("SUCCESS", LoginResult.SUCCESS), ("FAILURE", LoginResult.FAILURE)])
def test_results(result, expected):
    event = parse_web_line(line(result=result))
    assert event.source_type is SourceType.WEB
    assert event.result is expected
    assert event.source_ip == "192.0.2.10"
    assert event.username == "alice"
    assert event.timestamp == datetime(2026, 10, 5, 13, 42, 12, tzinfo=timezone(timedelta(hours=8)))
    assert event.raw_log == line(result=result)


@pytest.mark.parametrize("timestamp, offset, microsecond", [
    ("2026-10-05T05:42:12Z", timedelta(0), 0),
    ("2026-10-05T13:42:12+08:00", timedelta(hours=8), 0),
    ("2026-10-05T01:42:12-04:00", timedelta(hours=-4), 0),
    ("2026-10-05T05:42:12.1Z", timedelta(0), 100000),
    ("2026-10-05T13:42:12.12+08:00", timedelta(hours=8), 120000),
    ("2026-10-05T05:42:12.123Z", timedelta(0), 123000),
    ("2026-10-05T01:42:12.1234-04:00", timedelta(hours=-4), 123400),
    ("2026-10-05T05:42:12.12345Z", timedelta(0), 123450),
    ("2026-10-05T05:42:12.123456Z", timedelta(0), 123456),
])
def test_timezone(timestamp, offset, microsecond):
    event = parse_web_line(line(timestamp=timestamp))
    assert event.timestamp.tzinfo is not None
    assert event.timestamp.utcoffset() == offset
    assert event.timestamp.microsecond == microsecond
    assert event.raw_log == line(timestamp=timestamp)
    assert event.timestamp.astimezone(timezone.utc) == datetime(2026, 10, 5, 5, 42, 12, microsecond, tzinfo=timezone.utc)


def test_ipv6_normalization():
    event = parse_web_line(line(ip="2001:0DB8:0:0:0:0:0:10"))
    assert event.source_ip == "2001:db8::10"


@pytest.mark.parametrize("username", ["alice", "root", "user_01", "john.doe", "service-account", "alice@example.com"])
def test_usernames(username):
    assert parse_web_line(line(username=username)).username == username


@pytest.mark.parametrize("raw", [
    "2026-10-05T13:42:12+08:00 REQUEST path=/api/users status=200",
    "2026-10-05T13:42:12+08:00 REQUEST message=LOGIN",
    "2026-10-05T13:42:12+08:00 login username=alice ip=192.0.2.10 result=SUCCESS",
    "unrelated text", "", "\n",
])
def test_irrelevant(raw):
    assert parse_web_line(raw) is None


@pytest.mark.parametrize("field", ["username", "ip", "result"])
def test_missing_fields(field):
    raw = " ".join(token for token in line().split() if not token.startswith(field + "="))
    with pytest.raises(ParseError, match=f"missing field: {field}"):
        parse_web_line(raw)


@pytest.mark.parametrize("changes, error", [
    ({"username": ""}, "invalid web login username"),
    ({"username": "alice=admin"}, "invalid web login username"),
    ({"username": "alice/bob"}, "invalid web login username"),
    ({"ip": "999.999.1.1"}, "invalid source IP"),
    ({"ip": "2001:db8::zz"}, "invalid source IP"),
    ({"ip": ""}, "invalid source IP"),
    ({"result": "BLOCKED"}, "invalid web login result"),
    ({"result": "success"}, "invalid web login result"),
    ({"result": ""}, "invalid web login result"),
    ({"timestamp": "2026-10-05T13:42:12"}, "timestamp must include timezone"),
    ({"timestamp": "not-a-date"}, "invalid web login timestamp"),
    ({"timestamp": "2026-02-30T13:42:12Z"}, "invalid web login timestamp"),
    ({"timestamp": "2026-10-05T24:42:12Z"}, "invalid web login timestamp"),
    ({"timestamp": "2026-10-05T13:42:12+08:99"}, "invalid web login timezone offset"),
    ({"timestamp": "2026-10-05T13:42:12+24:00"}, "invalid web login timezone offset"),
])
def test_invalid_fields(changes, error):
    with pytest.raises(ParseError, match=error):
        parse_web_line(line(**changes))


@pytest.mark.parametrize("suffix, error", [
    (" username=bob", "duplicate field: username"),
    (" password=secret-example", "unexpected field"),
    (" broken-token", "unexpected field"),
    ("\nsecond line", "must occupy one line"),
])
def test_extra_or_duplicate_fields(suffix, error):
    with pytest.raises(ParseError, match=error) as caught:
        parse_web_line(line() + suffix)
    assert "secret-example" not in str(caught.value)


def test_field_order_is_fixed():
    with pytest.raises(ParseError, match="must be ordered"):
        parse_web_line("2026-10-05T13:42:12Z LOGIN ip=192.0.2.10 username=alice result=SUCCESS")


def test_missing_timestamp():
    with pytest.raises(ParseError, match="missing timestamp"):
        parse_web_line("LOGIN username=alice ip=192.0.2.10 result=SUCCESS")


@pytest.mark.parametrize("ending", ["", "\n", "\r\n"])
def test_raw_log_only_removes_line_ending(ending):
    raw = "  " + line() + " \t"
    assert parse_web_line(raw + ending).raw_log == raw


def test_error_does_not_echo_potential_secret():
    with pytest.raises(ParseError) as caught:
        parse_web_line(line(ip="secret-example"))
    assert str(caught.value) == "invalid source IP"
    assert caught.value.__suppress_context__
