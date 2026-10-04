from dataclasses import FrozenInstanceError
from datetime import datetime, timezone, tzinfo

import pytest

from app.models.event import LoginEvent, LoginResult, SourceType


class NoOffset(tzinfo):
    def utcoffset(self, dt):
        return None


def make_event(**changes):
    fields = dict(
        timestamp=datetime(2026, 10, 5, tzinfo=timezone.utc),
        source_type=SourceType.SSH,
        source_ip="192.0.2.10",
        username="alice",
        result=LoginResult.SUCCESS,
        raw_log="original log",
    )
    merged = fields.copy()
    merged.update(changes)
    return LoginEvent(**merged)


def test_event_fields_and_immutability():
    event = make_event()
    assert event.timestamp == datetime(2026, 10, 5, tzinfo=timezone.utc)
    assert event.source_type.value == "ssh"
    assert event.result.value == "success"
    assert event.source_ip == "192.0.2.10"
    assert event.username == "alice"
    assert event.raw_log == "original log"
    with pytest.raises(FrozenInstanceError):
        event.result = LoginResult.FAILURE


@pytest.mark.parametrize("timestamp", [datetime(2026, 10, 5), datetime(2026, 10, 5, tzinfo=NoOffset())])
def test_rejects_naive_or_ineffective_timezone(timestamp):
    with pytest.raises(ValueError, match="timestamp must include timezone"):
        make_event(timestamp=timestamp)


@pytest.mark.parametrize("changes, message", [
    ({"timestamp": "2026-10-05"}, "timestamp must be a datetime"),
    ({"source_type": "ssh"}, "source_type must be a SourceType"),
    ({"result": "success"}, "result must be a LoginResult"),
    ({"source_type": "ftp"}, "source_type must be a SourceType"),
    ({"result": "blocked"}, "result must be a LoginResult"),
])
def test_rejects_non_enum_states_and_wrong_timestamp_type(changes, message):
    with pytest.raises(TypeError, match=message):
        make_event(**changes)


@pytest.mark.parametrize("enum_type, values", [(SourceType, {"ssh", "web"}), (LoginResult, {"success", "failure"})])
def test_enum_domain(enum_type, values):
    assert {member.value for member in enum_type} == values
    with pytest.raises(ValueError):
        enum_type("unknown")
