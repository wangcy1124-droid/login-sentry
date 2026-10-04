from contextlib import closing
from datetime import datetime, timedelta, timezone

import pytest

from app.db.database import connect_database, initialize_database
from app.db.repositories import CollectorOffsetRepository, CollectorStateError, LoginEventRepository
from app.models.event import LoginEvent, LoginResult, SourceType


@pytest.fixture
def connection():
    with closing(connect_database(":memory:")) as db:
        initialize_database(db)
        yield db


@pytest.mark.parametrize("source_type,result", [(SourceType.SSH, LoginResult.FAILURE), (SourceType.WEB, LoginResult.SUCCESS)])
def test_event_round_trip_utc_and_identical_events(connection, source_type, result):
    instant = datetime(2026, 10, 5, 13, 42, 12, 123456, tzinfo=timezone(timedelta(hours=8)))
    event = LoginEvent(instant, source_type, "2001:db8::10", "alice'; DROP TABLE login_events;--", result, "  raw ' 日志  ")
    repo = LoginEventRepository(connection, clock=lambda: instant)
    with connection:
        first = repo.insert(event)
        second = repo.insert(event)
    assert second > first
    assert repo.count() == 2
    restored = repo.get_by_id(first)
    assert restored == event
    assert restored.timestamp.tzinfo is timezone.utc
    assert restored.source_type is source_type
    assert restored.result is result
    assert repo.list_all() == [event, event]
    assert repo.get_by_id(second + 1) is None
    row = connection.execute("SELECT timestamp_utc, created_at_utc FROM login_events WHERE id = ?", (first,)).fetchone()
    assert tuple(row) == ("2026-10-05T05:42:12.123456+00:00",) * 2


def test_offsets_canonical_paths_and_rollback(connection, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "quoted'日志.log"
    now = datetime(2026, 10, 5, tzinfo=timezone.utc)
    repo = CollectorOffsetRepository(connection, clock=lambda: now)
    assert repo.get(source) is None
    with connection:
        repo.upsert(source.name, 42, 10)
        repo.upsert(source, 42, 20)
    state = repo.get(source.name)
    assert (state.source_path, state.inode, state.offset_bytes, state.updated_at_utc) == (str(source), 42, 20, now)
    assert connection.execute("SELECT COUNT(*) FROM collector_offsets").fetchone()[0] == 1
    repo.upsert(source, 43, 30)
    connection.rollback()
    assert repo.get(source) == state


@pytest.mark.parametrize("inode,offset", [(0, 0), (-1, 0), (1, -1), ("bad", 0), (1, 1.5)])
def test_invalid_supplied_state(connection, inode, offset):
    with pytest.raises(CollectorStateError):
        CollectorOffsetRepository(connection).upsert("/example", inode, offset)


@pytest.mark.parametrize("inode,offset", [(0, 0), (-1, 0), (1, -1), ("bad", 0), (1, 1.5)])
def test_corrupt_persisted_state(connection, tmp_path, inode, offset):
    source = str(tmp_path / "source.log")
    with connection:
        connection.execute("INSERT INTO collector_offsets VALUES (?, ?, ?, ?)", (source, inode, offset, "2026-10-05T00:00:00+00:00"))
    with pytest.raises(CollectorStateError):
        CollectorOffsetRepository(connection).get(source)
