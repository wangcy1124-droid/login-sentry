from contextlib import closing

import pytest

from app.db.database import connect_database, initialize_database


@pytest.mark.parametrize("memory", [True, False])
def test_initialization_is_idempotent(tmp_path, memory):
    with closing(connect_database(":memory:" if memory else tmp_path / "events.sqlite3")) as connection:
        initialize_database(connection)
        initialize_database(connection)
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"login_events", "collector_offsets"} <= tables
        indexes = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        assert {"idx_login_events_timestamp", "idx_login_events_source_ip_timestamp", "idx_login_events_result_timestamp"} <= indexes


def test_initialization_does_not_commit_pending_work():
    with closing(connect_database(":memory:")) as connection:
        initialize_database(connection)
        connection.execute("INSERT INTO collector_offsets VALUES (?, ?, ?, ?)", ("/example", 1, 0, "2026-10-05T00:00:00+00:00"))
        with pytest.raises(ValueError, match="active transaction"):
            initialize_database(connection)
        connection.rollback()
        assert connection.execute("SELECT COUNT(*) FROM collector_offsets").fetchone()[0] == 0
