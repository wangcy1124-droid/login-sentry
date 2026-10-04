import os
from contextlib import closing

import pytest

from app.collectors.file_collector import CollectionStats, collect_file
from app.db.database import connect_database, initialize_database
from app.db.repositories import CollectorOffsetRepository, CollectorStateError, LoginEventRepository
from app.parsers.web import parse_web_line

WEB = b"2026-10-05T13:42:12+08:00 LOGIN username=alice ip=192.0.2.10 result=SUCCESS\n"


@pytest.fixture
def connection():
    with closing(connect_database(":memory:")) as db:
        initialize_database(db)
        yield db


def test_empty_and_partial_only_files(connection, tmp_path):
    path = tmp_path / "source.log"
    path.touch()
    assert collect_file(path, parse_web_line, connection) == CollectionStats()
    assert CollectorOffsetRepository(connection).get(path).offset_bytes == 0
    path.write_bytes(WEB[:-1])
    assert collect_file(path, parse_web_line, connection) == CollectionStats()
    assert CollectorOffsetRepository(connection).get(path).offset_bytes == 0
    with path.open("ab") as stream:
        stream.write(b"\n")
    assert collect_file(path, parse_web_line, connection) == CollectionStats(1, 1, 0, 0)


def test_missing_file_is_not_created(connection, tmp_path):
    path = tmp_path / "missing" / "source.log"
    with pytest.raises(FileNotFoundError):
        collect_file(path, parse_web_line, connection)
    assert not path.parent.exists()
    assert connection.execute("SELECT COUNT(*) FROM collector_offsets").fetchone()[0] == 0


def test_encoding_replacement_and_non_unicode_line_splitting(connection, tmp_path):
    path = tmp_path / "source.log"
    content = "unrelated 中文\u2028still one record".encode() + b"\xff\n" + WEB
    path.write_bytes(content)
    seen = []

    def parser(line):
        seen.append(line)
        return parse_web_line(line)

    assert collect_file(path, parser, connection) == CollectionStats(2, 1, 1, 0)
    assert seen[0] == "unrelated 中文\u2028still one record\ufffd\n"
    assert CollectorOffsetRepository(connection).get(path).offset_bytes == len(content)


def test_unexpected_parser_exception_is_not_swallowed(connection, tmp_path):
    path = tmp_path / "source.log"
    path.write_bytes(WEB)

    def broken(line):
        raise RuntimeError("parser bug")

    with pytest.raises(RuntimeError, match="parser bug"):
        collect_file(path, broken, connection)
    assert CollectorOffsetRepository(connection).get(path) is None
    assert LoginEventRepository(connection).count() == 0


def test_corrupt_offset_does_not_reset(connection, tmp_path):
    path = tmp_path / "source.log"
    path.write_bytes(WEB)
    with connection:
        connection.execute("INSERT INTO collector_offsets VALUES (?, ?, ?, ?)", (str(path), path.stat().st_ino, -1, "2026-10-05T00:00:00+00:00"))
    with pytest.raises(CollectorStateError, match="offset"):
        collect_file(path, parse_web_line, connection)
    assert LoginEventRepository(connection).count() == 0


def test_requires_idle_transactional_connection(connection, tmp_path):
    path = tmp_path / "source.log"
    path.write_bytes(WEB)
    connection.execute("BEGIN")
    with pytest.raises(ValueError, match="idle connection"):
        collect_file(path, parse_web_line, connection)
    connection.rollback()
    connection.isolation_level = None
    with pytest.raises(ValueError, match="transactions enabled"):
        collect_file(path, parse_web_line, connection)


def test_open_descriptor_inode_wins_stat_open_race(connection, tmp_path, monkeypatch):
    path = tmp_path / "source.log"
    path.write_bytes(WEB)
    assert collect_file(path, parse_web_line, connection).events_inserted == 1
    old_inode = path.stat().st_ino
    replacement = tmp_path / "replacement.log"
    replacement.write_bytes(WEB.replace(b"alice", b"bob"))
    original_open = type(path).open

    def racing_open(self, *args, **kwargs):
        if self == path:
            os.replace(str(replacement), str(path))
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(type(path), "open", racing_open)
    assert collect_file(path, parse_web_line, connection).events_inserted == 1
    state = CollectorOffsetRepository(connection).get(path)
    assert state.inode == path.stat().st_ino != old_inode
    assert LoginEventRepository(connection).list_all()[-1].username == "bob"
