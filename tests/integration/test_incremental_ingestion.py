import sqlite3
import subprocess
import sys
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.collectors.file_collector import CollectionStats, collect_file
from app.db.database import connect_database, initialize_database
from app.db.repositories import CollectorOffsetRepository, LoginEventRepository
from app.models.event import SourceType
from app.parsers.web import parse_web_line
from app.services.ingestion import ingest_file

WEB = b"2026-10-05T13:42:12+08:00 LOGIN username=alice ip=192.0.2.10 result=SUCCESS\n"
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def connection(tmp_path):
    with closing(connect_database(tmp_path / "events.sqlite3")) as db:
        initialize_database(db)
        yield db


def test_restart_append_and_canonical_alias(tmp_path, monkeypatch):
    source = tmp_path / "web.log"
    database = tmp_path / "events.sqlite3"
    source.write_bytes(WEB * 2)
    assert ingest_file(source, database, SourceType.WEB) == CollectionStats(2, 2, 0, 0)
    monkeypatch.chdir(tmp_path)
    assert ingest_file("web.log", database, SourceType.WEB) == CollectionStats()
    link = tmp_path / "alias.log"
    link.symlink_to(source)
    assert ingest_file(link, database, SourceType.WEB) == CollectionStats()
    with source.open("ab") as stream:
        stream.write(WEB)
    assert ingest_file(source, database, SourceType.WEB) == CollectionStats(1, 1, 0, 0)
    with closing(connect_database(database)) as db:
        assert LoginEventRepository(db).count() == 3
        assert CollectorOffsetRepository(db).get(source).offset_bytes == len(WEB) * 3
        assert db.execute("SELECT COUNT(*) FROM collector_offsets").fetchone()[0] == 1


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_utf8_byte_offsets_and_crlf(connection, tmp_path, ending):
    source = tmp_path / "web.log"
    data = "无关日志".encode() + ending + WEB.rstrip(b"\n") + ending
    source.write_bytes(data)
    assert collect_file(source, parse_web_line, connection) == CollectionStats(2, 1, 1, 0)
    assert CollectorOffsetRepository(connection).get(source).offset_bytes == len(data)
    assert collect_file(source, parse_web_line, connection) == CollectionStats()
    with source.open("ab") as stream:
        stream.write(WEB.rstrip(b"\n") + ending)
    assert collect_file(source, parse_web_line, connection) == CollectionStats(1, 1, 0, 0)
    assert CollectorOffsetRepository(connection).get(source).offset_bytes == source.stat().st_size
    assert LoginEventRepository(connection).count() == 2
    assert LoginEventRepository(connection).list_all()[0].raw_log == WEB.decode().rstrip("\n")


def test_partial_final_line_survives_restart(tmp_path):
    source = tmp_path / "web.log"
    database = tmp_path / "events.sqlite3"
    split = len(WEB) // 2
    source.write_bytes(WEB + WEB[:split])
    assert ingest_file(source, database, SourceType.WEB) == CollectionStats(1, 1, 0, 0)
    with closing(connect_database(database)) as db:
        assert CollectorOffsetRepository(db).get(source).offset_bytes == len(WEB)
    assert ingest_file(source, database, SourceType.WEB) == CollectionStats()
    with source.open("ab") as stream:
        stream.write(WEB[split:])
    assert ingest_file(source, database, SourceType.WEB) == CollectionStats(1, 1, 0, 0)
    assert ingest_file(source, database, SourceType.WEB) == CollectionStats()
    with closing(connect_database(database)) as db:
        assert LoginEventRepository(db).count() == 2
        assert CollectorOffsetRepository(db).get(source).offset_bytes == len(WEB) * 2


@pytest.mark.parametrize("reset", ["truncate", "rotate"])
@pytest.mark.parametrize("new_content", [b"", WEB[:20], WEB.replace(b"alice", b"bob")])
def test_file_lifecycle_resets(connection, tmp_path, reset, new_content):
    source = tmp_path / "web.log"
    source.write_bytes(WEB * 2)
    collect_file(source, parse_web_line, connection)
    old = source.stat()
    if reset == "rotate":
        source.rename(tmp_path / "web.log.1")
    source.write_bytes(new_content)
    if reset == "truncate":
        assert source.stat().st_ino == old.st_ino
        assert source.stat().st_size < old.st_size
    else:
        assert source.stat().st_ino != old.st_ino
    complete = int(new_content.endswith(b"\n"))
    assert collect_file(source, parse_web_line, connection) == CollectionStats(complete, complete, 0, 0)
    state = CollectorOffsetRepository(connection).get(source)
    assert state.inode == source.stat().st_ino
    assert state.offset_bytes == (len(new_content) if complete else 0)
    assert collect_file(source, parse_web_line, connection) == CollectionStats()
    assert LoginEventRepository(connection).count() == 2 + complete


def test_malformed_and_irrelevant_lines_progress(connection, tmp_path):
    source = tmp_path / "web.log"
    source.write_bytes(WEB + WEB.replace(b"192.0.2.10", b"999.999.1.1") + WEB)
    assert collect_file(source, parse_web_line, connection) == CollectionStats(3, 2, 0, 1)
    assert collect_file(source, parse_web_line, connection) == CollectionStats()
    with source.open("ab") as stream:
        stream.write(b"irrelevant\n" + WEB + b"irrelevant\n")
    assert collect_file(source, parse_web_line, connection) == CollectionStats(3, 1, 2, 0)
    assert CollectorOffsetRepository(connection).get(source).offset_bytes == source.stat().st_size


@pytest.mark.parametrize("failed_table", ["login_events", "collector_offsets"])
def test_database_failure_rolls_back_event_and_offset(connection, tmp_path, failed_table):
    source = tmp_path / "web.log"
    source.write_bytes(WEB)
    collect_file(source, parse_web_line, connection)
    saved = CollectorOffsetRepository(connection).get(source)
    # Table names are fixed test constants, never log/user input.
    connection.execute("CREATE TRIGGER fail_write BEFORE INSERT ON " + failed_table + " BEGIN SELECT RAISE(ABORT, 'simulated database failure'); END")
    with source.open("ab") as stream:
        stream.write(WEB)
    with pytest.raises(sqlite3.IntegrityError, match="simulated database failure"):
        collect_file(source, parse_web_line, connection)
    assert LoginEventRepository(connection).count() == 1
    assert CollectorOffsetRepository(connection).get(source) == saved
    assert not connection.in_transaction
    connection.execute("DROP TRIGGER fail_write")
    assert collect_file(source, parse_web_line, connection) == CollectionStats(1, 1, 0, 0)
    assert LoginEventRepository(connection).count() == 2


def test_ssh_integration_explicit_context(tmp_path):
    source = tmp_path / "ssh.log"
    database = tmp_path / "events.sqlite3"
    source.write_text("Oct  5 13:42:12 host sshd[1]: Failed password for root from 192.0.2.10 port 22 ssh2\n")
    tz = timezone(timedelta(hours=8))
    assert ingest_file(source, database, SourceType.SSH, year=2026, tzinfo=tz).events_inserted == 1
    with closing(connect_database(database)) as db:
        assert LoginEventRepository(db).list_all()[0].timestamp == datetime(2026, 10, 5, 5, 42, 12, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="explicit timezone"):
        ingest_file(source, database, SourceType.SSH)


@pytest.mark.parametrize("kind,context,events", [("web", [], 3), ("ssh", ["--year", "2026", "--timezone", "Z"], 4)])
def test_cli_samples_and_repeat(tmp_path, kind, context, events):
    command = [sys.executable, str(ROOT / "scripts/ingest_file.py"), "--type", kind, "--path", str(ROOT / "samples" / (kind + ".log")), "--database", str(tmp_path / "events.sqlite3")] + context
    first = subprocess.run(command, capture_output=True, text=True)
    assert first.returncode == 0, first.stderr
    assert first.stdout.strip() == "lines_read={} events_inserted={} ignored_lines=1 parse_errors=0".format(events + 1, events)
    second = subprocess.run(command, capture_output=True, text=True)
    assert second.returncode == 0, second.stderr
    assert second.stdout.strip() == "lines_read=0 events_inserted=0 ignored_lines=0 parse_errors=0"


@pytest.mark.parametrize("offset", ["Z", "+00:00", "+08:00", "-04:00"])
def test_cli_timezone_values(tmp_path, offset):
    database = tmp_path / "events.sqlite3"
    result = subprocess.run([
        sys.executable, str(ROOT / "scripts/ingest_file.py"), "--type", "ssh",
        "--path", str(ROOT / "samples/ssh.log"), "--database", str(database),
        "--year", "2026", "--timezone=" + offset,
    ], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    expected = {"Z": 0, "+00:00": 0, "+08:00": 8, "-04:00": -4}
    with closing(connect_database(database)) as db:
        event = LoginEventRepository(db).list_all()[0]
        assert event.timestamp == datetime(2026, 10, 5, 13, 42, 12, tzinfo=timezone.utc) - timedelta(hours=expected[offset])


@pytest.mark.parametrize("offset", ["UTC", "+24:00", "+01:60", "+8:00", "", "08:00"])
def test_cli_rejects_invalid_offsets(tmp_path, offset):
    database = tmp_path / "events.sqlite3"
    result = subprocess.run([
        sys.executable, str(ROOT / "scripts/ingest_file.py"), "--type", "ssh",
        "--path", str(ROOT / "samples/ssh.log"), "--database", str(database),
        "--year", "2026", "--timezone=" + offset,
    ], capture_output=True, text=True)
    assert result.returncode == 2
    assert "timezone" in result.stderr
    assert not database.exists()


def test_first_event_failure_does_not_create_offset(connection, tmp_path):
    source = tmp_path / "web.log"
    source.write_bytes(WEB)
    connection.execute("CREATE TRIGGER fail_write BEFORE INSERT ON collector_offsets BEGIN SELECT RAISE(ABORT, 'offset write failure'); END")
    with pytest.raises(sqlite3.IntegrityError, match="offset write failure"):
        collect_file(source, parse_web_line, connection)
    assert LoginEventRepository(connection).count() == 0
    assert CollectorOffsetRepository(connection).get(source) is None


def test_invalid_utf8_target_is_counted_and_consumed(connection, tmp_path):
    source = tmp_path / "web.log"
    source.write_bytes(WEB.replace(b"192.0.2.10", b"\xff") + WEB)
    assert collect_file(source, parse_web_line, connection) == CollectionStats(2, 1, 0, 1)
    assert collect_file(source, parse_web_line, connection) == CollectionStats()
