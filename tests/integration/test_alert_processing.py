import subprocess
import sys
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.db.alert_repositories import AlertRepository
from app.db.database import connect_database, initialize_database
from app.db.repositories import LoginEventRepository
from app.models.alert import occurrence_key
from app.models.event import LoginEvent, SourceType, LoginResult
from app.services.alerting import process_alerts
from app.services.detection import detect

ROOT = Path(__file__).resolve().parents[2]


def populate(connection, start=0):
    with connection:
        for seconds in range(start, start + 50, 10):
            LoginEventRepository(connection).insert(LoginEvent(
                datetime(2026, 10, 5, tzinfo=timezone.utc) + timedelta(seconds=seconds),
                SourceType.WEB, '192.0.2.10', 'alice', LoginResult.FAILURE, 'synthetic raw log'))


def test_restart_identity_and_cli_review(tmp_path, rules):
    path = tmp_path / 'alerts.sqlite3'
    with closing(connect_database(path)) as connection:
        initialize_database(connection)
        populate(connection)
        key = occurrence_key(detect(connection, rules).matches[0])
        assert process_alerts(connection, rules).alerts_created == 1
    with closing(connect_database(path)) as connection:
        assert occurrence_key(detect(connection, rules).matches[0]) == key
        assert process_alerts(connection, rules).duplicate_occurrences == 1
        assert AlertRepository(connection).get_by_id(1).occurrence_count == 1
        populate(connection, 100)
    command = [sys.executable, str(ROOT/'scripts/process_alerts.py'), '--database', str(path),
               '--config', str(ROOT/'config/default.toml')]
    first = subprocess.run(command, capture_output=True, text=True)
    assert first.returncode == 0, first.stderr
    assert first.stdout.strip() == 'matches_seen=2 alerts_created=0 alerts_aggregated=1 duplicate_occurrences=1 links_added=5'
    second = subprocess.run(command, capture_output=True, text=True)
    assert second.returncode == 0, second.stderr
    assert second.stdout.strip() == 'matches_seen=2 alerts_created=0 alerts_aggregated=0 duplicate_occurrences=2 links_added=0'
    review = [sys.executable, str(ROOT/'scripts/review_alert.py'), '--database', str(path),
              '--alert-id', '1', '--status', 'false_positive', '--note', 'shared office NAT']
    result = subprocess.run(review, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    rejected = subprocess.run(review, capture_output=True, text=True)
    assert rejected.returncode != 0
    assert 'invalid alert status transition' in rejected.stderr
    with closing(connect_database(path)) as connection:
        repo = AlertRepository(connection)
        assert repo.get_by_id(1).review_note == 'shared office NAT'
        assert repo.get_by_id(1).occurrence_count == 2
        assert len(repo.list_events(1)) == 10
        populate(connection, 200)
    third = subprocess.run(command, capture_output=True, text=True)
    assert third.returncode == 0, third.stderr
    assert third.stdout.strip() == 'matches_seen=3 alerts_created=1 alerts_aggregated=0 duplicate_occurrences=2 links_added=5'


def test_pre_stage4_upgrade_preserves_events_and_offsets(tmp_path):
    # Explicit previous schema, independent of the current initialization SQL.
    with closing(connect_database(tmp_path/'old.sqlite3')) as connection:
        connection.executescript('''
        CREATE TABLE login_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp_utc TEXT NOT NULL,
          source_type TEXT NOT NULL, source_ip TEXT NOT NULL, username TEXT NOT NULL,
          result TEXT NOT NULL, raw_log TEXT NOT NULL, created_at_utc TEXT NOT NULL);
        CREATE TABLE collector_offsets (source_path TEXT PRIMARY KEY, inode INTEGER NOT NULL,
          offset_bytes INTEGER NOT NULL, updated_at_utc TEXT NOT NULL);
        ''')
        populate(connection)
        with connection:
            connection.execute('INSERT INTO collector_offsets VALUES (?, ?, ?, ?)',
                               ('/synthetic/source.log', 123, 42, '2026-10-05T00:00:00.000000+00:00'))
        before = LoginEventRepository(connection).list_all()
        initialize_database(connection)
        initialize_database(connection)
        assert LoginEventRepository(connection).list_all() == before
        assert connection.execute('SELECT offset_bytes FROM collector_offsets').fetchone()[0] == 42
        assert AlertRepository(connection).count() == 0
        assert connection.execute('PRAGMA foreign_keys').fetchone()[0] == 1


def test_empty_and_invalid_config_cli(tmp_path):
    database = tmp_path/'empty.sqlite3'
    command = [sys.executable, str(ROOT/'scripts/process_alerts.py'), '--database', str(database)]
    bad = subprocess.run(command + ['--config', str(tmp_path/'missing.toml')], capture_output=True, text=True)
    assert bad.returncode != 0
    assert not database.exists()
    good = subprocess.run(command + ['--config', str(ROOT/'config/default.toml')], capture_output=True, text=True)
    assert good.returncode == 0, good.stderr
    assert good.stdout.strip() == 'matches_seen=0 alerts_created=0 alerts_aggregated=0 duplicate_occurrences=0 links_added=0'
