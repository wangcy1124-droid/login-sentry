import subprocess
import sys
from pathlib import Path

from app.db.database import connect_database
from app.db.repositories import LoginEventRepository

ROOT = Path(__file__).resolve().parents[2]


def test_ingest_then_detect_and_empty_database(tmp_path):
    database = tmp_path / 'events.sqlite3'
    command = [sys.executable, str(ROOT / 'scripts/detect_anomalies.py'), '--database', str(database),
               '--config', str(ROOT / 'config/default.toml')]
    empty = subprocess.run(command, capture_output=True, text=True)
    assert empty.returncode == 0, empty.stderr
    assert empty.stdout == 'matches=0\n'
    log = tmp_path / 'web.log'
    lines = []
    for index, (ip, username) in enumerate([('192.0.2.10', 'alice')] * 5 + [('198.51.100.20', name) for name in ('alice', 'bob', 'charlie', 'david')]):
        lines.append('2026-10-05T00:00:{:02d}Z LOGIN username={} ip={} result=FAILURE\n'.format(index, username, ip))
    log.write_text(''.join(lines))
    ingest = subprocess.run([sys.executable, str(ROOT / 'scripts/ingest_file.py'), '--type', 'web', '--path', str(log), '--database', str(database)], capture_output=True, text=True)
    assert ingest.returncode == 0, ingest.stderr
    output = subprocess.run(command, capture_output=True, text=True)
    assert output.returncode == 0, output.stderr
    assert output.stdout.splitlines()[0].startswith('rule=failure_burst source_ip=192.0.2.10 events=5')
    assert output.stdout.splitlines()[1].startswith('rule=multi_account source_ip=198.51.100.20 events=4')
    assert output.stdout.splitlines()[-1] == 'matches=2'
    repeated = subprocess.run(command, capture_output=True, text=True)
    assert repeated.returncode == 0, repeated.stderr
    assert repeated.stdout == output.stdout
    connection = connect_database(database)
    try:
        assert LoginEventRepository(connection).count() == 9
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert tables == {'login_events', 'collector_offsets', 'sqlite_sequence', 'alerts', 'alert_occurrences', 'alert_event_links'}
        assert connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0] == 0
        assert connection.execute('SELECT COUNT(*) FROM alert_occurrences').fetchone()[0] == 0
        assert connection.execute('SELECT COUNT(*) FROM alert_event_links').fetchone()[0] == 0
    finally:
        connection.close()


def test_cli_missing_config_fails_before_creating_database(tmp_path):
    database = tmp_path / 'events.sqlite3'
    result = subprocess.run([sys.executable, str(ROOT / 'scripts/detect_anomalies.py'), '--database', str(database), '--config', str(tmp_path / 'missing.toml')], capture_output=True, text=True)
    assert result.returncode != 0
    assert 'FileNotFoundError' in result.stderr
    assert not database.exists()
