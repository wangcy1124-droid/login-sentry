from dataclasses import replace
from datetime import timedelta, timezone
import sqlite3

import pytest

from app.alerts.manager import process_detection_report
from app.db.alert_repositories import AlertRepository
from app.models.alert import AlertStatus, Severity, fingerprint, occurrence_key
from app.models.detection import DetectionReport, RuleType
from app.services.alerting import process_alerts, review_alert
from app.services.detection import detect


@pytest.fixture
def occurrence(detection_db, persist_event, rules):
    for seconds in (0, 10, 20, 30, 40):
        persist_event(seconds=seconds)
    return detect(detection_db, rules).matches[0]


def process(db, rules, *matches):
    return process_detection_report(db, DetectionReport(tuple(matches)), rules)


def test_first_duplicate_and_trace(detection_db, rules, occurrence):
    clock = lambda: occurrence.window_end
    stats = process_detection_report(detection_db, DetectionReport((occurrence,)), rules, clock)
    assert (stats.alerts_created, stats.links_added) == (1, 5)
    repo = AlertRepository(detection_db)
    alert = repo.get_by_id(1)
    assert alert.status == AlertStatus.OPEN
    assert alert.severity == Severity.MEDIUM
    assert alert.occurrence_count == 1
    assert alert.first_seen == occurrence.window_start
    assert alert.last_seen == occurrence.window_end
    assert alert.created_at == alert.updated_at == clock()
    assert alert.created_at.tzinfo == timezone.utc
    records = repo.list_events(1)
    assert tuple(r.id for r in records) == occurrence.event_ids
    assert all(r.event.raw_log == 'synthetic event' for r in records)
    again = process_alerts(detection_db, rules)
    assert (again.alerts_created, again.alerts_aggregated, again.links_added, again.duplicate_occurrences) == (0, 0, 0, 1)
    assert repo.get_by_id(1) == alert


@pytest.mark.parametrize('delay,expected', [(100, 1), (300, 1), (300.000001, 2)])
def test_cooldown(detection_db, rules, occurrence, persist_event, delay, expected):
    process(detection_db, rules, occurrence)
    ids = tuple(persist_event(seconds=40 + delay - 4 + i) for i in range(5))
    later = replace(occurrence, window_start=occurrence.window_end + timedelta(seconds=delay-4),
                    window_end=occurrence.window_end + timedelta(seconds=delay), event_ids=ids)
    stats = process(detection_db, rules, later)
    repo = AlertRepository(detection_db)
    assert repo.count() == expected
    assert stats.alerts_aggregated == (expected == 1)
    assert repo.get_by_id(expected).last_seen == later.window_end
    assert repo.get_by_id(1).occurrence_count == (2 if expected == 1 else 1)


@pytest.mark.parametrize('status', [AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE, AlertStatus.CONFIRMED])
def test_review_then_new_activity(detection_db, rules, occurrence, persist_event, status):
    process(detection_db, rules, occurrence)
    reviewed = review_alert(detection_db, 1, status, 'shared office NAT')
    assert reviewed.review_note == 'shared office NAT'
    assert process(detection_db, rules, occurrence).duplicate_occurrences == 1
    for i in range(5):
        persist_event(seconds=100+i)
    stats = process_alerts(detection_db, rules)
    repo = AlertRepository(detection_db)
    if status == AlertStatus.CONFIRMED:
        assert stats.alerts_aggregated == 1
        assert repo.count() == 1
        assert repo.get_by_id(1).occurrence_count == 2
    else:
        assert stats.alerts_created == 1
        assert repo.count() == 2
        assert repo.get_by_id(2).status == AlertStatus.OPEN
        assert repo.list_event_ids(1) == list(occurrence.event_ids)
    assert repo.get_by_id(1).status == status
    assert detection_db.execute('SELECT COUNT(*) FROM alert_occurrences').fetchone()[0] == 2


def test_overlap_out_of_order_and_distinct_fingerprints(detection_db, rules, occurrence, persist_event):
    process(detection_db, rules, occurrence)
    extra = tuple(persist_event(seconds=i) for i in (-30, -20, -10))
    older = replace(occurrence, event_ids=extra + occurrence.event_ids[:2],
                    window_start=occurrence.window_start-timedelta(seconds=30),
                    window_end=occurrence.window_start+timedelta(seconds=10))
    stats = process(detection_db, rules, older)
    repo = AlertRepository(detection_db)
    assert stats.links_added == 3
    assert repo.list_event_ids(1) == list(extra + occurrence.event_ids)
    assert repo.get_by_id(1).first_seen == older.window_start
    assert repo.get_by_id(1).last_seen == occurrence.window_end
    assert repo.get_by_id(1).occurrence_count == 2
    # Different rule and IP identities must not merge.
    other_rule = replace(occurrence, rule_type=RuleType.MULTI_ACCOUNT)
    other_ids = tuple(persist_event(ip='2001:db8::10') for _ in range(5))
    other_ip = replace(occurrence, source_ip='2001:db8::10', event_ids=other_ids)
    process(detection_db, rules, other_rule, other_ip)
    assert repo.count() == 3
    assert repo.get_by_id(2).severity == Severity.HIGH
    assert len({a.fingerprint for a in repo.list_all()}) == 3


@pytest.mark.parametrize('table', ['alert_occurrences', 'alert_event_links'])
@pytest.mark.parametrize('existing', [False, True])
def test_atomic_rollback(detection_db, rules, occurrence, persist_event, table, existing):
    repo = AlertRepository(detection_db)
    if existing:
        process(detection_db, rules, occurrence)
        ids = tuple(persist_event(seconds=100+i) for i in range(5))
        occurrence = replace(occurrence, event_ids=ids, window_start=occurrence.window_end,
                             window_end=occurrence.window_end+timedelta(seconds=100))
    before = list(detection_db.iterdump())
    # Fixed test-owned SQL identifiers only.
    trigger = ('CREATE TRIGGER fail_occurrence BEFORE INSERT ON alert_occurrences '
               "BEGIN SELECT RAISE(ABORT, 'injected'); END;" if table == 'alert_occurrences' else
               'CREATE TRIGGER fail_occurrence BEFORE INSERT ON alert_event_links '
               "BEGIN SELECT RAISE(ABORT, 'injected'); END;")
    detection_db.execute(trigger)
    with pytest.raises(sqlite3.IntegrityError, match='injected'):
        process(detection_db, rules, occurrence)
    detection_db.execute('DROP TRIGGER fail_occurrence')
    assert list(detection_db.iterdump()) == before
    assert process(detection_db, rules, occurrence).links_added == 5
    assert repo.get_by_id(1).occurrence_count == (2 if existing else 1)
    assert process(detection_db, rules, occurrence).duplicate_occurrences == 1


def test_foreign_key_rolls_back_new_alert(detection_db, rules, occurrence):
    bad = replace(occurrence, event_ids=(1, 2, 3, 4, 99999))
    with pytest.raises(sqlite3.IntegrityError, match='FOREIGN KEY'):
        process(detection_db, rules, bad)
    assert AlertRepository(detection_db).count() == 0
    assert detection_db.execute('SELECT COUNT(*) FROM alert_occurrences').fetchone()[0] == 0
    assert detection_db.execute('SELECT COUNT(*) FROM alert_event_links').fetchone()[0] == 0


def test_caller_transaction_and_autocommit_rejected(detection_db, rules, occurrence):
    detection_db.execute('BEGIN')
    with pytest.raises(ValueError, match='idle connection'):
        process(detection_db, rules, occurrence)
    assert detection_db.in_transaction
    detection_db.rollback()
    detection_db.isolation_level = None
    with pytest.raises(ValueError, match='transactions enabled'):
        process(detection_db, rules, occurrence)


def test_stable_identity(occurrence):
    key = occurrence_key(occurrence)
    assert key == occurrence_key(replace(occurrence, event_ids=tuple(reversed(occurrence.event_ids))))
    assert key == occurrence_key(replace(occurrence, window_start=occurrence.window_start.astimezone(timezone(timedelta(hours=8)))))
    for changes in ({'event_ids': (1, 2, 3, 4, 99)}, {'rule_type': RuleType.MULTI_ACCOUNT}, {'source_ip': '2001:db8::10'}):
        assert key != occurrence_key(replace(occurrence, **changes))
    assert fingerprint(RuleType.FAILURE_BURST, '192.0.2.10') == 'failure_burst|192.0.2.10'


def test_dynamic_cooldown_from_toml(tmp_path, detection_db, rules, occurrence, persist_event):
    from pathlib import Path
    from app.config.loader import load_config

    process(detection_db, rules, occurrence)
    for i in range(5):
        persist_event(seconds=100+i)
    path = tmp_path / 'custom.toml'
    default = Path(__file__).resolve().parents[2] / 'config/default.toml'
    path.write_text(default.read_text().replace('cooldown_seconds = 300', 'cooldown_seconds = 10'))
    stats = process_alerts(detection_db, load_config(path))
    assert stats.alerts_created == 1
    assert stats.alerts_aggregated == 0
    assert stats.duplicate_occurrences == 1


@pytest.mark.parametrize('changes', [
    {'event_ids': (1, 1, 2, 3, 4)}, {'event_ids': (1, 2, 3, 4, -1)},
    {'event_count': 4}, {'event_ids': ()}, {'rule_type': 'failure_burst'},
])
def test_invalid_match_rejected_before_writes(detection_db, rules, occurrence, changes):
    with pytest.raises(ValueError):
        process(detection_db, rules, replace(occurrence, **changes))
    assert AlertRepository(detection_db).count() == 0
