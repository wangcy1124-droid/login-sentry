from dataclasses import replace, FrozenInstanceError
from datetime import datetime

import pytest

from app.db.alert_repositories import AlertRepository
from app.models.alert import AlertStatus
from app.services.alerting import process_alerts, review_alert


@pytest.fixture
def alert(detection_db, rules, persist_event):
    for _ in range(5):
        persist_event()
    process_alerts(detection_db, rules)
    return AlertRepository(detection_db).get_by_id(1)


@pytest.mark.parametrize('initial,target', [
    (AlertStatus.OPEN, AlertStatus.CONFIRMED), (AlertStatus.OPEN, AlertStatus.FALSE_POSITIVE),
    (AlertStatus.OPEN, AlertStatus.RESOLVED), (AlertStatus.CONFIRMED, AlertStatus.FALSE_POSITIVE),
    (AlertStatus.CONFIRMED, AlertStatus.RESOLVED)])
def test_allowed(detection_db, alert, initial, target):
    if initial != AlertStatus.OPEN:
        review_alert(detection_db, 1, initial)
    result = review_alert(detection_db, 1, target, "Robert'); DROP TABLE alerts;--", lambda: alert.last_seen)
    assert result.status == target
    assert result.updated_at == alert.last_seen
    assert result.severity == alert.severity
    assert result.review_note == "Robert'); DROP TABLE alerts;--"
    assert len(AlertRepository(detection_db).list_events(1)) == 5
    assert detection_db.execute('SELECT COUNT(*) FROM alert_occurrences').fetchone()[0] == 1


@pytest.mark.parametrize('initial,target', [
    (AlertStatus.RESOLVED, AlertStatus.OPEN), (AlertStatus.FALSE_POSITIVE, AlertStatus.CONFIRMED),
    (AlertStatus.RESOLVED, AlertStatus.CONFIRMED), (AlertStatus.OPEN, AlertStatus.OPEN),
    (AlertStatus.OPEN, 'confirmed')])
def test_rejected(detection_db, alert, initial, target):
    if initial != AlertStatus.OPEN:
        review_alert(detection_db, 1, initial)
    before = AlertRepository(detection_db).get_by_id(1)
    with pytest.raises(ValueError, match='transition'):
        review_alert(detection_db, 1, target)
    assert AlertRepository(detection_db).get_by_id(1) == before


@pytest.mark.parametrize('note', [None, '', 'a'*2000])
def test_note_allowed(detection_db, alert, note):
    assert review_alert(detection_db, 1, AlertStatus.CONFIRMED, note).review_note == note


@pytest.mark.parametrize('note', ['a'*2001, 123])
def test_note_rejected(detection_db, alert, note):
    with pytest.raises(ValueError, match='2000'):
        review_alert(detection_db, 1, AlertStatus.CONFIRMED, note)
    assert AlertRepository(detection_db).get_by_id(1) == alert


def test_missing_alert_and_model_validation(detection_db, alert):
    with pytest.raises(ValueError, match='does not exist'):
        review_alert(detection_db, 999, AlertStatus.CONFIRMED)
    with pytest.raises(FrozenInstanceError):
        alert.status = AlertStatus.RESOLVED
    for changes in ({'status': 'open'}, {'severity': 'high'}, {'occurrence_count': 0},
                    {'first_seen': datetime(2026, 1, 1)}):
        with pytest.raises(ValueError):
            replace(alert, **changes)
