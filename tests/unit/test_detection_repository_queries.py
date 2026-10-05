from datetime import datetime, timedelta, timezone

import pytest

from app.db.repositories import LoginEventRepository
from app.models.event import LoginResult, SourceType
from app.services.detection import detect

BASE = datetime(2026, 10, 5, tzinfo=timezone.utc)


def test_inclusive_range_ip_result_and_order(detection_db, persist_event):
    later = persist_event(20)
    first = persist_event(0)
    middle = persist_event(10)
    tie = persist_event(10)
    persist_event(10, ip='198.51.100.20')
    persist_event(10, result=LoginResult.SUCCESS)
    repo = LoginEventRepository(detection_db)
    records = repo.list_between(BASE, BASE + timedelta(seconds=20), source_ip='192.0.2.10', result=LoginResult.FAILURE)
    assert [record.id for record in records] == [first, middle, tie, later]
    assert all(record.event.timestamp.tzinfo is timezone.utc for record in records)
    assert [record.id for record in repo.list_between(BASE + timedelta(seconds=10), BASE + timedelta(seconds=10), source_ip='192.0.2.10', result=LoginResult.FAILURE)] == [middle, tie]
    offset = timezone(timedelta(hours=8))
    assert repo.list_between(BASE.astimezone(offset), (BASE + timedelta(seconds=20)).astimezone(offset), source_ip='192.0.2.10', result=LoginResult.FAILURE) == records
    assert repo.list_between(source_ip="' OR 1=1 --") == []


def test_scrambled_insertion_ties_cross_source_and_both_rules(detection_db, persist_event, rules):
    ids = {}
    for second, user, source in [(40, 'alice', SourceType.SSH), (0, 'alice', SourceType.WEB),
                                 (20, 'charlie', SourceType.WEB), (10, 'bob', SourceType.SSH),
                                 (20, 'david', SourceType.SSH)]:
        ids[(second, user)] = persist_event(second, user, source=source)
    matches = detect(detection_db, rules).matches
    assert [match.rule_type.value for match in matches] == ['failure_burst', 'multi_account']
    expected = tuple(ids[key] for key in [(0, 'alice'), (10, 'bob'), (20, 'charlie'), (20, 'david'), (40, 'alice')])
    assert all(match.event_ids == expected and match.distinct_usernames == 4 for match in matches)
    assert all(match.window_start == BASE and match.window_end == BASE + timedelta(seconds=40) for match in matches)
    assert detect(detection_db, rules, start_time=BASE + timedelta(seconds=10)).matches[0].rule_type.value == 'multi_account'
    assert detect(detection_db, rules, end_time=BASE + timedelta(seconds=10)).matches == ()


def test_identical_timestamps_count_and_output_order(detection_db, rules, persist_event):
    for ip in ('2001:db8::10', '192.0.2.10'):
        for name in ('alice', 'bob', 'charlie', 'david', 'alice'):
            persist_event(0, name, ip=ip)
    matches = detect(detection_db, rules).matches
    assert [(m.source_ip, m.rule_type.value) for m in matches] == [
        ('192.0.2.10', 'failure_burst'), ('192.0.2.10', 'multi_account'),
        ('2001:db8::10', 'failure_burst'), ('2001:db8::10', 'multi_account')]
    assert all(m.event_count == 5 and len(set(m.event_ids)) == 5 and m.event_ids == tuple(sorted(m.event_ids)) for m in matches)
    assert detect(detection_db, rules).matches == matches


@pytest.mark.parametrize('start,end', [(datetime(2026, 10, 5), None), (None, datetime(2026, 10, 5)), (BASE + timedelta(seconds=1), BASE)])
def test_invalid_ranges(detection_db, rules, start, end):
    with pytest.raises(ValueError):
        detect(detection_db, rules, start, end)
    with pytest.raises(ValueError):
        LoginEventRepository(detection_db).list_between(start, end)


def test_empty_database(detection_db, rules):
    assert detect(detection_db, rules).matches == ()
