from dataclasses import replace
from datetime import timedelta

import pytest

from app.db.repositories import LoginEventRepository
from app.detectors.failure_burst import detect_failure_burst
from app.models.event import LoginResult


def test_ipv6_two_nonoverlapping_clusters(detection_db, persist_event, rules):
    ids = [persist_event(second, ip='2001:db8::10') for second in (0, 10, 20, 30, 40, 60, 61, 70, 80, 90, 100)]
    matches = detect_failure_burst(LoginEventRepository(detection_db).list_between(), rules.failure_burst)
    assert [match.event_ids for match in matches] == [tuple(ids[:6]), tuple(ids[6:])]
    assert [match.event_count for match in matches] == [6, 5]
    assert all(match.window_end - match.window_start <= timedelta(seconds=60) for match in matches)
    assert all(match.source_ip == '2001:db8::10' for match in matches)


def test_sliding_search_discards_old_failure(detection_db, persist_event, rules):
    persist_event(0)
    ids = [persist_event(second) for second in (100, 110, 120, 130, 140)]
    records = LoginEventRepository(detection_db).list_between()
    assert detect_failure_burst(records, rules.failure_burst)[0].event_ids == tuple(ids)
    with pytest.raises(ValueError, match='ordered'):
        detect_failure_burst(records[::-1], rules.failure_burst)


def test_pure_detector_ignores_success_and_disabled(detection_db, persist_event, rules):
    for index in range(5):
        persist_event(index, result=LoginResult.SUCCESS)
    records = LoginEventRepository(detection_db).list_between()
    assert detect_failure_burst(records, rules.failure_burst) == []
    assert detect_failure_burst(records, replace(rules.failure_burst, enabled=False)) == []
