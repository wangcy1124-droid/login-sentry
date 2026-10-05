from datetime import timedelta

import pytest

from app.models.detection import RuleType
from app.services.detection import detect


@pytest.mark.parametrize("extra,expected", [(0, 1), (0.000001, 0)])
@pytest.mark.parametrize("rule,seconds,users", [
    (RuleType.FAILURE_BURST, [0, 10, 20, 30, 60], ["alice"] * 5),
    (RuleType.MULTI_ACCOUNT, [0, 100, 200, 300], ["alice", "bob", "charlie", "david"]),
])
def test_inclusive_window_and_microsecond_outside(detection_db, rules, persist_event, extra, expected, rule, seconds, users):
    ids = [persist_event(value + (extra if index == len(seconds) - 1 else 0), user)
           for index, (value, user) in enumerate(zip(seconds, users))]
    matches = detect(detection_db, rules).matches
    assert len(matches) == expected
    if matches:
        assert matches[0].rule_type is rule
        assert matches[0].event_ids == tuple(ids)
        assert matches[0].window_end - matches[0].window_start == timedelta(seconds=seconds[-1])
