from app.models.detection import RuleType
from app.services.detection import detect


def test_threshold_and_contiguous_extension(detection_db, rules, persist_event):
    ids = [persist_event(seconds) for seconds in (0, 10, 20, 30)]
    assert detect(detection_db, rules).matches == ()
    ids.append(persist_event(40))
    matches = detect(detection_db, rules).matches
    assert len(matches) == 1
    assert matches[0].rule_type is RuleType.FAILURE_BURST
    ids.append(persist_event(50))
    matches = detect(detection_db, rules).matches
    assert len(matches) == 1
    assert matches[0].event_ids == tuple(ids)
    assert matches[0].event_count == 6
    assert matches[0].distinct_usernames == 1
