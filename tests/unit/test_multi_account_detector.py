from dataclasses import replace

from app.db.repositories import LoginEventRepository
from app.detectors.multi_account import detect_multi_account


def test_repeated_names_do_not_inflate_count(detection_db, persist_event, rules):
    ids = [persist_event(index, name) for index, name in enumerate(['alice', 'alice', 'bob', 'bob', 'charlie'])]
    repo = LoginEventRepository(detection_db)
    assert detect_multi_account(repo.list_between(), rules.multi_account) == []
    ids.append(persist_event(5, 'david'))
    matches = detect_multi_account(repo.list_between(), rules.multi_account)
    assert len(matches) == 1
    assert matches[0].event_ids == tuple(ids)
    assert matches[0].event_count == 6
    assert matches[0].distinct_usernames == 4


def test_username_counter_eviction(detection_db, persist_event, rules):
    for second, name in [(0, 'old'), (1, 'old'), (299, 'alice'), (300, 'bob'), (302, 'charlie')]:
        persist_event(second, name)
    repo = LoginEventRepository(detection_db)
    assert detect_multi_account(repo.list_between(), rules.multi_account) == []
    persist_event(303, 'david')
    match = detect_multi_account(repo.list_between(), rules.multi_account)[0]
    assert match.distinct_usernames == 4
    assert match.event_count == 4
    assert detect_multi_account(repo.list_between(), replace(rules.multi_account, enabled=False)) == []
