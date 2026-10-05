from app.models.event import LoginResult
from app.services.detection import detect


def test_shared_ip_successes_and_mixed_activity(detection_db, rules, persist_event):
    for index, user in enumerate(("alice", "bob", "charlie", "david")):
        persist_event(index, user, result=LoginResult.SUCCESS)
    assert detect(detection_db, rules).matches == ()
    persist_event(5, "alice")
    persist_event(6, "bob", result=LoginResult.SUCCESS)
    assert detect(detection_db, rules).matches == ()
