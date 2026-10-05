from app.models.event import LoginResult
from app.services.detection import detect


def test_normal_typo_then_success(detection_db, rules, persist_event):
    persist_event(0)
    persist_event(10)
    persist_event(20, result=LoginResult.SUCCESS)
    assert detect(detection_db, rules).matches == ()
