from typing import List, Sequence

from app.config.loader import MultiAccountConfig
from app.detectors.base import qualifying_clusters
from app.models.detection import DetectionMatch, RuleType, StoredLoginEvent


def detect_multi_account(events: Sequence[StoredLoginEvent], config: MultiAccountConfig) -> List[DetectionMatch]:
    if not config.enabled:
        return []
    return qualifying_clusters(events, config.window_seconds, config.distinct_username_threshold, RuleType.MULTI_ACCOUNT, True)
