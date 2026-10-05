from typing import List, Sequence

from app.config.loader import FailureBurstConfig
from app.detectors.base import qualifying_clusters
from app.models.detection import DetectionMatch, RuleType, StoredLoginEvent


def detect_failure_burst(events: Sequence[StoredLoginEvent], config: FailureBurstConfig) -> List[DetectionMatch]:
    if not config.enabled:
        return []
    return qualifying_clusters(events, config.window_seconds, config.threshold, RuleType.FAILURE_BURST, False)
