"""Read persisted failure candidates and evaluate pure, deterministic rules."""

import sqlite3
from datetime import datetime
from typing import Dict, List, Optional

from app.config.loader import DetectionConfig
from app.db.repositories import LoginEventRepository, utc_text
from app.detectors.failure_burst import detect_failure_burst
from app.detectors.multi_account import detect_multi_account
from app.models.detection import DetectionReport, StoredLoginEvent
from app.models.event import LoginResult


def detect(
    connection: sqlite3.Connection, config: DetectionConfig,
    start_time: Optional[datetime] = None, end_time: Optional[datetime] = None,
) -> DetectionReport:
    start = utc_text(start_time) if start_time is not None else None
    end = utc_text(end_time) if end_time is not None else None
    if start is not None and end is not None and start > end:
        raise ValueError("start_time must not exceed end_time")
    if not config.failure_burst.enabled and not config.multi_account.enabled:
        return DetectionReport(())
    candidates = LoginEventRepository(connection).list_between(start_time, end_time, result=LoginResult.FAILURE)
    groups: Dict[str, List[StoredLoginEvent]] = {}
    for record in candidates:
        groups.setdefault(record.event.source_ip, []).append(record)
    matches = []
    for events in groups.values():
        matches.extend(detect_failure_burst(events, config.failure_burst))
        matches.extend(detect_multi_account(events, config.multi_account))
    return DetectionReport(tuple(sorted(matches, key=lambda match: (match.window_end, match.source_ip, match.rule_type.value))))
