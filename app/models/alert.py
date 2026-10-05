"""Immutable alert read models and stable occurrence identity."""

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional

from app.db.repositories import utc_text
from app.models.detection import DetectionMatch, RuleType


class AlertStatus(str, Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"


class Severity(str, Enum):
    MEDIUM = "medium"
    HIGH = "high"


def severity_for(rule_type: RuleType) -> Severity:
    return {RuleType.FAILURE_BURST: Severity.MEDIUM,
            RuleType.MULTI_ACCOUNT: Severity.HIGH}[rule_type]


def fingerprint(rule_type: RuleType, source_ip: str) -> str:
    return rule_type.value + "|" + source_ip


def occurrence_key(match: DetectionMatch) -> str:
    if not isinstance(match.rule_type, RuleType):
        raise ValueError("rule_type must be a RuleType")
    start, end = utc_text(match.window_start), utc_text(match.window_end)
    if start > end:
        raise ValueError("match window_start must not exceed window_end")
    if (not match.event_ids or any(type(i) is not int or i <= 0 for i in match.event_ids)
            or len(set(match.event_ids)) != len(match.event_ids)
            or match.event_count != len(match.event_ids)):
        raise ValueError("match must contain unique positive event IDs matching event_count")
    payload = [match.rule_type.value, match.source_ip, start, end, sorted(match.event_ids)]
    return hashlib.sha256(json.dumps(payload, separators=(",", ":")).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Alert:
    id: int
    rule_type: RuleType
    source_ip: str
    fingerprint: str
    severity: Severity
    status: AlertStatus
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int
    review_note: Optional[str]
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.status, AlertStatus) or not isinstance(self.rule_type, RuleType):
            raise ValueError("alert status and rule_type must be enums")
        if not isinstance(self.severity, Severity):
            raise ValueError("alert severity must be a Severity")
        for value in (self.first_seen, self.last_seen, self.created_at, self.updated_at):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("alert timestamps must include timezone")
        if self.first_seen > self.last_seen:
            raise ValueError("alert first_seen must not exceed last_seen")
        if type(self.occurrence_count) is not int or self.occurrence_count <= 0:
            raise ValueError("occurrence_count must be a positive integer")


@dataclass(frozen=True)
class AlertProcessingStats:
    matches_seen: int = 0
    alerts_created: int = 0
    alerts_aggregated: int = 0
    duplicate_occurrences: int = 0
    links_added: int = 0
