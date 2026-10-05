"""Detection results only, with database identity separate from LoginEvent."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Tuple

from app.models.event import LoginEvent


class RuleType(str, Enum):
    FAILURE_BURST = "failure_burst"
    MULTI_ACCOUNT = "multi_account"


@dataclass(frozen=True)
class StoredLoginEvent:
    id: int
    event: LoginEvent


@dataclass(frozen=True)
class DetectionMatch:
    rule_type: RuleType
    source_ip: str
    window_start: datetime
    window_end: datetime
    event_ids: Tuple[int, ...]
    event_count: int
    distinct_usernames: int


@dataclass(frozen=True)
class DetectionReport:
    matches: Tuple[DetectionMatch, ...]
