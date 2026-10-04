"""Shared, immutable login event; parsers validate source-specific fields."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class SourceType(str, Enum):
    SSH = "ssh"
    WEB = "web"


class LoginResult(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"


@dataclass(frozen=True)
class LoginEvent:
    timestamp: datetime
    source_type: SourceType
    source_ip: str
    username: str
    result: LoginResult
    raw_log: str

    def __post_init__(self) -> None:
        if not isinstance(self.timestamp, datetime):
            raise TypeError("timestamp must be a datetime")
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("timestamp must include timezone")
        if not isinstance(self.source_type, SourceType):
            raise TypeError("source_type must be a SourceType")
        if not isinstance(self.result, LoginResult):
            raise TypeError("result must be a LoginResult")
