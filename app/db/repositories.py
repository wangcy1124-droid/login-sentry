"""Parameterized repositories. Writes never commit; callers own transactions."""

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional, Union

from app.models.event import LoginEvent, LoginResult, SourceType


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("stored timestamp must include timezone")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def canonical_path(path: Union[str, Path]) -> str:
    return str(Path(path).resolve())


class CollectorStateError(ValueError):
    """Stored or supplied offset state is invalid."""


@dataclass(frozen=True)
class CollectorOffset:
    source_path: str
    inode: int
    offset_bytes: int
    updated_at_utc: datetime


def validate_position(inode: int, offset_bytes: int) -> None:
    if type(inode) is not int or inode <= 0:
        raise CollectorStateError("collector inode must be a positive integer")
    if type(offset_bytes) is not int or offset_bytes < 0:
        raise CollectorStateError("collector offset must be a non-negative integer")


class LoginEventRepository:
    def __init__(self, connection: sqlite3.Connection, clock: Callable[[], datetime] = utc_now):
        self.connection = connection
        self.clock = clock

    def insert(self, event: LoginEvent) -> int:
        cursor = self.connection.execute(
            "INSERT INTO login_events "
            "(timestamp_utc, source_type, source_ip, username, result, raw_log, created_at_utc) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (utc_text(event.timestamp), event.source_type.value, event.source_ip,
             event.username, event.result.value, event.raw_log, utc_text(self.clock())),
        )
        return cursor.lastrowid

    @staticmethod
    def _event(row: sqlite3.Row) -> LoginEvent:
        return LoginEvent(
            timestamp=datetime.fromisoformat(row["timestamp_utc"]).astimezone(timezone.utc),
            source_type=SourceType(row["source_type"]), source_ip=row["source_ip"],
            username=row["username"], result=LoginResult(row["result"]), raw_log=row["raw_log"],
        )

    def get_by_id(self, event_id: int) -> Optional[LoginEvent]:
        row = self.connection.execute("SELECT * FROM login_events WHERE id = ?", (event_id,)).fetchone()
        return None if row is None else self._event(row)

    def count(self) -> int:
        return self.connection.execute("SELECT COUNT(*) FROM login_events").fetchone()[0]

    def list_all(self) -> List[LoginEvent]:
        return [self._event(row) for row in self.connection.execute("SELECT * FROM login_events ORDER BY id")]


class CollectorOffsetRepository:
    def __init__(self, connection: sqlite3.Connection, clock: Callable[[], datetime] = utc_now):
        self.connection = connection
        self.clock = clock

    def get(self, source_path: Union[str, Path]) -> Optional[CollectorOffset]:
        row = self.connection.execute(
            "SELECT * FROM collector_offsets WHERE source_path = ?", (canonical_path(source_path),)
        ).fetchone()
        if row is None:
            return None
        validate_position(row["inode"], row["offset_bytes"])
        return CollectorOffset(row["source_path"], row["inode"], row["offset_bytes"],
                               datetime.fromisoformat(row["updated_at_utc"]))

    def upsert(self, source_path: Union[str, Path], inode: int, offset_bytes: int) -> None:
        validate_position(inode, offset_bytes)
        self.connection.execute(
            "INSERT INTO collector_offsets (source_path, inode, offset_bytes, updated_at_utc) "
            "VALUES (?, ?, ?, ?) ON CONFLICT(source_path) DO UPDATE SET "
            "inode = excluded.inode, offset_bytes = excluded.offset_bytes, "
            "updated_at_utc = excluded.updated_at_utc",
            (canonical_path(source_path), inode, offset_bytes, utc_text(self.clock())),
        )
