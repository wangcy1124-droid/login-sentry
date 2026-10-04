"""Synchronous binary ingestion; one writer per database/source workflow."""

import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Union

from app.db.repositories import CollectorOffsetRepository, LoginEventRepository
from app.models.event import LoginEvent
from app.parsers.base import ParseError


@dataclass
class CollectionStats:
    lines_read: int = 0
    events_inserted: int = 0
    ignored_lines: int = 0
    parse_errors: int = 0


def collect_file(
    path: Union[str, Path],
    parser: Callable[[str], Optional[LoginEvent]],
    connection: sqlite3.Connection,
) -> CollectionStats:
    """Commit each complete line's event and next byte offset together.

    A partial final line is retried later. Rotation follows only the current
    resolved path, not the renamed file. Other exceptions propagate unchanged.
    """
    if connection.in_transaction or connection.isolation_level is None:
        raise ValueError("collection requires an idle connection with transactions enabled")
    source = Path(path).resolve()
    source.stat()  # Fail clearly for a missing source; never create it.
    events = LoginEventRepository(connection)
    offsets = CollectorOffsetRepository(connection)
    stats = CollectionStats()
    with source.open("rb") as stream:
        observed = os.fstat(stream.fileno())  # Opened descriptor wins stat/open races.
        saved = offsets.get(source)
        start = 0
        if saved is not None and saved.inode == observed.st_ino and observed.st_size >= saved.offset_bytes:
            start = saved.offset_bytes
        stream.seek(start)
        while True:
            raw = stream.readline()
            if not raw or not raw.endswith(b"\n"):
                break
            event = None
            malformed = False
            try:
                event = parser(raw.decode("utf-8", errors="replace"))
            except ParseError:
                malformed = True
            with connection:
                if event is not None:
                    events.insert(event)
                offsets.upsert(source, observed.st_ino, stream.tell())
            stats.lines_read += 1
            stats.events_inserted += int(event is not None)
            stats.parse_errors += int(malformed)
            stats.ignored_lines += int(event is None and not malformed)
        # Record an empty/replaced/truncated file without consuming partial bytes.
        if stats.lines_read == 0 and (saved is None or saved.inode != observed.st_ino or saved.offset_bytes != start):
            with connection:
                offsets.upsert(source, observed.st_ino, start)
    return stats
