"""Linear sliding search followed by bounded, non-overlapping cluster extension."""

from datetime import timezone
from typing import Dict, List, Sequence

from app.models.detection import DetectionMatch, RuleType, StoredLoginEvent
from app.models.event import LoginResult


def qualifying_clusters(
    records: Sequence[StoredLoginEvent], window_seconds: int, threshold: int,
    rule_type: RuleType, distinct: bool,
) -> List[DetectionMatch]:
    """Input is one IP ordered by (timestamp, id); successes are ignored.

    On reaching threshold, freeze the left edge and extend until the next
    failure would exceed the duration. Emit once and resume at that next event.
    This deliberately does not enumerate overlapping qualifying windows.
    """
    events = [record for record in records if record.event.result is LoginResult.FAILURE]
    if not events:
        return []
    ip = events[0].event.source_ip
    previous = None
    ids = set()
    for record in events:
        key = (record.event.timestamp, record.id)
        if record.event.source_ip != ip or (previous is not None and key < previous):
            raise ValueError("detector requires one source IP ordered by timestamp/id")
        if record.id in ids:
            raise ValueError("detector requires unique persisted event IDs")
        ids.add(record.id)
        previous = key
    matches = []
    usernames: Dict[str, int] = {}
    left = 0
    active = False

    def emit(end: int) -> None:
        included = events[left:end]
        matches.append(DetectionMatch(
            rule_type, ip,
            included[0].event.timestamp.astimezone(timezone.utc),
            included[-1].event.timestamp.astimezone(timezone.utc),
            tuple(record.id for record in included), len(included), len(usernames),
        ))

    for right, record in enumerate(events):
        if active and (record.event.timestamp - events[left].event.timestamp).total_seconds() > window_seconds:
            emit(right)
            left = right
            usernames.clear()
            active = False
        username = record.event.username
        usernames[username] = usernames.get(username, 0) + 1
        if not active:
            while (record.event.timestamp - events[left].event.timestamp).total_seconds() > window_seconds:
                old = events[left].event.username
                usernames[old] -= 1
                if usernames[old] == 0:
                    del usernames[old]
                left += 1
            active = (len(usernames) if distinct else right - left + 1) >= threshold
    if active:
        emit(len(events))
    return matches
