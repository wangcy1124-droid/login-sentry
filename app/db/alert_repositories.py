"""Bound SQL only. Repository writes never commit; services own transactions."""

import sqlite3
from datetime import datetime
from typing import List, Optional

from app.db.repositories import LoginEventRepository, utc_text
from app.models.alert import Alert, AlertStatus, Severity, fingerprint, severity_for
from app.models.detection import DetectionMatch, RuleType, StoredLoginEvent


def validate_review(current: AlertStatus, target: AlertStatus, note: Optional[str]) -> None:
    allowed = {
        AlertStatus.OPEN: (AlertStatus.CONFIRMED, AlertStatus.FALSE_POSITIVE, AlertStatus.RESOLVED),
        AlertStatus.CONFIRMED: (AlertStatus.FALSE_POSITIVE, AlertStatus.RESOLVED),
    }
    if not isinstance(target, AlertStatus) or target not in allowed.get(current, ()):
        raise ValueError("invalid alert status transition")
    if note is not None and (not isinstance(note, str) or len(note) > 2000):
        raise ValueError("review_note must be text of at most 2000 characters or None")


class AlertRepository:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    @staticmethod
    def _alert(row: sqlite3.Row) -> Alert:
        return Alert(row['id'], RuleType(row['rule_type']), row['source_ip'], row['fingerprint'],
                     Severity(row['severity']), AlertStatus(row['status']),
                     datetime.fromisoformat(row['first_seen_utc']), datetime.fromisoformat(row['last_seen_utc']),
                     row['occurrence_count'], row['review_note'],
                     datetime.fromisoformat(row['created_at_utc']), datetime.fromisoformat(row['updated_at_utc']))

    def get_by_id(self, alert_id: int) -> Optional[Alert]:
        row = self.connection.execute('SELECT * FROM alerts WHERE id = ?', (alert_id,)).fetchone()
        return None if row is None else self._alert(row)

    def list_all(self) -> List[Alert]:
        return [self._alert(row) for row in self.connection.execute('SELECT * FROM alerts ORDER BY id')]

    def count(self) -> int:
        return self.connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]

    def get_latest_active_by_fingerprint(self, value: str) -> Optional[Alert]:
        row = self.connection.execute(
            "SELECT * FROM alerts WHERE fingerprint = ? AND status IN (?, ?) "
            "ORDER BY last_seen_utc DESC, id DESC LIMIT 1",
            (value, AlertStatus.OPEN.value, AlertStatus.CONFIRMED.value)).fetchone()
        return None if row is None else self._alert(row)

    def create(self, match: DetectionMatch, now: datetime) -> int:
        stamp = utc_text(now)
        return self.connection.execute(
            'INSERT INTO alerts (rule_type, source_ip, fingerprint, severity, status, first_seen_utc, '
            'last_seen_utc, occurrence_count, review_note, created_at_utc, updated_at_utc) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, 1, NULL, ?, ?)',
            (match.rule_type.value, match.source_ip, fingerprint(match.rule_type, match.source_ip),
             severity_for(match.rule_type).value, AlertStatus.OPEN.value,
             utc_text(match.window_start), utc_text(match.window_end), stamp, stamp)).lastrowid

    def update_aggregate(self, alert: Alert, match: DetectionMatch, now: datetime) -> None:
        self.connection.execute(
            'UPDATE alerts SET occurrence_count = occurrence_count + 1, first_seen_utc = ?, '
            'last_seen_utc = ?, updated_at_utc = ? WHERE id = ?',
            (utc_text(min(alert.first_seen, match.window_start)),
             utc_text(max(alert.last_seen, match.window_end)), utc_text(now), alert.id))

    def update_review(self, alert_id: int, status: AlertStatus, note: Optional[str], now: datetime) -> None:
        alert = self.get_by_id(alert_id)
        if alert is None:
            raise ValueError("alert does not exist")
        validate_review(alert.status, status, note)
        self.connection.execute(
            'UPDATE alerts SET status = ?, review_note = ?, updated_at_utc = ? WHERE id = ?',
            (status.value, note, utc_text(now), alert_id))

    def add_links(self, alert_id: int, match: DetectionMatch, now: datetime) -> int:
        stamp = utc_text(now)
        added = 0
        for event_id in match.event_ids:
            added += self.connection.execute(
                'INSERT OR IGNORE INTO alert_event_links (alert_id, event_id, linked_at_utc) VALUES (?, ?, ?)',
                (alert_id, event_id, stamp)).rowcount
        return added

    def list_events(self, alert_id: int) -> List[StoredLoginEvent]:
        rows = self.connection.execute(
            'SELECT e.* FROM login_events e JOIN alert_event_links l ON e.id = l.event_id '
            'WHERE l.alert_id = ? ORDER BY e.timestamp_utc, e.id', (alert_id,))
        return [StoredLoginEvent(row['id'], LoginEventRepository._event(row)) for row in rows]

    def list_event_ids(self, alert_id: int) -> List[int]:
        return [record.id for record in self.list_events(alert_id)]


class OccurrenceRepository:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def exists(self, key: str) -> bool:
        return self.connection.execute(
            'SELECT 1 FROM alert_occurrences WHERE occurrence_key = ?', (key,)).fetchone() is not None

    def insert(self, key: str, alert_id: int, match: DetectionMatch, now: datetime) -> None:
        self.connection.execute(
            'INSERT INTO alert_occurrences (occurrence_key, alert_id, rule_type, source_ip, '
            'window_start_utc, window_end_utc, created_at_utc) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (key, alert_id, match.rule_type.value, match.source_ip,
             utc_text(match.window_start), utc_text(match.window_end), utc_text(now)))
