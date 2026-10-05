"""Persist each new detection occurrence atomically; single-writer workflow."""

import sqlite3
from datetime import datetime, timedelta
from typing import Callable

from app.config.loader import DetectionConfig
from app.db.alert_repositories import AlertRepository, OccurrenceRepository
from app.db.repositories import utc_now
from app.models.alert import AlertProcessingStats, fingerprint, occurrence_key
from app.models.detection import DetectionReport, RuleType


def require_transaction_control(connection: sqlite3.Connection) -> None:
    if connection.in_transaction or connection.isolation_level is None:
        raise ValueError("alert service requires an idle connection with transactions enabled")


def process_detection_report(
    connection: sqlite3.Connection, report: DetectionReport, config: DetectionConfig,
    clock: Callable[[], datetime] = utc_now,
) -> AlertProcessingStats:
    require_transaction_control(connection)
    alerts, occurrences = AlertRepository(connection), OccurrenceRepository(connection)
    created = aggregated = duplicates = links = 0
    for match in report.matches:
        key = occurrence_key(match)
        # One transaction per occurrence, not per report. Earlier successful occurrences survive errors.
        with connection:
            if occurrences.exists(key):
                duplicates += 1
                continue
            now = clock()
            active = alerts.get_latest_active_by_fingerprint(fingerprint(match.rule_type, match.source_ip))
            rule = config.failure_burst if match.rule_type == RuleType.FAILURE_BURST else config.multi_account
            merge = active is not None and match.window_end <= active.last_seen + timedelta(seconds=rule.cooldown_seconds)
            if merge:
                alert_id = active.id
                alerts.update_aggregate(active, match, now)
            else:
                alert_id = alerts.create(match, now)
            occurrences.insert(key, alert_id, match, now)
            added = alerts.add_links(alert_id, match, now)
        links += added
        if merge:
            aggregated += 1
        else:
            created += 1
    return AlertProcessingStats(len(report.matches), created, aggregated, duplicates, links)
