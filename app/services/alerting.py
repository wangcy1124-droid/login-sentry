"""One-shot detection/alert orchestration and conservative human review."""

import sqlite3
from datetime import datetime
from typing import Callable, Optional

from app.alerts.manager import process_detection_report, require_transaction_control
from app.config.loader import DetectionConfig
from app.db.alert_repositories import AlertRepository
from app.db.repositories import utc_now
from app.models.alert import Alert, AlertProcessingStats, AlertStatus
from app.services.detection import detect


def process_alerts(connection: sqlite3.Connection, config: DetectionConfig,
                   clock: Callable[[], datetime] = utc_now) -> AlertProcessingStats:
    return process_detection_report(connection, detect(connection, config), config, clock)


def review_alert(connection: sqlite3.Connection, alert_id: int, status: AlertStatus,
                 note: Optional[str] = None, clock: Callable[[], datetime] = utc_now) -> Alert:
    require_transaction_control(connection)
    repository = AlertRepository(connection)
    with connection:
        repository.update_review(alert_id, status, note, clock())
    return repository.get_by_id(alert_id)
