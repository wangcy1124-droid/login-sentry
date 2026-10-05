"""Persisted detection fixtures; all event times are explicit."""

from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.config.loader import load_config
from app.db.database import connect_database, initialize_database
from app.db.repositories import LoginEventRepository
from app.models.event import LoginEvent, LoginResult, SourceType


@pytest.fixture
def detection_db():
    with closing(connect_database(":memory:")) as connection:
        initialize_database(connection)
        yield connection


@pytest.fixture
def rules():
    return load_config(Path(__file__).resolve().parents[1] / "config/default.toml")


@pytest.fixture
def persist_event(detection_db):
    def insert(seconds=0, username="alice", ip="192.0.2.10", result=LoginResult.FAILURE, source=SourceType.WEB):
        event = LoginEvent(datetime(2026, 10, 5, tzinfo=timezone.utc) + timedelta(seconds=seconds),
                           source, ip, username, result, "synthetic event")
        with detection_db:
            return LoginEventRepository(detection_db).insert(event)
    return insert
