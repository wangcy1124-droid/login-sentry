"""Small SQLite connection helpers. Callers own connection lifetime."""

import sqlite3
from pathlib import Path
from typing import Union

from app.db.schema import SCHEMA


def connect_database(path: Union[str, Path]) -> sqlite3.Connection:
    connection = sqlite3.connect(str(path))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database(connection: sqlite3.Connection) -> None:
    # executescript commits a pending transaction; never commit caller work.
    if connection.in_transaction:
        raise ValueError("initialize_database requires no active transaction")
    connection.executescript(SCHEMA)
