"""Stage 2 storage only; no detection or alert state."""

SCHEMA = """
CREATE TABLE IF NOT EXISTS login_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    username TEXT NOT NULL,
    result TEXT NOT NULL,
    raw_log TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_events_timestamp
    ON login_events(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_login_events_source_ip_timestamp
    ON login_events(source_ip, timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_login_events_result_timestamp
    ON login_events(result, timestamp_utc);
CREATE TABLE IF NOT EXISTS collector_offsets (
    source_path TEXT PRIMARY KEY,
    inode INTEGER NOT NULL,
    offset_bytes INTEGER NOT NULL,
    updated_at_utc TEXT NOT NULL
);
"""
