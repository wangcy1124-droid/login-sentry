"""Event, collector and persistent alert storage; initialization is additive."""

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
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_type TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    first_seen_utc TEXT NOT NULL,
    last_seen_utc TEXT NOT NULL,
    occurrence_count INTEGER NOT NULL CHECK (occurrence_count > 0),
    review_note TEXT,
    created_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint_status_last_seen
    ON alerts(fingerprint, status, last_seen_utc);
CREATE TABLE IF NOT EXISTS alert_event_links (
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    event_id INTEGER NOT NULL REFERENCES login_events(id) ON DELETE CASCADE,
    linked_at_utc TEXT NOT NULL,
    PRIMARY KEY (alert_id, event_id)
);
CREATE TABLE IF NOT EXISTS alert_occurrences (
    occurrence_key TEXT PRIMARY KEY,
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    rule_type TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    window_start_utc TEXT NOT NULL,
    window_end_utc TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
"""
