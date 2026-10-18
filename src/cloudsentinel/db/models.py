import os
import sqlite3
from pathlib import Path

ALLOWED_SEVERITIES = {"Critical", "High", "Medium", "Low", "Unknown"}
ALLOWED_FINDING_STATUSES = {"Open", "Acknowledged", "Resolved", "Suppressed"}
ALLOWED_SCAN_STATUSES = {"completed", "partial", "failed"}

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    provenance_label TEXT NOT NULL,
    region TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    status TEXT NOT NULL,
    resources_scanned INTEGER NOT NULL DEFAULT 0,
    errors_count INTEGER NOT NULL DEFAULT 0,
    diagnostics_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    region TEXT NOT NULL,
    severity TEXT NOT NULL,
    risk_score INTEGER,
    title TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    score_breakdown_json TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Open',
    fingerprint TEXT NOT NULL UNIQUE,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    analyst_note TEXT DEFAULT '',
    suppressed_by TEXT DEFAULT '',
    suppressed_reason TEXT DEFAULT '',
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_event_id TEXT NOT NULL UNIQUE,
    event_time TEXT NOT NULL,
    event_name TEXT NOT NULL,
    actor TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    region TEXT NOT NULL,
    status TEXT NOT NULL,
    raw_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    actor_label TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    details_json TEXT NOT NULL
);
"""


def init_db(db_path: str | Path) -> None:
    """Create SQLite database parent directory, initialize MVP tables, and set 0600 permissions."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.executescript(SCHEMA_SQL)
    if path.exists() and os.name == "posix":
        os.chmod(path, 0o600)
