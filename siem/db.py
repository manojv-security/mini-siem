"""SQLite storage layer.

Plain ``sqlite3`` keeps the project dependency-free and easy to inspect with
any SQLite browser. Three tables:

* events       - normalized log events (one row per accepted log record)
* alerts       - detections, one row per incident, with triage status/notes
* ingest_runs  - one row per uploaded file with processed/rejected/duplicate counts
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS ingest_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    filename        TEXT NOT NULL,
    source_type     TEXT,
    uploaded_at     TEXT NOT NULL,
    total_records   INTEGER NOT NULL DEFAULT 0,
    processed       INTEGER NOT NULL DEFAULT 0,
    rejected        INTEGER NOT NULL DEFAULT 0,
    duplicates      INTEGER NOT NULL DEFAULT 0,
    rejection_summary TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT NOT NULL,           -- UTC, 'YYYY-MM-DD HH:MM:SS'
    source_ip     TEXT,
    username      TEXT,
    event_type    TEXT NOT NULL,
    status        TEXT,
    http_method   TEXT,
    http_status   INTEGER,
    request_path  TEXT,
    user_agent    TEXT,
    bytes_sent    INTEGER,
    host          TEXT,
    process       TEXT,
    source_type   TEXT,
    raw_log       TEXT,
    event_hash    TEXT NOT NULL UNIQUE,    -- de-duplication key
    ingest_id     INTEGER REFERENCES ingest_runs(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(username);

CREATE TABLE IF NOT EXISTS alerts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_key     TEXT NOT NULL UNIQUE,
    rule_id          TEXT NOT NULL,
    rule_name        TEXT NOT NULL,
    severity         TEXT NOT NULL,
    title            TEXT NOT NULL,
    description      TEXT,
    source_ip        TEXT,
    username         TEXT,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    event_count      INTEGER NOT NULL DEFAULT 0,
    details          TEXT,                 -- JSON: rule-specific context
    event_ids        TEXT,                 -- JSON list of evidence event ids
    mitre_tactic     TEXT,
    mitre_technique  TEXT,
    recommendation   TEXT,
    status           TEXT NOT NULL DEFAULT 'open',
    analyst_notes    TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(source_ip);
"""

ALERT_STATUSES = ("open", "investigating", "resolved", "false_positive")
SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

EVENT_COLUMNS = (
    "timestamp", "source_ip", "username", "event_type", "status", "http_method",
    "http_status", "request_path", "user_agent", "bytes_sent", "host", "process",
    "source_type", "raw_log", "event_hash", "ingest_id",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Open a connection with sensible defaults and make sure the schema exists."""
    db_path = str(db_path)
    if db_path != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, detect_types=0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    return conn


# --------------------------------------------------------------------------
# Ingest runs and events
# --------------------------------------------------------------------------
def create_ingest_run(conn, filename: str, source_type: str | None) -> int:
    cur = conn.execute(
        "INSERT INTO ingest_runs (filename, source_type, uploaded_at) VALUES (?, ?, ?)",
        (filename, source_type, utc_now()),
    )
    return cur.lastrowid


def finish_ingest_run(conn, run_id: int, source_type: str, total: int, processed: int,
                      rejected: int, duplicates: int, rejection_summary: dict) -> None:
    conn.execute(
        """UPDATE ingest_runs SET source_type=?, total_records=?, processed=?, rejected=?,
           duplicates=?, rejection_summary=? WHERE id=?""",
        (source_type, total, processed, rejected, duplicates, json.dumps(rejection_summary), run_id),
    )


def insert_events(conn, events: list[dict]) -> tuple[int, int]:
    """Insert events, skipping any whose event_hash already exists.

    Returns (inserted, duplicates).
    """
    if not events:
        return 0, 0
    placeholders = ", ".join("?" for _ in EVENT_COLUMNS)
    sql = f"INSERT OR IGNORE INTO events ({', '.join(EVENT_COLUMNS)}) VALUES ({placeholders})"
    before = conn.total_changes
    conn.executemany(sql, [tuple(event.get(col) for col in EVENT_COLUMNS) for event in events])
    inserted = conn.total_changes - before
    return inserted, len(events) - inserted


def get_ingest_runs(conn, limit: int = 20) -> list[dict]:
    rows = conn.execute("SELECT * FROM ingest_runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    runs = []
    for row in rows:
        run = dict(row)
        run["rejection_summary"] = json.loads(run["rejection_summary"] or "{}")
        runs.append(run)
    return runs


def query_events(conn, filters: dict | None = None, limit: int = 50, offset: int = 0):
    """Filtered, paginated event search for the Events page. Returns (rows, total)."""
    filters = filters or {}
    clauses, params = [], []
    if filters.get("source_ip"):
        clauses.append("source_ip = ?")
        params.append(filters["source_ip"])
    if filters.get("username"):
        clauses.append("username = ?")
        params.append(filters["username"])
    if filters.get("event_type"):
        clauses.append("event_type = ?")
        params.append(filters["event_type"])
    if filters.get("status"):
        clauses.append("status = ?")
        params.append(filters["status"])
    if filters.get("source_type"):
        clauses.append("source_type = ?")
        params.append(filters["source_type"])
    if filters.get("start"):
        clauses.append("timestamp >= ?")
        params.append(filters["start"])
    if filters.get("end"):
        clauses.append("timestamp <= ?")
        params.append(filters["end"])
    if filters.get("q"):
        clauses.append("raw_log LIKE ? ESCAPE '\\'")
        escaped = filters["q"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        params.append(f"%{escaped}%")
    if filters.get("ids"):
        ids = [int(i) for i in filters["ids"]][:500]
        clauses.append(f"id IN ({', '.join('?' for _ in ids)})")
        params.extend(ids)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    total = conn.execute(f"SELECT COUNT(*) FROM events {where}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT * FROM events {where} ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?",
        [*params, limit, offset],
    ).fetchall()
    return [dict(r) for r in rows], total


# --------------------------------------------------------------------------
# Alerts
# --------------------------------------------------------------------------
def _decode_alert(row) -> dict:
    alert = dict(row)
    alert["details"] = json.loads(alert.get("details") or "{}")
    alert["event_ids"] = json.loads(alert.get("event_ids") or "[]")
    return alert


def get_alert(conn, alert_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return _decode_alert(row) if row else None


def query_alerts(conn, filters: dict | None = None, limit: int = 500) -> list[dict]:
    filters = filters or {}
    clauses, params = [], []
    for field in ("severity", "status", "rule_id", "source_ip"):
        if filters.get(field):
            clauses.append(f"{field} = ?")
            params.append(filters[field])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    order = ("CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
             "WHEN 'medium' THEN 2 ELSE 3 END, last_seen DESC")
    rows = conn.execute(
        f"SELECT * FROM alerts {where} ORDER BY {order} LIMIT ?", [*params, limit]
    ).fetchall()
    return [_decode_alert(r) for r in rows]


def find_overlapping_alert(conn, rule_id: str, source_ip, username, first_seen: str,
                           last_seen: str, merge_gap_seconds: int) -> dict | None:
    """Find an existing alert for the same rule + entity whose time range
    overlaps (or nearly touches) the new incident. Used to avoid duplicates
    when detection is re-run after more logs arrive."""
    row = conn.execute(
        """SELECT * FROM alerts
           WHERE rule_id = ?
             AND source_ip IS ? AND username IS ?
             AND datetime(first_seen) <= datetime(?, '+' || ? || ' seconds')
             AND datetime(last_seen)  >= datetime(?, '-' || ? || ' seconds')
           ORDER BY first_seen LIMIT 1""",
        (rule_id, source_ip, username, last_seen, merge_gap_seconds, first_seen, merge_gap_seconds),
    ).fetchone()
    return _decode_alert(row) if row else None


def insert_alert(conn, alert: dict) -> int:
    now = utc_now()
    cur = conn.execute(
        """INSERT INTO alerts (incident_key, rule_id, rule_name, severity, title, description,
               source_ip, username, first_seen, last_seen, event_count, details, event_ids,
               mitre_tactic, mitre_technique, recommendation, status, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)""",
        (
            alert["incident_key"], alert["rule_id"], alert["rule_name"], alert["severity"],
            alert["title"], alert["description"], alert["source_ip"], alert["username"],
            alert["first_seen"], alert["last_seen"], alert["event_count"],
            json.dumps(alert["details"], default=str), json.dumps(alert["event_ids"]),
            alert["mitre_tactic"], alert["mitre_technique"], alert["recommendation"], now, now,
        ),
    )
    return cur.lastrowid


def update_alert_from_detection(conn, existing: dict, alert: dict) -> bool:
    """Refresh an existing alert with the latest detection result.

    The incident window only ever grows. Analyst status and notes are kept,
    except that a resolved / false-positive alert is re-opened when *new*
    activity extends it. Returns True if anything changed.
    """
    first_seen = min(existing["first_seen"], alert["first_seen"])
    last_seen = max(existing["last_seen"], alert["last_seen"])
    event_count = max(existing["event_count"], alert["event_count"])
    severity = max(existing["severity"], alert["severity"], key=lambda s: SEVERITY_RANK.get(s, 0))
    status, notes = existing["status"], existing["analyst_notes"]
    if last_seen > existing["last_seen"] and status in ("resolved", "false_positive"):
        status = "open"
        notes = ((notes or "") + f"\n[{utc_now()}] Re-opened automatically: new activity after "
                 f"{existing['last_seen']}.").strip()

    changed = (
        first_seen != existing["first_seen"] or last_seen != existing["last_seen"]
        or event_count != existing["event_count"] or severity != existing["severity"]
        or alert["details"] != existing["details"] or status != existing["status"]
    )
    if not changed:
        return False
    event_ids = list(dict.fromkeys([*existing["event_ids"], *alert["event_ids"]]))[:100]
    conn.execute(
        """UPDATE alerts SET severity=?, title=?, description=?, first_seen=?, last_seen=?,
               event_count=?, details=?, event_ids=?, status=?, analyst_notes=?, updated_at=?
           WHERE id=?""",
        (
            severity, alert["title"], alert["description"], first_seen, last_seen, event_count,
            json.dumps(alert["details"], default=str), json.dumps(event_ids),
            status, notes, utc_now(), existing["id"],
        ),
    )
    return True


def update_alert_triage(conn, alert_id: int, status: str, notes: str | None) -> None:
    if status not in ALERT_STATUSES:
        raise ValueError(f"invalid status: {status}")
    conn.execute(
        "UPDATE alerts SET status=?, analyst_notes=?, updated_at=? WHERE id=?",
        (status, notes, utc_now(), alert_id),
    )


def reset_database(conn) -> None:
    """Delete all events, alerts and ingest history (keeps the schema)."""
    conn.executescript("DELETE FROM alerts; DELETE FROM events; DELETE FROM ingest_runs;")
    conn.commit()
