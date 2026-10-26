"""Aggregations behind the dashboard (SQL for counts, Pandas for the timeline)."""

from __future__ import annotations

import pandas as pd

from ..db import SEVERITIES

# Candidate bucket sizes for the timeline; we pick the smallest that keeps
# the chart under ~120 points.
_BUCKETS = (("1min", 60), ("5min", 300), ("15min", 900), ("1h", 3600), ("6h", 21600), ("1D", 86400),
            ("7D", 604800))


def _scalar(conn, sql, params=()):
    return conn.execute(sql, params).fetchone()[0]


def _pick_bucket(span_seconds: float) -> tuple[str, int]:
    for freq, seconds in _BUCKETS:
        if span_seconds / seconds <= 120:
            return freq, seconds
    return _BUCKETS[-1]


def kpis(conn) -> dict:
    open_by_sev = dict(conn.execute(
        "SELECT severity, COUNT(*) FROM alerts WHERE status IN ('open', 'investigating') GROUP BY severity"
    ).fetchall())
    return {
        "total_events": _scalar(conn, "SELECT COUNT(*) FROM events"),
        "web_requests": _scalar(conn, "SELECT COUNT(*) FROM events WHERE event_type = 'web_request'"),
        "auth_failures": _scalar(conn, "SELECT COUNT(*) FROM events WHERE event_type = 'auth_failure'"),
        "auth_successes": _scalar(conn, "SELECT COUNT(*) FROM events WHERE event_type = 'auth_success'"),
        "unique_ips": _scalar(conn, "SELECT COUNT(DISTINCT source_ip) FROM events WHERE source_ip IS NOT NULL"),
        "total_alerts": _scalar(conn, "SELECT COUNT(*) FROM alerts"),
        "open_alerts": sum(open_by_sev.values()),
        "open_critical_high": open_by_sev.get("critical", 0) + open_by_sev.get("high", 0),
        "files_ingested": _scalar(conn, "SELECT COUNT(*) FROM ingest_runs"),
        "first_event": _scalar(conn, "SELECT MIN(timestamp) FROM events"),
        "last_event": _scalar(conn, "SELECT MAX(timestamp) FROM events"),
    }


def timeline(conn) -> dict:
    frame = pd.read_sql_query("SELECT timestamp, event_type FROM events", conn)
    if frame.empty:
        return {"labels": [], "series": {}, "bucket": None}
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], format="%Y-%m-%d %H:%M:%S", errors="coerce")
    frame = frame.dropna(subset=["timestamp"])
    span = (frame["timestamp"].max() - frame["timestamp"].min()).total_seconds()
    freq, _ = _pick_bucket(max(span, 60))
    frame["bucket"] = frame["timestamp"].dt.floor(freq)
    table = frame.pivot_table(index="bucket", columns="event_type", aggfunc="size", fill_value=0)
    full_index = pd.date_range(table.index.min(), table.index.max(), freq=freq)
    table = table.reindex(full_index, fill_value=0)

    alerts = pd.read_sql_query("SELECT first_seen FROM alerts", conn)
    alert_counts = pd.Series(0, index=full_index)
    if not alerts.empty:
        starts = pd.to_datetime(alerts["first_seen"], format="%Y-%m-%d %H:%M:%S", errors="coerce").dt.floor(freq)
        alert_counts = starts.value_counts().reindex(full_index, fill_value=0)

    def column(name):
        return [int(v) for v in table[name]] if name in table.columns else [0] * len(full_index)

    label_fmt = "%m-%d %H:%M" if freq not in ("1D", "7D") else "%Y-%m-%d"
    return {
        "bucket": freq,
        "labels": [ts.strftime(label_fmt) for ts in full_index],
        "series": {
            "Web requests": column("web_request"),
            "Failed logins": column("auth_failure"),
            "Successful logins": column("auth_success"),
            "New alerts": [int(v) for v in alert_counts],
        },
    }


def alerts_breakdown(conn) -> dict:
    by_severity = dict(conn.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity").fetchall())
    by_rule = conn.execute(
        "SELECT rule_name, COUNT(*) AS n FROM alerts GROUP BY rule_name ORDER BY n DESC"
    ).fetchall()
    by_status = dict(conn.execute("SELECT status, COUNT(*) FROM alerts GROUP BY status").fetchall())
    return {
        "by_severity": {sev: by_severity.get(sev, 0) for sev in reversed(SEVERITIES)},
        "by_rule": {row[0]: row[1] for row in by_rule},
        "by_status": by_status,
    }


def top_source_ips(conn, limit: int = 10) -> list[dict]:
    rows = conn.execute(
        """SELECT e.source_ip,
                  COUNT(*) AS events,
                  SUM(e.event_type = 'auth_failure') AS failed_logins,
                  SUM(e.http_status >= 400) AS http_errors,
                  (SELECT COUNT(*) FROM alerts a WHERE a.source_ip = e.source_ip) AS alerts,
                  (SELECT MAX(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                                            WHEN 'medium' THEN 2 ELSE 1 END)
                     FROM alerts a WHERE a.source_ip = e.source_ip) AS worst
           FROM events e
           WHERE e.source_ip IS NOT NULL
           GROUP BY e.source_ip
           ORDER BY alerts DESC, events DESC
           LIMIT ?""",
        (limit,),
    ).fetchall()
    names = {4: "critical", 3: "high", 2: "medium", 1: "low"}
    return [
        {
            "source_ip": r["source_ip"], "events": r["events"], "failed_logins": r["failed_logins"] or 0,
            "http_errors": r["http_errors"] or 0, "alerts": r["alerts"],
            "worst_severity": names.get(r["worst"]),
        }
        for r in rows
    ]


def http_status_breakdown(conn) -> dict:
    rows = conn.execute(
        "SELECT http_status, COUNT(*) FROM events WHERE http_status IS NOT NULL "
        "GROUP BY http_status ORDER BY http_status"
    ).fetchall()
    return {str(code): count for code, count in rows}


def event_type_breakdown(conn) -> dict:
    return dict(conn.execute(
        "SELECT event_type, COUNT(*) FROM events GROUP BY event_type ORDER BY COUNT(*) DESC"
    ).fetchall())


def recent_alerts(conn, limit: int = 8) -> list[dict]:
    rows = conn.execute(
        "SELECT id, severity, title, rule_name, source_ip, username, last_seen, status "
        "FROM alerts ORDER BY last_seen DESC, id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def dashboard_payload(conn) -> dict:
    return {
        "kpis": kpis(conn),
        "timeline": timeline(conn),
        "alerts": alerts_breakdown(conn),
        "top_ips": top_source_ips(conn),
        "http_status": http_status_breakdown(conn),
        "event_types": event_type_breakdown(conn),
        "recent_alerts": recent_alerts(conn),
    }
