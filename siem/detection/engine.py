"""Detection engine: load events -> run every enabled rule -> store alerts.

Alert de-duplication happens at two levels:

1. Inside a rule, overlapping time windows are merged into one burst, so a
   10-minute brute-force attack is one alert, not hundreds.
2. When alerts are stored, an existing alert for the same rule and the same
   entity (IP / username) whose time range overlaps the new one is *updated*
   instead of a new row being inserted. Re-running detection, or uploading
   more logs that extend an ongoing attack, therefore never duplicates alerts.
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field

import pandas as pd

from .. import db
from .base import epoch_seconds
from .rules import ALL_RULES

EVENT_FIELDS = ("id", "timestamp", "source_ip", "username", "event_type", "status", "http_method",
                "http_status", "request_path", "user_agent", "source_type")


@dataclass
class DetectionSummary:
    events_analyzed: int = 0
    new_alerts: int = 0
    updated_alerts: int = 0
    unchanged_alerts: int = 0
    per_rule: dict = field(default_factory=dict)
    errors: dict = field(default_factory=dict)
    duration_ms: int = 0

    def as_dict(self) -> dict:
        return self.__dict__.copy()


def prepare_events(records) -> pd.DataFrame:
    """Turn event rows (list of dicts or a DataFrame) into the frame rules expect.

    * guarantees every column exists (missing fields become NaN/None),
    * parses timestamps and adds ``_t`` (epoch seconds),
    * drops rows without a usable timestamp,
    * sorts by time, then id - rules never depend on the order logs arrived in.
    """
    df = records.copy() if isinstance(records, pd.DataFrame) else pd.DataFrame(list(records))
    for column in EVENT_FIELDS:
        if column not in df.columns:
            df[column] = None
    if df.empty:
        df["_t"] = pd.Series(dtype="int64")
        return df
    if df["id"].isna().any():
        df["id"] = range(1, len(df) + 1)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", format="mixed")
    df = df[df["timestamp"].notna()].copy()
    df["_t"] = epoch_seconds(df["timestamp"])
    df["http_status"] = pd.to_numeric(df["http_status"], errors="coerce")
    for column in ("source_ip", "username", "event_type", "request_path", "user_agent", "source_type"):
        df[column] = df[column].astype(object).where(df[column].notna(), None)
    return df.sort_values(["_t", "id"], kind="mergesort").reset_index(drop=True)


def load_events(conn) -> pd.DataFrame:
    frame = pd.read_sql_query(f"SELECT {', '.join(EVENT_FIELDS)} FROM events", conn)
    return prepare_events(frame)


def apply_allowlist(df: pd.DataFrame, allowlist) -> pd.DataFrame:
    """Remove events whose source IP is inside any allow-listed IP/CIDR."""
    networks = []
    for entry in allowlist or []:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            continue
    if not networks or df.empty:
        return df
    cache = {}

    def allowed(ip):
        if ip is None:
            return False
        if ip not in cache:
            try:
                address = ipaddress.ip_address(ip)
                cache[ip] = any(address.version == n.version and address in n for n in networks)
            except ValueError:
                cache[ip] = False
        return cache[ip]

    return df[~df["source_ip"].map(allowed)]


def run_rules(df: pd.DataFrame, config: dict):
    """Run enabled rules on a prepared frame. Returns (alerts, per_rule, errors)."""
    df = apply_allowlist(df, config.get("global", {}).get("allowlist_ips"))
    alerts, per_rule, errors = [], {}, {}
    for rule in ALL_RULES:
        cfg = config["rules"].get(rule.id, rule.defaults())
        if not cfg.get("enabled", True):
            per_rule[rule.id] = None
            continue
        try:
            found = rule.detect(df, cfg) if not df.empty else []
        except Exception as exc:  # one broken rule must not stop the others
            errors[rule.id] = f"{type(exc).__name__}: {exc}"
            found = []
        per_rule[rule.id] = len(found)
        alerts.extend((rule, alert) for alert in found)
    return alerts, per_rule, errors


def persist_alerts(conn, rule_alerts, config: dict, summary: DetectionSummary) -> None:
    for rule, alert in rule_alerts:
        record = alert.to_record()
        existing = db.find_overlapping_alert(
            conn, record["rule_id"], record["source_ip"], record["username"],
            record["first_seen"], record["last_seen"],
            rule.merge_gap_seconds(config["rules"].get(rule.id, rule.defaults())),
        )
        if existing is None:
            db.insert_alert(conn, record)
            summary.new_alerts += 1
        elif db.update_alert_from_detection(conn, existing, record):
            summary.updated_alerts += 1
        else:
            summary.unchanged_alerts += 1
    conn.commit()


def run_detection(conn, config: dict) -> DetectionSummary:
    """Full detection pass over every stored event."""
    started = time.perf_counter()
    summary = DetectionSummary()
    df = load_events(conn)
    summary.events_analyzed = len(df)
    rule_alerts, summary.per_rule, summary.errors = run_rules(df, config)
    persist_alerts(conn, rule_alerts, config, summary)
    summary.duration_ms = int((time.perf_counter() - started) * 1000)
    return summary
