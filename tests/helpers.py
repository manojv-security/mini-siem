"""Helpers for building test events (imported by the test modules)."""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from siem.detection import prepare_events  # noqa: E402

BASE = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)
REFERENCE_TIME = datetime(2026, 10, 26, tzinfo=timezone.utc)


def at(seconds: float) -> str:
    """Timestamp string `seconds` after BASE (UTC)."""
    return (BASE + timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S")


def event(seconds, event_type="web_request", **fields):
    record = {"timestamp": at(seconds), "event_type": event_type}
    record.update(fields)
    return record


def events_frame(records):
    """Give records ids and build the DataFrame the rules expect."""
    rows = [dict(r, id=i + 1) for i, r in enumerate(records)]
    return prepare_events(rows)
