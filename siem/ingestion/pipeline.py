"""Ingestion pipeline: file -> parse -> normalize -> de-duplicate -> SQLite.

De-duplication
--------------
Each stored event gets ``event_hash = sha256(source_type | raw record | n)``
where *n* is how many times that exact record has already appeared in the
same file. This means:

* uploading the same file twice stores nothing the second time
  (every record is counted as a duplicate), and
* identical lines *inside one file* are all kept, because a request flood
  legitimately produces identical lines in the same second.
"""

from __future__ import annotations

import hashlib
import io
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import pandas as pd

from .. import db
from . import parsers
from .parsers import ParseError

ALLOWED_EXTENSIONS = (".log", ".txt", ".csv")
_ROTATED_LOG = re.compile(r"\.log\.\d+$", re.IGNORECASE)  # auth.log.1
SUPPORTED_FORMATS = ("auto", "web_access", "auth_log", "csv")
MAX_SAMPLES = 8
BATCH_SIZE = 5000


class IngestError(ValueError):
    """The whole file was refused (wrong type, binary, empty, unusable CSV)."""


@dataclass
class IngestResult:
    filename: str
    source_type: str
    total: int = 0
    processed: int = 0
    rejected: int = 0
    duplicates: int = 0
    missing_ip: int = 0
    reasons: Counter = field(default_factory=Counter)
    samples: list = field(default_factory=list)
    run_id: int | None = None

    def as_dict(self) -> dict:
        return {
            "filename": self.filename,
            "source_type": self.source_type,
            "total": self.total,
            "processed": self.processed,
            "rejected": self.rejected,
            "duplicates": self.duplicates,
            "missing_ip": self.missing_ip,
            "reasons": dict(self.reasons),
            "samples": self.samples,
            "run_id": self.run_id,
        }

    def reject(self, line_no: int, raw: str, reason: str) -> None:
        self.rejected += 1
        self.reasons[reason] += 1
        if len(self.samples) < MAX_SAMPLES:
            self.samples.append({"line": line_no, "reason": reason, "raw": raw[:200]})


def allowed_file(filename: str) -> bool:
    name = filename.lower()
    return name.endswith(ALLOWED_EXTENSIONS) or bool(_ROTATED_LOG.search(name))


def decode_content(content: bytes) -> str:
    """Decode uploaded bytes. Refuses binary files; never fails on odd encodings."""
    if not content or not content.strip():
        raise IngestError("the file is empty")
    # Windows tools (PowerShell 5 'Out-File', Event Viewer) often write UTF-16.
    if content.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return content.decode("utf-16")
        except UnicodeDecodeError as exc:
            raise IngestError("the file claims to be UTF-16 but could not be decoded") from exc
    if b"\x00" in content[:8192]:
        raise IngestError("the file looks binary, not a text log")
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError:
        return content.decode("latin-1")  # every byte sequence is valid latin-1


def _event_hash(source_type: str, raw: str, occurrence: int) -> str:
    return hashlib.sha256(f"{source_type}\x1f{raw}\x1f{occurrence}".encode("utf-8", "replace")).hexdigest()


def _iter_text_records(text: str, fmt: str, default_tz: str, reference_time):
    """Yield (line_no, raw, event | None, reason | None) for a text log."""
    for line_no, line in enumerate(text.splitlines(), start=1):
        raw = line.rstrip("\r\n")
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        try:
            event = parsers.parse_text_line(raw, fmt, default_tz=default_tz,
                                            reference_time=reference_time)
            yield line_no, raw, event, None
        except ParseError as exc:
            yield line_no, raw, None, str(exc)


def _iter_csv_records(text: str, default_tz: str):
    """Yield (line_no, raw, event | None, reason | None) for a CSV file."""
    bad_lines = []

    def on_bad_line(fields):
        bad_lines.append(fields)
        return None  # skip the row

    try:
        frame = pd.read_csv(io.StringIO(text), dtype=str, keep_default_na=False,
                            on_bad_lines=on_bad_line, engine="python", skipinitialspace=True)
    except (pd.errors.ParserError, pd.errors.EmptyDataError, UnicodeDecodeError) as exc:
        raise IngestError(f"could not read CSV: {exc}") from exc

    column_map = parsers.map_csv_columns(frame.columns)
    if "timestamp" not in column_map.values():
        expected = ", ".join(sorted(parsers.CSV_COLUMN_ALIASES["timestamp"])[:6])
        raise IngestError(f"CSV has no timestamp column (expected a header such as {expected})")

    for bad in bad_lines:
        yield 0, ",".join(str(f) for f in bad), None, "wrong number of columns"

    for position, record in enumerate(frame.to_dict(orient="records")):
        raw = ",".join(str(record.get(col, "")) for col in frame.columns)
        line_no = position + 2  # +1 for header, +1 for 1-based numbering
        try:
            event = parsers.parse_csv_record(record, column_map, default_tz=default_tz, raw_log=raw)
            yield line_no, raw, event, None
        except ParseError as exc:
            yield line_no, raw, None, str(exc)


def ingest_content(conn, content: bytes | str, filename: str, fmt: str = "auto",
                   default_tz: str = "UTC", reference_time: datetime | None = None) -> IngestResult:
    """Parse and store one log file. Commits on success and returns the stats."""
    if fmt not in SUPPORTED_FORMATS:
        raise IngestError(f"unsupported format '{fmt}'")
    if not allowed_file(filename):
        raise IngestError("only .log, .txt and .csv files are accepted")
    text = content if isinstance(content, str) else decode_content(content)
    if not text.strip():
        raise IngestError("the file is empty")

    is_csv = fmt == "csv" or (fmt == "auto" and filename.lower().endswith(".csv"))
    if is_csv:
        source_type = "csv"
        records = _iter_csv_records(text, default_tz)
    else:
        source_type = fmt if fmt != "auto" else parsers.detect_text_format(text.splitlines()[:200])
        records = _iter_text_records(text, source_type, default_tz, reference_time)

    run_id = db.create_ingest_run(conn, Path(filename).name, source_type)
    result = IngestResult(filename=Path(filename).name, source_type=source_type, run_id=run_id)
    seen = Counter()
    batch: list[dict] = []
    try:
        for line_no, raw, event, reason in records:
            result.total += 1
            if event is None:
                result.reject(line_no, raw, reason or "unparseable")
                continue
            occurrence = seen[raw]
            seen[raw] += 1
            event["event_hash"] = _event_hash(event["source_type"], raw, occurrence)
            event["ingest_id"] = run_id
            if event["source_ip"] is None and event["event_type"] != "other":
                result.missing_ip += 1
            batch.append(event)
            if len(batch) >= BATCH_SIZE:
                inserted, dupes = db.insert_events(conn, batch)
                result.processed += inserted
                result.duplicates += dupes
                batch.clear()
        inserted, dupes = db.insert_events(conn, batch)
        result.processed += inserted
        result.duplicates += dupes
        db.finish_ingest_run(
            conn, run_id, source_type, result.total, result.processed, result.rejected,
            result.duplicates, {"reasons": dict(result.reasons), "samples": result.samples,
                                "missing_ip": result.missing_ip},
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return result


def ingest_path(conn, path: str | Path, fmt: str = "auto", default_tz: str = "UTC",
                reference_time: datetime | None = None) -> IngestResult:
    path = Path(path)
    return ingest_content(conn, path.read_bytes(), path.name, fmt, default_tz, reference_time)
