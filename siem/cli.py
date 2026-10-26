"""Command-line interface - handy on Kali or a headless server.

    python -m siem.cli ingest /var/log/auth.log /var/log/nginx/access.log --tz Asia/Kolkata
    python -m siem.cli detect
    python -m siem.cli alerts --severity critical
    python -m siem.cli samples        # regenerate sample_logs/
    python -m siem.cli reset --yes
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import PROJECT_ROOT, db
from .detection import load_config, run_detection
from .ingestion import IngestError, ingest_path
from .ingestion.pipeline import SUPPORTED_FORMATS
from .samples import generate_samples

DEFAULT_DB = PROJECT_ROOT / "instance" / "minisiem.db"
DEFAULT_RULES = PROJECT_ROOT / "instance" / "rules.json"


def cmd_ingest(args, conn):
    for path in args.files:
        try:
            r = ingest_path(conn, path, fmt=args.format, default_tz=args.tz)
        except (IngestError, OSError) as exc:
            print(f"[refused] {path}: {exc}")
            continue
        print(f"[{r.source_type}] {r.filename}: {r.total} records, {r.processed} processed, "
              f"{r.rejected} rejected, {r.duplicates} duplicates")
        for reason, count in r.reasons.items():
            print(f"    {count} x {reason}")
    if not args.no_detect:
        cmd_detect(args, conn)


def cmd_detect(args, conn):
    s = run_detection(conn, load_config(args.rules))
    print(f"Detection: {s.events_analyzed} events in {s.duration_ms} ms -> {s.new_alerts} new, "
          f"{s.updated_alerts} updated, {s.unchanged_alerts} unchanged alerts")
    for rule_id, count in s.per_rule.items():
        print(f"    {rule_id:24} {'disabled' if count is None else count}")
    for rule_id, error in s.errors.items():
        print(f"    ERROR {rule_id}: {error}")


def cmd_alerts(args, conn):
    rows = db.query_alerts(conn, {"severity": args.severity, "status": args.status}, limit=args.limit)
    for a in rows:
        entity = a["source_ip"] or ""
        if a["username"]:
            entity += f" ({a['username']})"
        print(f"#{a['id']:<4} {a['severity'].upper():8} {a['first_seen']}  {a['rule_id']:22} {entity:28} {a['title']}")
    print(f"{len(rows)} alert(s)")


def cmd_samples(args, _conn):
    for path in generate_samples(args.out):
        print(f"wrote {path}")


def cmd_reset(args, conn):
    if not args.yes:
        print("Refusing to delete data without --yes")
        return 1
    db.reset_database(conn)
    print("All events, alerts and ingest history deleted.")


def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--db", default=str(DEFAULT_DB), help="SQLite database path")
    common.add_argument("--rules", default=str(DEFAULT_RULES), help="rules JSON path")
    parser = argparse.ArgumentParser(prog="python -m siem.cli", description="Mini-SIEM command line")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("ingest", parents=[common], help="import log files")
    p.add_argument("files", nargs="+", type=Path)
    p.add_argument("--format", choices=SUPPORTED_FORMATS, default="auto")
    p.add_argument("--tz", default="UTC", help="time zone for timestamps without an offset")
    p.add_argument("--no-detect", action="store_true", help="skip detection after import")
    p.set_defaults(func=cmd_ingest)

    sub.add_parser("detect", parents=[common], help="run every enabled rule").set_defaults(func=cmd_detect)

    p = sub.add_parser("alerts", parents=[common], help="list alerts")
    p.add_argument("--severity", choices=db.SEVERITIES)
    p.add_argument("--status", choices=db.ALERT_STATUSES)
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=cmd_alerts)

    p = sub.add_parser("samples", parents=[common], help="regenerate the synthetic sample logs")
    p.add_argument("--out", default=str(PROJECT_ROOT / "sample_logs"))
    p.set_defaults(func=cmd_samples)

    p = sub.add_parser("reset", parents=[common], help="delete all stored data")
    p.add_argument("--yes", action="store_true")
    p.set_defaults(func=cmd_reset)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    conn = db.connect(args.db)
    try:
        return args.func(args, conn) or 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
