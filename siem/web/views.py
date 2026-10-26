"""HTML pages: dashboard, upload, events, alerts, rules."""

from __future__ import annotations

import csv
import io
import math
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import available_timezones

from flask import (Blueprint, Response, abort, current_app, flash, redirect, render_template,
                   request, url_for)
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from .. import __version__, db
from ..detection import ALL_RULES, RULES_BY_ID, load_config, run_detection, save_config
from ..detection.config import GLOBAL_PARAMS, config_from_form, default_config, form_value
from ..ingestion import IngestError, ingest_content
from ..ingestion.normalizer import EVENT_TYPES
from ..ingestion.pipeline import SUPPORTED_FORMATS, ingest_path
from ..samples import SAMPLE_FILES, generate_samples
from .security import csv_safe

ui_bp = Blueprint("ui", __name__)

VENDOR_ASSETS = {
    "bootstrap_css": ("bootstrap.min.css", "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"),
    "bootstrap_js": ("bootstrap.bundle.min.js", "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"),
    "chart_js": ("chart.umd.js", "https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.js"),
}
COMMON_TIMEZONES = ["UTC", "Asia/Kolkata", "Europe/London", "Europe/Berlin", "America/New_York",
                    "America/Los_Angeles", "Asia/Singapore", "Asia/Tokyo", "Australia/Sydney"]
FORMAT_LABELS = {
    "auto": "Auto-detect",
    "web_access": "Web access log (Apache / Nginx)",
    "auth_log": "Linux auth log (auth.log / secure)",
    "csv": "CSV (incl. Windows 4624/4625 export)",
}
SEVERITY_CLASSES = {"critical": "danger", "high": "warning", "medium": "info", "low": "secondary"}
STATUS_LABELS = {"open": "Open", "investigating": "Investigating", "resolved": "Resolved",
                 "false_positive": "False positive"}
PAGE_SIZE = 50


def conn():
    return current_app.get_db()


def rules_config() -> dict:
    return load_config(current_app.config["RULES_PATH"])


def safe_next(target: str | None) -> str | None:
    """Only allow redirects to local paths (prevents open redirects)."""
    if target and target.startswith("/") and not target.startswith(("//", "/\\")):
        return target
    return None


def valid_timezone(name: str) -> bool:
    return name == "UTC" or name in available_timezones()


@ui_bp.app_context_processor
def inject_globals():
    static_vendor = Path(current_app.static_folder) / "vendor"

    def asset_url(name: str) -> str:
        filename, cdn = VENDOR_ASSETS[name]
        if (static_vendor / filename).exists():
            return url_for("static", filename=f"vendor/{filename}")
        return cdn

    return {
        "asset_url": asset_url,
        "app_version": __version__,
        "severity_classes": SEVERITY_CLASSES,
        "status_labels": STATUS_LABELS,
    }


@ui_bp.app_template_filter("sev_class")
def sev_class(severity: str) -> str:
    return SEVERITY_CLASSES.get(severity, "secondary")


@ui_bp.app_errorhandler(RequestEntityTooLarge)
def too_large(_exc):
    limit = current_app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
    flash(f"Upload refused: files must be smaller than {limit} MB in total.", "danger")
    return redirect(url_for("ui.upload"))


@ui_bp.app_errorhandler(400)
def bad_request(exc):
    return render_template("error.html", code=400, message=exc.description), 400


@ui_bp.app_errorhandler(404)
def not_found(_exc):
    return render_template("error.html", code=404, message="Page not found."), 404


# --------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------
@ui_bp.get("/")
def dashboard():
    return render_template("dashboard.html", active="dashboard")


# --------------------------------------------------------------------------
# Upload / ingestion
# --------------------------------------------------------------------------
def _upload_context(**extra):
    return dict(
        active="upload",
        formats=FORMAT_LABELS,
        timezones=COMMON_TIMEZONES,
        default_tz=current_app.config["DEFAULT_TIMEZONE"],
        runs=db.get_ingest_runs(conn(), limit=15),
        sample_files=list(SAMPLE_FILES),
        **extra,
    )


@ui_bp.get("/upload")
def upload():
    return render_template("upload.html", **_upload_context())


@ui_bp.post("/upload")
def upload_post():
    files = [f for f in request.files.getlist("logfiles") if f and f.filename]
    fmt = request.form.get("format", "auto")
    tz = request.form.get("timezone", "UTC").strip() or "UTC"
    detect = request.form.get("run_detection") == "on"

    if not files:
        flash("Choose at least one log file to upload.", "warning")
        return redirect(url_for("ui.upload"))
    if fmt not in SUPPORTED_FORMATS:
        flash("Unknown log format.", "danger")
        return redirect(url_for("ui.upload"))
    if not valid_timezone(tz):
        flash(f"Unknown time zone '{tz}'. Use an IANA name such as Asia/Kolkata.", "danger")
        return redirect(url_for("ui.upload"))

    results = []
    for storage in files:
        filename = secure_filename(storage.filename) or "upload.log"
        try:
            result = ingest_content(conn(), storage.read(), filename, fmt=fmt, default_tz=tz)
            results.append({"ok": True, **result.as_dict()})
        except IngestError as exc:
            results.append({"ok": False, "filename": filename, "error": str(exc)})

    summary = None
    if detect and any(r["ok"] and r["processed"] for r in results):
        summary = run_detection(conn(), rules_config()).as_dict()
    return render_template("upload.html", **_upload_context(results=results, detection=summary))


@ui_bp.post("/samples/load")
def load_samples():
    sample_dir = Path(current_app.config["SAMPLE_DIR"])
    if not all((sample_dir / name).exists() for name in SAMPLE_FILES):
        generate_samples(sample_dir)
    # Pin the syslog year to the sample data's year so auth.log lines up with the others.
    reference = datetime(2026, 10, 26, tzinfo=timezone.utc)
    results = []
    for name, fmt in SAMPLE_FILES.items():
        try:
            result = ingest_path(conn(), sample_dir / name, fmt=fmt, default_tz="UTC", reference_time=reference)
            results.append({"ok": True, **result.as_dict()})
        except IngestError as exc:
            results.append({"ok": False, "filename": name, "error": str(exc)})
    summary = run_detection(conn(), rules_config()).as_dict()
    return render_template("upload.html", **_upload_context(results=results, detection=summary))


@ui_bp.post("/reset")
def reset():
    if request.form.get("confirm") != "DELETE":
        flash("Type DELETE to confirm clearing all data.", "warning")
        return redirect(url_for("ui.upload"))
    db.reset_database(conn())
    flash("All events, alerts and upload history were deleted.", "success")
    return redirect(url_for("ui.upload"))


# --------------------------------------------------------------------------
# Events
# --------------------------------------------------------------------------
EVENT_FILTERS = ("source_ip", "username", "event_type", "status", "source_type", "q", "start", "end")


@ui_bp.get("/events")
def events():
    filters = {key: request.args.get(key, "").strip() for key in EVENT_FILTERS}
    for key in ("start", "end"):  # <input type=datetime-local> sends 'YYYY-MM-DDTHH:MM'
        if filters[key]:
            filters[key] = filters[key].replace("T", " ")
            if len(filters[key]) == 16:
                filters[key] += ":00" if key == "start" else ":59"
    page = max(request.args.get("page", 1, type=int), 1)
    rows, total = db.query_events(conn(), filters, limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE)
    pages = max(math.ceil(total / PAGE_SIZE), 1)
    source_types = [r[0] for r in conn().execute(
        "SELECT DISTINCT source_type FROM events WHERE source_type IS NOT NULL ORDER BY 1")]
    query_args = {k: request.args.get(k) for k in EVENT_FILTERS if request.args.get(k)}
    return render_template("events.html", active="events", rows=rows, total=total, page=page,
                           pages=pages, filters=filters, event_types=EVENT_TYPES,
                           source_types=source_types, query_args=query_args)


# --------------------------------------------------------------------------
# Alerts
# --------------------------------------------------------------------------
ALERT_FILTERS = ("severity", "status", "rule_id", "source_ip")


def _alert_filters():
    return {key: request.args.get(key, "").strip() for key in ALERT_FILTERS}


@ui_bp.get("/alerts")
def alerts():
    filters = _alert_filters()
    rows = db.query_alerts(conn(), filters)
    return render_template("alerts.html", active="alerts", alerts=rows, filters=filters,
                           rules=ALL_RULES, severities=db.SEVERITIES, statuses=db.ALERT_STATUSES,
                           query_args={k: v for k, v in filters.items() if v})


@ui_bp.get("/alerts/export.csv")
def export_alerts():
    rows = db.query_alerts(conn(), _alert_filters(), limit=100000)
    columns = ["id", "severity", "status", "rule_id", "title", "source_ip", "username", "first_seen",
               "last_seen", "event_count", "mitre_technique", "description", "analyst_notes"]
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(columns)
    for row in rows:
        writer.writerow([csv_safe(row.get(c)) for c in columns])
    filename = f"minisiem_alerts_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}.csv"
    return Response(buffer.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={filename}"})


@ui_bp.get("/alerts/<int:alert_id>")
def alert_detail(alert_id: int):
    alert = db.get_alert(conn(), alert_id)
    if alert is None:
        abort(404)
    evidence, _ = db.query_events(conn(), {"ids": alert["event_ids"]}, limit=100) if alert["event_ids"] else ([], 0)
    evidence.sort(key=lambda e: (e["timestamp"], e["id"]))
    related = []
    if alert["source_ip"]:
        related = [a for a in db.query_alerts(conn(), {"source_ip": alert["source_ip"]}) if a["id"] != alert_id]
    return render_template("alert_detail.html", active="alerts", alert=alert, evidence=evidence,
                           related=related, rule=RULES_BY_ID.get(alert["rule_id"]),
                           statuses=db.ALERT_STATUSES)


@ui_bp.post("/alerts/<int:alert_id>")
def alert_update(alert_id: int):
    if db.get_alert(conn(), alert_id) is None:
        abort(404)
    status = request.form.get("status", "")
    notes = (request.form.get("analyst_notes") or "").strip()[:5000] or None
    try:
        db.update_alert_triage(conn(), alert_id, status, notes)
        conn().commit()
        flash("Alert updated.", "success")
    except ValueError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("ui.alert_detail", alert_id=alert_id))


@ui_bp.post("/detect")
def detect():
    summary = run_detection(conn(), rules_config())
    if summary.errors:
        flash("Some rules failed: " + "; ".join(f"{k}: {v}" for k, v in summary.errors.items()), "danger")
    flash(
        f"Detection finished in {summary.duration_ms} ms over {summary.events_analyzed} events: "
        f"{summary.new_alerts} new, {summary.updated_alerts} updated, "
        f"{summary.unchanged_alerts} unchanged alert(s).",
        "success",
    )
    return redirect(safe_next(request.form.get("next")) or url_for("ui.alerts"))


# --------------------------------------------------------------------------
# Rules / thresholds
# --------------------------------------------------------------------------
@ui_bp.get("/rules")
def rules():
    config = rules_config()
    return render_template("rules.html", active="rules", rules=ALL_RULES, config=config,
                           global_params=GLOBAL_PARAMS, form_value=form_value, errors=[])


@ui_bp.post("/rules")
def rules_post():
    config, errors = config_from_form(request.form)
    if errors:
        # Re-show what was submitted (invalid fields fall back to their defaults).
        return render_template("rules.html", active="rules", rules=ALL_RULES, config=config,
                               global_params=GLOBAL_PARAMS, form_value=form_value, errors=errors), 400
    save_config(current_app.config["RULES_PATH"], config)
    flash("Detection settings saved.", "success")
    if request.form.get("rerun") == "1":
        summary = run_detection(conn(), config)
        flash(f"Detection re-run: {summary.new_alerts} new, {summary.updated_alerts} updated alert(s).",
              "info")
    return redirect(url_for("ui.rules"))


@ui_bp.post("/rules/reset")
def rules_reset():
    save_config(current_app.config["RULES_PATH"], default_config())
    flash("All rules reset to their default thresholds.", "success")
    return redirect(url_for("ui.rules"))
