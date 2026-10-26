"""JSON endpoints used by the dashboard (and handy for scripting / curl)."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from .. import db
from ..detection import load_config, run_detection
from . import stats

api_bp = Blueprint("api", __name__)


def _conn():
    return current_app.get_db()


@api_bp.get("/stats")
def api_stats():
    return jsonify(stats.dashboard_payload(_conn()))


@api_bp.get("/alerts")
def api_alerts():
    filters = {k: request.args.get(k) for k in ("severity", "status", "rule_id", "source_ip")}
    limit = min(request.args.get("limit", 200, type=int), 1000)
    return jsonify(db.query_alerts(_conn(), filters, limit=limit))


@api_bp.get("/events")
def api_events():
    filters = {k: request.args.get(k) for k in ("source_ip", "username", "event_type", "status", "q")}
    limit = min(request.args.get("limit", 100, type=int), 1000)
    offset = max(request.args.get("offset", 0, type=int), 0)
    rows, total = db.query_events(_conn(), filters, limit=limit, offset=offset)
    return jsonify({"total": total, "events": rows})


@api_bp.post("/detect")
def api_detect():
    summary = run_detection(_conn(), load_config(current_app.config["RULES_PATH"]))
    return jsonify(summary.as_dict())


@api_bp.get("/health")
def api_health():
    return jsonify({"status": "ok"})
