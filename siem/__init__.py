"""Mini-SIEM: security log monitoring and threat detection.

``create_app()`` builds the Flask application. Everything runs locally:
SQLite for storage, no cloud services, no API keys.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from flask import Flask, g

__version__ = "1.0.0"

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _load_secret_key(instance_path: Path) -> str:
    """Use MINISIEM_SECRET_KEY if set, otherwise a random key stored in instance/."""
    env_key = os.environ.get("MINISIEM_SECRET_KEY")
    if env_key:
        return env_key
    key_file = instance_path / ".secret_key"
    if key_file.exists():
        return key_file.read_text(encoding="utf-8").strip()
    key = secrets.token_hex(32)
    key_file.write_text(key, encoding="utf-8")
    return key


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_path=str(PROJECT_ROOT / "instance"), instance_relative_config=True)
    instance = Path(app.instance_path)
    instance.mkdir(parents=True, exist_ok=True)

    app.config.update(
        DATABASE=str(instance / "minisiem.db"),
        RULES_PATH=str(instance / "rules.json"),
        SAMPLE_DIR=str(PROJECT_ROOT / "sample_logs"),
        MAX_CONTENT_LENGTH=int(os.environ.get("MINISIEM_MAX_UPLOAD_MB", "25")) * 1024 * 1024,
        DEFAULT_TIMEZONE=os.environ.get("MINISIEM_TZ", "UTC"),
        CSRF_ENABLED=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    if test_config:
        app.config.update(test_config)
    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = _load_secret_key(instance)

    from . import db as database
    from .web import security
    from .web.api import api_bp
    from .web.views import ui_bp

    def get_db():
        if "db" not in g:
            g.db = database.connect(app.config["DATABASE"])
        return g.db

    app.get_db = get_db

    @app.teardown_appcontext
    def close_db(_exc):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    app.before_request(security.check_csrf)
    app.after_request(security.add_security_headers)
    app.jinja_env.globals["csrf_token"] = security.csrf_token
    app.register_blueprint(ui_bp)
    app.register_blueprint(api_bp, url_prefix="/api")

    with app.app_context():
        get_db()  # create the schema on first start
    return app
