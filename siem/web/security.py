"""Small, dependency-free hardening for the web UI.

* CSRF protection: a per-session random token must accompany every POST
  (hidden form field ``csrf_token`` or ``X-CSRF-Token`` header).
* Security headers: CSP, no framing, no MIME sniffing, strict referrer.
* CSV export sanitising to prevent formula (CSV) injection in Excel.
"""

from __future__ import annotations

import hmac
import secrets

from flask import abort, current_app, request, session

CSRF_SESSION_KEY = "_csrf_token"

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.jsdelivr.net; "
    "style-src 'self' https://cdn.jsdelivr.net; "
    "img-src 'self' data:; "
    "font-src 'self' https://cdn.jsdelivr.net data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none'"
)


def csrf_token() -> str:
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def check_csrf() -> None:
    """before_request hook: reject state-changing requests without a valid token."""
    if not current_app.config.get("CSRF_ENABLED", True):
        return
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    expected = session.get(CSRF_SESSION_KEY, "")
    if not expected or not hmac.compare_digest(str(sent), str(expected)):
        abort(400, description="Missing or invalid CSRF token. Reload the page and try again.")


def add_security_headers(response):
    response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response


_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value):
    """Prefix values that spreadsheet apps would execute as formulas."""
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value
