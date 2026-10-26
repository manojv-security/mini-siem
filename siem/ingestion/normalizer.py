"""Normalization helpers.

Every parser hands raw values to these functions so that all events end up
in one consistent internal format, no matter which log source they came from.

Canonical event fields
----------------------
timestamp      UTC time as 'YYYY-MM-DD HH:MM:SS' (required)
source_ip      validated IPv4/IPv6 string or None
username       lower-level identity string or None
event_type     one of EVENT_TYPES
status         'success' / 'failure' / HTTP code as text / other short status
request_path   URL path (web logs) or None
user_agent     HTTP user agent or None
raw_log        the original line / row, kept for evidence
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from dateutil import parser as date_parser

CANONICAL_FIELDS = (
    "timestamp",
    "source_ip",
    "username",
    "event_type",
    "status",
    "http_method",
    "http_status",
    "request_path",
    "user_agent",
    "bytes_sent",
    "host",
    "process",
    "source_type",
    "raw_log",
)

# Small, explicit vocabulary keeps the detection rules simple.
EVENT_TYPES = (
    "auth_success",   # successful login / logon
    "auth_failure",   # failed login / logon
    "auth_other",     # auth-related noise: invalid user notices, disconnects, sudo
    "web_request",    # HTTP request from an access log
    "other",          # anything else we could parse but not classify
)

_EVENT_TYPE_SYNONYMS = {
    "auth_success": {
        "auth_success", "success", "login_success", "logon_success", "accepted",
        "login", "logon", "successful_login", "authenticated", "allow", "allowed",
        "4624",
    },
    "auth_failure": {
        "auth_failure", "failure", "failed", "fail", "login_failed", "login_failure",
        "logon_failure", "failed_login", "denied", "deny", "rejected", "invalid_password",
        "4625", "4771", "4776_failure",
    },
    "auth_other": {"auth_other", "invalid_user", "logout", "logoff", "4634", "4647", "sudo"},
    "web_request": {"web_request", "http", "http_request", "request", "web", "access"},
}
_SYNONYM_LOOKUP = {
    synonym: canonical
    for canonical, synonyms in _EVENT_TYPE_SYNONYMS.items()
    for synonym in synonyms
}

_STATUS_SYNONYMS = {
    "success": {"success", "succeeded", "ok", "accepted", "allow", "allowed", "true", "pass", "passed"},
    "failure": {"failure", "failed", "fail", "denied", "deny", "rejected", "false", "error", "invalid"},
}
_STATUS_LOOKUP = {s: canon for canon, syns in _STATUS_SYNONYMS.items() for s in syns}

_EMPTY_MARKERS = {"", "-", "--", "null", "none", "nan", "n/a", "na", "unknown"}

# Formats tried before falling back to dateutil's flexible parser.
_TIMESTAMP_FORMATS = (
    "%d/%b/%Y:%H:%M:%S %z",      # Apache / Nginx: 25/Oct/2026:10:15:32 +0000
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y/%m/%d %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",      # Windows Event Viewer (US locale): 10/25/2026 10:15:32 AM
    "%d-%m-%Y %H:%M:%S",
)
_SYSLOG_TS = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})$")
_EPOCH = re.compile(r"^\d{9,10}(\.\d+)?$")


def is_empty(value) -> bool:
    """True for None, NaN and the usual 'no value' placeholders found in logs."""
    if value is None:
        return True
    if isinstance(value, float) and value != value:  # NaN
        return True
    return str(value).strip().lower() in _EMPTY_MARKERS


def clean_text(value, max_length: int = 2048) -> str | None:
    """Strip whitespace, drop placeholders and control characters, cap length."""
    if is_empty(value):
        return None
    text = str(value).strip()
    text = "".join(ch if ch.isprintable() else "?" for ch in text)
    return text[:max_length]


def get_timezone(name: str | None):
    """Return a tzinfo for an IANA name (e.g. 'Asia/Kolkata'); UTC if unknown."""
    if not name or name.upper() == "UTC":
        return timezone.utc
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return timezone.utc


def _to_utc_string(dt: datetime, default_tz) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=default_tz)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _plausible(dt: datetime) -> bool:
    return 1990 <= dt.year <= 2100


def normalize_timestamp(value, default_tz: str | None = "UTC",
                        reference_time: datetime | None = None) -> str | None:
    """Parse many timestamp styles into a UTC 'YYYY-MM-DD HH:MM:SS' string.

    * Timestamps carrying an offset (+0530, Z, ...) are converted to UTC.
    * Naive timestamps are interpreted in ``default_tz`` (the log's local zone).
    * Classic syslog timestamps have no year ("Oct 25 10:15:32"). We use the
      reference year and step back one year if that would put the event more
      than a day in the future (e.g. December logs read in January).
    Returns None when the value cannot be parsed.
    """
    if is_empty(value):
        return None
    tz = get_timezone(default_tz)

    if isinstance(value, datetime):
        return _to_utc_string(value, tz) if _plausible(value) else None

    text = str(value).strip()

    if _EPOCH.match(text):
        dt = datetime.fromtimestamp(float(text), tz=timezone.utc)
        return _to_utc_string(dt, tz) if _plausible(dt) else None

    syslog = _SYSLOG_TS.match(text)
    if syslog:
        ref = reference_time or datetime.now(timezone.utc)
        try:
            dt = datetime.strptime(
                f"{ref.year} {syslog['mon']} {syslog['day']} {syslog['time']}", "%Y %b %d %H:%M:%S"
            ).replace(tzinfo=tz)
        except ValueError:
            return None
        if dt.astimezone(timezone.utc) > ref.astimezone(timezone.utc) + timedelta(days=1):
            dt = dt.replace(year=dt.year - 1)
        return _to_utc_string(dt, tz)

    for fmt in _TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(text, fmt)
            return _to_utc_string(dt, tz) if _plausible(dt) else None
        except ValueError:
            continue

    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return _to_utc_string(dt, tz) if _plausible(dt) else None
    except ValueError:
        pass

    try:
        dt = date_parser.parse(text)
    except (ValueError, OverflowError, TypeError):
        return None
    return _to_utc_string(dt, tz) if _plausible(dt) else None


def normalize_ip(value) -> str | None:
    """Validate an IP address, stripping ports, brackets and IPv4-mapped IPv6.

    '203.0.113.5:443' -> '203.0.113.5', '[2001:db8::1]:22' -> '2001:db8::1',
    '::ffff:10.0.0.1' -> '10.0.0.1'. Anything that is not an IP returns None.
    """
    if is_empty(value):
        return None
    text = str(value).strip()
    if text.startswith("["):  # [IPv6]:port
        text = text[1:].split("]", 1)[0]
    elif text.count(":") == 1:  # IPv4:port
        text = text.split(":", 1)[0]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def normalize_username(value) -> str | None:
    """Trim a username; strip a 'DOMAIN\\' prefix so 'CORP\\alice' == 'alice'."""
    text = clean_text(value, max_length=128)
    if text is None:
        return None
    if "\\" in text:
        text = text.rsplit("\\", 1)[-1]
    text = text.strip()
    return text or None


def normalize_status(value) -> str | None:
    """Map status words to 'success'/'failure'; keep HTTP codes as text."""
    text = clean_text(value, max_length=64)
    if text is None:
        return None
    if text.isdigit():
        return text
    return _STATUS_LOOKUP.get(text.lower().replace(" ", "_"), text.lower())


def normalize_http_status(value) -> int | None:
    """Return a valid HTTP status code (100-599) or None."""
    if is_empty(value):
        return None
    try:
        code = int(float(str(value).strip()))
    except ValueError:
        return None
    return code if 100 <= code <= 599 else None


def normalize_event_type(value=None, status: str | None = None,
                         http_status: int | None = None) -> str:
    """Pick the canonical event type.

    Uses an explicit event type when it is recognised, otherwise infers one:
    an HTTP status means a web request, a success/failure status means an
    authentication event, everything else is 'other'.
    """
    if not is_empty(value):
        key = str(value).strip().lower().replace(" ", "_").replace("-", "_")
        if key in _SYNONYM_LOOKUP:
            canonical = _SYNONYM_LOOKUP[key]
            # A generic 'login'/'logon' event with a failure status is a failure.
            if canonical == "auth_success" and status == "failure":
                return "auth_failure"
            return canonical
        if key in ("auth", "authentication", "login_attempt", "logon_attempt"):
            if status == "success":
                return "auth_success"
            if status == "failure":
                return "auth_failure"
            return "auth_other"
    if http_status is not None:
        return "web_request"
    if status == "success":
        return "auth_success"
    if status == "failure":
        return "auth_failure"
    return "other"


def normalize_path(value) -> str | None:
    """Keep the URL path as logged (query string included) with a length cap."""
    return clean_text(value, max_length=2048)


def normalize_int(value) -> int | None:
    if is_empty(value):
        return None
    try:
        return int(float(str(value).strip()))
    except ValueError:
        return None


def empty_event() -> dict:
    """A dict with every canonical field present (and None)."""
    return {field: None for field in CANONICAL_FIELDS}
