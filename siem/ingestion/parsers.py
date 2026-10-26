"""Log parsers.

Each parser turns one raw record into a *normalized* event dict, or raises
``ParseError`` with a short human-readable reason. The ingestion pipeline
counts those reasons so the dashboard can show why records were rejected.

Supported sources
-----------------
* Web access logs  - Apache / Nginx "common" and "combined" formats
* Auth logs        - Linux syslog auth.log / secure (sshd, sudo, su, PAM)
* CSV              - any CSV whose headers map onto the canonical fields
                     (aliases below), including Windows Security exports
                     with Event IDs 4624 / 4625.
"""

from __future__ import annotations

import re
from datetime import datetime

from . import normalizer as norm


class ParseError(ValueError):
    """Raised when a record cannot be turned into a valid event."""


# --------------------------------------------------------------------------
# Web access logs (Apache / Nginx)
# --------------------------------------------------------------------------
# 203.0.113.7 - - [25/Oct/2026:10:15:32 +0000] "GET /admin HTTP/1.1" 404 512 "-" "Mozilla/5.0"
ACCESS_LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<request>(?:[^"\\]|\\.)*)"\s+(?P<status>\d{3}|-)\s+(?P<bytes>\d+|-)'
    r'(?:\s+"(?P<referer>(?:[^"\\]|\\.)*)"\s+"(?P<agent>(?:[^"\\]|\\.)*)")?\s*$'
)


def parse_access_line(line: str, default_tz: str = "UTC", **_) -> dict:
    match = ACCESS_LOG_RE.match(line)
    if not match:
        raise ParseError("not a recognised access-log line")

    timestamp = norm.normalize_timestamp(match["ts"], default_tz)
    if timestamp is None:
        raise ParseError("invalid timestamp")

    request = match["request"]
    parts = request.split()
    if len(parts) == 3:
        method, path, _protocol = parts
    elif len(parts) == 2:
        method, path = parts
    else:
        # Garbage such as TLS handshakes sent to a plain-HTTP port.
        method, path = None, request or None
    if method is not None and not method.isalpha():
        method, path = None, request

    http_status = norm.normalize_http_status(match["status"])
    event = norm.empty_event()
    event.update(
        timestamp=timestamp,
        source_ip=norm.normalize_ip(match["ip"]),
        username=norm.normalize_username(match["user"]),
        event_type="web_request",
        status=str(http_status) if http_status else None,
        http_method=method.upper() if method else None,
        http_status=http_status,
        request_path=norm.normalize_path(path),
        user_agent=norm.clean_text(match["agent"], max_length=512),
        bytes_sent=norm.normalize_int(match["bytes"]),
        source_type="web_access",
        raw_log=line,
    )
    return event


# --------------------------------------------------------------------------
# Linux auth.log / secure
# --------------------------------------------------------------------------
# Oct 25 02:10:11 web01 sshd[2211]: Failed password for invalid user oracle from 203.0.113.15 port 51122 ssh2
# 2026-10-25T02:10:11.123456+00:00 web01 sshd[2211]: Accepted publickey for alice from 10.0.0.12 port 50022 ssh2
SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-./()]+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
_IP = r"(?P<ip>[0-9A-Fa-f:.]+)"
AUTH_MESSAGE_PATTERNS = (
    # (regex, event_type, status)
    (re.compile(r"Failed (?:password|publickey|keyboard-interactive(?:/pam)?|none) for "
                r"(?:invalid user )?(?P<user>\S*) from " + _IP), "auth_failure", "failure"),
    (re.compile(r"Accepted (?:password|publickey|keyboard-interactive(?:/pam)?|gssapi-with-mic) for "
                r"(?P<user>\S+) from " + _IP), "auth_success", "success"),
    (re.compile(r"Invalid user (?P<user>\S*) from " + _IP), "auth_other", "invalid_user"),
    (re.compile(r"(?:Connection closed|Disconnected) by (?:authenticating |invalid )?user (?P<user>\S+) "
                + _IP), "auth_other", "disconnect"),
    (re.compile(r"maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from "
                + _IP), "auth_other", "max_attempts"),
    # su / sudo / login failures recorded by PAM
    # (sshd's own PAM line is skipped on purpose: sshd already logs "Failed password".)
    (re.compile(r"pam_unix\((?:sudo|su|su-l|login|sudo-i):auth\): authentication failure;"
                r"(?:(?=.*?\brhost=(?P<ip>\S*)))?(?=.*?\buser=(?P<user>\S+))"), "auth_failure", "failure"),
    (re.compile(r"FAILED SU \(to (?P<user>\S+)\)"), "auth_failure", "failure"),
    (re.compile(r"^\s*(?P<user>\S+) : .*COMMAND="), "auth_other", "sudo_command"),
)


def parse_auth_line(line: str, default_tz: str = "UTC",
                    reference_time: datetime | None = None, **_) -> dict:
    match = SYSLOG_RE.match(line)
    if not match:
        raise ParseError("not a recognised syslog line")

    timestamp = norm.normalize_timestamp(match["ts"], default_tz, reference_time)
    if timestamp is None:
        raise ParseError("invalid timestamp")

    event = norm.empty_event()
    event.update(
        timestamp=timestamp,
        host=norm.clean_text(match["host"], 255),
        process=norm.clean_text(match["proc"], 64),
        event_type="other",
        source_type="auth_log",
        raw_log=line,
    )

    message = match["msg"]
    for pattern, event_type, status in AUTH_MESSAGE_PATTERNS:
        found = pattern.search(message)
        if found:
            groups = found.groupdict()
            event.update(
                event_type=event_type,
                status=status,
                username=norm.normalize_username(groups.get("user")),
                source_ip=norm.normalize_ip(groups.get("ip")),
            )
            break
    return event


# --------------------------------------------------------------------------
# CSV
# --------------------------------------------------------------------------
# Header aliases (lower-cased, spaces/dashes -> underscores) -> canonical field.
CSV_COLUMN_ALIASES = {
    "timestamp": {"timestamp", "time", "datetime", "date_time", "date_and_time", "event_time",
                  "timecreated", "time_created", "@timestamp", "ts", "date", "logged"},
    "source_ip": {"source_ip", "src_ip", "ip", "ip_address", "ipaddress", "client_ip", "clientip",
                  "remote_addr", "remote_ip", "src", "source_address", "c_ip", "rhost", "source_network_address"},
    "username": {"username", "user", "user_name", "account", "account_name", "targetusername",
                 "target_user_name", "login", "cs_username", "subject_user_name"},
    "event_type": {"event_type", "event", "action", "type", "activity", "category"},
    "event_id": {"event_id", "eventid", "id", "event_code"},
    "status": {"status", "result", "outcome", "auth_result", "login_status"},
    "http_status": {"http_status", "status_code", "response_code", "sc_status", "http_code"},
    "http_method": {"http_method", "method", "verb", "cs_method", "request_method"},
    "request_path": {"request_path", "path", "url", "uri", "request", "endpoint", "cs_uri_stem", "resource"},
    "user_agent": {"user_agent", "useragent", "agent", "ua", "cs(user_agent)", "http_user_agent"},
    "host": {"host", "hostname", "computer", "machine", "machinename", "server"},
    "bytes_sent": {"bytes", "bytes_sent", "size", "sc_bytes", "response_size"},
}
_ALIAS_LOOKUP = {
    alias: canonical for canonical, aliases in CSV_COLUMN_ALIASES.items() for alias in aliases
}

# Windows Security event IDs that matter for authentication monitoring.
WINDOWS_EVENT_IDS = {
    "4624": ("auth_success", "success"),
    "4625": ("auth_failure", "failure"),
    "4771": ("auth_failure", "failure"),  # Kerberos pre-auth failed
    "4634": ("auth_other", "logoff"),
    "4647": ("auth_other", "logoff"),
    "4740": ("auth_other", "account_locked"),
}


def map_csv_columns(columns) -> dict:
    """Return {original_column: canonical_field} for the columns we understand.

    The first column that maps to a field wins, so an export with both 'Time'
    and 'Date' uses whichever comes first.
    """
    mapping, used = {}, set()
    for column in columns:
        key = str(column).strip().lower().replace(" ", "_").replace("-", "_")
        canonical = _ALIAS_LOOKUP.get(key)
        if canonical and canonical not in used:
            mapping[column] = canonical
            used.add(canonical)
    return mapping


def parse_csv_record(record: dict, column_map: dict, default_tz: str = "UTC",
                     raw_log: str | None = None, **_) -> dict:
    """Normalize one CSV row (already split into columns)."""
    values = {canonical: record.get(column) for column, canonical in column_map.items()}

    timestamp = norm.normalize_timestamp(values.get("timestamp"), default_tz)
    if timestamp is None:
        reason = "missing timestamp" if norm.is_empty(values.get("timestamp")) else "invalid timestamp"
        raise ParseError(reason)

    status = norm.normalize_status(values.get("status"))
    http_status = norm.normalize_http_status(values.get("http_status"))
    if http_status is None and status and status.isdigit():
        http_status = norm.normalize_http_status(status)

    event_type = None
    event_id = norm.clean_text(values.get("event_id"), 16)
    if event_id in WINDOWS_EVENT_IDS:
        event_type, implied_status = WINDOWS_EVENT_IDS[event_id]
        status = status if status in ("success", "failure") else implied_status
    if event_type is None:
        event_type = norm.normalize_event_type(values.get("event_type"), status, http_status)
    if event_type == "web_request" and http_status is not None:
        status = str(http_status)

    event = norm.empty_event()
    event.update(
        timestamp=timestamp,
        source_ip=norm.normalize_ip(values.get("source_ip")),
        username=norm.normalize_username(values.get("username")),
        event_type=event_type,
        status=status,
        http_method=(norm.clean_text(values.get("http_method"), 16) or "").upper() or None,
        http_status=http_status,
        request_path=norm.normalize_path(values.get("request_path")),
        user_agent=norm.clean_text(values.get("user_agent"), 512),
        bytes_sent=norm.normalize_int(values.get("bytes_sent")),
        host=norm.clean_text(values.get("host"), 255),
        process=f"EventID {event_id}" if event_id else None,
        source_type="csv",
        raw_log=raw_log,
    )
    return event


# --------------------------------------------------------------------------
# Format detection
# --------------------------------------------------------------------------
TEXT_PARSERS = {
    "web_access": parse_access_line,
    "auth_log": parse_auth_line,
}


def detect_text_format(lines) -> str:
    """Guess 'web_access' or 'auth_log' from the first non-empty lines.

    Returns 'auto' when the sample is inconclusive; the pipeline then tries
    every text parser on each line.
    """
    scores = {"web_access": 0, "auth_log": 0}
    checked = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        checked += 1
        if ACCESS_LOG_RE.match(line):
            scores["web_access"] += 1
        elif SYSLOG_RE.match(line):
            scores["auth_log"] += 1
        if checked >= 50:
            break
    best = max(scores, key=scores.get)
    if checked and scores[best] >= max(1, int(checked * 0.6)):
        return best
    return "auto"


def parse_text_line(line: str, fmt: str, **kwargs) -> dict:
    """Parse a line with the chosen parser, or try them all for 'auto'."""
    if fmt in TEXT_PARSERS:
        return TEXT_PARSERS[fmt](line, **kwargs)
    last_error = None
    for parser in TEXT_PARSERS.values():
        try:
            return parser(line, **kwargs)
        except ParseError as exc:
            last_error = exc
    raise ParseError(str(last_error) if last_error else "unrecognised line")
