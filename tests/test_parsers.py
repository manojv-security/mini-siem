import pytest

from helpers import REFERENCE_TIME
from siem.ingestion import parsers
from siem.ingestion.parsers import ParseError


# --- web access logs -------------------------------------------------------
def test_combined_access_log_line():
    line = ('203.0.113.7 - - [25/Oct/2026:10:15:32 +0000] "GET /admin/login.php?x=1 HTTP/1.1" 404 512 '
            '"https://example.com/" "Mozilla/5.0 (Nikto/2.5.0)"')
    e = parsers.parse_access_line(line)
    assert e["timestamp"] == "2026-10-25 10:15:32"
    assert e["source_ip"] == "203.0.113.7"
    assert e["event_type"] == "web_request"
    assert e["http_method"] == "GET"
    assert e["http_status"] == 404 and e["status"] == "404"
    assert e["request_path"] == "/admin/login.php?x=1"
    assert e["user_agent"] == "Mozilla/5.0 (Nikto/2.5.0)"
    assert e["bytes_sent"] == 512
    assert e["raw_log"] == line


def test_common_log_format_without_agent():
    e = parsers.parse_access_line('10.0.0.1 - alice [25/Oct/2026:10:15:32 +0000] "POST /login HTTP/1.0" 302 -')
    assert e["username"] == "alice"
    assert e["user_agent"] is None
    assert e["bytes_sent"] is None


def test_tls_garbage_request_is_kept_without_method():
    line = '203.0.113.33 - - [25/Oct/2026:07:12:05 +0000] "\\x16\\x03\\x01\\x02\\x00" 400 157 "-" "-"'
    e = parsers.parse_access_line(line)
    assert e["http_method"] is None
    assert e["http_status"] == 400


@pytest.mark.parametrize("line", [
    "GET /index.html HTTP/1.1",
    '198.51.100.7 - - [25/Oct/2026:11:00:01 +0000] "GET /products HT',
    "",
])
def test_malformed_access_lines_raise(line):
    with pytest.raises(ParseError):
        parsers.parse_access_line(line)


def test_access_line_with_bad_timestamp_reports_reason():
    with pytest.raises(ParseError, match="invalid timestamp"):
        parsers.parse_access_line('1.2.3.4 - - [99/Foo/2026:25:61:00 +0000] "GET / HTTP/1.1" 200 1 "-" "-"')


# --- auth logs -------------------------------------------------------------
@pytest.mark.parametrize("message, event_type, user, ip", [
    ("sshd[1]: Failed password for root from 203.0.113.15 port 22 ssh2", "auth_failure", "root", "203.0.113.15"),
    ("sshd[1]: Failed password for invalid user oracle from 203.0.113.15 port 22 ssh2", "auth_failure", "oracle", "203.0.113.15"),
    ("sshd[1]: Accepted publickey for alice from 10.0.0.12 port 50022 ssh2: ED25519 SHA256:x", "auth_success", "alice", "10.0.0.12"),
    ("sshd[1]: Accepted password for deploy from 2001:db8::9 port 50022 ssh2", "auth_success", "deploy", "2001:db8::9"),
    ("sshd[1]: Invalid user test from 203.0.113.15 port 4444", "auth_other", "test", "203.0.113.15"),
    ("sudo: pam_unix(sudo:auth): authentication failure; logname=bob uid=1001 euid=0 tty=/dev/pts/1 ruser=bob rhost=  user=bob",
     "auth_failure", "bob", None),
    ("sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update", "auth_other", "alice", None),
    ("CRON[9]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)", "other", None, None),
])
def test_auth_log_messages(message, event_type, user, ip):
    e = parsers.parse_auth_line(f"Oct 25 02:10:11 web01 {message}", reference_time=REFERENCE_TIME)
    assert e["timestamp"] == "2026-10-25 02:10:11"
    assert e["host"] == "web01"
    assert e["event_type"] == event_type
    assert e["username"] == user
    assert e["source_ip"] == ip


def test_rsyslog_iso_timestamp():
    e = parsers.parse_auth_line(
        "2026-10-25T02:10:11.123456+05:30 web01 sshd[2]: Failed password for root from 203.0.113.1 port 1 ssh2")
    assert e["timestamp"] == "2026-10-24 20:40:11"


def test_auth_log_timezone_applies_to_naive_syslog_time():
    e = parsers.parse_auth_line("Oct 25 10:00:00 web01 sshd[2]: Failed password for root from 1.2.3.4 port 1 ssh2",
                                default_tz="Asia/Kolkata", reference_time=REFERENCE_TIME)
    assert e["timestamp"] == "2026-10-25 04:30:00"


def test_non_syslog_line_raises():
    with pytest.raises(ParseError):
        parsers.parse_auth_line("web01 kernel: this line has no timestamp")


def test_format_detection():
    access = ['1.2.3.4 - - [25/Oct/2026:10:15:32 +0000] "GET / HTTP/1.1" 200 1 "-" "-"'] * 5
    auth = ["Oct 25 02:10:11 web01 sshd[1]: Accepted publickey for a from 10.0.0.1 port 1 ssh2"] * 5
    assert parsers.detect_text_format(access) == "web_access"
    assert parsers.detect_text_format(auth) == "auth_log"
    assert parsers.detect_text_format(access[:2] + auth[:2] + ["junk"] * 3) == "auto"


def test_auto_mode_parses_mixed_lines():
    assert parsers.parse_text_line(
        "Oct 25 02:10:11 web01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2", "auto",
        reference_time=REFERENCE_TIME)["event_type"] == "auth_failure"


# --- CSV ------------------------------------------------------------------
def test_csv_column_aliases():
    mapping = parsers.map_csv_columns(["Time Created", "Client-IP", "User", "Result", "URL", "User Agent", "junk"])
    assert mapping == {
        "Time Created": "timestamp", "Client-IP": "source_ip", "User": "username",
        "Result": "status", "URL": "request_path", "User Agent": "user_agent",
    }


def test_windows_event_ids_map_to_auth_events():
    columns = ["timestamp", "event_id", "username", "source_ip"]
    mapping = parsers.map_csv_columns(columns)
    failed = parsers.parse_csv_record(
        {"timestamp": "2026-10-25T23:00:00Z", "event_id": "4625", "username": "WS01\\Administrator",
         "source_ip": "203.0.113.200"}, mapping)
    assert failed["event_type"] == "auth_failure" and failed["status"] == "failure"
    assert failed["username"] == "Administrator"
    ok = parsers.parse_csv_record({"timestamp": "2026-10-25T23:00:00Z", "event_id": "4624", "username": "priya",
                                   "source_ip": "-"}, mapping)
    assert ok["event_type"] == "auth_success" and ok["source_ip"] is None


def test_csv_web_row_and_missing_fields():
    mapping = parsers.map_csv_columns(["time", "ip", "status_code", "path"])
    e = parsers.parse_csv_record({"time": "2026-10-25 10:00:00", "ip": "1.2.3.4", "status_code": "404",
                                  "path": "/.env"}, mapping)
    assert e["event_type"] == "web_request" and e["http_status"] == 404
    assert e["username"] is None and e["user_agent"] is None


def test_csv_missing_timestamp_raises():
    mapping = parsers.map_csv_columns(["timestamp", "ip"])
    with pytest.raises(ParseError, match="missing timestamp"):
        parsers.parse_csv_record({"timestamp": "", "ip": "1.2.3.4"}, mapping)
