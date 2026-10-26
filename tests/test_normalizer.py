from datetime import datetime, timezone

import pytest

from siem.ingestion import normalizer as norm


@pytest.mark.parametrize("raw, tz, expected", [
    ("25/Oct/2026:10:15:32 +0000", "UTC", "2026-10-25 10:15:32"),
    ("25/Oct/2026:10:15:32 +0530", "UTC", "2026-10-25 04:45:32"),        # offset wins over default tz
    ("2026-10-25 10:15:32", "Asia/Kolkata", "2026-10-25 04:45:32"),      # naive -> default tz
    ("2026-10-25T10:15:32Z", "Asia/Kolkata", "2026-10-25 10:15:32"),
    ("2026-10-25T10:15:32.123456+02:00", "UTC", "2026-10-25 08:15:32"),
    ("10/25/2026 10:15:32 PM", "UTC", "2026-10-25 22:15:32"),           # Windows Event Viewer
    ("1792923332", "UTC", "2026-10-25 10:15:32"),                         # epoch seconds
])
def test_timestamp_formats(raw, tz, expected):
    assert norm.normalize_timestamp(raw, tz) == expected


@pytest.mark.parametrize("raw", [None, "", "-", "not a date", "99/Foo/2026:25:61:00 +0000", "0001-01-01 00:00:00"])
def test_bad_timestamps_return_none(raw):
    assert norm.normalize_timestamp(raw) is None


def test_syslog_timestamp_gets_year_from_reference():
    ref = datetime(2026, 10, 26, tzinfo=timezone.utc)
    assert norm.normalize_timestamp("Oct 25 02:10:11", "UTC", ref) == "2026-10-25 02:10:11"
    assert norm.normalize_timestamp("Oct  5 02:10:11", "UTC", ref) == "2026-10-05 02:10:11"


def test_syslog_december_logs_read_in_january_use_previous_year():
    ref = datetime(2027, 1, 2, tzinfo=timezone.utc)
    assert norm.normalize_timestamp("Dec 31 23:59:00", "UTC", ref) == "2026-12-31 23:59:00"


def test_unknown_timezone_falls_back_to_utc():
    assert norm.normalize_timestamp("2026-10-25 10:00:00", "Mars/Olympus") == "2026-10-25 10:00:00"


@pytest.mark.parametrize("raw, expected", [
    ("203.0.113.5", "203.0.113.5"),
    ("203.0.113.5:443", "203.0.113.5"),
    ("[2001:db8::1]:22", "2001:db8::1"),
    ("2001:db8::1", "2001:db8::1"),
    ("::ffff:10.0.0.1", "10.0.0.1"),
    (" 10.0.0.7 ", "10.0.0.7"),
    ("-", None),
    ("999.1.1.1", None),
    ("localhost", None),
    (None, None),
])
def test_ip_normalization(raw, expected):
    assert norm.normalize_ip(raw) == expected


def test_username_strips_domain_and_placeholders():
    assert norm.normalize_username("CORP\\alice") == "alice"
    assert norm.normalize_username("  bob ") == "bob"
    assert norm.normalize_username("-") is None


@pytest.mark.parametrize("value, status, expected", [
    ("Failed", None, "auth_failure"),
    ("login_success", None, "auth_success"),
    ("login", "failure", "auth_failure"),
    ("authentication", "success", "auth_success"),
    ("4625", None, "auth_failure"),
    (None, None, "other"),
    (None, "failure", "auth_failure"),
    ("something-new", None, "other"),
])
def test_event_type_mapping(value, status, expected):
    assert norm.normalize_event_type(value, status) == expected


def test_event_type_inferred_from_http_status():
    assert norm.normalize_event_type(None, None, 404) == "web_request"


def test_http_status_range():
    assert norm.normalize_http_status("404") == 404
    assert norm.normalize_http_status("999") is None
    assert norm.normalize_http_status("abc") is None


def test_status_synonyms():
    assert norm.normalize_status("Succeeded") == "success"
    assert norm.normalize_status("DENIED") == "failure"
    assert norm.normalize_status("403") == "403"


def test_clean_text_removes_control_characters():
    assert norm.clean_text("abc\x1b[31mred") == "abc?[31mred"
