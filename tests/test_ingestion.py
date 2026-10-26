import pytest

from helpers import REFERENCE_TIME
from siem import db
from siem.ingestion import IngestError, ingest_content, ingest_path

ACCESS = '203.0.113.{n} - - [25/Oct/2026:10:15:{s:02d} +0000] "GET /x HTTP/1.1" 200 10 "-" "Mozilla/5.0"'


def test_sample_files_ingest_with_expected_counts(conn, sample_dir):
    access = ingest_path(conn, sample_dir / "access.log")
    assert access.source_type == "web_access"
    assert access.rejected == 6 and access.processed == access.total - 6
    auth = ingest_path(conn, sample_dir / "auth.log", reference_time=REFERENCE_TIME)
    assert auth.source_type == "auth_log"
    assert auth.rejected == 2
    windows = ingest_path(conn, sample_dir / "windows_security.csv")
    assert windows.source_type == "csv"
    assert windows.rejected == 3
    assert set(windows.reasons) == {"wrong number of columns", "missing timestamp", "invalid timestamp"}
    stored = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert stored == access.processed + auth.processed + windows.processed


def test_reuploading_a_file_counts_duplicates(conn, sample_dir):
    first = ingest_path(conn, sample_dir / "access.log")
    second = ingest_path(conn, sample_dir / "access.log")
    assert second.processed == 0
    assert second.duplicates == first.processed
    runs = db.get_ingest_runs(conn)
    assert runs[0]["duplicates"] == first.processed


def test_identical_lines_inside_one_file_are_all_kept(conn):
    line = ACCESS.format(n=1, s=1)
    result = ingest_content(conn, "\n".join([line] * 5), "flood.log")
    assert result.processed == 5 and result.duplicates == 0


def test_partial_overlap_only_stores_new_lines(conn):
    lines = [ACCESS.format(n=i, s=i) for i in range(10)]
    ingest_content(conn, "\n".join(lines[:6]), "part1.log")
    result = ingest_content(conn, "\n".join(lines[3:]), "part2.log")
    assert result.duplicates == 3 and result.processed == 4


def test_blank_and_comment_lines_are_skipped(conn):
    text = "#Fields: whatever\n\n" + ACCESS.format(n=1, s=1) + "\n   \n"
    result = ingest_content(conn, text, "a.log")
    assert result.total == 1 and result.processed == 1


@pytest.mark.parametrize("content, filename, message", [
    (b"", "empty.log", "empty"),
    (b"\x00\x01\x02binary", "bin.log", "binary"),
    (b"hello", "evil.exe", ".log, .txt and .csv"),
    (b"a,b\n1,2\n", "no_time.csv", "no timestamp column"),
])
def test_files_that_are_refused(conn, content, filename, message):
    with pytest.raises(IngestError, match=message):
        ingest_content(conn, content, filename)


def test_rotated_log_names_are_accepted(conn):
    result = ingest_content(conn, ACCESS.format(n=1, s=1), "access.log.1")
    assert result.processed == 1


def test_utf16_csv_from_windows_is_decoded(conn):
    text = "timestamp,event_id,username,source_ip\n2026-10-25T10:00:00Z,4625,admin,203.0.113.9\n"
    result = ingest_content(conn, text.encode("utf-16"), "win.csv")
    assert result.processed == 1
    row = conn.execute("SELECT event_type, username FROM events").fetchone()
    assert tuple(row) == ("auth_failure", "admin")


def test_csv_with_only_a_timestamp_column_does_not_crash(conn):
    result = ingest_content(conn, "time\n2026-10-25 10:00:00\n2026-10-25 10:01:00\n", "min.csv")
    assert result.processed == 2
    assert conn.execute("SELECT DISTINCT event_type FROM events").fetchone()[0] == "other"


def test_missing_ip_is_counted_but_kept(conn):
    text = "Oct 25 10:00:00 web01 sudo:    alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls\n"
    result = ingest_content(conn, text, "auth.log", reference_time=REFERENCE_TIME)
    assert result.processed == 1 and result.missing_ip == 1


def test_rejected_samples_are_reported(conn):
    text = ACCESS.format(n=1, s=1) + "\nthis is junk\n"
    result = ingest_content(conn, text, "a.log", fmt="web_access")
    assert result.rejected == 1
    assert result.samples[0]["line"] == 2 and "junk" in result.samples[0]["raw"]


def test_unknown_format_is_refused(conn):
    with pytest.raises(IngestError):
        ingest_content(conn, "x", "a.log", fmt="evtx")
