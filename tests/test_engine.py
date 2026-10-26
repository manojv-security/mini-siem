"""Alert persistence and de-duplication across detection runs."""

from helpers import REFERENCE_TIME, at
from siem import db
from siem.detection import run_detection
from siem.ingestion import ingest_content, ingest_path


def ssh_failures(ip, count, start, step=10):
    lines = []
    for i in range(count):
        ts = at(start + i * step)  # 'YYYY-MM-DD HH:MM:SS'
        lines.append(f"{ts.replace(' ', 'T')}+00:00 web01 sshd[{i}]: Failed password for root from {ip} port {i} ssh2")
    return "\n".join(lines)


def test_rerunning_detection_creates_no_duplicates(conn, config):
    ingest_content(conn, ssh_failures("203.0.113.15", 10, 0), "auth.log")
    first = run_detection(conn, config)
    second = run_detection(conn, config)
    assert first.new_alerts >= 1
    assert second.new_alerts == 0 and second.updated_alerts == 0
    assert conn.execute("SELECT COUNT(*) FROM alerts WHERE rule_id='brute_force'").fetchone()[0] == 1


def test_ongoing_attack_updates_the_same_alert(conn, config):
    ingest_content(conn, ssh_failures("203.0.113.15", 10, 0), "part1.log")
    run_detection(conn, config)
    ingest_content(conn, ssh_failures("203.0.113.15", 10, 100), "part2.log")  # continues the attack
    summary = run_detection(conn, config)
    rows = db.query_alerts(conn, {"rule_id": "brute_force"})
    assert len(rows) == 1 and summary.updated_alerts >= 1
    assert rows[0]["event_count"] == 20
    assert rows[0]["last_seen"] == at(190)


def test_new_attack_later_is_a_new_alert(conn, config):
    ingest_content(conn, ssh_failures("203.0.113.15", 10, 0), "a.log")
    ingest_content(conn, ssh_failures("203.0.113.15", 10, 7200), "b.log")
    run_detection(conn, config)
    assert len(db.query_alerts(conn, {"rule_id": "brute_force"})) == 2


def test_triage_survives_rerun_and_reopens_on_new_activity(conn, config):
    ingest_content(conn, ssh_failures("203.0.113.15", 10, 0), "a.log")
    run_detection(conn, config)
    alert = db.query_alerts(conn, {"rule_id": "brute_force"})[0]
    db.update_alert_triage(conn, alert["id"], "resolved", "blocked at firewall")
    conn.commit()

    run_detection(conn, config)
    assert db.get_alert(conn, alert["id"])["status"] == "resolved"

    ingest_content(conn, ssh_failures("203.0.113.15", 10, 120), "c.log")
    run_detection(conn, config)
    reopened = db.get_alert(conn, alert["id"])
    assert reopened["status"] == "open"
    assert "blocked at firewall" in reopened["analyst_notes"] and "Re-opened" in reopened["analyst_notes"]


def test_alert_evidence_points_at_real_events(conn, config):
    ingest_content(conn, ssh_failures("203.0.113.15", 6, 0), "a.log")
    run_detection(conn, config)
    alert = db.query_alerts(conn, {"rule_id": "brute_force"})[0]
    rows, total = db.query_events(conn, {"ids": alert["event_ids"]})
    assert total == 6 and all(r["source_ip"] == "203.0.113.15" for r in rows)


def test_sample_data_triggers_every_rule(conn, config, sample_dir):
    for name in ("access.log", "auth.log", "windows_security.csv"):
        ingest_path(conn, sample_dir / name, reference_time=REFERENCE_TIME)
    summary = run_detection(conn, config)
    assert summary.errors == {}
    assert all(count for count in summary.per_rule.values()), summary.per_rule
    by_rule = {}
    for a in db.query_alerts(conn):
        by_rule.setdefault(a["rule_id"], set()).add(a["source_ip"] or a["username"])
    assert "203.0.113.15" in by_rule["brute_force"]
    assert "203.0.113.200" in by_rule["brute_force"]
    assert "203.0.113.50" in by_rule["request_flood"]
    assert "203.0.113.77" in by_rule["sensitive_path_probing"]
    assert "203.0.113.99" in by_rule["suspicious_user_agent"]
    assert "203.0.113.120" in by_rule["http_error_spike"]
    compromised = {a["username"] for a in db.query_alerts(conn, {"rule_id": "fail_then_success"})}
    assert compromised == {"deploy", "bob"}
    probe = db.query_alerts(conn, {"rule_id": "sensitive_path_probing"})[0]
    assert probe["severity"] == "critical" and "/.env" in probe["details"]["successful_hits"]
