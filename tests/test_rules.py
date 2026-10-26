import random

import pytest

from helpers import event, events_frame
from siem.detection import RULES_BY_ID, run_rules


def detect(rule_id, records, config):
    return RULES_BY_ID[rule_id].detect(events_frame(records), config["rules"][rule_id])


def failures(ip, count, start=0, step=10, users=("root",)):
    return [event(start + i * step, "auth_failure", source_ip=ip, username=users[i % len(users)], status="failure")
            for i in range(count)]


def requests(ip, count, start=0, step=1.0, path="/", status=200, agent="Mozilla/5.0"):
    return [event(start + i * step, source_ip=ip, request_path=path, http_status=status, status=str(status),
                  user_agent=agent) for i in range(count)]


# --- 1. brute force ---------------------------------------------------------
def test_brute_force_detected(config):
    alerts = detect("brute_force", failures("203.0.113.15", 6, step=20), config)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.source_ip == "203.0.113.15" and a.event_count == 6 and a.severity == "high"
    assert a.mitre_technique.startswith("T1110")


def test_brute_force_below_threshold_or_too_slow(config):
    assert detect("brute_force", failures("203.0.113.15", 4, step=5), config) == []
    # 10 failures, but one every 2 minutes: never 5 inside a 5-minute window.
    assert detect("brute_force", failures("203.0.113.15", 10, step=120), config) == []


def test_long_attack_produces_one_alert_not_many(config):
    alerts = detect("brute_force", failures("203.0.113.15", 300, step=3), config)
    assert len(alerts) == 1 and alerts[0].event_count == 300


def test_password_spraying_is_labelled_and_escalated(config):
    users = ("root", "admin", "test", "oracle", "guest")
    a = detect("brute_force", failures("203.0.113.15", 10, users=users), config)[0]
    assert a.details["pattern"] == "password_spraying"
    assert a.severity == "critical"
    assert a.title.startswith("Password spraying")


def test_thresholds_are_configurable(config):
    config["rules"]["brute_force"]["threshold"] = 3
    assert len(detect("brute_force", failures("1.2.3.4", 3), config)) == 1


def test_unsorted_logs_give_the_same_result(config):
    records = failures("203.0.113.15", 8, step=15) + failures("198.51.100.1", 8, start=5000, step=15)
    shuffled = records[:]
    random.Random(1).shuffle(shuffled)
    ordered = [(a.source_ip, a.first_seen, a.event_count) for a in detect("brute_force", records, config)]
    unordered = [(a.source_ip, a.first_seen, a.event_count) for a in detect("brute_force", shuffled, config)]
    assert sorted(ordered) == sorted(unordered)


# --- 2. suspicious IP --------------------------------------------------------
def baseline_traffic(n_ips=10, per_ip=50):
    records = []
    for i in range(n_ips):
        records += requests(f"198.51.100.{i + 1}", per_ip + i, start=i * 7, step=60)
    return records


def test_suspicious_ip_request_outlier(config):
    records = baseline_traffic() + requests("203.0.113.50", 900, step=0.5)
    alerts = detect("suspicious_ip", records, config)
    assert [a.source_ip for a in alerts] == ["203.0.113.50"]
    assert alerts[0].details["outlier_score"] > 3.5


def test_suspicious_ip_many_failed_logins(config):
    alerts = detect("suspicious_ip", failures("203.0.113.15", 15, step=600), config)
    assert alerts and "15 failed logins" in alerts[0].description


def test_suspicious_ip_error_ratio_and_severity_escalation(config):
    records = baseline_traffic() + requests("203.0.113.120", 200, step=1, status=404)
    a = [a for a in detect("suspicious_ip", records, config) if a.source_ip == "203.0.113.120"][0]
    assert len(a.details["reasons"]) == 2  # volume outlier + error ratio
    assert a.severity == "high"


def test_normal_traffic_is_not_suspicious(config):
    assert detect("suspicious_ip", baseline_traffic(), config) == []


# --- 3. HTTP error spike ------------------------------------------------------
def test_http_error_spike(config):
    records = requests("203.0.113.77", 25, step=2, status=404) + requests("203.0.113.77", 5, start=60, status=403)
    a = detect("http_error_spike", records, config)[0]
    assert a.details["status_breakdown"] == {"404": 25, "403": 5}


def test_http_errors_ignore_other_codes_and_slow_rates(config):
    assert detect("http_error_spike", requests("1.2.3.4", 50, step=1, status=500), config) == []
    assert detect("http_error_spike", requests("1.2.3.4", 50, step=30, status=404), config) == []


# --- 4. request flood ---------------------------------------------------------
def test_request_flood(config):
    a = detect("request_flood", requests("203.0.113.50", 300, step=0.25), config)[0]
    assert a.event_count == 300 and a.details["peak_in_window"] >= 120


def test_steady_traffic_is_not_a_flood(config):
    assert detect("request_flood", requests("10.0.0.1", 500, step=1), config) == []  # 61/min


# --- 5. sensitive paths --------------------------------------------------------
def test_sensitive_path_probing_with_url_encoding(config):
    records = [
        event(0, source_ip="203.0.113.77", request_path="/wp-login.php", http_status=404),
        event(5, source_ip="203.0.113.77", request_path="/%2e%65%6e%76", http_status=404),  # /.env
        event(9, source_ip="203.0.113.77", request_path="/.git/config", http_status=403),
    ]
    a = detect("sensitive_path_probing", records, config)[0]
    assert a.severity == "high"
    assert set(a.details["matched_patterns"]) == {"/wp-login.php", "/.env", "/.git"}


def test_successful_sensitive_hit_is_critical(config):
    records = [event(i, source_ip="203.0.113.77", request_path=p, http_status=s)
               for i, (p, s) in enumerate([("/admin", 403), ("/.env", 200), ("/phpmyadmin/", 404)])]
    a = detect("sensitive_path_probing", records, config)[0]
    assert a.severity == "critical" and a.details["successful_hits"] == ["/.env"]


def test_normal_paths_are_not_probes(config):
    records = [event(i, source_ip="10.0.0.1", request_path=p, http_status=200)
               for i, p in enumerate(["/", "/products", "/cart", "/login", "/static/app.js"] * 5)]
    assert detect("sensitive_path_probing", records, config) == []


# --- 6. suspicious user agents --------------------------------------------------
def test_attack_tool_user_agent_is_high(config):
    a = detect("suspicious_user_agent", requests("203.0.113.99", 3, agent="sqlmap/1.7.2#stable"), config)[0]
    assert a.severity == "high" and "sqlmap" in a.details["matched_patterns"]


def test_scripted_client_is_low_and_browsers_ignored(config):
    records = requests("10.0.0.5", 3, agent="curl/8.4.0") + requests("10.0.0.6", 50, agent="Mozilla/5.0 Chrome/129")
    alerts = detect("suspicious_user_agent", records, config)
    assert [(a.source_ip, a.severity) for a in alerts] == [("10.0.0.5", "low")]


def test_empty_user_agent_flag_can_be_disabled(config):
    records = requests("203.0.113.33", 2, agent=None)
    assert len(detect("suspicious_user_agent", records, config)) == 1
    config["rules"]["suspicious_user_agent"]["flag_empty_user_agent"] = False
    assert detect("suspicious_user_agent", records, config) == []


def test_several_tools_from_one_ip_make_one_alert(config):
    records = requests("203.0.113.77", 3, agent="Nikto/2.5") + requests("203.0.113.77", 3, start=10, agent="sqlmap/1.7")
    alerts = detect("suspicious_user_agent", records, config)
    assert len(alerts) == 1 and set(alerts[0].details["matched_patterns"]) == {"nikto", "sqlmap"}


# --- 7. failures followed by success ------------------------------------------
def success(seconds, ip, user):
    return event(seconds, "auth_success", source_ip=ip, username=user, status="success")


def test_failures_then_success(config):
    records = failures("198.51.100.200", 4, users=("deploy",)) + [success(60, "198.51.100.200", "deploy")]
    a = detect("fail_then_success", records, config)[0]
    assert a.username == "deploy" and a.severity == "critical"
    assert a.event_count == 5 and a.details["success_from_new_ip"] is False


def test_single_typo_is_not_an_alert(config):
    records = failures("10.0.0.9", 1, users=("bob",)) + [success(5, "10.0.0.9", "bob")]
    assert detect("fail_then_success", records, config) == []


def test_failures_outside_lookback_are_ignored(config):
    records = failures("1.2.3.4", 5, step=10, users=("bob",)) + [success(3600, "1.2.3.4", "bob")]
    assert detect("fail_then_success", records, config) == []


def test_distributed_attack_is_caught_by_username(config):
    records = []
    for i, ip in enumerate(["192.0.2.10", "192.0.2.11", "192.0.2.12"]):
        records += failures(ip, 1, start=i * 20, users=("bob",))
    records.append(success(90, "192.0.2.44", "bob"))
    a = detect("fail_then_success", records, config)[0]
    assert a.details["success_from_new_ip"] is True and len(a.details["failure_ips"]) == 3
    config["rules"]["fail_then_success"]["correlate_by"] = "username_and_ip"
    assert detect("fail_then_success", records, config) == []


def test_one_attack_two_successes_alerts_once(config):
    records = failures("1.2.3.4", 4, users=("bob",)) + [success(50, "1.2.3.4", "bob"), success(55, "1.2.3.4", "bob")]
    assert len(detect("fail_then_success", records, config)) == 1


# --- engine-level behaviour ------------------------------------------------------
def test_allowlist_suppresses_all_rules(config):
    records = failures("10.0.0.5", 20) + requests("10.0.0.5", 3, agent="curl/8")
    config["global"]["allowlist_ips"] = ["10.0.0.0/24"]
    alerts, per_rule, errors = run_rules(events_frame(records), config)
    assert alerts == [] and errors == {}


def test_disabled_rule_is_skipped(config):
    config["rules"]["brute_force"]["enabled"] = False
    alerts, per_rule, _ = run_rules(events_frame(failures("1.2.3.4", 20)), config)
    assert per_rule["brute_force"] is None
    assert all(rule.id != "brute_force" for rule, _ in alerts)


def test_missing_columns_do_not_crash(config):
    records = [{"timestamp": "2026-10-25 10:00:00"}, {"timestamp": "garbage"}, {"event_type": "web_request"}]
    alerts, _, errors = run_rules(events_frame(records), config)
    assert errors == {} and alerts == []


@pytest.mark.parametrize("rule_id", list(RULES_BY_ID))
def test_every_rule_documents_itself(rule_id):
    rule = RULES_BY_ID[rule_id]
    assert rule.name and rule.how_it_works and rule.false_positives and rule.recommendation
    assert rule.mitre_technique.startswith("T")
    assert set(rule.defaults()) >= {"enabled", "severity"}
