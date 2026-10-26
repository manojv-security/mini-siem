"""Flask routes, uploads, triage and web hardening."""

import io
import re

import pytest

from siem import create_app

ACCESS_LINES = "\n".join(
    f'203.0.113.77 - - [25/Oct/2026:14:05:{i:02d} +0000] "GET /admin{i} HTTP/1.1" 404 10 "-" "Nikto/2.5.0"'
    for i in range(30)
)


def upload(client, content: str, name="access.log", **fields):
    data = {"logfiles": (io.BytesIO(content.encode()), name), "format": "auto", "timezone": "UTC",
            "run_detection": "on", **fields}
    return client.post("/upload", data=data, content_type="multipart/form-data")


@pytest.mark.parametrize("url", ["/", "/upload", "/events", "/alerts", "/rules", "/api/stats",
                                 "/api/alerts", "/api/events", "/api/health"])
def test_pages_load_on_an_empty_database(client, url):
    assert client.get(url).status_code == 200


def test_upload_shows_counts_and_creates_alerts(client):
    response = upload(client, ACCESS_LINES + "\nnot a log line\n")
    html = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "Import results" in html and ">30<" in html  # processed
    stats = client.get("/api/stats").get_json()
    assert stats["kpis"]["total_events"] == 30
    assert stats["kpis"]["total_alerts"] >= 2  # error spike + user agent at least
    assert any(a["rule_id"] == "suspicious_user_agent" for a in client.get("/api/alerts").get_json())


def test_upload_rejects_bad_extension_and_timezone(client):
    html = upload(client, "x", name="malware.exe").get_data(as_text=True)
    assert "Refused" in html
    response = upload(client, ACCESS_LINES, timezone="Not/AZone")
    assert response.status_code == 302


def test_load_samples_then_browse(client):
    html = client.post("/samples/load").get_data(as_text=True)
    assert "access.log" in html and "windows_security.csv" in html
    alerts = client.get("/api/alerts").get_json()
    assert len(alerts) >= 15
    alert_id = alerts[0]["id"]
    detail = client.get(f"/alerts/{alert_id}")
    assert detail.status_code == 200 and "Evidence" in detail.get_data(as_text=True)
    assert client.get("/events?source_ip=203.0.113.77&q=env").status_code == 200
    assert client.get("/alerts?severity=critical&status=open").status_code == 200
    assert client.get("/alerts/99999").status_code == 404


def test_triage_updates_status_and_escapes_notes(client):
    client.post("/samples/load")
    alert_id = client.get("/api/alerts").get_json()[0]["id"]
    response = client.post(f"/alerts/{alert_id}", data={"status": "false_positive", "analyst_notes": "<b>x</b>"})
    assert response.status_code == 302
    html = client.get(f"/alerts/{alert_id}").get_data(as_text=True)
    assert "&lt;b&gt;x&lt;/b&gt;" in html and "<b>x</b>" not in html
    bad = client.post(f"/alerts/{alert_id}", data={"status": "deleted"}, follow_redirects=True)
    assert "invalid status" in bad.get_data(as_text=True)


def test_csv_export_neutralises_formulas(client, app):
    client.post("/samples/load")
    alert_id = client.get("/api/alerts").get_json()[0]["id"]
    client.post(f"/alerts/{alert_id}", data={"status": "open", "analyst_notes": "=HYPERLINK(\"http://evil\")"})
    csv_text = client.get("/alerts/export.csv").get_data(as_text=True)
    assert csv_text.startswith("id,severity,status")
    assert "'=HYPERLINK" in csv_text


def test_rules_page_validation(client):
    response = client.post("/rules", data={"brute_force__threshold": "-5", "global__allowlist_ips": "not-an-ip"})
    html = response.get_data(as_text=True)
    assert response.status_code == 400
    assert "must be at least" in html and "not an IP address" in html


def test_rules_reset(client, app):
    assert client.post("/rules/reset").status_code == 302


def test_reset_requires_confirmation(client):
    client.post("/samples/load")
    client.post("/reset", data={"confirm": "nope"})
    assert client.get("/api/stats").get_json()["kpis"]["total_events"] > 0
    client.post("/reset", data={"confirm": "DELETE"})
    assert client.get("/api/stats").get_json()["kpis"]["total_events"] == 0


def test_detect_redirect_cannot_leave_the_site(client):
    response = client.post("/detect", data={"next": "https://evil.example/"})
    assert response.headers["Location"].endswith("/alerts")


def test_security_headers(client):
    headers = client.get("/").headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_csrf_is_enforced_when_enabled(tmp_path):
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "c.db"), "RULES_PATH": str(tmp_path / "r.json"),
                      "SECRET_KEY": "k", "CSRF_ENABLED": True})
    client = app.test_client()
    assert client.post("/detect").status_code == 400
    page = client.get("/upload").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    assert client.post("/detect", data={"csrf_token": token}).status_code == 302
