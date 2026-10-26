"""Synthetic but realistic sample logs for demos and tests.

All addresses come from private ranges (10.0.0.0/8) or the RFC 5737
documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), so
the samples never point at a real person's IP.

Built-in attack scenarios (all times UTC on the base date):

=====  ================  ===========================================  =========================================
Label  Source            What happens                                  Rules it should trigger
=====  ================  ===========================================  =========================================
A      203.0.113.50      HTTP flood, ~4 req/s for 3 min (10:30)       request_flood, suspicious_ip
B      203.0.113.77      Nikto scan; /.env answered 200 (14:05)        sensitive_path_probing (critical),
                                                                       http_error_spike, suspicious_user_agent,
                                                                       suspicious_ip
C      203.0.113.99      sqlmap injection attempts (16:20)             suspicious_user_agent
D      203.0.113.120     scripted POST /login, all 401 (19:00)         http_error_spike, suspicious_user_agent
E      203.0.113.15      SSH password spraying, ~90 tries (02:10)      brute_force (spraying), suspicious_ip
F      198.51.100.200    6 SSH failures then success for 'deploy'      brute_force, fail_then_success
G      192.0.2.10-.13    distributed failures for 'bob', success       fail_then_success
                         from 192.0.2.44 (21:00)
H      203.0.113.200     RDP brute force, Windows 4625 (23:00)         brute_force
-      10.0.0.5          curl health check every 5 min                 suspicious_user_agent (low) - a tuning
                                                                       example: allow-list it
=====  ================  ===========================================  =========================================
"""

from __future__ import annotations

import csv
import io
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_DATE = datetime(2026, 10, 25, tzinfo=timezone.utc)

BROWSER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
]
CRAWLER_AGENT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

NORMAL_PATHS = [
    ("/", 200, 14), ("/index.html", 200, 4), ("/products", 200, 10), ("/products/{id}", 200, 14),
    ("/cart", 200, 5), ("/checkout", 200, 2), ("/login", 200, 4), ("/about", 200, 2),
    ("/contact", 200, 2), ("/static/css/main.css", 200, 9), ("/static/js/app.js", 200, 9),
    ("/images/product-{id}.jpg", 200, 10), ("/api/products?page={page}", 200, 6),
    ("/api/cart", 200, 3), ("/favicon.ico", 404, 2), ("/images/banner-old.png", 404, 1),
]

SCANNER_PATHS = [
    "/admin", "/admin/login.php", "/administrator/", "/wp-login.php", "/wp-admin/", "/xmlrpc.php",
    "/.env", "/.git/HEAD", "/.git/config", "/.svn/entries", "/.htaccess", "/phpmyadmin/",
    "/pma/", "/config.php", "/web.config", "/server-status", "/backup.zip", "/backup/db.sql",
    "/cgi-bin/test.cgi", "/actuator/env", "/console", "/shell.php", "/etc/passwd",
    "/index.php?page=../../../../etc/passwd", "/.aws/credentials", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
]
WORDLIST = ["old", "test", "dev", "tmp", "uploads", "files", "private", "secret", "db", "data",
            "logs", "api/v1", "api/v2", "staging", "beta", "include", "lib", "scripts", "temp", "www"]


def _apache_ts(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def _access_line(ip, dt, method, path, status, size, agent, referer="-", user="-"):
    return f'{ip} - {user} [{_apache_ts(dt)}] "{method} {path} HTTP/1.1" {status} {size} "{referer}" "{agent}"'


def _normal_ip_pool(rng: random.Random):
    pool = [f"10.0.{rng.randint(1, 3)}.{rng.randint(10, 250)}" for _ in range(12)]
    pool += [f"198.51.100.{n}" for n in rng.sample(range(2, 180), 22)]
    pool += [f"192.0.2.{n}" for n in rng.sample(range(100, 250), 10)]
    # Some visitors are much busier than others (log-normal weights).
    weights = [rng.lognormvariate(0, 0.6) for _ in pool]
    return pool, weights


def generate_access_log(rng: random.Random, base: datetime = BASE_DATE) -> list[str]:
    entries: list[tuple[datetime, str]] = []
    pool, weights = _normal_ip_pool(rng)
    agent_for = {ip: rng.choice(BROWSER_AGENTS) for ip in pool}
    paths, statuses, path_weights = zip(*NORMAL_PATHS)

    # --- normal browsing ----------------------------------------------------
    for _ in range(4200):
        ip = rng.choices(pool, weights)[0]
        dt = base + timedelta(seconds=rng.randint(0, 86399))
        index = rng.choices(range(len(paths)), path_weights)[0]
        path = paths[index].format(id=rng.randint(1, 60), page=rng.randint(1, 8))
        status = statuses[index]
        method = "GET"
        if path == "/login" and rng.random() < 0.4:
            method, status = "POST", rng.choices([302, 401], [0.9, 0.1])[0]
        elif status == 200 and rng.random() < 0.08:
            status = 304
        size = 0 if status in (302, 304) else rng.randint(300, 48000)
        entries.append((dt, _access_line(ip, dt, method, path, status, size, agent_for[ip],
                                         referer="https://shop.example.com/")))

    # Search-engine crawler: steady and well behaved.
    for minute in range(0, 1440, 9):
        dt = base + timedelta(minutes=minute, seconds=rng.randint(0, 59))
        path = rng.choice(["/", "/products", f"/products/{rng.randint(1, 60)}", "/about"])
        entries.append((dt, _access_line("198.51.100.250", dt, "GET", path, 200, rng.randint(2000, 30000),
                                         CRAWLER_AGENT)))

    # Internal health check with curl (tuning example).
    for minute in range(0, 1440, 5):
        dt = base + timedelta(minutes=minute, seconds=2)
        entries.append((dt, _access_line("10.0.0.5", dt, "GET", "/health", 200, 17, "curl/8.4.0")))

    # --- A: request flood ---------------------------------------------------
    start = base + timedelta(hours=10, minutes=30)
    for i in range(720):
        dt = start + timedelta(seconds=i // 4)
        status = 503 if i > 600 and rng.random() < 0.5 else 200
        path = rng.choice([f"/api/products?page={rng.randint(1, 500)}", f"/search?q=item{rng.randint(1, 999)}", "/"])
        entries.append((dt, _access_line("203.0.113.50", dt, "GET", path, status, rng.randint(200, 9000),
                                         BROWSER_AGENTS[0])))

    # --- B: Nikto scan with sensitive paths ----------------------------------
    start = base + timedelta(hours=14, minutes=5)
    nikto = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:{test:06d})"
    probes = SCANNER_PATHS + [f"/{word}/" for word in WORDLIST] * 6
    rng.shuffle(probes)
    for i, path in enumerate(probes):
        dt = start + timedelta(seconds=int(i * 1.6))
        if path == "/.env":
            status, size = 200, 1184          # misconfigured server leaks .env
        elif path.startswith(("/admin", "/server-status", "/.htaccess")):
            status, size = 403, 199
        else:
            status, size = 404, 196
        entries.append((dt, _access_line("203.0.113.77", dt, "GET", path, status, size,
                                         nikto.format(test=rng.randint(1, 999999)))))

    # --- C: sqlmap ------------------------------------------------------------
    start = base + timedelta(hours=16, minutes=20)
    payloads = ["1%27", "1%20AND%201%3D1", "1%20AND%201%3D2", "1%27%20OR%20%271%27%3D%271",
                "1%20UNION%20ALL%20SELECT%20NULL--", "1%3BSELECT%20SLEEP(5)--", "1)%20AND%20(SELECT%201)"]
    for i in range(45):
        dt = start + timedelta(seconds=i * 3)
        status = rng.choice([200, 200, 500])
        entries.append((dt, _access_line("203.0.113.99", dt, "GET", f"/products?id={rng.choice(payloads)}",
                                         status, rng.randint(150, 5000),
                                         "sqlmap/1.7.2#stable (https://sqlmap.org)")))

    # --- D: scripted login guessing over HTTP ----------------------------------
    start = base + timedelta(hours=19)
    for i in range(60):
        dt = start + timedelta(seconds=i * 4)
        entries.append((dt, _access_line("203.0.113.120", dt, "POST", "/login", 401, 64,
                                         "python-requests/2.31.0")))

    # --- odd but valid: TLS handshake sent to the HTTP port ---------------------
    dt = base + timedelta(hours=7, minutes=12, seconds=5)
    entries.append((dt, f'203.0.113.33 - - [{_apache_ts(dt)}] "\\x16\\x03\\x01\\x02\\x00\\x01\\x00\\x01\\xfc\\x03\\x03" 400 157 "-" "-"'))

    entries.sort(key=lambda item: item[0])
    lines = [line for _, line in entries]

    # --- malformed records (should be rejected, not crash anything) -----------
    malformed = [
        "GET /index.html HTTP/1.1",
        '203.0.113.5 - - [99/Foo/2026:25:61:00 +0000] "GET / HTTP/1.1" 200 12 "-" "-"',
        '198.51.100.7 - - [25/Oct/2026:11:00:01 +0000] "GET /products HT',
        "------------------------------------------------",
        '{"msg": "this is a JSON fragment, not an access log"}',
        "lorem ipsum dolor sit amet",
    ]
    for line in malformed:
        lines.insert(rng.randint(1, len(lines) - 1), line)
    return lines


def _syslog_ts(dt: datetime) -> str:
    return dt.strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1) if dt.day < 10 else dt.strftime("%b %d %H:%M:%S")


def generate_auth_log(rng: random.Random, base: datetime = BASE_DATE) -> list[str]:
    entries: list[tuple[datetime, str]] = []
    pid = [3000]

    def add(dt, process, message, with_pid=True):
        pid[0] += rng.randint(1, 7)
        proc = f"{process}[{pid[0]}]" if with_pid else process
        entries.append((dt, f"{_syslog_ts(dt)} web01 {proc}: {message}"))

    # --- normal activity ------------------------------------------------------
    staff = {"alice": "10.0.1.21", "bob": "10.0.1.34", "deploy": "10.0.2.15", "ubuntu": "10.0.2.40"}
    for _ in range(70):
        user = rng.choice(list(staff))
        dt = base + timedelta(seconds=rng.randint(6 * 3600, 21 * 3600))
        port = rng.randint(40000, 65000)
        add(dt, "sshd", f"Accepted publickey for {user} from {staff[user]} port {port} ssh2: ED25519 SHA256:k3yF1ngerPr1nt{rng.randint(10, 99)}")
        add(dt + timedelta(seconds=1), "systemd-logind", f"New session {rng.randint(100, 999)} of user {user}.", with_pid=True)
    for hour in range(24):
        dt = base + timedelta(hours=hour, minutes=17)
        add(dt, "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
        add(dt + timedelta(seconds=1), "CRON", "pam_unix(cron:session): session closed for user root")
    for _ in range(12):
        dt = base + timedelta(seconds=rng.randint(8 * 3600, 20 * 3600))
        cmd = rng.choice(["/usr/bin/systemctl restart nginx", "/usr/bin/apt update", "/usr/bin/tail -f /var/log/nginx/access.log"])
        add(dt, "sudo", f"   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND={cmd}", with_pid=False)
    # A typo: one failure then success - must NOT be an alert.
    dt = base + timedelta(hours=9, minutes=3)
    add(dt, "sshd", "Failed password for bob from 10.0.1.34 port 51234 ssh2")
    add(dt + timedelta(seconds=6), "sshd", "Accepted password for bob from 10.0.1.34 port 51240 ssh2")
    add(base + timedelta(hours=11, minutes=42), "sudo",
        "pam_unix(sudo:auth): authentication failure; logname=bob uid=1001 euid=0 tty=/dev/pts/1 ruser=bob rhost=  user=bob")

    # --- E: password spraying from one IP -------------------------------------
    start = base + timedelta(hours=2, minutes=10)
    users = ["root", "admin", "test", "oracle", "postgres", "ubuntu", "guest", "user", "ftp", "git"]
    for i in range(90):
        dt = start + timedelta(seconds=i * 8 + rng.randint(0, 3))
        user = users[i % len(users)]
        port = rng.randint(30000, 60000)
        if user in ("root", "ubuntu"):
            add(dt, "sshd", f"Failed password for {user} from 203.0.113.15 port {port} ssh2")
        else:
            add(dt, "sshd", f"Invalid user {user} from 203.0.113.15 port {port}")
            add(dt, "sshd", f"Failed password for invalid user {user} from 203.0.113.15 port {port} ssh2")
        if i % 6 == 5:
            add(dt + timedelta(seconds=1), "sshd", f"Connection closed by authenticating user {user} 203.0.113.15 port {port} [preauth]")

    # --- F: brute force that succeeds ----------------------------------------
    start = base + timedelta(hours=3, minutes=40)
    for i in range(6):
        add(start + timedelta(seconds=i * 25), "sshd",
            f"Failed password for deploy from 198.51.100.200 port {50100 + i} ssh2")
    add(start + timedelta(seconds=170), "sshd", "Accepted password for deploy from 198.51.100.200 port 50107 ssh2")
    add(start + timedelta(seconds=171), "systemd-logind", "New session 666 of user deploy.")

    # --- G: distributed guessing for one account ------------------------------
    start = base + timedelta(hours=21)
    step = 0
    for ip in ("192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13"):
        for _ in range(2):
            add(start + timedelta(seconds=step * 55), "sshd",
                f"Failed password for bob from {ip} port {rng.randint(30000, 60000)} ssh2")
            step += 1
    add(start + timedelta(seconds=step * 55 + 30), "sshd",
        f"Accepted password for bob from 192.0.2.44 port {rng.randint(30000, 60000)} ssh2")

    entries.sort(key=lambda item: item[0])
    lines = [line for _, line in entries]
    lines.insert(len(lines) // 2, "web01 kernel: this line has no timestamp")
    lines.insert(len(lines) // 3, "Oct 32 25:99:00 web01 sshd[1]: impossible timestamp")
    return lines


def generate_windows_csv(rng: random.Random, base: datetime = BASE_DATE) -> str:
    """Windows Security log export (4624 / 4625), newest first like Event Viewer."""
    rows = []
    users = {"priya": "10.0.3.11", "rahul": "10.0.3.12", "svc_backup": "10.0.3.50", "WS-HR01\\meera": "10.0.3.14"}
    for _ in range(80):
        user = rng.choice(list(users))
        dt = base + timedelta(seconds=rng.randint(7 * 3600, 20 * 3600))
        logon_type = rng.choice([2, 3, 3, 10])
        ip = users[user] if logon_type != 2 else "-"
        rows.append([dt, 4624, user, ip, logon_type, "success", "WS-FILE01"])
    for _ in range(4):  # occasional typos
        user = rng.choice(["priya", "rahul"])
        dt = base + timedelta(seconds=rng.randint(7 * 3600, 20 * 3600))
        rows.append([dt, 4625, user, users[user], 2, "failure", "WS-FILE01"])

    # --- H: RDP brute force ------------------------------------------------
    start = base + timedelta(hours=23)
    for i in range(30):
        user = rng.choice(["Administrator", "admin", "administrator", "user"])
        rows.append([start + timedelta(seconds=i * 8), 4625, user, "203.0.113.200", 10, "failure", "WS-FILE01"])

    rows.sort(key=lambda r: r[0], reverse=True)
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(["timestamp", "event_id", "username", "source_ip", "logon_type", "status", "host"])
    for row in rows:
        writer.writerow([row[0].strftime("%Y-%m-%dT%H:%M:%SZ"), *row[1:]])
    text = out.getvalue().splitlines()
    # Malformed rows: extra columns, missing timestamp, unparseable timestamp.
    text.insert(10, "2026-10-25T12:00:00Z,4624,priya,10.0.3.11,3,success,WS-FILE01,EXTRA,COLUMNS")
    text.insert(20, ",4625,rahul,10.0.3.12,2,failure,WS-FILE01")
    text.insert(30, "sometime yesterday,4624,priya,10.0.3.11,3,success,WS-FILE01")
    return "\n".join(text) + "\n"


SAMPLE_FILES = {
    "access.log": "web_access",
    "auth.log": "auth_log",
    "windows_security.csv": "csv",
}


def generate_samples(out_dir: str | Path, seed: int = 42, base: datetime = BASE_DATE) -> list[Path]:
    """Write the three sample files and return their paths."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    paths = []
    access = out / "access.log"
    access.write_text("\n".join(generate_access_log(rng, base)) + "\n", encoding="utf-8")
    auth = out / "auth.log"
    auth.write_text("\n".join(generate_auth_log(rng, base)) + "\n", encoding="utf-8")
    windows = out / "windows_security.csv"
    windows.write_text(generate_windows_csv(rng, base), encoding="utf-8")
    paths.extend([access, auth, windows])
    return paths
