# Detection rules

All seven rules live in `siem/detection/rules.py`. Each one declares its thresholds as `Param`s, which
drive both validation and the form on the *Detection rules* page. Settings are saved in
`instance/rules.json`; anything missing falls back to the defaults below.

## Shared mechanics

**Time, not file order.** The engine parses every timestamp to UTC epoch seconds and sorts events by
`(timestamp, id)` before any rule runs. Uploading logs out of order, newest-first (as Windows Event Viewer
exports are), or in several overlapping files gives the same result.

**Sliding-window bursts** (`siem/detection/windows.py`). Rules 1, 3, 4, 5 and 6 group events by source IP
and ask: *is there any window of `window_seconds` containing at least `threshold` events?* A two-pointer
scan does this in one pass:

```
left = 0
for right in range(n):
    while t[right] - t[left] > window: left += 1      # shrink window from the left
    if right - left + 1 >= threshold:                  # window qualifies
        if it overlaps / is within `window` of the current burst: extend the burst
        else: close the current burst and start a new one
```

Each burst becomes one alert with `first_seen`, `last_seen`, `event_count` and `peak_in_window`
(the busiest single window). That is the first layer of alert de-duplication.

**Alert merging across runs** (`siem/detection/engine.py`, `siem/db.py`). Before storing an alert the
engine looks for an existing alert with the same `rule_id`, `source_ip` and `username` whose time range
overlaps the new one (allowing a rule-specific gap, usually the rule's window). If one exists it is updated
instead of duplicated; analyst status and notes are kept, and a resolved/false-positive alert re-opens only
if the new activity ends later than before.

**Allow-list.** IPs or CIDR ranges in *Global settings → Allow-listed IPs* are removed before any rule
runs. Defaults: `127.0.0.1`, `::1`.

**Common settings.** Every rule has `enabled` and `severity` (the base severity; some rules escalate it).

---

## 1. Brute-force login attempts — `brute_force`

**Detects:** many failed authentications from one IP in a short time – SSH password guessing, RDP brute
force, credential stuffing.

**Logic:** select `event_type = auth_failure` with a source IP (sshd `Failed password`, Windows 4625/4771,
CSV failures); group by IP; find bursts of ≥ `threshold` failures within `window_seconds`. Count the
distinct usernames tried; ≥ `spray_user_threshold` labels the alert **password spraying**.

| Parameter | Default | Meaning |
|---|---|---|
| `threshold` | 5 | failures needed inside the window |
| `window_seconds` | 300 | window length |
| `spray_user_threshold` | 5 | distinct usernames that make it password spraying |

**Severity:** high; one level higher (critical) for spraying or when the peak is ≥ 4 × threshold.
**MITRE:** Credential Access – T1110 Brute Force (T1110.003 Password Spraying).
**False positives:** a user or script with an expired saved password; a misconfigured service account.
**Response:** check whether the IP later logged in successfully (rule 7), block or rate-limit it, enforce
key-only SSH / account lockout / MFA.

`sshd` also writes an `Invalid user` line next to each `Failed password for invalid user` line; the parser
classifies the former as `auth_other` so attempts are not double-counted.

## 2. Suspicious IP activity — `suspicious_ip`

**Detects:** IPs whose overall behaviour stands out, even when they never cross a burst threshold.

**Logic:** build a profile per IP across all events – failed logins, web requests, HTTP ≥ 400 responses.
Flag when any reason applies:

1. failed logins ≥ `min_failed_logins`;
2. requests ≥ `min_requests` **and** the IP's request count is an outlier: modified z-score
   `0.6745 × (x − median) / MAD ≥ outlier_score` computed over all IPs that sent web traffic (needs at least
   `min_ips_for_baseline` IPs). Median and MAD are used instead of mean and standard deviation because the
   attacker's own volume would otherwise inflate the baseline and hide itself;
3. requests ≥ `min_requests_for_ratio` and error share ≥ `error_ratio`.

| Parameter | Default |
|---|---|
| `min_failed_logins` | 15 |
| `min_requests` | 100 |
| `outlier_score` | 3.5 |
| `min_ips_for_baseline` | 5 |
| `error_ratio` | 0.6 |
| `min_requests_for_ratio` | 30 |

**Severity:** medium; high when two or more reasons apply.
**MITRE:** Reconnaissance T1595, Credential Access T1110.
**False positives:** NAT gateways, office proxies, monitoring probes, crawlers (see `10.0.0.5` in the
samples).
**Response:** reputation and ownership lookup (WHOIS, AbuseIPDB), review the IP's timeline and its other
alerts, block if not a known system.

## 3. HTTP error spike — `http_error_spike`

**Detects:** directory brute-forcing (many 404s), access-control probing (403s), credential guessing
against web logins (401s).

**Logic:** web events with `http_status` in `status_codes`, grouped by IP, bursts of ≥ `threshold` in
`window_seconds`. The alert lists the status breakdown and the most-requested paths.

| Parameter | Default |
|---|---|
| `status_codes` | 401, 403, 404 |
| `threshold` | 20 |
| `window_seconds` | 300 |

**Severity:** medium. **MITRE:** T1595.003 Wordlist Scanning.
**False positives:** broken links after a deployment, a misconfigured client, an SEO crawler.
**Response:** look for scanning patterns in the paths, check whether any later request succeeded, add a WAF
rule or temporary block.

## 4. Request flooding — `request_flood`

**Detects:** application-layer denial of service, aggressive scrapers, scanners.

**Logic:** every web request per IP, bursts of ≥ `threshold` within `window_seconds`. Reports the peak
per window and the average rate.

| Parameter | Default |
|---|---|
| `threshold` | 120 |
| `window_seconds` | 60 |

**Severity:** high; critical when the peak is ≥ 4 × threshold. **MITRE:** Impact – T1499 Endpoint DoS.
**False positives:** load tests, bulk API clients, many users behind one NAT.
**Response:** confirm the source, rate-limit at the reverse proxy / WAF, block if unexpected, check server
health.

## 5. Sensitive-path probing — `sensitive_path_probing`

**Detects:** hunting for admin panels, secrets and config files.

**Logic:** URL-decode each path twice (so `%2e%65%6e%76` and double-encoded variants become `.env`),
lower-case it and check it against `paths` (case-insensitive substring, so `/.git` matches
`/.git/config`). Bursts of ≥ `threshold` matches per IP within `window_seconds`. If **any** matching request
got a 2xx response, the alert becomes **critical** and lists the exposed paths.

| Parameter | Default |
|---|---|
| `paths` | `/admin`, `/administrator`, `/wp-admin`, `/wp-login.php`, `/xmlrpc.php`, `/.env`, `/.git`, `/.svn`, `/.htaccess`, `/.aws`, `/phpmyadmin`, `/pma`, `/config.php`, `/web.config`, `/server-status`, `/actuator`, `/console`, `/cgi-bin`, `/backup`, `/etc/passwd`, `/shell`, `/boaform`, `/vendor/phpunit` |
| `threshold` | 3 |
| `window_seconds` | 600 |

**Severity:** high; critical on a successful hit. **MITRE:** T1595.003.
**False positives:** your own admins using `/admin`; uptime checks on `/server-status`.
**Response:** verify the probed files are not reachable (especially anything that returned 200 – rotate any
secrets in an exposed `.env`), restrict admin paths by IP/VPN, block the scanner.

## 6. Suspicious user agent — `suspicious_user_agent`

**Detects:** attack tools and scripted clients.

**Logic:** case-insensitive substring match of each User-Agent against `patterns` (`pattern = severity`).
Patterns are tried from the highest severity down, so a UA matching two patterns gets the worse one.
Matching requests from one IP are one incident while they keep arriving within `group_window_seconds`.
Optionally, empty User-Agents are flagged as low.

| Parameter | Default |
|---|---|
| `patterns` | high: sqlmap, nikto, nmap, masscan, nuclei, acunetix, wpscan, gobuster, dirbuster, ffuf, hydra, metasploit, w3af, havij · medium: zgrab, libwww-perl · low: python-requests, curl/, wget/, go-http-client, scrapy, httpclient |
| `min_matches` | 1 |
| `group_window_seconds` | 3600 |
| `flag_empty_user_agent` | on |

**Severity:** highest matched pattern. **MITRE:** T1595.002 Vulnerability Scanning.
**False positives:** health checks and automation using curl / python-requests (allow-list them). User
agents are trivially spoofed, so *no* match proves nothing – this rule complements the behavioural rules.
**Response:** treat tool matches as active scanning; correlate with rules 3 and 5 for the same IP.

## 7. Failed logins followed by success — `fail_then_success`

**Detects:** a brute-force or guessing attack that worked – the most important alert in the set.

**Logic:** walk authentication events in time order per correlation key (`username` by default). Keep a
queue of failures from the last `lookback_seconds`. On a success: if the queue holds ≥ `min_failures`,
raise an alert (failures + the success as evidence), then clear the queue so the same attack is not
reported twice. A success with fewer failures also clears the queue, so an occasional typo never adds up.

| Parameter | Default | Meaning |
|---|---|---|
| `min_failures` | 3 | failures before the success |
| `lookback_seconds` | 900 | how far back to count |
| `correlate_by` | `username` | `username` catches distributed attacks (failures from many IPs, success from another); `source_ip` or `username_and_ip` are stricter |

**Severity:** critical. **MITRE:** T1110 Brute Force + T1078 Valid Accounts.
**False positives:** a real user who mistyped a few times.
**Response:** confirm with the account owner; if unconfirmed, disable the account or reset credentials,
kill sessions, and review what the session did.

---

## Tuning checklist

1. Load your normal traffic, run detection, sort alerts by rule.
2. For every false positive, prefer the narrowest fix: allow-list the IP, then raise the specific
   threshold, then lower the severity – disabling a rule is the last resort.
3. Mark false positives as *False positive* with a note explaining why; they stay as an audit trail.
4. Re-run detection after saving (the *Save and re-run* button) and check the change did what you expected.
