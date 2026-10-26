"""The seven detection rules.

Every rule receives the full, time-sorted events DataFrame produced by
``engine.prepare_events`` (columns: id, timestamp, _t [epoch seconds],
source_ip, username, event_type, status, http_status, request_path,
user_agent, ...) plus its own configuration dict, and returns ``Alert``s.
"""

from __future__ import annotations

from collections import deque
from urllib.parse import unquote

import numpy as np
import pandas as pd

from ..db import SEVERITIES, SEVERITY_RANK
from .base import Param, Rule, escalate, ids_of, top_counts, ts_str
from .windows import find_bursts


def _web(df: pd.DataFrame) -> pd.DataFrame:
    return df[(df["event_type"] == "web_request") & df["source_ip"].notna()]


# ---------------------------------------------------------------------------
# 1. Brute force
# ---------------------------------------------------------------------------
class BruteForceRule(Rule):
    id = "brute_force"
    name = "Brute-force login attempts"
    summary = "Many failed logins from one IP in a short time window."
    how_it_works = (
        "Takes every failed authentication (SSH 'Failed password', Windows 4625, CSV failures), "
        "groups them by source IP and slides a time window over each IP's failures. When "
        "'threshold' or more failures fall inside 'window_seconds', the IP is flagged. Overlapping "
        "windows are merged so one sustained attack produces one alert. If the IP tried at least "
        "'spray_user_threshold' different usernames, the alert is labelled password spraying."
    )
    false_positives = "A user or script with a stale saved password; misconfigured service accounts."
    recommendation = (
        "Check whether any login from this IP later succeeded. Block or rate-limit the IP at the "
        "firewall, enforce key-based SSH / account lockout, and confirm targeted accounts use MFA."
    )
    mitre_tactic = "Credential Access"
    mitre_technique = "T1110 - Brute Force"
    default_severity = "high"
    params = (
        Param("threshold", "int", 5, "Failed logins", "Failures needed inside the window.", 2, 10000),
        Param("window_seconds", "int", 300, "Window (seconds)", "Length of the sliding window.", 10, 86400),
        Param("spray_user_threshold", "int", 5, "Distinct users for 'spraying'",
              "Usernames tried by one IP that turn the alert into password spraying.", 2, 1000),
    )

    def detect(self, df, cfg):
        alerts = []
        failures = df[(df["event_type"] == "auth_failure") & df["source_ip"].notna()]
        for ip, group in failures.groupby("source_ip", sort=False):
            for burst in find_bursts(group["_t"].to_numpy(), cfg["window_seconds"], cfg["threshold"]):
                rows = group.iloc[burst.start:burst.end + 1]
                users = sorted(rows["username"].dropna().astype(str).unique())
                spraying = len(users) >= cfg["spray_user_threshold"]
                severity = cfg["severity"]
                if burst.peak >= cfg["threshold"] * 4 or spraying:
                    severity = escalate(severity)
                kind = "Password spraying" if spraying else "Brute-force login attempts"
                alerts.append(self.alert(
                    cfg,
                    severity=severity,
                    title=f"{kind} from {ip}",
                    description=(
                        f"{burst.count} failed logins from {ip} between {ts_str(rows['_t'].iloc[0])} and "
                        f"{ts_str(rows['_t'].iloc[-1])} UTC (peak {burst.peak} within "
                        f"{cfg['window_seconds']}s; threshold {cfg['threshold']}). "
                        f"{len(users)} account(s) targeted."
                    ),
                    source_ip=ip,
                    first_seen=ts_str(rows["_t"].iloc[0]),
                    last_seen=ts_str(rows["_t"].iloc[-1]),
                    event_count=burst.count,
                    event_ids=ids_of(rows),
                    details={
                        "pattern": "password_spraying" if spraying else "brute_force",
                        "peak_in_window": burst.peak,
                        "window_seconds": cfg["window_seconds"],
                        "targeted_usernames": users[:25],
                        "targeted_username_count": len(users),
                        "log_sources": top_counts(rows["source_type"]),
                    },
                ))
        return alerts


# ---------------------------------------------------------------------------
# 2. Suspicious IP (statistical outliers over the whole dataset)
# ---------------------------------------------------------------------------
def modified_z_scores(values: np.ndarray) -> np.ndarray:
    """Robust outlier score (Iglewicz & Hoaglin): 0.6745 * (x - median) / MAD.

    Unlike the mean and standard deviation, the median and MAD are not dragged
    upwards by the very attacker we are trying to find. If more than half the
    values are identical (MAD == 0) we fall back to the mean absolute deviation.
    """
    values = np.asarray(values, dtype=float)
    median = np.median(values)
    mad = np.median(np.abs(values - median))
    if mad > 0:
        return 0.6745 * (values - median) / mad
    mean_ad = np.mean(np.abs(values - median))
    if mean_ad > 0:
        return (values - median) / (1.253314 * mean_ad)
    return np.zeros_like(values)


class SuspiciousIPRule(Rule):
    id = "suspicious_ip"
    name = "Suspicious IP activity"
    summary = "IPs whose failed logins, request volume or error ratio stand out from the rest."
    how_it_works = (
        "Builds a profile for every IP across all stored events: failed logins, web requests and "
        "the share of requests that returned an HTTP error. An IP is flagged when (a) its failed "
        "logins reach 'min_failed_logins', (b) its request count is a statistical outlier "
        "(modified z-score using the median and MAD of all IPs >= 'outlier_score') and at least "
        "'min_requests', or (c) at least 'error_ratio' of its requests failed (with at least "
        "'min_requests_for_ratio' requests). Two or more reasons raise the severity."
    )
    false_positives = "Busy NAT gateways, office proxies, monitoring probes and search-engine crawlers."
    recommendation = (
        "Look up the IP's reputation and ownership (WHOIS, AbuseIPDB), review its full event timeline "
        "and other alerts, and block it if it is not a known partner or internal system."
    )
    mitre_tactic = "Reconnaissance / Credential Access"
    mitre_technique = "T1595 - Active Scanning; T1110 - Brute Force"
    default_severity = "medium"
    params = (
        Param("min_failed_logins", "int", 15, "Failed logins (total)",
              "Total failed logins that make an IP suspicious on their own.", 1, 100000),
        Param("min_requests", "int", 100, "Minimum requests for outlier",
              "Ignore volume outliers below this many requests.", 1, 10000000),
        Param("outlier_score", "float", 3.5, "Outlier score (modified z)",
              "3.5 is the usual cut-off for the modified z-score.", 1.0, 100.0),
        Param("min_ips_for_baseline", "int", 5, "IPs needed for a baseline",
              "Skip volume outliers if fewer IPs than this sent web traffic.", 3, 100000),
        Param("error_ratio", "float", 0.6, "HTTP error ratio",
              "Share of requests answered with 4xx/5xx.", 0.05, 1.0),
        Param("min_requests_for_ratio", "int", 30, "Minimum requests for ratio", "", 1, 1000000),
    )

    def merge_gap_seconds(self, cfg):
        return 86400

    def detect(self, df, cfg):
        with_ip = df[df["source_ip"].notna()]
        if with_ip.empty:
            return []
        web = with_ip["event_type"] == "web_request"
        profile = pd.DataFrame({
            "failed_logins": (with_ip["event_type"] == "auth_failure").groupby(with_ip["source_ip"]).sum(),
            "requests": web.groupby(with_ip["source_ip"]).sum(),
            "errors": (web & (with_ip["http_status"] >= 400)).groupby(with_ip["source_ip"]).sum(),
            "first": with_ip.groupby("source_ip")["_t"].min(),
            "last": with_ip.groupby("source_ip")["_t"].max(),
            "events": with_ip.groupby("source_ip").size(),
        })
        profile["score"] = 0.0
        senders = profile[profile["requests"] > 0]
        if len(senders) >= cfg["min_ips_for_baseline"]:
            profile.loc[senders.index, "score"] = modified_z_scores(senders["requests"].to_numpy())
        median_requests = float(senders["requests"].median()) if len(senders) else 0.0

        alerts = []
        for ip, row in profile.iterrows():
            reasons = []
            if row["failed_logins"] >= cfg["min_failed_logins"]:
                reasons.append(f"{int(row['failed_logins'])} failed logins in total")
            if row["requests"] >= cfg["min_requests"] and row["score"] >= cfg["outlier_score"]:
                reasons.append(
                    f"{int(row['requests'])} requests (median per IP {median_requests:.0f}, "
                    f"outlier score {row['score']:.1f})"
                )
            ratio = row["errors"] / row["requests"] if row["requests"] else 0.0
            if row["requests"] >= cfg["min_requests_for_ratio"] and ratio >= cfg["error_ratio"]:
                reasons.append(f"{ratio:.0%} of {int(row['requests'])} requests returned HTTP errors")
            if not reasons:
                continue
            ip_rows = with_ip[with_ip["source_ip"] == ip]
            evidence = ip_rows[(ip_rows["event_type"] == "auth_failure") | (ip_rows["http_status"] >= 400)]
            severity = escalate(cfg["severity"]) if len(reasons) >= 2 else cfg["severity"]
            alerts.append(self.alert(
                cfg,
                severity=severity,
                title=f"Suspicious activity from {ip}",
                description=f"{ip} stands out: " + "; ".join(reasons) + ".",
                source_ip=ip,
                first_seen=ts_str(row["first"]),
                last_seen=ts_str(row["last"]),
                event_count=int(row["events"]),
                event_ids=ids_of(evidence if len(evidence) else ip_rows),
                details={
                    "reasons": reasons,
                    "failed_logins": int(row["failed_logins"]),
                    "requests": int(row["requests"]),
                    "http_errors": int(row["errors"]),
                    "error_ratio": round(float(ratio), 3),
                    "outlier_score": round(float(row["score"]), 2),
                    "median_requests_per_ip": median_requests,
                },
            ))
        return alerts


# ---------------------------------------------------------------------------
# 3. HTTP error spike
# ---------------------------------------------------------------------------
class HttpErrorSpikeRule(Rule):
    id = "http_error_spike"
    name = "HTTP error spike"
    summary = "Burst of 401/403/404 responses to one IP."
    how_it_works = (
        "Selects web requests whose status is in 'status_codes' (401, 403, 404 by default), groups "
        "them by source IP and flags any IP that receives 'threshold' or more of those errors inside "
        "'window_seconds'. Lots of 404s usually mean directory or file brute-forcing; lots of "
        "401/403s mean credential guessing or access-control probing."
    )
    false_positives = "Broken links after a deployment, a misconfigured client, or an SEO crawler."
    recommendation = (
        "Review the requested paths for scanning patterns, check whether any later request from "
        "the IP succeeded, and consider a WAF rule or temporary block."
    )
    mitre_tactic = "Reconnaissance"
    mitre_technique = "T1595.003 - Active Scanning: Wordlist Scanning"
    default_severity = "medium"
    params = (
        Param("status_codes", "int_list", [401, 403, 404], "Status codes", "One code per line."),
        Param("threshold", "int", 20, "Error responses", "Errors needed inside the window.", 2, 100000),
        Param("window_seconds", "int", 300, "Window (seconds)", "", 10, 86400),
    )

    def detect(self, df, cfg):
        codes = [int(c) for c in cfg["status_codes"]]
        web = _web(df)
        errors = web[web["http_status"].isin(codes)]
        alerts = []
        for ip, group in errors.groupby("source_ip", sort=False):
            for burst in find_bursts(group["_t"].to_numpy(), cfg["window_seconds"], cfg["threshold"]):
                rows = group.iloc[burst.start:burst.end + 1]
                breakdown = {str(int(k)): int(v) for k, v in rows["http_status"].value_counts().items()}
                alerts.append(self.alert(
                    cfg,
                    title=f"HTTP error spike from {ip}",
                    description=(
                        f"{burst.count} responses with status {', '.join(breakdown)} sent to {ip} "
                        f"(peak {burst.peak} within {cfg['window_seconds']}s; threshold {cfg['threshold']})."
                    ),
                    source_ip=ip,
                    first_seen=ts_str(rows["_t"].iloc[0]),
                    last_seen=ts_str(rows["_t"].iloc[-1]),
                    event_count=burst.count,
                    event_ids=ids_of(rows),
                    details={
                        "status_breakdown": breakdown,
                        "peak_in_window": burst.peak,
                        "top_paths": top_counts(rows["request_path"], 10),
                    },
                ))
        return alerts


# ---------------------------------------------------------------------------
# 4. Request flooding
# ---------------------------------------------------------------------------
class RequestFloodRule(Rule):
    id = "request_flood"
    name = "Request flooding"
    summary = "Abnormally high request rate from one IP."
    how_it_works = (
        "Counts every web request per source IP in a sliding window. 'threshold' requests inside "
        "'window_seconds' (120 per minute by default) is far above what a human browsing the site "
        "produces and points to an application-layer DoS, an aggressive scraper or a scanner. "
        "Bursts that are four times the threshold are raised one severity level."
    )
    false_positives = "Load tests, API clients doing bulk sync, or many users behind one NAT."
    recommendation = (
        "Confirm the source, apply rate limiting at the reverse proxy / WAF, and block the IP if the "
        "traffic is not expected. Check server health metrics for impact."
    )
    mitre_tactic = "Impact"
    mitre_technique = "T1499 - Endpoint Denial of Service"
    default_severity = "high"
    params = (
        Param("threshold", "int", 120, "Requests", "Requests needed inside the window.", 5, 10000000),
        Param("window_seconds", "int", 60, "Window (seconds)", "", 1, 86400),
    )

    def detect(self, df, cfg):
        alerts = []
        for ip, group in _web(df).groupby("source_ip", sort=False):
            for burst in find_bursts(group["_t"].to_numpy(), cfg["window_seconds"], cfg["threshold"]):
                rows = group.iloc[burst.start:burst.end + 1]
                duration = max(int(rows["_t"].iloc[-1] - rows["_t"].iloc[0]), 1)
                severity = cfg["severity"]
                if burst.peak >= cfg["threshold"] * 4:
                    severity = escalate(severity)
                alerts.append(self.alert(
                    cfg,
                    severity=severity,
                    title=f"Request flood from {ip}",
                    description=(
                        f"{burst.count} requests from {ip} in {duration}s; peak {burst.peak} requests "
                        f"within {cfg['window_seconds']}s (threshold {cfg['threshold']})."
                    ),
                    source_ip=ip,
                    first_seen=ts_str(rows["_t"].iloc[0]),
                    last_seen=ts_str(rows["_t"].iloc[-1]),
                    event_count=burst.count,
                    event_ids=ids_of(rows),
                    details={
                        "peak_in_window": burst.peak,
                        "window_seconds": cfg["window_seconds"],
                        "average_requests_per_second": round(burst.count / duration, 2),
                        "top_paths": top_counts(rows["request_path"], 5),
                        "status_breakdown": top_counts(rows["http_status"].astype("Int64"), 10),
                    },
                ))
        return alerts


# ---------------------------------------------------------------------------
# 5. Sensitive path probing
# ---------------------------------------------------------------------------
DEFAULT_SENSITIVE_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/wp-login.php", "/xmlrpc.php", "/.env", "/.git",
    "/.svn", "/.htaccess", "/.aws", "/phpmyadmin", "/pma", "/config.php", "/web.config",
    "/server-status", "/actuator", "/console", "/cgi-bin", "/backup", "/etc/passwd",
    "/shell", "/boaform", "/vendor/phpunit",
]


class SensitivePathProbingRule(Rule):
    id = "sensitive_path_probing"
    name = "Sensitive-path probing"
    summary = "Repeated requests for admin panels, secrets and config files."
    how_it_works = (
        "Decodes each requested URL (so %2e%65%6e%76 becomes .env), lower-cases it and checks it "
        "against the configurable 'paths' list (substring match, so '/.git' also catches "
        "'/.git/config'). An IP that makes 'threshold' or more such requests within "
        "'window_seconds' is flagged. If any of those requests got a 2xx response the alert is "
        "escalated to critical, because something sensitive may actually have been exposed."
    )
    false_positives = "Your own admins using /admin, or uptime checks against /server-status."
    recommendation = (
        "Verify that none of the probed files are publicly reachable (especially any that returned "
        "200), restrict admin paths by IP or VPN, and block the scanning IP."
    )
    mitre_tactic = "Reconnaissance / Discovery"
    mitre_technique = "T1595.003 - Active Scanning: Wordlist Scanning"
    default_severity = "high"
    params = (
        Param("paths", "str_list", DEFAULT_SENSITIVE_PATHS, "Sensitive paths",
              "One path per line; matched as a case-insensitive substring of the decoded URL."),
        Param("threshold", "int", 3, "Probe requests", "Matching requests needed inside the window.", 1, 100000),
        Param("window_seconds", "int", 600, "Window (seconds)", "", 10, 86400),
    )

    @staticmethod
    def match_path(path, patterns) -> str | None:
        if not isinstance(path, str) or not path:
            return None
        decoded = unquote(unquote(path)).lower()
        for pattern in patterns:
            if pattern and pattern.lower() in decoded:
                return pattern
        return None

    def detect(self, df, cfg):
        patterns = [p.strip() for p in cfg["paths"] if p and p.strip()]
        if not patterns:
            return []
        web = _web(df)
        matched = web["request_path"].map(lambda p: self.match_path(p, patterns))
        probes = web.assign(_matched=matched)[matched.notna()]
        alerts = []
        for ip, group in probes.groupby("source_ip", sort=False):
            for burst in find_bursts(group["_t"].to_numpy(), cfg["window_seconds"], cfg["threshold"]):
                rows = group.iloc[burst.start:burst.end + 1]
                exposed = rows[(rows["http_status"] >= 200) & (rows["http_status"] < 300)]
                severity = "critical" if len(exposed) else cfg["severity"]
                description = (
                    f"{ip} requested {burst.count} sensitive path(s) "
                    f"({rows['_matched'].nunique()} distinct patterns) within the window."
                )
                if len(exposed):
                    description += (f" {len(exposed)} request(s) returned 2xx - possible exposure of "
                                    f"{', '.join(exposed['request_path'].astype(str).unique()[:5])}.")
                alerts.append(self.alert(
                    cfg,
                    severity=severity,
                    title=f"Sensitive-path probing from {ip}",
                    description=description,
                    source_ip=ip,
                    first_seen=ts_str(rows["_t"].iloc[0]),
                    last_seen=ts_str(rows["_t"].iloc[-1]),
                    event_count=burst.count,
                    event_ids=ids_of(rows),
                    details={
                        "matched_patterns": top_counts(rows["_matched"], 25),
                        "paths": top_counts(rows["request_path"], 25),
                        "successful_hits": exposed["request_path"].astype(str).unique().tolist()[:25],
                        "status_breakdown": top_counts(rows["http_status"].astype("Int64"), 10),
                    },
                ))
        return alerts


# ---------------------------------------------------------------------------
# 6. Suspicious user agents
# ---------------------------------------------------------------------------
DEFAULT_UA_PATTERNS = {
    "sqlmap": "high", "nikto": "high", "nmap": "high", "masscan": "high", "zgrab": "medium",
    "nuclei": "high", "acunetix": "high", "wpscan": "high", "gobuster": "high", "dirbuster": "high",
    "ffuf": "high", "hydra": "high", "metasploit": "high", "w3af": "high", "havij": "high",
    "python-requests": "low", "curl/": "low", "wget/": "low", "go-http-client": "low",
    "libwww-perl": "medium", "scrapy": "low", "httpclient": "low",
}
EMPTY_UA = "<empty user agent>"


class SuspiciousUserAgentRule(Rule):
    id = "suspicious_user_agent"
    name = "Suspicious user agent"
    summary = "Requests from attack tools, scanners or scripted clients."
    how_it_works = (
        "Checks each web request's User-Agent against the configurable 'patterns' list "
        "(case-insensitive substring -> severity). Known attack tools such as sqlmap or Nikto are "
        "high severity; generic scripting clients such as curl or python-requests are low. "
        "Matching requests from one IP are grouped into one incident while they keep arriving "
        "within 'group_window_seconds'; the alert takes the highest severity seen. Optionally, "
        "requests with an empty User-Agent are flagged too."
    )
    false_positives = (
        "Health checks and internal automation often use curl or python-requests - add those IPs "
        "to the allow-list. User agents are trivially spoofed, so absence of a match proves nothing."
    )
    recommendation = (
        "Treat attack-tool matches as active scanning: correlate with error spikes and path probing "
        "from the same IP, review what the tool requested, and block the IP."
    )
    mitre_tactic = "Reconnaissance"
    mitre_technique = "T1595.002 - Active Scanning: Vulnerability Scanning"
    default_severity = "medium"
    params = (
        Param("patterns", "pattern_map", DEFAULT_UA_PATTERNS, "User-agent patterns",
              "One 'pattern = severity' per line (low, medium, high, critical)."),
        Param("min_matches", "int", 1, "Matching requests", "Requests needed to raise an alert.", 1, 100000),
        Param("group_window_seconds", "int", 3600, "Grouping window (seconds)",
              "Matches closer together than this belong to the same incident.", 60, 604800),
        Param("flag_empty_user_agent", "bool", True, "Flag empty user agents (low)"),
    )

    def merge_gap_seconds(self, cfg):
        return int(cfg["group_window_seconds"])

    def classify(self, user_agents: pd.Series, cfg) -> tuple[pd.Series, pd.Series]:
        """Return (matched pattern, severity) for every user agent."""
        lowered = user_agents.fillna("").astype(str).str.lower()
        pattern_out = pd.Series(None, index=user_agents.index, dtype=object)
        severity_out = pd.Series(None, index=user_agents.index, dtype=object)
        # Highest severity first so a UA matching two patterns gets the worst one.
        ordered = sorted(cfg["patterns"].items(), key=lambda kv: -SEVERITY_RANK.get(kv[1], 0))
        for pattern, severity in ordered:
            if not pattern:
                continue
            hit = lowered.str.contains(pattern.lower(), regex=False) & pattern_out.isna()
            pattern_out[hit] = pattern
            severity_out[hit] = severity
        if cfg.get("flag_empty_user_agent"):
            empty = user_agents.isna() & pattern_out.isna()
            pattern_out[empty] = EMPTY_UA
            severity_out[empty] = "low"
        return pattern_out, severity_out

    def detect(self, df, cfg):
        web = _web(df)
        if web.empty:
            return []
        pattern, severity = self.classify(web["user_agent"], cfg)
        hits = web.assign(_pattern=pattern, _severity=severity)[pattern.notna()]
        alerts = []
        for ip, group in hits.groupby("source_ip", sort=False):
            for burst in find_bursts(group["_t"].to_numpy(), cfg["group_window_seconds"], cfg["min_matches"]):
                rows = group.iloc[burst.start:burst.end + 1]
                worst = max(rows["_severity"], key=lambda s: SEVERITY_RANK.get(s, 0))
                tools = top_counts(rows["_pattern"], 10)
                alerts.append(self.alert(
                    cfg,
                    severity=worst if worst in SEVERITIES else cfg["severity"],
                    title=f"Suspicious user agent ({', '.join(list(tools)[:3])}) from {ip}",
                    description=(
                        f"{burst.count} request(s) from {ip} with user agents matching: "
                        + ", ".join(f"{k} x{v}" for k, v in tools.items()) + "."
                    ),
                    source_ip=ip,
                    first_seen=ts_str(rows["_t"].iloc[0]),
                    last_seen=ts_str(rows["_t"].iloc[-1]),
                    event_count=burst.count,
                    event_ids=ids_of(rows),
                    details={
                        "matched_patterns": tools,
                        "user_agents": top_counts(rows["user_agent"].fillna(EMPTY_UA), 10),
                        "top_paths": top_counts(rows["request_path"], 10),
                    },
                ))
        return alerts


# ---------------------------------------------------------------------------
# 7. Failures followed by a success (possible account compromise)
# ---------------------------------------------------------------------------
class FailThenSuccessRule(Rule):
    id = "fail_then_success"
    name = "Failed logins followed by success"
    summary = "Repeated failures then a successful login - possible compromised account."
    how_it_works = (
        "Walks through authentication events in time order for each username (or IP, or "
        "username+IP - see 'correlate_by'). It remembers recent failures; when a successful login "
        "arrives and at least 'min_failures' failures happened in the preceding 'lookback_seconds', "
        "it raises an alert and then forgets those failures so the same attack is not reported "
        "twice. Correlating by username also catches distributed attacks where the failures come "
        "from many IPs and the success from yet another one."
    )
    false_positives = "A real user who mistyped their password a few times before getting it right."
    recommendation = (
        "Contact the account owner to confirm the login. If unconfirmed: disable the account or "
        "reset its credentials, kill active sessions, and review what the session did afterwards."
    )
    mitre_tactic = "Credential Access / Initial Access"
    mitre_technique = "T1110 - Brute Force; T1078 - Valid Accounts"
    default_severity = "critical"
    params = (
        Param("min_failures", "int", 3, "Failures before success", "", 1, 10000),
        Param("lookback_seconds", "int", 900, "Look-back (seconds)",
              "How far before the success to count failures.", 10, 604800),
        Param("correlate_by", "choice", "username", "Correlate by",
              "username catches distributed attacks; username_and_ip is the strictest.",
              choices=("username", "source_ip", "username_and_ip")),
    )

    def merge_gap_seconds(self, cfg):
        return int(cfg["lookback_seconds"])

    def detect(self, df, cfg):
        auth = df[df["event_type"].isin(["auth_failure", "auth_success"])]
        keys = {"username": ["username"], "source_ip": ["source_ip"],
                "username_and_ip": ["username", "source_ip"]}[cfg["correlate_by"]]
        auth = auth.dropna(subset=keys)
        lookback = int(cfg["lookback_seconds"])
        alerts = []
        for key, group in auth.groupby(keys, sort=False):
            failures: deque = deque()  # (epoch, row position)
            positions = np.arange(len(group))
            types = group["event_type"].to_numpy()
            times = group["_t"].to_numpy()
            for pos, etype, t in zip(positions, types, times):
                while failures and t - failures[0][0] > lookback:
                    failures.popleft()
                if etype == "auth_failure":
                    failures.append((t, pos))
                    continue
                if len(failures) < cfg["min_failures"]:
                    failures.clear()  # a clean login resets the counter
                    continue
                fail_rows = group.iloc[[p for _, p in failures]]
                success = group.iloc[pos]
                failure_ips = sorted(fail_rows["source_ip"].dropna().astype(str).unique())
                success_ip = success["source_ip"] if isinstance(success["source_ip"], str) else None
                user = success["username"] if isinstance(success["username"], str) else None
                new_ip = bool(success_ip) and success_ip not in failure_ips
                description = (
                    f"{len(fail_rows)} failed login(s) for {user or 'unknown user'} from "
                    f"{len(failure_ips)} IP(s) followed by a successful login from "
                    f"{success_ip or 'an unknown IP'} at {ts_str(t)} UTC."
                )
                if len(failure_ips) > 1:
                    description += " Failures came from multiple IPs (possible distributed attack)."
                alerts.append(self.alert(
                    cfg,
                    title=f"Possible account compromise: {user or success_ip}",
                    description=description,
                    source_ip=success_ip,
                    username=user,
                    first_seen=ts_str(fail_rows["_t"].iloc[0]),
                    last_seen=ts_str(t),
                    event_count=len(fail_rows) + 1,
                    event_ids=ids_of(fail_rows) + [int(success["id"])],
                    details={
                        "failures": int(len(fail_rows)),
                        "failure_ips": failure_ips[:25],
                        "success_ip": success_ip,
                        "success_from_new_ip": new_ip,
                        "correlated_by": cfg["correlate_by"],
                        "success_time": ts_str(t),
                    },
                ))
                failures.clear()
        return alerts


ALL_RULES: tuple[Rule, ...] = (
    BruteForceRule(),
    SuspiciousIPRule(),
    HttpErrorSpikeRule(),
    RequestFloodRule(),
    SensitivePathProbingRule(),
    SuspiciousUserAgentRule(),
    FailThenSuccessRule(),
)
RULES_BY_ID = {rule.id: rule for rule in ALL_RULES}
