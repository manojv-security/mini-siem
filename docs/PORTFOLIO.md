# Portfolio notes

## Resume bullets (pick 2–3)

- Built **Mini-SIEM**, a Python/Flask security monitoring platform that ingests Apache/Nginx, Linux
  auth and Windows Security logs, normalizes them into a common event schema in SQLite, and detects
  attacks with 7 configurable rules mapped to MITRE ATT&CK.
- Implemented time-window correlation (O(n) sliding-window burst detection) and robust statistical
  outlier scoring (median/MAD modified z-score) with Pandas, plus incident merging so repeated runs never
  duplicate alerts.
- Detected brute force, password spraying, a compromised account (failures followed by success, including
  a distributed attack), Nikto/sqlmap scans, sensitive-file exposure and HTTP floods in realistic
  synthetic logs; wrote ~150 pytest cases and CI on Windows and Linux.
- Added a SOC triage workflow (status, analyst notes, auto re-open, CSV export) and hardened the app with
  CSRF tokens, a strict Content-Security-Policy and CSV-injection protection.

## Two-minute demo script

1. **Dashboard, empty** → *Load sample data*. Point at the import table: "6,131 events, 11 malformed
   records rejected with reasons."
2. **Load again** → every record is a duplicate. "De-duplication by content hash, but identical lines in
   one file are kept because floods are real."
3. **Dashboard** → spikes in the timeline line up with alerts; top IPs table shows the attackers.
4. **Alerts** → open *Possible account compromise: bob*. "Eight failures from four IPs, then a success
   from a fifth – an IP-based rule would miss this, so I correlate by username." Show evidence and
   the recommended response; set status to *Investigating* with a note.
5. Open *Sensitive-path probing from 203.0.113.77* → critical because `/.env` returned 200. "Severity
   reflects impact, not just volume."
6. **Detection rules** → allow-list `10.0.0.5` (the curl health check) and explain false-positive tuning.
7. **Terminal** → `pytest` passing.

## Questions you may be asked

**Why not just count failures per IP?**
Counts over the whole file hide timing. Five failures in a day are normal; five in thirty seconds are an
attack. Sliding windows on event timestamps capture rate, and sorting first means file order is irrelevant.

**How do you avoid alert fatigue?**
Overlapping windows merge into one burst; stored alerts are matched by rule + entity + overlapping time and
updated instead of duplicated; severities escalate only with evidence (spraying, 2xx on a sensitive path,
multiple reasons); an allow-list removes known-good sources.

**Why median and MAD for outliers?**
The mean and standard deviation are pulled up by the very outlier you want to find. The median and MAD are
robust to that; 3.5 is the usual modified z-score threshold (Iglewicz and Hoaglin).

**What are the rule's blind spots?**
Low-and-slow attacks under the thresholds, attackers rotating IPs (partly covered by username correlation
in rule 7), spoofed user agents, and anything not in the logs you ingest. A real SIEM adds threat
intelligence, longer baselines and many more sources.

**How would you scale it?**
Stream logs instead of batch uploads (syslog listener or file tailing), run rules incrementally over a
recent window instead of the whole table, move storage to PostgreSQL/Elasticsearch, and express rules in a
standard format such as Sigma.

**Is the app itself secure?**
Parameterized SQL, auto-escaping plus `textContent` in JavaScript, a CSP without inline scripts, CSRF
tokens, upload validation and size limits, CSV-formula neutralisation, localhost binding. It has no
authentication, so it is a single-analyst lab tool.

## Screenshots to add to the repo

Save into `docs/screenshots/` and link them from the README:

- `dashboard.png` – after loading the sample data
- `alert-compromise.png` – the *Possible account compromise: bob* alert
- `alert-env-exposed.png` – the critical sensitive-path alert
- `upload-results.png` – the import table with rejected/duplicate counts
- `rules.png` – the rules page with thresholds
