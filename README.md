# Firewall-Watch - Firewall & Login Threat Dashboard
Python + Flask + SQLite dashboard that monitors login attempts and firewall logs, and flags suspicious external IPs using the VirusTotal API.

## Features
- Admin-only login (session based)
- Every login attempt saved to `soc_logs.db` and shown in **Authentication Logs** (date, time, user, status, source IP)
- 3 wrong attempts -> status `Locked`, a **Critical Brute Force** alert is created, login is locked for **5 minutes** (per source IP)
- FortiGate-style firewall logs parsed from `firewall_logs.txt` (synthetic sample data included) and shown with allowed/blocked traffic, risk ratings and destination countries
- Doughnut charts + searchable tables, auto-refresh every 15s

## Run
```
python -m venv .venv && .venv\Scripts\activate      (Windows)
pip install -r requirements.txt
python main.py
```
Open http://127.0.0.1:5000. Copy `.env.example` to `.env` first and set your own
`ADMIN_USER`, `ADMIN_PASSWORD`, `SECRET_KEY` (and optionally `VT_API_KEY`).

## Use your own firewall logs
Put your firewall log file in the project folder named `firewall_logs.txt` (see format in `firewall_parser.py`) and restart.
Note: charts load Chart.js from a CDN, so an internet connection is needed the first time.


## Firewall log format (updated)
`firewall_logs.txt` now includes: date/time, source IP & port, destination IP & port, action,
app, FortiGate risk rating, VirusTotal risk score, malicious flag, destination country, service,
sent/received bytes, and policy. The sample file is **synthetic data generated for demo purposes**
- replace it with your real company export (same key=value style) before using it for anything official.

## High Severity Alerts
This table now shows only login-lockout events (3 failed attempts -> Critical Brute Force alert).
Firewall risk data (blocked/denied traffic, risk ratings) is shown in the Firewall Logs table and
the dashboard charts instead.


## VT verdict (VirusTotal-style)
The firewall table's **VT verdict** column is derived from the VT risk score: a score of 50+
(or an explicit malicious flag in the source data) is marked **Suspicious**; otherwise **Clean**.
Adjust the cut-off via `VT_SUSPICIOUS_THRESHOLD` in `firewall_parser.py`.

## Authentication Logs grouping
Authentication Logs are grouped by source IP (one row per device). Click a row to expand it and
see every individual login attempt from that IP, newest first. The search box filters groups and
auto-expands any group with a match.

## Fixed: works from any folder
Earlier versions looked for `firewall_logs.txt` relative to wherever you ran `python main.py`
from, which silently produced an empty dashboard if you launched it from the wrong folder.
Paths are now resolved relative to the project folder itself, so this works regardless of your
terminal's current directory.


## Login credentials
Set `ADMIN_USER` / `ADMIN_PASSWORD` in your `.env` file. Use a strong password if you ever run this outside a local demo.

## Live VirusTotal lookups (optional)
By default the firewall table's VT risk score/verdict come from the simulated data already in
`firewall_logs.txt`. To use **real** VirusTotal data instead:
1. Create a free account at virustotal.com and copy your API key from your profile page.
2. Set `VT_API_KEY=your-key-here` in `.env` (see `.env.example`).
3. Restart the app (`python main.py`). The console will show `[VT] live lookups enabled...`
   and progress as it checks each unique external IP.

Notes:
- The free VT tier allows ~4 requests/minute and 500/day, so checking many unique IPs the
  first time can take a while - the console prints progress so it doesn't look frozen.
- Every IP is cached in `soc_logs.db` (table `vt_cache`), so re-running the app only re-checks
  new IPs, not ones already looked up.
- Private IPs (192.168.x.x, 10.x.x.x, etc.) are skipped automatically, since VT only has
  reputation data for public internet addresses.
- With no key set, nothing changes - it keeps using the existing simulated values.

## Using your API key (.env)
1. Copy `.env.example` to `.env` and put your key on the `VT_API_KEY=` line (no quotes, no spaces).
2. `pip install -r requirements.txt` (now includes `python-dotenv`, which is what loads `.env`).
3. `python main.py` - the console should say `[VT] live lookups enabled`.
- Each start-up checks up to `VT_MAX_LOOKUPS` (default 25) new IPs, riskiest first (denied/blocked, High
  FortiGuard risk). Results are cached, so every restart covers more IPs; the rest keep the log's values.
- If VirusTotal rejects the key or the daily quota is hit, lookups stop for that run instead of retrying.
- `.env` is in `.gitignore` - never commit your key.
