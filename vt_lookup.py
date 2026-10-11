"""Optional LIVE VirusTotal IP reputation lookups.

Set VT_API_KEY (in your environment or a .env file) to turn this on. Get a free key
at https://www.virustotal.com/gui/join-us -> your profile -> API key.

Without a key, firewall_parser falls back to the simulated vt_risk/verdict already
present in the log file, and nothing here is called.

The free VT tier is rate-limited (~4 requests/minute, 500/day), so every IP that's
looked up is cached in soc_logs.db (table vt_cache) and only ever queried once -
re-running the app re-uses the cache instead of re-hitting the API.
"""
import os, time, json, ipaddress, urllib.request, urllib.error
import database

VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"
RATE_LIMIT_SECONDS = 16  # ~4 requests/minute, the free-tier limit
MAX_LOOKUPS_PER_RUN = int(os.getenv("VT_MAX_LOOKUPS", "25"))  # new (uncached) IPs checked per start-up
_stop = False  # set when VT rejects the key or the quota is used up, so we stop calling it


def _cache_init():
    with database.conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS vt_cache(ip TEXT PRIMARY KEY, malicious INTEGER,
            suspicious INTEGER, harmless INTEGER, vt_risk INTEGER, verdict TEXT, checked_at TEXT)""")


def _cached(ip):
    with database.conn() as c:
        row = c.execute("SELECT * FROM vt_cache WHERE ip=?", (ip,)).fetchone()
    return dict(row) if row else None


def _save(ip, mal, susp, harm, risk, verdict):
    with database.conn() as c:
        c.execute("""INSERT OR REPLACE INTO vt_cache(ip,malicious,suspicious,harmless,vt_risk,verdict,checked_at)
            VALUES(?,?,?,?,?,?,datetime('now'))""", (ip, mal, susp, harm, risk, verdict))


def is_public(ip):
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def lookup(ip):
    """Return {'vt_risk': 0-100, 'verdict': 'Suspicious'|'Clean'} for a public IP,
    or None if there's no API key, the IP is private, or the request fails."""
    global _stop
    if not VT_API_KEY or not is_public(ip):
        return None
    _cache_init()
    cached = _cached(ip)
    if cached:
        return {"vt_risk": cached["vt_risk"], "verdict": cached["verdict"]}
    if _stop:
        return None

    req = urllib.request.Request(VT_URL.format(ip), headers={"x-apikey": VT_API_KEY})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"[VT] {ip}: HTTP {e.code} ({e.reason}) - check your VT_API_KEY / daily quota")
        if e.code in (401, 403, 429):
            _stop = True  # bad key or quota exhausted - don't keep hammering the API
        return None
    except Exception as e:
        print(f"[VT] {ip}: lookup failed - {e}")
        return None

    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    mal, susp, harm = stats.get("malicious", 0), stats.get("suspicious", 0), stats.get("harmless", 0)
    total = max(mal + susp + harm + stats.get("undetected", 0), 1)
    risk = round((mal + susp) / total * 100)
    verdict = "Suspicious" if (mal > 0 or susp > 0) else "Clean"
    _save(ip, mal, susp, harm, risk, verdict)
    time.sleep(RATE_LIMIT_SECONDS)  # stay under the free-tier rate limit
    return {"vt_risk": risk, "verdict": verdict}


def enrich(rows):
    """Given parsed firewall_logs rows (tuples, see firewall_parser.parse_line), replace the
    vt_risk/verdict fields (indexes 9, 10) with real VirusTotal data for the public IP in each
    connection. A no-op (returns rows unchanged) if VT_API_KEY isn't set.

    Only VT_MAX_LOOKUPS new IPs are queried per start-up (already-cached ones are free), most
    suspicious-looking first (denied/blocked, high FortiGuard risk, malicious flag). IPs not
    reached yet keep the log's own values and get checked on the next run."""
    if not VT_API_KEY:
        print("[VT] no VT_API_KEY found in .env - using the log file's own risk values")
        return rows
    target_of = lambda r: r[4] if not is_public(r[2]) else r[2]  # the external-facing side
    def priority(r):
        return (r[6] != "Allowed", r[8] == "High", r[10] == "Suspicious", r[9])
    order = []
    for r in sorted(rows, key=priority, reverse=True):
        t = target_of(r)
        if t not in order:
            order.append(t)
    cached_n = sum(1 for t in order if is_public(t) and _cached_safe(t))
    todo = [t for t in order if is_public(t) and not _cached_safe(t)][:MAX_LOOKUPS_PER_RUN]
    print(f"[VT] live lookups enabled - {len(order)} unique IPs, {cached_n} cached, "
          f"checking {len(todo)} new one(s) now (~{round(len(todo) * RATE_LIMIT_SECONDS / 60, 1)} min)")
    results = {}
    for i, t in enumerate(todo, 1):
        results[t] = lookup(t) or {}
        if i % 5 == 0 or i == len(todo):
            print(f"[VT] checked {i}/{len(todo)} IPs...")
    out = []
    for r in rows:
        r = list(r)
        t = target_of(r)
        res = results.get(t) or (_cached_safe(t) and {"vt_risk": _cached_safe(t)["vt_risk"],
                                                     "verdict": _cached_safe(t)["verdict"]})
        if res:
            r[9], r[10] = res["vt_risk"], res["verdict"]
        out.append(tuple(r))
    return out


def _cached_safe(ip):
    _cache_init()
    return _cached(ip)
