"""Parses firewall traffic logs (key=value lines) into soc_logs.db.

Expected line style (FortiGate-like):
  2026-08-30 10:25:00 srcip=1.2.3.4 srcport=51422 dstip=5.6.7.8 dstport=443 action=allow
      app=HTTPS fortirisk=Low vtrisk=4 malicious=no dstcountry="United States" service=HTTPS
      sentbyte=2048 rcvdbyte=15320 policyid=LAN-to-WAN-01
"""
import re, os, database, vt_lookup

KV = re.compile(r'(\w+)=("[^"]*"|\S+)')
TS = re.compile(r'^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})')
ALIAS = {"srcip": "src_ip", "dstip": "dst_ip", "srcport": "src_port", "dstport": "dst_port",
         "fortirisk": "forti_risk", "vtrisk": "vt_risk", "dstcountry": "dst_country",
         "sentbyte": "sent", "rcvdbyte": "rcvd", "rcvbyte": "rcvd", "policyid": "policy"}
ACTION = {"allow": "Allowed", "accept": "Allowed", "pass": "Allowed", "close": "Allowed",
          "block": "Blocked", "blocked": "Blocked", "deny": "Denied", "denied": "Denied",
          "drop": "Dropped", "dropped": "Dropped"}
VT_SUSPICIOUS_THRESHOLD = 50  # vt_risk score (0-100) at/above this is flagged Suspicious

def _int(v):
    try: return int(v)
    except (TypeError, ValueError): return 0

def parse_line(line):
    line = line.strip()
    kv = {ALIAS.get(k.lower(), k.lower()): v.strip('"') for k, v in KV.findall(line)}
    m = TS.match(line)
    d, t = m.groups() if m else (kv.get("date", ""), kv.get("time", ""))
    if "src_ip" not in kv or not d:
        return None
    vt_risk = _int(kv.get("vt_risk"))
    flagged = (kv.get("malicious", "no") or "no").lower() in ("yes", "true", "1")
    # VirusTotal-style verdict: a source IP is called Suspicious once enough security
    # vendors / its risk score cross the threshold, same idea as a VT reputation check.
    verdict = "Suspicious" if (vt_risk >= VT_SUSPICIOUS_THRESHOLD or flagged) else "Clean"
    return (d, t, kv["src_ip"], kv.get("src_port", ""), kv.get("dst_ip", ""), kv.get("dst_port", ""),
            ACTION.get(kv.get("action", "").lower(), "Others"), kv.get("app", ""),
            (kv.get("forti_risk", "") or "Low").title(), vt_risk, verdict,
            kv.get("dst_country", "Unknown"), kv.get("service", kv.get("app", "")),
            _int(kv.get("sent")), _int(kv.get("rcvd")), kv.get("policy", ""))

def ingest(path=None):
    """(Re)load the firewall_logs table from `path`. Returns (parsed, skipped)."""
    if path is None:
        path = os.path.join(database.BASE_DIR, "firewall_logs.txt")
    if not os.path.exists(path):
        print(f"[!] {path} not found - put your firewall log file in the project folder.")
        return 0, 0
    with open(path, errors="ignore") as f:
        lines = [l for l in f if l.strip()]
    data = [r for r in map(parse_line, lines) if r]
    data.sort(key=lambda r: (r[0], r[1]))
    data = vt_lookup.enrich(data)  # no-op unless VT_API_KEY is set
    with database.conn() as c:
        database.create_firewall(c, drop=True)
        c.executemany("INSERT INTO firewall_logs(date,time,src_ip,src_port,dst_ip,dst_port,action,"
                      "app,forti_risk,vt_risk,malicious,dst_country,service,sent,rcvd,policy) "
                      "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", data)
    return len(data), len(lines) - len(data)
