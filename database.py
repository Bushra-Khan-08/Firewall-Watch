import sqlite3, datetime as dt, os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE_DIR, "soc_logs.db")

def conn():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init():
    with conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS auth_logs(id INTEGER PRIMARY KEY, date TEXT, time TEXT,
            user TEXT, status TEXT, source_ip TEXT);
        CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, date TEXT, time TEXT,
            alert_type TEXT, severity TEXT, source_ip TEXT, details TEXT);
        """)
        create_firewall(c)

def create_firewall(c, drop=False):
    if drop:
        c.execute("DROP TABLE IF EXISTS firewall_logs")
    c.execute("""CREATE TABLE IF NOT EXISTS firewall_logs(id INTEGER PRIMARY KEY, date TEXT, time TEXT,
        src_ip TEXT, src_port TEXT, dst_ip TEXT, dst_port TEXT, action TEXT, app TEXT,
        forti_risk TEXT, vt_risk INTEGER, malicious TEXT, dst_country TEXT, service TEXT,
        sent INTEGER, rcvd INTEGER, policy TEXT)""")

def _now():
    n = dt.datetime.now()
    return n.strftime("%Y-%m-%d"), n.strftime("%H:%M:%S")

def add_auth(user, status, ip):
    d, t = _now()
    with conn() as c:
        c.execute("INSERT INTO auth_logs(date,time,user,status,source_ip) VALUES(?,?,?,?,?)",
                  (d, t, user, status, ip))

def add_alert(alert_type, severity, ip, details=""):
    d, t = _now()
    with conn() as c:
        c.execute("INSERT INTO alerts(date,time,alert_type,severity,source_ip,details) VALUES(?,?,?,?,?,?)",
                  (d, t, alert_type, severity, ip, details))

def rows(table, limit=1000):
    with conn() as c:
        return c.execute(f"SELECT * FROM {table} ORDER BY date DESC, time DESC, id DESC LIMIT ?",
                         (limit,)).fetchall()

def counts(table, col):
    with conn() as c:
        return {r[0]: r[1] for r in c.execute(f"SELECT {col}, COUNT(*) FROM {table} GROUP BY {col}")}

def top_counts(table, col, limit=6, add_other=True, other_label="Others"):
    """Top `limit` values of col by frequency; remainder grouped into other_label."""
    with conn() as c:
        data = c.execute(f"SELECT {col}, COUNT(*) n FROM {table} GROUP BY {col} "
                         "ORDER BY n DESC").fetchall()
    d = {r[0]: r[1] for r in data[:limit]}
    rest = sum(r[1] for r in data[limit:])
    if add_other and rest:
        d[other_label] = rest
    return d

def auth_grouped_by_ip():
    """Authentication logs grouped by source IP (one 'device'), newest group first,
    each with its own log entries newest first."""
    groups = {}
    for r in rows("auth_logs"):
        g = groups.setdefault(r["source_ip"], {"ip": r["source_ip"], "logs": [],
            "latest_time": f"{r['date']} {r['time']}", "success": 0, "failed": 0, "locked": 0})
        g["logs"].append(dict(r))
        key = {"Success": "success", "Failed": "failed", "Locked": "locked"}.get(r["status"])
        if key:
            g[key] += 1
    return sorted(groups.values(), key=lambda g: g["latest_time"], reverse=True)

def login_admin_vs_other(admin_user):
    with conn() as c:
        admin = c.execute("SELECT COUNT(*) FROM auth_logs WHERE user=? AND status='Success'",
                          (admin_user,)).fetchone()[0]
        other = c.execute("SELECT COUNT(*) FROM auth_logs WHERE NOT(user=? AND status='Success')",
                          (admin_user,)).fetchone()[0]
    return {"Admin logins": admin, "Other login attempts": other}
