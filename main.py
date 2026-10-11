import os, time
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))  # must run before importing modules that read env vars
from functools import wraps
from flask import Flask, render_template, request, redirect, session, url_for
import database, firewall_parser

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "change-me")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASSWORD", "change-me")
MAX_ATTEMPTS, LOCK_SECONDS = 3, 300          # 3 wrong tries -> locked for 5 minutes
attempts = {}                                 # ip -> {"fails": int, "until": float}

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        return f(*a, **k) if session.get("admin") else redirect(url_for("login"))
    return w

@app.route("/login", methods=["GET", "POST"])
def login():
    ip = request.remote_addr
    st = attempts.setdefault(ip, {"fails": 0, "until": 0})
    remaining = int(st["until"] - time.time())
    if remaining > 0:
        return render_template("login.html", locked=remaining, error=None)
    error = None
    if request.method == "POST":
        user, pw = request.form.get("username", "").strip(), request.form.get("password", "")
        if user == ADMIN_USER and pw == ADMIN_PASS:
            st["fails"] = 0
            database.add_auth(user, "Success", ip)
            session["admin"] = True
            return redirect(url_for("dashboard"))
        st["fails"] += 1
        if st["fails"] >= MAX_ATTEMPTS:
            database.add_auth(user or "unknown", "Locked", ip)
            database.add_alert("Brute Force", "Critical", ip,
                               f"{MAX_ATTEMPTS} failed logins - locked for {LOCK_SECONDS // 60} min")
            st["fails"], st["until"] = 0, time.time() + LOCK_SECONDS
            return render_template("login.html", locked=LOCK_SECONDS, error=None)
        database.add_auth(user or "unknown", "Failed", ip)
        error = f"Wrong username or password. {MAX_ATTEMPTS - st['fails']} attempt(s) left."
    return render_template("login.html", locked=0, error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    alerts = [a for a in database.rows("alerts") if a["alert_type"] == "Brute Force"]
    fw = [dict(r) for r in database.rows("firewall_logs")]
    for r in fw:
        r["date_time"] = f"{r['date']} {r['time']}"
    c_fw_all = database.counts("firewall_logs", "action")
    c_block = {k: v for k, v in c_fw_all.items() if k != "Allowed"}
    return render_template("dashboard.html",
        auth_groups=database.auth_grouped_by_ip(), alerts=alerts, fw=fw,
        c_auth=database.counts("auth_logs", "status"),
        c_block=c_block,
        c_country=database.top_counts("firewall_logs", "dst_country", 6),
        c_country_bar=database.top_counts("firewall_logs", "dst_country", 8, add_other=False),
        c_login=database.login_admin_vs_other(ADMIN_USER))

if __name__ == "__main__":
    database.init()
    ok, bad = firewall_parser.ingest()
    print(f"Firewall logs parsed: {ok}  (skipped: {bad})")
    app.run(host="127.0.0.1", port=5000, debug=False)
