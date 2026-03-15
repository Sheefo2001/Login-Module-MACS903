import hashlib
import json
import logging
import os
import time
import uuid

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from dotenv import load_dotenv
from flask import Flask, g, make_response, redirect, render_template_string, request, url_for
from sqlalchemy import Column, Integer, MetaData, String, Table, Text, create_engine, text

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is required (postgresql+psycopg2://... or mysql+pymysql://...)"
    )
if not (DATABASE_URL.startswith("postgresql") or DATABASE_URL.startswith("mysql")):
    raise RuntimeError("DATABASE_URL must be PostgreSQL or MySQL")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
metadata = MetaData()

users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String(255), nullable=False, unique=True),
    Column("insecure_password_plain", Text),
    Column("insecure_password_md5", String(32)),
    Column("secure_password_hash", Text, nullable=False),
)

ph = PasswordHasher()

RATE_LIMIT_IP = 5
RATE_LIMIT_USER = 5
WINDOW_SECONDS = 300
_RATE_STORE_IP = {}
_RATE_STORE_USER = {}

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-only-secret")

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("auth")

DASHBOARD_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Login Assessment Tool</title>
    <style>
      @import url("https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap");
      :root {
        --bg: #f4f1ec;
        --bg-accent: #e8f0ef;
        --ink: #141414;
        --muted: #5b5b5b;
        --card: #ffffff;
        --accent: #0f766e;
        --accent-2: #164e63;
        --warn: #c2410c;
        --shadow: 0 20px 40px rgba(15, 23, 42, 0.08);
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        font-family: "IBM Plex Sans", "Segoe UI", system-ui, sans-serif;
        color: var(--ink);
        background:
          radial-gradient(1200px 600px at 10% -10%, #e6f2f1 0%, transparent 60%),
          radial-gradient(900px 500px at 90% 0%, #f6e7d7 0%, transparent 55%),
          var(--bg);
      }
      .shell { max-width: 1100px; margin: 0 auto; padding: 48px 24px 80px; }
      .hero {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
        gap: 24px;
        align-items: center;
      }
      .brand {
        font-family: "Space Grotesk", "Segoe UI", system-ui, sans-serif;
        font-size: 38px;
        line-height: 1.1;
        margin: 0 0 12px;
      }
      .subtitle { color: var(--muted); font-size: 16px; margin: 0 0 20px; }
      .card {
        background: var(--card);
        border-radius: 18px;
        padding: 28px;
        box-shadow: var(--shadow);
        border: 1px solid rgba(15, 23, 42, 0.06);
      }
      .grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 16px;
        margin-top: 18px;
      }
      .cta {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 10px;
        padding: 12px 18px;
        border-radius: 10px;
        text-decoration: none;
        color: #fff;
        background: linear-gradient(135deg, var(--accent), var(--accent-2));
        border: none;
        cursor: pointer;
        font-weight: 600;
        transition: transform 200ms ease, box-shadow 200ms ease;
        box-shadow: 0 10px 20px rgba(15, 118, 110, 0.25);
      }
      .cta.secondary { background: #111827; box-shadow: 0 8px 16px rgba(15, 23, 42, 0.18); }
      .cta.light { background: #f8fafc; color: #0f172a; border: 1px solid #e2e8f0; box-shadow: none; }
      .cta:hover { transform: translateY(-2px); }
      .pill {
        display: inline-block;
        padding: 6px 12px;
        border-radius: 999px;
        background: var(--bg-accent);
        color: var(--accent-2);
        font-weight: 600;
        font-size: 12px;
        letter-spacing: 0.4px;
      }
      .note { margin-top: 12px; color: var(--muted); font-size: 14px; }
      .section-title { font-family: "Space Grotesk", sans-serif; font-size: 20px; margin: 0 0 8px; }
      .list { margin: 0; padding-left: 18px; color: var(--muted); }
      .list li { margin-bottom: 6px; }
      .fade-in { animation: fade 0.6s ease; }
      @keyframes fade { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
    </style>
  </head>
  <body>
    <div class="shell">
      <div class="hero fade-in">
        <div class="card">
          <span class="pill">Security Lab</span>
          <h1 class="brand">Dual-Module Login Assessment</h1>
          <p class="subtitle">Explore the contrast between a deliberately vulnerable login flow and its hardened counterpart.</p>
          <div class="grid">
            <a class="cta" href="{{ url_for('login_insecure') }}">Login Insecure</a>
            <a class="cta secondary" href="{{ url_for('login_secure') }}">Login Secure</a>
            <a class="cta light" href="{{ url_for('diff_view') }}">Diff View</a>
            <a class="cta light" href="{{ url_for('admin') }}">Admin</a>
          </div>
          <form method="post" action="{{ url_for('reset_db') }}" style="margin-top: 16px;">
            <button class="cta light" type="submit">Reset Database</button>
          </form>
          <p class="note">Resetting loads three test users with plaintext, MD5, and Argon2 hashes.</p>
        </div>
        <div class="card">
          <h2 class="section-title">What you can validate</h2>
          <ul class="list">
            <li>SQL injection exposure vs parameterized queries.</li>
            <li>Weak hashing vs Argon2 with unique salts.</li>
            <li>Verbose errors vs generic failures.</li>
            <li>Rate limiting and account lockouts.</li>
          </ul>
          <p class="note">Start at the insecure module, then compare outcomes in the secure flow.</p>
        </div>
      </div>
    </div>
  </body>
</html>
"""

LOGIN_INSECURE_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Insecure Login</title>
    <style>
      @import url("https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap");
      :root { --bg: #fff4f2; --card: #ffffff; --ink: #151515; --muted: #6b6b6b; --accent: #b91c1c; --accent-2: #7f1d1d; --shadow: 0 18px 36px rgba(127, 29, 29, 0.12); }
      * { box-sizing: border-box; }
      body { margin: 0; font-family: "IBM Plex Sans", "Segoe UI", system-ui, sans-serif; background: radial-gradient(900px 500px at 10% -10%, #ffe3e0 0%, transparent 60%), var(--bg); color: var(--ink); }
      .shell { max-width: 980px; margin: 0 auto; padding: 48px 24px; }
      .card { background: var(--card); border-radius: 18px; padding: 28px; box-shadow: var(--shadow); border: 1px solid rgba(185, 28, 28, 0.15); }
      .title { font-family: "Space Grotesk", sans-serif; font-size: 30px; margin: 0 0 6px; }
      .subtitle { color: var(--muted); margin: 0 0 20px; }
      label { display: block; font-weight: 600; margin-bottom: 6px; }
      input { width: 100%; padding: 12px 12px; margin: 6px 0 16px; border-radius: 10px; border: 1px solid #f4c7c3; background: #fff; }
      button { padding: 12px 16px; background: linear-gradient(135deg, var(--accent), var(--accent-2)); color: white; border: none; border-radius: 10px; font-weight: 600; cursor: pointer; }
      .error { color: #9f1239; font-weight: 600; }
      .success { color: #065f46; font-weight: 600; }
      .sql { background: #fff1f2; border: 1px dashed #f5b4bb; padding: 12px; border-radius: 10px; margin-top: 12px; }
      pre { white-space: pre-wrap; word-break: break-word; margin: 0; }
      .row { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; color: var(--muted); }
      a { color: #7f1d1d; text-decoration: none; font-weight: 600; }
    </style>
  </head>
  <body>
    <div class="shell">
      <div class="card">
        <h2 class="title">Login (Insecure)</h2>
        <p class="subtitle">Intentionally vulnerable for training and contrast.</p>
        {% if db_error %}<p class="error">{{ db_error }}</p>{% endif %}
        {% if error %}<p class="error">{{ error }}</p>{% endif %}
        {% if result %}<p class="success">{{ result }}</p>{% endif %}
        <form method="post">
          <label>Username</label>
          <input name="username" autocomplete="off" />
          <label>Password</label>
          <input name="password" type="password" autocomplete="off" />
          <div class="row">
            <input type="checkbox" name="show_sql" id="show_sql" {% if show_sql %}checked{% endif %} />
            <label for="show_sql" style="margin:0;">Show SQL debug</label>
          </div>
          <button type="submit">Sign In</button>
        </form>
        {% if show_sql and queries %}
          <div class="sql">
            <strong>SQL Debug</strong>
            <pre>{{ queries.user_query }}</pre>
            <pre>{{ queries.auth_query }}</pre>
          </div>
        {% endif %}
        <p style="margin-top:16px;"><a href="{{ url_for('index') }}">Back to dashboard</a></p>
      </div>
    </div>
  </body>
</html>
"""

LOGIN_SECURE_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Secure Login</title>
    <style>
      @import url("https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap");
      :root { --bg: #eef6ff; --card: #ffffff; --ink: #0f172a; --muted: #64748b; --accent: #0f766e; --accent-2: #164e63; --shadow: 0 18px 36px rgba(15, 118, 110, 0.12); }
      * { box-sizing: border-box; }
      body { margin: 0; font-family: "IBM Plex Sans", "Segoe UI", system-ui, sans-serif; background: radial-gradient(900px 500px at 10% -10%, #d9f2ee 0%, transparent 60%), var(--bg); color: var(--ink); }
      .shell { max-width: 980px; margin: 0 auto; padding: 48px 24px; }
      .card { background: var(--card); border-radius: 18px; padding: 28px; box-shadow: var(--shadow); border: 1px solid rgba(15, 118, 110, 0.15); }
      .title { font-family: "Space Grotesk", sans-serif; font-size: 30px; margin: 0 0 6px; }
      .subtitle { color: var(--muted); margin: 0 0 20px; }
      label { display: block; font-weight: 600; margin-bottom: 6px; }
      input { width: 100%; padding: 12px 12px; margin: 6px 0 16px; border-radius: 10px; border: 1px solid #cde5e1; background: #fff; }
      button { padding: 12px 16px; background: linear-gradient(135deg, var(--accent), var(--accent-2)); color: white; border: none; border-radius: 10px; font-weight: 600; cursor: pointer; }
      .error { color: #9f1239; font-weight: 600; }
      .success { color: #065f46; font-weight: 600; }
      a { color: #0f766e; text-decoration: none; font-weight: 600; }
    </style>
  </head>
  <body>
    <div class="shell">
      <div class="card">
        <h2 class="title">Login (Secure)</h2>
        <p class="subtitle">Hardened flow with parameterized queries and lockouts.</p>
        {% if db_error %}<p class="error">{{ db_error }}</p>{% endif %}
        {% if error %}<p class="error">{{ error }}</p>{% endif %}
        {% if result %}<p class="success">{{ result }}</p>{% endif %}
        <form method="post">
          <label>Username</label>
          <input name="username" autocomplete="off" />
          <label>Password</label>
          <input name="password" type="password" autocomplete="off" />
          <button type="submit">Sign In</button>
        </form>
        <p style="margin-top:16px;"><a href="{{ url_for('index') }}">Back to dashboard</a></p>
      </div>
    </div>
  </body>
</html>
"""

DIFF_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Insecure vs Secure Diff</title>
    <style>
      @import url("https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap");
      :root { --bg: #f6f4ef; --card: #ffffff; --ink: #111827; --muted: #6b7280; --accent: #0f766e; --accent-2: #164e63; --shadow: 0 18px 36px rgba(15, 23, 42, 0.12); }
      * { box-sizing: border-box; }
      body { margin: 0; font-family: "IBM Plex Sans", "Segoe UI", system-ui, sans-serif; background: radial-gradient(900px 500px at 10% -10%, #e6f2f1 0%, transparent 60%), var(--bg); color: var(--ink); }
      .shell { max-width: 1100px; margin: 0 auto; padding: 48px 24px; }
      .card { background: var(--card); border-radius: 18px; padding: 28px; box-shadow: var(--shadow); border: 1px solid rgba(15, 23, 42, 0.06); }
      h2 { font-family: "Space Grotesk", sans-serif; margin: 0 0 8px; }
      p { color: var(--muted); margin: 0 0 18px; }
      table { width: 100%; border-collapse: collapse; margin-top: 8px; }
      th, td { text-align: left; padding: 12px; border-bottom: 1px solid #eee; vertical-align: top; }
      th { background: #f0f7f6; color: #0f172a; }
      a { color: var(--accent-2); text-decoration: none; font-weight: 600; }
    </style>
  </head>
  <body>
    <div class="shell">
      <div class="card">
        <h2>Insecure vs Secure: What Changed</h2>
        <p>Side-by-side comparison of the behaviors you can validate in this lab.</p>
        <table>
          <tr><th>Area</th><th>Insecure</th><th>Secure</th></tr>
          <tr><td>SQL Query</td><td>Raw string concatenation (SQLi possible)</td><td>Parameterized query</td></tr>
          <tr><td>Password Storage</td><td>Plaintext or MD5</td><td>Argon2 with unique salts</td></tr>
          <tr><td>Error Messages</td><td>Verbose (user enumeration)</td><td>Generic "Invalid credentials"</td></tr>
          <tr><td>Rate Limiting</td><td>None</td><td>Per-IP + per-user lockout window</td></tr>
          <tr><td>Cookies</td><td>Insecure session cookie</td><td>HttpOnly + Secure + SameSite=Strict</td></tr>
          <tr><td>Logging</td><td>None</td><td>Structured logs with correlation IDs</td></tr>
        </table>
        <p style="margin-top:16px;"><a href="{{ url_for('index') }}">Back to dashboard</a></p>
      </div>
    </div>
  </body>
</html>
"""

ADMIN_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Admin</title>
    <style>
      @import url("https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap");
      :root { --bg: #f3f1ed; --card: #ffffff; --ink: #111827; --muted: #6b7280; --accent: #0f766e; --accent-2: #164e63; --shadow: 0 18px 36px rgba(15, 23, 42, 0.12); }
      * { box-sizing: border-box; }
      body { margin: 0; font-family: "IBM Plex Sans", "Segoe UI", system-ui, sans-serif; background: radial-gradient(900px 500px at 10% -10%, #e6f2f1 0%, transparent 60%), var(--bg); color: var(--ink); }
      .shell { max-width: 1100px; margin: 0 auto; padding: 48px 24px; }
      .card { background: var(--card); border-radius: 18px; padding: 28px; box-shadow: var(--shadow); border: 1px solid rgba(15, 23, 42, 0.06); }
      h2 { font-family: "Space Grotesk", sans-serif; margin: 0 0 8px; }
      h3 { font-family: "Space Grotesk", sans-serif; margin: 20px 0 8px; }
      table { width: 100%; border-collapse: collapse; margin-top: 12px; }
      th, td { text-align: left; padding: 12px; border-bottom: 1px solid #eee; }
      th { background: #f0f7f6; }
      input[type="text"], input[type="password"] { width: 100%; padding: 12px; margin: 6px 0 12px; border-radius: 10px; border: 1px solid #e2e8f0; }
      button { padding: 12px 16px; background: linear-gradient(135deg, var(--accent), var(--accent-2)); color: white; border: none; border-radius: 10px; font-weight: 600; cursor: pointer; }
      .row { display: flex; gap: 12px; flex-wrap: wrap; }
      .error { color: #9f1239; font-weight: 600; }
      .success { color: #065f46; font-weight: 600; }
      .muted { color: var(--muted); }
      a { color: var(--accent-2); text-decoration: none; font-weight: 600; }
    </style>
  </head>
  <body>
    <div class="shell">
      <div class="card">
        <h2>Admin</h2>
        <p class="muted">Manage data safely for demo and testing.</p>
        {% if error %}<p class="error">{{ error }}</p>{% endif %}
        {% if status %}<p class="success">{{ status }}</p>{% endif %}

        <div class="row">
          <form method="post" action="{{ url_for('reset_db') }}">
            <button type="submit">Reset Database</button>
          </form>
          <form method="post" action="{{ url_for('logout') }}">
            <button type="submit">Logout (clear cookies)</button>
          </form>
        </div>

        <h3>Create User</h3>
        <form method="post" action="{{ url_for('admin_create_user') }}">
          <label>Username</label>
          <input name="username" type="text" required />
          <label>Password (used for secure hash and optional insecure storage)</label>
          <input name="password" type="password" required />
          <div class="row" style="margin-bottom: 8px;">
            <label><input type="checkbox" name="store_plain" checked /> Store plaintext (insecure)</label>
            <label><input type="checkbox" name="store_md5" checked /> Store MD5 (insecure)</label>
          </div>
          <button type="submit">Create User</button>
        </form>

        <h3>Users</h3>
        <table>
          <tr><th>Username</th><th>Plaintext Stored</th><th>MD5 Stored</th><th>Secure Hash</th></tr>
          {% for user in users %}
            <tr>
              <td>{{ user.username }}</td>
              <td>{{ "Yes" if user.has_plain else "No" }}</td>
              <td>{{ "Yes" if user.has_md5 else "No" }}</td>
              <td>{{ "Yes" if user.has_secure else "No" }}</td>
            </tr>
          {% endfor %}
        </table>

        <p style="margin-top:16px;"><a href="{{ url_for('index') }}">Back to dashboard</a></p>
      </div>
    </div>
  </body>
</html>
"""


def md5_hex(value):
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def _prune_attempts(attempts, window_seconds):
    now = time.time()
    return [t for t in attempts if now - t < window_seconds]


def is_rate_limited(ip, username):
    ip_attempts = _prune_attempts(_RATE_STORE_IP.get(ip, []), WINDOW_SECONDS)
    _RATE_STORE_IP[ip] = ip_attempts
    user_attempts = []
    if username:
        user_attempts = _prune_attempts(_RATE_STORE_USER.get(username, []), WINDOW_SECONDS)
        _RATE_STORE_USER[username] = user_attempts
    return len(ip_attempts) >= RATE_LIMIT_IP or (
        username and len(user_attempts) >= RATE_LIMIT_USER
    )


def register_failed_attempt(ip, username):
    now = time.time()
    ip_attempts = _prune_attempts(_RATE_STORE_IP.get(ip, []), WINDOW_SECONDS)
    ip_attempts.append(now)
    _RATE_STORE_IP[ip] = ip_attempts
    if username:
        user_attempts = _prune_attempts(_RATE_STORE_USER.get(username, []), WINDOW_SECONDS)
        user_attempts.append(now)
        _RATE_STORE_USER[username] = user_attempts


def clear_attempts(ip, username):
    if ip:
        _RATE_STORE_IP.pop(ip, None)
    if username:
        _RATE_STORE_USER.pop(username, None)


def log_event(event, **fields):
    payload = {
        "event": event,
        "correlation_id": getattr(g, "correlation_id", None),
        "ip": request.remote_addr,
    }
    payload.update(fields)
    logger.info(json.dumps(payload))


def get_user_count():
    with engine.connect() as conn:
        return conn.execute(text("SELECT COUNT(*) FROM users")).scalar()


def fetch_users():
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT username, insecure_password_plain, insecure_password_md5, secure_password_hash "
                "FROM users ORDER BY username"
            )
        ).mappings().all()
    return [
        {
            "username": row["username"],
            "has_plain": bool(row["insecure_password_plain"]),
            "has_md5": bool(row["insecure_password_md5"]),
            "has_secure": bool(row["secure_password_hash"]),
        }
        for row in rows
    ]


@app.route("/")
def index():
    return render_template_string(DASHBOARD_TEMPLATE)


@app.before_request
def assign_correlation_id():
    g.correlation_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())


@app.after_request
def add_correlation_header(response):
    response.headers["X-Request-Id"] = g.correlation_id
    return response


@app.route("/health")
def health():
    try:
        count = get_user_count()
        return {"status": "ok", "db": "ok", "users": count}, 200
    except Exception as exc:
        log_event("health_check_failed", error=str(exc))
        return {"status": "error", "db": "error", "error": "database_unavailable"}, 500


@app.route("/diff")
def diff_view():
    return render_template_string(DIFF_TEMPLATE)


@app.route("/admin")
def admin():
    error = request.args.get("error")
    status = request.args.get("status")
    users_list = []
    try:
        users_list = fetch_users()
    except Exception as exc:
        error = "Database not ready. Run: alembic upgrade head"
        log_event("admin_db_error", error=str(exc))
    return render_template_string(
        ADMIN_TEMPLATE, users=users_list, error=error, status=status
    )


@app.route("/admin/create-user", methods=["POST"])
def admin_create_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    store_plain = request.form.get("store_plain") == "on"
    store_md5 = request.form.get("store_md5") == "on"

    if not username or not password:
        return redirect(url_for("admin", error="Username and password are required"))

    user_data = {
        "username": username,
        "plain": password if store_plain else None,
        "md5": md5_hex(password) if store_md5 else None,
        "secure": ph.hash(password),
    }

    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO users (username, insecure_password_plain, insecure_password_md5, secure_password_hash)
                    VALUES (:username, :plain, :md5, :secure)
                    """
                ),
                user_data,
            )
        log_event("admin_create_user", username=username)
        return redirect(url_for("admin", status="User created"))
    except Exception as exc:
        log_event("admin_create_user_failed", username=username, error=str(exc))
        return redirect(url_for("admin", error="User already exists or DB error"))


@app.route("/logout", methods=["POST"])
def logout():
    response = redirect(url_for("index"))
    response.set_cookie("secure_session", "", expires=0)
    response.set_cookie("insecure_session", "", expires=0)
    return response


@app.route("/reset-db", methods=["POST"])
def reset_db():
    test_users = [
        {
            "username": "alice_plain",
            "plain": "password123",
            "md5": None,
            "secure": ph.hash("password123"),
        },
        {
            "username": "bob_md5",
            "plain": None,
            "md5": md5_hex("letmein"),
            "secure": ph.hash("letmein"),
        },
        {
            "username": "charlie_demo",
            "plain": "welcome1",
            "md5": md5_hex("welcome1"),
            "secure": ph.hash("welcome1"),
        },
    ]

    try:
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM users"))
            insert_sql = text(
                """
                INSERT INTO users (username, insecure_password_plain, insecure_password_md5, secure_password_hash)
                VALUES (:username, :plain, :md5, :secure)
                """
            )
            for user in test_users:
                conn.execute(insert_sql, user)
        log_event("db_reset")
        return redirect(url_for("index"))
    except Exception as exc:
        log_event("db_reset_failed", error=str(exc))
        return "Database not ready. Run: alembic upgrade head", 500


@app.route("/login-insecure", methods=["GET", "POST"])
def login_insecure():
    error = None
    result = None
    db_error = None
    queries = {"user_query": "", "auth_query": ""}
    show_sql = request.args.get("show_sql") == "1"

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        password_md5 = md5_hex(password)
        show_sql = request.form.get("show_sql") == "on"

        try:
            with engine.connect() as conn:
                user_query = f"SELECT * FROM users WHERE username = '{username}'"
                queries["user_query"] = user_query
                user = conn.exec_driver_sql(user_query).mappings().first()
                if not user:
                    error = "User does not exist"
                    log_event("login_insecure", username=username, outcome="user_not_found")
                else:
                    auth_query = (
                        "SELECT * FROM users WHERE username = '"
                        + username
                        + "' AND (insecure_password_plain = '"
                        + password
                        + "' OR insecure_password_md5 = '"
                        + password_md5
                        + "')"
                    )
                    queries["auth_query"] = auth_query
                    auth = conn.exec_driver_sql(auth_query).mappings().first()
                    if not auth:
                        error = "Incorrect password"
                        log_event(
                            "login_insecure", username=username, outcome="bad_password"
                        )
                    else:
                        result = "Logged in (insecure)."
                        log_event("login_insecure", username=username, outcome="success")
        except Exception as exc:
            db_error = "Database not ready. Run: alembic upgrade head"
            log_event("login_insecure_db_error", error=str(exc))

        if result:
            response = make_response(
                render_template_string(
                    LOGIN_INSECURE_TEMPLATE,
                    error=None,
                    result=result,
                    db_error=None,
                    show_sql=show_sql,
                    queries=queries,
                )
            )
            response.set_cookie("insecure_session", "demo-session")
            return response

    return render_template_string(
        LOGIN_INSECURE_TEMPLATE,
        error=error,
        result=result,
        db_error=db_error,
        show_sql=show_sql,
        queries=queries,
    )


@app.route("/login-secure", methods=["GET", "POST"])
def login_secure():
    error = None
    result = None
    db_error = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        ip = request.remote_addr or "unknown"

        if is_rate_limited(ip, username):
            log_event("login_secure_rate_limited", username=username)
            return (
                render_template_string(
                    LOGIN_SECURE_TEMPLATE,
                    error="Too many attempts. Try again later.",
                    result=None,
                    db_error=None,
                ),
                429,
            )

        try:
            with engine.connect() as conn:
                stmt = text("SELECT * FROM users WHERE username = :username")
                user = conn.execute(stmt, {"username": username}).mappings().first()
        except Exception as exc:
            db_error = "Database not ready. Run: alembic upgrade head"
            log_event("login_secure_db_error", error=str(exc))
            return render_template_string(
                LOGIN_SECURE_TEMPLATE, error=None, result=None, db_error=db_error
            )

        valid = False
        if user:
            try:
                ph.verify(user["secure_password_hash"], password)
                valid = True
            except VerifyMismatchError:
                valid = False

        if not valid:
            register_failed_attempt(ip, username)
            error = "Invalid credentials"
            log_event("login_secure", username=username, outcome="invalid_credentials")
        else:
            clear_attempts(ip, username)
            result = "Logged in (secure)."
            log_event("login_secure", username=username, outcome="success")
            response = make_response(
                render_template_string(
                    LOGIN_SECURE_TEMPLATE,
                    error=None,
                    result=result,
                    db_error=None,
                )
            )
            response.set_cookie(
                "secure_session",
                value=str(uuid.uuid4()),
                httponly=True,
                secure=True,
                samesite="Strict",
            )
            return response

    return render_template_string(
        LOGIN_SECURE_TEMPLATE, error=error, result=result, db_error=db_error
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
