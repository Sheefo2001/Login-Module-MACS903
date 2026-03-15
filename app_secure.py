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
logger = logging.getLogger("auth_secure")

HOME_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Secure Module</title>
    <style>
      @import url("https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap");
      :root { --bg:#ecf8f5; --card:#fff; --ink:#152022; --muted:#5f6b6d; --accent:#0f766e; --accent2:#164e63; --shadow:0 20px 36px rgba(22, 78, 99, 0.14); }
      * { box-sizing:border-box; }
      body { margin:0; font-family:"IBM Plex Sans", sans-serif; color:var(--ink); background:radial-gradient(900px 500px at 12% -10%, #ccf0e8 0%, transparent 60%), var(--bg); }
      .shell { max-width:1060px; margin:0 auto; padding:44px 22px; }
      .card { background:var(--card); border:1px solid #c2ece3; border-radius:18px; box-shadow:var(--shadow); padding:28px; }
      h1 { font-family:"Space Grotesk", sans-serif; margin:0 0 8px; font-size:34px; }
      p { color:var(--muted); margin:0 0 18px; }
      .row { display:flex; gap:12px; flex-wrap:wrap; }
      .btn { padding:12px 16px; border-radius:10px; border:none; text-decoration:none; cursor:pointer; color:#fff; font-weight:600; background:linear-gradient(135deg, var(--accent), var(--accent2)); }
      .btn.alt { background:#0f172a; }
      .note { margin-top:14px; font-size:14px; }
    </style>
  </head>
  <body>
    <div class="shell">
      <div class="card">
        <h1>Secure Login Module</h1>
        <p>Standalone hardened authentication application for focused security testing and Bandit analysis.</p>
        <div class="row">
          <a class="btn" href="{{ url_for('login_secure') }}">Open Login</a>
          <a class="btn alt" href="{{ url_for('admin') }}">Admin</a>
          <form method="post" action="{{ url_for('reset_db') }}">
            <button class="btn alt" type="submit">Reset Database</button>
          </form>
        </div>
        <p class="note">Health endpoint: <code>/health</code></p>
      </div>
    </div>
  </body>
</html>
"""

LOGIN_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Secure Login</title>
    <style>
      @import url("https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap");
      :root { --bg:#edf8f6; --card:#fff; --ink:#132427; --muted:#607073; --accent:#0f766e; --accent2:#164e63; --shadow:0 20px 36px rgba(22, 78, 99, 0.14); }
      * { box-sizing:border-box; }
      body { margin:0; font-family:"IBM Plex Sans", sans-serif; color:var(--ink); background:radial-gradient(900px 500px at 12% -10%, #ccf0e8 0%, transparent 60%), var(--bg); }
      .shell { max-width:920px; margin:0 auto; padding:44px 22px; }
      .card { background:var(--card); border:1px solid #c2ece3; border-radius:18px; box-shadow:var(--shadow); padding:28px; }
      h2 { font-family:"Space Grotesk", sans-serif; margin:0 0 6px; font-size:30px; }
      p { margin:0 0 16px; color:var(--muted); }
      label { display:block; font-weight:600; margin:6px 0; }
      input[type="text"], input[type="password"] { width:100%; padding:12px; border:1px solid #bde3db; border-radius:10px; margin-bottom:12px; }
      button { padding:12px 16px; border:none; border-radius:10px; color:#fff; cursor:pointer; font-weight:600; background:linear-gradient(135deg, var(--accent), var(--accent2)); }
      .error { color:#9f1239; font-weight:600; }
      .success { color:#065f46; font-weight:600; }
      a { color:#0f766e; text-decoration:none; font-weight:600; }
    </style>
  </head>
  <body>
    <div class="shell">
      <div class="card">
        <h2>Login (Secure)</h2>
        <p>Parameterized query + Argon2 + generic errors + rate limiting.</p>
        {% if db_error %}<p class="error">{{ db_error }}</p>{% endif %}
        {% if error %}<p class="error">{{ error }}</p>{% endif %}
        {% if result %}<p class="success">{{ result }}</p>{% endif %}
        <form method="post">
          <label>Username</label>
          <input type="text" name="username" autocomplete="off" required />
          <label>Password</label>
          <input type="password" name="password" autocomplete="off" required />
          <button type="submit">Sign In</button>
        </form>
        <p style="margin-top:14px;"><a href="{{ url_for('index') }}">Back to home</a></p>
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
    <title>Secure Admin</title>
    <style>
      @import url("https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap");
      :root { --bg:#f0f8f6; --card:#fff; --ink:#152022; --muted:#5f6b6d; --accent:#0f766e; --accent2:#164e63; --shadow:0 20px 36px rgba(22, 78, 99, 0.14); }
      * { box-sizing:border-box; }
      body { margin:0; font-family:"IBM Plex Sans", sans-serif; color:var(--ink); background:radial-gradient(900px 500px at 12% -10%, #ccf0e8 0%, transparent 60%), var(--bg); }
      .shell { max-width:1060px; margin:0 auto; padding:44px 22px; }
      .card { background:var(--card); border:1px solid #c2ece3; border-radius:18px; box-shadow:var(--shadow); padding:28px; }
      h2, h3 { font-family:"Space Grotesk", sans-serif; margin:0 0 10px; }
      .muted { color:var(--muted); }
      .row { display:flex; gap:12px; flex-wrap:wrap; }
      input[type="text"], input[type="password"] { width:100%; padding:12px; border:1px solid #bde3db; border-radius:10px; margin-bottom:12px; }
      button { padding:12px 16px; border:none; border-radius:10px; color:#fff; cursor:pointer; font-weight:600; background:linear-gradient(135deg, var(--accent), var(--accent2)); }
      table { width:100%; border-collapse:collapse; margin-top:12px; }
      th, td { text-align:left; padding:12px; border-bottom:1px solid #e4f1ee; }
      th { background:#eef8f5; }
      .error { color:#9f1239; font-weight:600; }
      .success { color:#065f46; font-weight:600; }
      a { color:#0f766e; text-decoration:none; font-weight:600; }
    </style>
  </head>
  <body>
    <div class="shell">
      <div class="card">
        <h2>Secure Module Admin</h2>
        <p class="muted">Create users with Argon2 hashes only. No insecure password fields are stored from this UI.</p>
        {% if error %}<p class="error">{{ error }}</p>{% endif %}
        {% if status %}<p class="success">{{ status }}</p>{% endif %}

        <div class="row">
          <form method="post" action="{{ url_for('reset_db') }}">
            <button type="submit">Reset Database</button>
          </form>
          <form method="post" action="{{ url_for('logout') }}">
            <button type="submit">Logout</button>
          </form>
        </div>

        <h3 style="margin-top:18px;">Create Secure User</h3>
        <form method="post" action="{{ url_for('admin_create_user') }}">
          <label>Username</label>
          <input type="text" name="username" required />
          <label>Password</label>
          <input type="password" name="password" required />
          <button type="submit">Create User</button>
        </form>

        <h3 style="margin-top:18px;">Users</h3>
        <table>
          <tr><th>Username</th><th>Argon2 Hash Stored</th></tr>
          {% for user in users %}
          <tr>
            <td>{{ user.username }}</td>
            <td>{{ "Yes" if user.has_secure else "No" }}</td>
          </tr>
          {% endfor %}
        </table>

        <p style="margin-top:14px;"><a href="{{ url_for('index') }}">Back to home</a></p>
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

    return len(ip_attempts) >= RATE_LIMIT_IP or (username and len(user_attempts) >= RATE_LIMIT_USER)


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
            text("SELECT username, secure_password_hash FROM users ORDER BY username")
        ).mappings().all()

    return [
        {
            "username": row["username"],
            "has_secure": bool(row["secure_password_hash"]),
        }
        for row in rows
    ]


def seed_users():
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


@app.before_request
def assign_correlation_id():
    g.correlation_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())


@app.after_request
def add_correlation_header(response):
    response.headers["X-Request-Id"] = g.correlation_id
    return response


@app.route("/")
def index():
    return render_template_string(HOME_TEMPLATE)


@app.route("/health")
def health():
    try:
        count = get_user_count()
        return {"status": "ok", "db": "ok", "users": count, "module": "secure"}, 200
    except Exception as exc:
        log_event("health_check_failed", error=str(exc))
        return {"status": "error", "db": "error", "error": "database_unavailable"}, 500


@app.route("/reset-db", methods=["POST"])
def reset_db():
    try:
        seed_users()
        log_event("db_reset")
        return redirect(url_for("index"))
    except Exception as exc:
        log_event("db_reset_failed", error=str(exc))
        return "Database not ready. Run: alembic upgrade head", 500


@app.route("/admin")
def admin():
    error = request.args.get("error")
    status = request.args.get("status")

    try:
        users_list = fetch_users()
    except Exception as exc:
        log_event("admin_db_error", error=str(exc))
        return redirect(url_for("admin", error="Database not ready. Run: alembic upgrade head"))

    return render_template_string(ADMIN_TEMPLATE, users=users_list, error=error, status=status)


@app.route("/admin/create-user", methods=["POST"])
def admin_create_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        return redirect(url_for("admin", error="Username and password are required"))

    user_data = {
        "username": username,
        "plain": None,
        "md5": None,
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
                    LOGIN_TEMPLATE,
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
            return render_template_string(LOGIN_TEMPLATE, error=None, result=None, db_error=db_error)

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
            response = make_response(render_template_string(LOGIN_TEMPLATE, error=None, result=result, db_error=None))
            response.set_cookie(
                "secure_session",
                value=str(uuid.uuid4()),
                httponly=True,
                secure=True,
                samesite="Strict",
            )
            return response

    return render_template_string(LOGIN_TEMPLATE, error=error, result=result, db_error=db_error)


@app.route("/logout", methods=["POST"])
def logout():
    response = redirect(url_for("index"))
    response.set_cookie("secure_session", "", expires=0)
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5002")), debug=True)