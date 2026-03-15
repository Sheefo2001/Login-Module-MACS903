import hashlib
import json
import logging
import os
import uuid

from argon2 import PasswordHasher
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

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-only-secret")

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("auth_insecure")

HOME_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Insecure Module</title>
    <style>
      @import url("https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap");
      :root { --bg:#fff5f2; --card:#fff; --ink:#1a1a1a; --muted:#6d6d6d; --accent:#b42318; --accent2:#7a1a12; --shadow:0 20px 36px rgba(122, 26, 18, 0.14); }
      * { box-sizing:border-box; }
      body { margin:0; font-family:"IBM Plex Sans", sans-serif; color:var(--ink); background:radial-gradient(900px 500px at 12% -10%, #ffd8d3 0%, transparent 60%), var(--bg); }
      .shell { max-width:980px; margin:0 auto; padding:44px 22px; }
      .card { background:var(--card); border:1px solid #f5c2bc; border-radius:18px; box-shadow:var(--shadow); padding:28px; }
      h1 { font-family:"Space Grotesk", sans-serif; margin:0 0 8px; font-size:34px; }
      p { color:var(--muted); margin:0 0 18px; }
      .row { display:flex; gap:12px; flex-wrap:wrap; }
      .btn { padding:12px 16px; border-radius:10px; border:none; text-decoration:none; cursor:pointer; color:#fff; font-weight:600; background:linear-gradient(135deg, var(--accent), var(--accent2)); }
      .btn.alt { background:#111827; }
      .note { margin-top:14px; font-size:14px; }
    </style>
  </head>
  <body>
    <div class="shell">
      <div class="card">
        <h1>Insecure Login Module</h1>
        <p>Standalone vulnerable application for security testing and Bandit analysis.</p>
        <div class="row">
          <a class="btn" href="{{ url_for('login_insecure') }}">Open Login</a>
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
    <title>Insecure Login</title>
    <style>
      @import url("https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap");
      :root { --bg:#fff1ef; --card:#fff; --ink:#191919; --muted:#737373; --accent:#b42318; --accent2:#7a1a12; --shadow:0 20px 36px rgba(122, 26, 18, 0.14); }
      * { box-sizing:border-box; }
      body { margin:0; font-family:"IBM Plex Sans", sans-serif; color:var(--ink); background:radial-gradient(900px 500px at 12% -10%, #ffd8d3 0%, transparent 60%), var(--bg); }
      .shell { max-width:920px; margin:0 auto; padding:44px 22px; }
      .card { background:var(--card); border:1px solid #f5c2bc; border-radius:18px; box-shadow:var(--shadow); padding:28px; }
      h2 { font-family:"Space Grotesk", sans-serif; margin:0 0 6px; font-size:30px; }
      p { margin:0 0 16px; color:var(--muted); }
      label { display:block; font-weight:600; margin:6px 0; }
      input[type="text"], input[type="password"] { width:100%; padding:12px; border:1px solid #f2bbb5; border-radius:10px; margin-bottom:12px; }
      button { padding:12px 16px; border:none; border-radius:10px; color:#fff; cursor:pointer; font-weight:600; background:linear-gradient(135deg, var(--accent), var(--accent2)); }
      .error { color:#9f1239; font-weight:600; }
      .success { color:#065f46; font-weight:600; }
      .sql { margin-top:12px; border:1px dashed #f5b4bb; background:#fff3f4; border-radius:10px; padding:12px; }
      pre { margin:0; white-space:pre-wrap; word-break:break-word; }
      a { color:#7a1a12; text-decoration:none; font-weight:600; }
    </style>
  </head>
  <body>
    <div class="shell">
      <div class="card">
        <h2>Login (Insecure)</h2>
        <p>Deliberately vulnerable. SQLi and weak password storage are enabled by design.</p>
        {% if db_error %}<p class="error">{{ db_error }}</p>{% endif %}
        {% if error %}<p class="error">{{ error }}</p>{% endif %}
        {% if result %}<p class="success">{{ result }}</p>{% endif %}
        <form method="post">
          <label>Username</label>
          <input type="text" name="username" autocomplete="off" required />
          <label>Password</label>
          <input type="password" name="password" autocomplete="off" required />
          <label><input type="checkbox" name="show_sql" {% if show_sql %}checked{% endif %} /> Show SQL debug</label>
          <button type="submit">Sign In</button>
        </form>
        {% if show_sql %}
        <div class="sql">
          <strong>SQL Debug</strong>
          <pre>{{ queries.user_query }}</pre>
          <pre>{{ queries.auth_query }}</pre>
        </div>
        {% endif %}
        <p style="margin-top:14px;"><a href="{{ url_for('index') }}">Back to home</a></p>
      </div>
    </div>
  </body>
</html>
"""


def md5_hex(value):
    return hashlib.md5(value.encode("utf-8")).hexdigest()


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
        return {"status": "ok", "db": "ok", "users": count, "module": "insecure"}, 200
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
                        log_event("login_insecure", username=username, outcome="bad_password")
                    else:
                        result = "Logged in (insecure)."
                        log_event("login_insecure", username=username, outcome="success")
        except Exception as exc:
            db_error = "Database not ready. Run: alembic upgrade head"
            log_event("login_insecure_db_error", error=str(exc))

        if result:
            response = make_response(
                render_template_string(
                    LOGIN_TEMPLATE,
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
        LOGIN_TEMPLATE,
        error=error,
        result=result,
        db_error=db_error,
        show_sql=show_sql,
        queries=queries,
    )


@app.route("/logout", methods=["POST"])
def logout():
    response = redirect(url_for("index"))
    response.set_cookie("insecure_session", "", expires=0)
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5001")), debug=True)
