import argparse
import os
import sys
import time
import uuid
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_env():
    try:
        from dotenv import load_dotenv
    except Exception:
        return
    dotenv_path = PROJECT_ROOT / ".env"
    load_dotenv(dotenv_path=dotenv_path)


def record(results, name, ok, note):
    results.append((name, ok, note))


def run_black_box(base_url, advanced, skip_admin):
    import requests

    session = requests.Session()
    results = []
    secure_failures = 0

    def post(path, data=None, headers=None):
        return session.post(f"{base_url}{path}", data=data or {}, headers=headers or {}, timeout=10)

    def get(path, headers=None):
        return session.get(f"{base_url}{path}", headers=headers or {}, timeout=10)

    try:
        r = post("/reset-db")
        record(results, "reset-db", r.status_code < 400, f"status {r.status_code}")
    except Exception as exc:
        record(results, "reset-db", False, f"error: {exc}")
        return results

    req_id = f"harness-{uuid.uuid4()}"
    r = get("/health", headers={"X-Request-Id": req_id})
    ok_health = r.status_code == 200
    record(results, "health", ok_health, f"status {r.status_code}")
    record(
        results,
        "correlation-id",
        r.headers.get("X-Request-Id") == req_id,
        "expected echo of X-Request-Id",
    )
    if ok_health:
        try:
            payload = r.json()
            record(
                results,
                "health-payload",
                payload.get("status") == "ok" and payload.get("db") == "ok",
                "expected status=db ok",
            )
        except Exception:
            record(results, "health-payload", False, "invalid json payload")

    new_user = f"tester_{uuid.uuid4().hex[:6]}"
    new_pass = "Password123!"
    if not skip_admin:
        r = post(
            "/admin/create-user",
            data={
                "username": new_user,
                "password": new_pass,
                "store_plain": "on",
                "store_md5": "on",
            },
        )
        record(results, "admin-create-user", r.status_code < 400, f"status {r.status_code}")

        r = post("/login-insecure", {"username": new_user, "password": new_pass})
        record(results, "admin-user-insecure-login", "Logged in (insecure)." in r.text, "expected login")

        r = post("/login-secure", {"username": new_user, "password": new_pass})
        record(results, "admin-user-secure-login", "Logged in (secure)." in r.text, "expected login")
        cookie = r.headers.get("Set-Cookie", "")
        record(
            results,
            "secure-cookie-flags",
            "secure_session=" in cookie and "HttpOnly" in cookie and "Secure" in cookie and "SameSite=Strict" in cookie,
            "expected HttpOnly + Secure + SameSite=Strict",
        )

    r = post("/login-insecure", {"username": "ghost_user", "password": "x"})
    record(results, "insecure-user-enum", "User does not exist" in r.text, "expected verbose user error")

    r = post("/login-insecure", {"username": "alice_plain", "password": "wrong"})
    record(results, "insecure-bad-pass", "Incorrect password" in r.text, "expected incorrect password")

    r = post("/login-insecure", {"username": "alice_plain", "password": "password123"})
    record(results, "insecure-valid", "Logged in (insecure)." in r.text, "expected login")

    r = post("/login-insecure", {"username": "alice_plain' OR '1'='1' -- ", "password": "x"})
    record(results, "insecure-sqli-user", "Logged in (insecure)." in r.text, "expected SQLi bypass")

    r = post("/login-insecure", {"username": "alice_plain", "password": "' OR '1'='1' -- "})
    record(results, "insecure-sqli-pass", "Logged in (insecure)." in r.text, "expected SQLi bypass")

    if advanced:
        r = post("/login-insecure", {"username": "alice_plain", "password": "x", "show_sql": "on"})
        record(results, "insecure-show-sql", "SQL Debug" in r.text, "expected SQL debug output")

    r = post("/login-secure", {"username": "ghost_user", "password": "x"})
    secure_failures += 1
    record(
        results,
        "secure-generic-error",
        "Invalid credentials" in r.text and "User does not exist" not in r.text,
        "expected generic error",
    )

    r = post("/login-secure", {"username": "alice_plain' OR '1'='1' -- ", "password": "x"})
    secure_failures += 1
    record(results, "secure-sqli-blocked", "Invalid credentials" in r.text, "expected SQLi blocked")

    rate_limit_threshold = 5
    while secure_failures < rate_limit_threshold:
        post("/login-secure", {"username": "alice_plain", "password": "wrong"})
        secure_failures += 1
        time.sleep(0.05)

    r = post("/login-secure", {"username": "alice_plain", "password": "wrong"})
    record(results, "secure-rate-limit", r.status_code == 429, "expected HTTP 429")

    r = post("/login-secure", {"username": "alice_plain", "password": "password123"})
    record(results, "secure-lockout-blocks-valid", r.status_code == 429, "expected lockout to block")

    return results


def run_white_box(advanced, skip_admin):
    load_env()
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))

    if not os.getenv("DATABASE_URL"):
        return [("env-database-url", False, "DATABASE_URL not set or .env missing")]

    from app import app as flask_app

    results = []
    secure_failures = 0
    client = flask_app.test_client()

    client.post("/reset-db")

    req_id = f"harness-{uuid.uuid4()}"
    r = client.get("/health", headers={"X-Request-Id": req_id})
    record(results, "health", r.status_code == 200, f"status {r.status_code}")
    record(
        results,
        "correlation-id",
        r.headers.get("X-Request-Id") == req_id,
        "expected echo of X-Request-Id",
    )

    new_user = f"tester_{uuid.uuid4().hex[:6]}"
    new_pass = "Password123!"
    if not skip_admin:
        r = client.post(
            "/admin/create-user",
            data={"username": new_user, "password": new_pass, "store_plain": "on", "store_md5": "on"},
        )
        record(results, "admin-create-user", r.status_code < 400, f"status {r.status_code}")

        r = client.post("/login-insecure", data={"username": new_user, "password": new_pass})
        record(results, "admin-user-insecure-login", b"Logged in (insecure)." in r.data, "expected login")

        r = client.post("/login-secure", data={"username": new_user, "password": new_pass})
        record(results, "admin-user-secure-login", b"Logged in (secure)." in r.data, "expected login")
        cookie = r.headers.get("Set-Cookie", "")
        record(
            results,
            "secure-cookie-flags",
            "secure_session=" in cookie and "HttpOnly" in cookie and "Secure" in cookie and "SameSite=Strict" in cookie,
            "expected HttpOnly + Secure + SameSite=Strict",
        )

    r = client.post("/login-insecure", data={"username": "ghost_user", "password": "x"})
    record(results, "insecure-user-enum", b"User does not exist" in r.data, "expected verbose user error")

    r = client.post("/login-insecure", data={"username": "alice_plain", "password": "wrong"})
    record(results, "insecure-bad-pass", b"Incorrect password" in r.data, "expected incorrect password")

    r = client.post("/login-insecure", data={"username": "alice_plain", "password": "password123"})
    record(results, "insecure-valid", b"Logged in (insecure)." in r.data, "expected login")

    r = client.post("/login-insecure", data={"username": "alice_plain' OR '1'='1' -- ", "password": "x"})
    record(results, "insecure-sqli-user", b"Logged in (insecure)." in r.data, "expected SQLi bypass")

    r = client.post("/login-insecure", data={"username": "alice_plain", "password": "' OR '1'='1' -- "})
    record(results, "insecure-sqli-pass", b"Logged in (insecure)." in r.data, "expected SQLi bypass")

    if advanced:
        r = client.post("/login-insecure", data={"username": "alice_plain", "password": "x", "show_sql": "on"})
        record(results, "insecure-show-sql", b"SQL Debug" in r.data, "expected SQL debug output")

    r = client.post("/login-secure", data={"username": "ghost_user", "password": "x"})
    secure_failures += 1
    record(
        results,
        "secure-generic-error",
        b"Invalid credentials" in r.data and b"User does not exist" not in r.data,
        "expected generic error",
    )

    r = client.post("/login-secure", data={"username": "alice_plain' OR '1'='1' -- ", "password": "x"})
    secure_failures += 1
    record(results, "secure-sqli-blocked", b"Invalid credentials" in r.data, "expected SQLi blocked")

    rate_limit_threshold = 5
    while secure_failures < rate_limit_threshold:
        client.post("/login-secure", data={"username": "alice_plain", "password": "wrong"})
        secure_failures += 1
        time.sleep(0.01)

    r = client.post("/login-secure", data={"username": "alice_plain", "password": "wrong"})
    record(results, "secure-rate-limit", r.status_code == 429, "expected HTTP 429")

    r = client.post("/login-secure", data={"username": "alice_plain", "password": "password123"})
    record(results, "secure-lockout-blocks-valid", r.status_code == 429, "expected lockout to block")

    return results


def render(results):
    failed = 0
    for name, ok, note in results:
        status = "PASS" if ok else "FAIL"
        if not ok:
            failed += 1
        if ok:
            print(f"{status:4}  {name:26}")
        else:
            print(f"{status:4}  {name:26}  {note}")
    return failed


def main():
    parser = argparse.ArgumentParser(description="Login Assessment Test Harness")
    parser.add_argument(
        "--mode",
        choices=["black", "white"],
        default="black",
        help="black=HTTP against running server, white=Flask test client",
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost:5000",
        help="Base URL for black-box mode",
    )
    parser.add_argument(
        "--basic",
        action="store_true",
        help="Skip advanced checks (SQL debug, cookie flags, lockout validation)",
    )
    parser.add_argument(
        "--skip-admin",
        action="store_true",
        help="Skip admin create-user flow",
    )
    args = parser.parse_args()

    advanced = not args.basic

    if args.mode == "black":
        results = run_black_box(args.base_url, advanced, args.skip_admin)
    else:
        results = run_white_box(advanced, args.skip_admin)

    failed = render(results)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    load_env()
    main()
