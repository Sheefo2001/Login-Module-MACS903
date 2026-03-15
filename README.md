# Dual-Module Login Assessment Tool

This Flask app provides two login flows side-by-side: an intentionally vulnerable login and a hardened login. It uses a PostgreSQL or MySQL database and a single `users` table managed by Alembic migrations.

## Environment Isolation

Use a dedicated virtual environment for this project. Your global Python currently has incompatible packages (`faradaysec` pins older Flask/Werkzeug/SQLAlchemy).

Recommended interpreter: Python `3.11` or `3.12`.

```bash
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```
## Setup

1. Create a PostgreSQL or MySQL database.
2. Set `DATABASE_URL` to a Postgres or MySQL SQLAlchemy URL. You can either export it in your shell or create a `.env` file.

Examples:
- `postgresql+psycopg2://user:pass@localhost:5432/smartnotebook`
- `mysql+pymysql://user:pass@localhost:3306/smartnotebook`

3. If using `.env`, copy `.env.example` to `.env` and fill in your values.

4. Install dependencies:

```bash
pip install -r requirements.txt
```

5. Run migrations:

```bash
alembic upgrade head
```

6. Start the app:

```bash
python app.py
```

7. Open `http://localhost:5000` and click **Reset Database** to load test users.


## Run Individual Modules

These are fully standalone apps (no import from app.py), each with its own routes, templates, and runtime logic derived from app.py for separate Bandit analysis.

Insecure-only app (blocks `/login-secure`):

```bash
python app_insecure.py
```

Secure-only app (blocks `/login-insecure`):

```bash
python app_secure.py
```

Default ports:
- `app_insecure.py`: `5001`
- `app_secure.py`: `5002`

Override either with `PORT`, example:

```bash
PORT=5010 python app_secure.py
```
## Key Pages

- `/` Dashboard
- `/login-insecure` Vulnerable login
- `/login-secure` Hardened login
- `/diff` Side-by-side comparison
- `/admin` Admin page (reset DB, create users, logout)
- `/health` JSON health check with DB connectivity + user count

## Test Harness (Black-Box + White-Box)

Run black-box tests against a running server:

```bash
python scripts/test_harness.py --mode black --base-url http://localhost:5000
```

Run white-box tests using Flask's test client:

```bash
python scripts/test_harness.py --mode white
```

Advanced options:

```bash
python scripts/test_harness.py --mode black --basic
python scripts/test_harness.py --mode black --skip-admin
```

## Test Users (loaded by Reset Database)

- `alice_plain` / `password123` (plaintext for insecure login)
- `bob_md5` / `letmein` (MD5 for insecure login)
- `charlie_demo` / `welcome1` (plaintext + MD5 for insecure login)

All users also have Argon2 hashes for the secure login flow.

## SQL Injection Demo (Insecure Module)

The insecure login builds SQL using raw string formatting. That allows classic SQL injection.

Example bypass on **/login-insecure**:

- Username: `alice_plain' OR '1'='1' -- `
- Password: `anything`

The injected username turns the WHERE clause into an always-true condition and comments out the password check. For MySQL you can also use `#` as a comment delimiter. For PostgreSQL/MySQL, the `--` form requires a trailing space.

You can also see username enumeration because the insecure route returns:
- `User does not exist` when the username lookup fails
- `Incorrect password` when the username exists but the password is wrong

Tip: enable **Show SQL debug** on the insecure page to see the raw query strings.

## Rate Limiting + Account Lockout (Secure Module)

The secure login uses an in-memory lockout policy:

- Keyed by client IP (`request.remote_addr`) and username.
- Window size is 5 minutes (300 seconds).
- If either the IP or the username has 5 or more failures in the window, the endpoint returns HTTP 429.
- A successful login clears the attempt history for that IP and username.

Note: because it is in-memory, the rate limit resets when the server restarts. Swap the in-memory store for Redis for a production-safe variant.

## Structured Logging + Correlation IDs

Login events and admin actions are logged as JSON with a `correlation_id`.

- If the request includes `X-Request-Id`, that value is used.
- Otherwise a UUID is generated and returned in the `X-Request-Id` response header.

## Admin Page

The `/admin` page lets you:

- Reset the database.
- Create new users (choose whether to store plaintext and/or MD5 for insecure login).
- Logout (clears both secure and insecure cookies).

Passwords and hashes are never shown in the UI.




