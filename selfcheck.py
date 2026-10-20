"""Self-check: proves the security properties by actually exercising the API.

Uses Flask's test client, so no server and no port are needed.
The last line is the summary that matters:

    ==== PASS=N FAIL=0 ====

Run:  python selfcheck.py
"""

import os
import sys

DB_FILE = os.path.abspath(".selfcheck.db")
if os.path.exists(DB_FILE):
    os.remove(DB_FILE)
os.environ["APP_DB"] = DB_FILE  # must be set before app is imported

from app import app  # noqa: E402  (import order is deliberate)

results = []

# The passwords used below are hardcoded on purpose: they are dummy fixtures
# for the tests, not secrets, so bandit's B105 guess is suppressed on those lines.


def check(name, condition, detail=""):
    ok = bool(condition)
    results.append(ok)
    # Detail only makes sense when something went wrong; on PASS it would contradict.
    line = "[{}] {}".format("PASS" if ok else "FAIL", name)
    if not ok and detail:
        line += "  -> " + detail
    print(line)


def main():
    client = app.test_client()

    # --- authentication ---------------------------------------------------
    response = client.post("/auth/login", json={"login": "alice", "password": "secret123"})  # nosec B105
    token = (response.get_json() or {}).get("token") if response.status_code == 200 else None
    check("login with valid credentials returns 200 + token", response.status_code == 200 and token,
          "status={}".format(response.status_code))

    response = client.post("/auth/login", json={"login": "alice", "password": "wrong"})  # nosec B105
    check("login with wrong password is rejected (401)", response.status_code == 401,
          "status={}".format(response.status_code))

    response = client.post("/auth/login", json={"login": "nobody", "password": "x"})  # nosec B105
    check("login for unknown user is rejected (401)", response.status_code == 401,
          "status={}".format(response.status_code))

    # --- SQL injection ----------------------------------------------------
    for payload in ["alice' OR '1'='1", "' OR 1=1--", "admin'--"]:
        response = client.post("/auth/login", json={"login": payload, "password": "x"})  # nosec B105
        check("SQLi in login rejected: {!r}".format(payload), response.status_code == 401,
              "status={}".format(response.status_code))

    auth = {"Authorization": "Bearer " + token} if token else {}
    response = client.get("/api/data", query_string={"q": "' OR 1=1--"}, headers=auth)
    body = response.get_json() or {}
    check("SQLi in ?q= filter matches nothing (no row leak)",
          response.status_code == 200 and body.get("count") == 0,
          "count={}".format(body.get("count")))

    # --- access control ---------------------------------------------------
    response = client.get("/api/data")
    check("GET /api/data without token is denied (401)", response.status_code == 401,
          "status={}".format(response.status_code))

    response = client.get("/api/data", headers={"Authorization": "Bearer not-a-real-token"})
    check("GET /api/data with a bogus token is denied (401)", response.status_code == 401,
          "status={}".format(response.status_code))

    if token:
        tampered = token[:-4] + ("aaaa" if not token.endswith("aaaa") else "bbbb")
        response = client.get("/api/data", headers={"Authorization": "Bearer " + tampered})
        check("GET /api/data with a tampered signature is denied (401)",
              response.status_code == 401, "status={}".format(response.status_code))

    response = client.get("/api/data", headers=auth)
    body = response.get_json() or {}
    check("GET /api/data with a valid token returns the users",
          response.status_code == 200 and body.get("count", 0) >= 2,
          "count={}".format(body.get("count")))

    response = client.post("/api/posts", json={"content": "no token here"})
    check("POST /api/posts without token is denied (401)", response.status_code == 401,
          "status={}".format(response.status_code))

    # --- XSS --------------------------------------------------------------
    payload = "<script>alert('xss')</script>"
    response = client.post("/api/posts", json={"content": payload}, headers=auth)
    check("POST /api/posts with a valid token creates the post (201)",
          response.status_code == 201, "status={}".format(response.status_code))

    response = client.get("/api/posts", headers=auth)
    raw = response.get_data(as_text=True)
    check("stored <script> is escaped in the JSON response",
          "<script>alert" not in raw and "&lt;script&gt;" in raw,
          "raw script tag leaked into response")

    response = client.get("/api/posts", query_string={"format": "html"}, headers=auth)
    html_body = response.get_data(as_text=True)
    check("stored <script> is escaped in the HTML view too",
          "<script>alert" not in html_body and "&lt;script&gt;" in html_body,
          "raw script tag leaked into HTML")

    # --- password storage -------------------------------------------------
    from db import connect

    db_conn = connect()
    try:
        stored = db_conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", ("alice",)
        ).fetchone()["password_hash"]
    finally:
        db_conn.close()
    check("password is stored as a scrypt hash, never plaintext",
          stored.startswith("scrypt$") and "secret123" not in stored,
          "stored value: {!r}".format(stored[:24] + "..."))

    # --- summary ----------------------------------------------------------
    passed = sum(1 for ok in results if ok)
    failed = len(results) - passed
    print()
    print("==== PASS={} FAIL={} ====".format(passed, failed))

    if failed == 0 and os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
