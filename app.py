"""Secure REST API for the Work 1 assignment.

Endpoints
    POST /auth/login   public  {"login": "...", "password": "..."}  -> JWT
    GET  /api/data     auth    list of users, optional ?q= filter
    POST /api/posts    auth    {"content": "..."}  -> create a post (self-chosen endpoint)
    GET  /api/posts    auth    list posts; ?format=html shows the escaping

Run:  python app.py            (listens on http://127.0.0.1:5000)
"""

from functools import wraps

from flask import Flask, g, jsonify, request

import db
import security


def public_user(row) -> dict:
    """Serialise a user row, escaping every user-controlled field."""
    return {
        "id": row["id"],
        "username": security.escape(row["username"]),
        "bio": security.escape(row["bio"]),
    }


def require_auth(view):
    """Reject anything without a valid, unexpired JWT."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            return jsonify(error="missing bearer token"), 401
        try:
            g.user = security.decode_token(token.strip())
        except Exception:
            # Any signature/expiry/format problem is the same answer: no.
            return jsonify(error="invalid or expired token"), 401
        return view(*args, **kwargs)

    return wrapper


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
    db.init_db()

    # --- authentication ---------------------------------------------------

    @app.post("/auth/login")
    def login():
        body = request.get_json(silent=True) or {}
        username = str(body.get("login") or body.get("username") or "").strip()
        password = str(body.get("password") or "")

        user = db.get_user_by_username(username)
        # Same response for "no such user" and "wrong password": no user enumeration.
        if user is None or not security.verify_password(password, user["password_hash"]):
            return jsonify(error="invalid credentials"), 401

        # token_type is a JSON field naming the auth scheme, not a credential, so
        # bandit's B106 guess is a false positive. A bare `nosec` (no rule id) is
        # used deliberately: with a rule id bandit emits a spurious matching warning.
        return jsonify(
            token=security.issue_token(user),
            token_type="Bearer",  # nosec
            expires_in=security.TOKEN_TTL_SECONDS,
        )

    # --- protected data ---------------------------------------------------

    @app.get("/api/data")
    @require_auth
    def get_data():
        users = [public_user(row) for row in db.list_users(request.args.get("q", ""))]
        return jsonify(count=len(users), users=users)

    # --- self-chosen endpoint: create a post ------------------------------

    @app.post("/api/posts")
    @require_auth
    def create_post():
        body = request.get_json(silent=True) or {}
        content = str(body.get("content") or "").strip()
        if not content:
            return jsonify(error="content is required"), 400
        if len(content) > 1000:
            return jsonify(error="content must be at most 1000 characters"), 400

        post_id = db.create_post(int(g.user["sub"]), content)
        # The raw text stays in the database; only the response is escaped.
        return jsonify(id=post_id, content=security.escape(content)), 201

    @app.get("/api/posts")
    @require_auth
    def list_posts():
        rows = db.list_posts()
        posts = [
            {
                "id": row["id"],
                "author": security.escape(row["username"]),
                "content": security.escape(row["content"]),
            }
            for row in rows
        ]

        # Small HTML view, purely so the escaping can be seen and screenshotted.
        if request.args.get("format") == "html":
            items = "".join(
                f"<li><b>{p['author']}</b>: {p['content']}</li>" for p in posts
            )
            page = (
                "<!doctype html><meta charset='utf-8'>"
                "<h1>Posts</h1><ul>" + items + "</ul>"
            )
            return page, 200, {"Content-Type": "text/html; charset=utf-8"}

        return jsonify(count=len(posts), posts=posts)

    # --- hardening headers ------------------------------------------------

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        return response

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
