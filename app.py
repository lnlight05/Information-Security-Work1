from functools import wraps

from flask import Flask, g, jsonify, request

import db
import security


def public_user(row) -> dict:
    return {
        "id": row["id"],
        "username": security.escape(row["username"]),
        "bio": security.escape(row["bio"]),
    }


def require_auth(view):

    @wraps(view)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            return jsonify(error="missing bearer token"), 401
        try:
            g.user = security.decode_token(token.strip())
        except Exception:
            return jsonify(error="invalid or expired token"), 401
        return view(*args, **kwargs)

    return wrapper


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
    db.init_db()


    @app.post("/auth/login")
    def login():
        body = request.get_json(silent=True) or {}
        username = str(body.get("login") or body.get("username") or "").strip()
        password = str(body.get("password") or "")

        user = db.get_user_by_username(username)
        if user is None or not security.verify_password(password, user["password_hash"]):
            return jsonify(error="invalid credentials"), 401

        return jsonify(
            token=security.issue_token(user),
            token_type="Bearer",  # nosec
            expires_in=security.TOKEN_TTL_SECONDS,
        )


    @app.get("/api/data")
    @require_auth
    def get_data():
        users = [public_user(row) for row in db.list_users(request.args.get("q", ""))]
        return jsonify(count=len(users), users=users)


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
        return jsonify(id=post_id, content=security.escape(content)), 201


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
