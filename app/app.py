"""Secure REST API - Work 1 reference implementation.

Endpoints
    POST /auth/login     - authenticate, returns a signed JWT
    GET  /api/data       - protected, returns posts (XSS-escaped)
    POST /api/posts      - protected, creates a post owned by the caller
    GET  /api/me         - protected, returns the current principal
"""
import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from html import escape

import bcrypt
import jwt
from flask import Flask, g, jsonify, request

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.db")
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-only-secret-change-me-0123456789abcdef")
JWT_ALG = "HS256"
JWT_TTL_MIN = 30

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


# ---------------------------------------------------------------- database ---
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    login    TEXT NOT NULL UNIQUE,
    pw_hash  TEXT NOT NULL,
    role     TEXT NOT NULL DEFAULT 'user'
);
CREATE TABLE IF NOT EXISTS posts (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id INTEGER NOT NULL REFERENCES users(id),
    title    TEXT NOT NULL,
    body     TEXT NOT NULL,
    created  TEXT NOT NULL
);
"""

SEED = [
    ("alice", "Passw0rd!alice", "admin"),
    ("bob", "Passw0rd!bob", "user"),
    ("carol", "Passw0rd!carol", "user"),
]

SEED_POSTS = [
    (1, "Welcome", "First post on the secure API"),
    (2, "Notes", "&lt;script&gt;alert(1)&lt;/script&gt; is stored escaped, not executed"),
]


def init_db(force: bool = False) -> None:
    if force and os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA)
    if con.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        for login, pw, role in SEED:
            # bcrypt with a per-user random salt; cost factor 12
            hashed = bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12)).decode()
            con.execute(
                "INSERT INTO users (login, pw_hash, role) VALUES (?, ?, ?)",
                (login, hashed, role),
            )
        for author_id, title, body in SEED_POSTS:
            con.execute(
                "INSERT INTO posts (author_id, title, body, created) VALUES (?, ?, ?, ?)",
                (author_id, title, body, datetime.now(timezone.utc).isoformat()),
            )
    con.commit()
    con.close()


# --------------------------------------------------------------- auth layer ---
def make_token(user_row) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_row["id"]),
        "login": user_row["login"],
        "role": user_row["role"],
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_TTL_MIN)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def jwt_required(fn):
    """Verify the bearer token before the view runs (A07 protection)."""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify(error="missing or malformed Authorization header"), 401
        token = header[7:].strip()
        try:
            claims = jwt.decode(
                token,
                JWT_SECRET,
                algorithms=[JWT_ALG],          # algorithm pinned: blocks alg=none / RS->HS confusion
                options={"require": ["exp", "sub"]},
            )
        except jwt.ExpiredSignatureError:
            return jsonify(error="token expired"), 401
        except jwt.InvalidTokenError:
            return jsonify(error="invalid token"), 401
        g.claims = claims
        return fn(*args, **kwargs)

    return wrapper


# ------------------------------------------------------------------- helpers ---
def clean(value, max_len=200):
    """Trim + length-limit + HTML-escape user supplied text (A03: XSS)."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > max_len:
        return None
    return escape(value, quote=True)


# -------------------------------------------------------------------- routes ---
@app.post("/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    login_name = data.get("login")
    password = data.get("password")
    if not isinstance(login_name, str) or not isinstance(password, str):
        return jsonify(error="login and password are required"), 400
    if not login_name or len(login_name) > 64 or len(password) > 128:
        return jsonify(error="invalid credentials"), 400

    db = get_db()
    # Parameterized query: the payload stays data, never becomes SQL (A03: SQLi)
    row = db.execute(
        "SELECT id, login, pw_hash, role FROM users WHERE login = ?", (login_name,)
    ).fetchone()

    if row is None:
        bcrypt.checkpw(b"dummy", bcrypt.hashpw(b"dummy", bcrypt.gensalt()))  # constant-ish time
        return jsonify(error="invalid credentials"), 401
    if not bcrypt.checkpw(password.encode(), row["pw_hash"].encode()):
        return jsonify(error="invalid credentials"), 401

    return jsonify(access_token=make_token(row), token_type="Bearer",  # nosec B106
                   expires_in=JWT_TTL_MIN * 60)


@app.get("/api/data")
@jwt_required
def get_data():
    rows = get_db().execute(
        "SELECT p.id, p.title, p.body, p.created, u.login AS author "
        "FROM posts p JOIN users u ON u.id = p.author_id ORDER BY p.id"
    ).fetchall()
    return jsonify(
        count=len(rows),
        items=[
            {
                "id": r["id"],
                "title": r["title"],      # stored escaped
                "body": r["body"],        # stored escaped
                "author": r["author"],
                "created": r["created"],
            }
            for r in rows
        ],
    )


@app.post("/api/posts")
@jwt_required
def create_post():
    data = request.get_json(silent=True) or {}
    title = clean(data.get("title"), 120)
    body = clean(data.get("body"), 2000)
    if title is None or body is None:
        return jsonify(error="title and body are required (<=120 / <=2000 chars)"), 400

    db = get_db()
    cur = db.execute(
        "INSERT INTO posts (author_id, title, body, created) VALUES (?, ?, ?, ?)",
        (int(g.claims["sub"]), title, body, datetime.now(timezone.utc).isoformat()),
    )
    db.commit()
    return jsonify(id=cur.lastrowid, title=title, body=body, author=g.claims["login"]), 201


@app.get("/api/me")
@jwt_required
def me():
    return jsonify(sub=g.claims["sub"], login=g.claims["login"], role=g.claims["role"])


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return resp


@app.errorhandler(404)
def not_found(_e):
    return jsonify(error="not found"), 404


@app.errorhandler(500)
def server_error(_e):
    return jsonify(error="internal server error"), 500


if __name__ == "__main__":
    init_db()
    print(f"DB ready at {DB_PATH}")
    app.run(host="127.0.0.1", port=5000, debug=False)
