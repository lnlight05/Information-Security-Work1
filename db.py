import os
import sqlite3

DB_PATH = os.environ.get("APP_DB", "app.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    bio           TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS posts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id INTEGER NOT NULL REFERENCES users(id),
    content   TEXT    NOT NULL
);
"""


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(seed: bool = True) -> None:
    conn = connect()
    try:
        with conn:
            conn.executescript(SCHEMA)
            already = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            if seed and already == 0:
                from security import hash_password

                conn.executemany(
                    "INSERT INTO users (username, password_hash, bio) VALUES (?, ?, ?)",
                    [
                        ("alice", hash_password("secret123"), "Demo administrator"),
                        ("bob", hash_password("hunter2"), "Regular user"),
                    ],
                )
                conn.execute(
                    "INSERT INTO posts (author_id, content) VALUES (?, ?)",
                    (1, "Hello from alice"),
                )
    finally:
        conn.close()


def get_user_by_username(username: str):
    conn = connect()
    try:
        return conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    finally:
        conn.close()


def list_users(search: str = ""):
    pattern = "%" + search + "%"
    conn = connect()
    try:
        return conn.execute(
            "SELECT * FROM users WHERE username LIKE ? ORDER BY id",
            (pattern,),
        ).fetchall()
    finally:
        conn.close()


def create_post(author_id: int, content: str) -> int:
    conn = connect()
    try:
        with conn:
            cursor = conn.execute(
                "INSERT INTO posts (author_id, content) VALUES (?, ?)",
                (author_id, content),
            )
            return cursor.lastrowid
    finally:
        conn.close()
