"""Data access layer.

Rule for this whole file: SQL text is written once, as a constant, and every
user-supplied value travels in the parameter tuple. There is no f-string, no
``%`` and no ``+`` building a query anywhere below -- that is what makes SQL
injection structurally impossible instead of "filtered".
"""

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
        with conn:  # a transaction: commit on success, rollback on error
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


# --- reads ---------------------------------------------------------------

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
    # The LIKE pattern is a *bound value*; the SQL text never changes.
    pattern = "%" + search + "%"
    conn = connect()
    try:
        return conn.execute(
            "SELECT * FROM users WHERE username LIKE ? ORDER BY id",
            (pattern,),
        ).fetchall()
    finally:
        conn.close()


def list_posts():
    conn = connect()
    try:
        return conn.execute(
            "SELECT posts.id, users.username, posts.content "
            "FROM posts JOIN users ON users.id = posts.author_id "
            "ORDER BY posts.id",
        ).fetchall()
    finally:
        conn.close()


# --- writes --------------------------------------------------------------

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
