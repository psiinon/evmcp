"""
SQLite database singleton for evmcp.
Call init_db() once at startup; then use get_conn() everywhere.
"""
from __future__ import annotations

import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")
_conn: sqlite3.Connection | None = None


def get_conn() -> sqlite3.Connection:
    assert _conn is not None, "DB not initialised — call init_db() first"
    return _conn


def init_db() -> None:
    global _conn
    _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = _conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            name     TEXT NOT NULL,
            email    TEXT NOT NULL,
            role     TEXT NOT NULL DEFAULT 'user',
            password TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS secrets (
            id    INTEGER PRIMARY KEY AUTOINCREMENT,
            label TEXT NOT NULL,
            value TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id    INTEGER PRIMARY KEY AUTOINCREMENT,
            name  TEXT NOT NULL,
            price REAL NOT NULL
        )
    """)

    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO users (name, email, role, password) VALUES (?,?,?,?)",
            [
                ("alice", "alice@evmcp.local", "user",  "hunter2"),
                ("bob",   "bob@evmcp.local",   "user",  "password1"),
                ("carol", "carol@evmcp.local", "user",  "qwerty123"),
                ("admin", "admin@evmcp.local", "admin", "Sup3rS3cr3t!"),
                ("dbsvc", "db@evmcp.local",    "svc",   "db_service_p@ss"),
            ],
        )

    cur.execute("SELECT COUNT(*) FROM secrets")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO secrets (label, value) VALUES (?,?)",
            [
                ("AWS_ACCESS_KEY",   "AKIAIOSFODNN7EXAMPLE"),
                ("AWS_SECRET_KEY",   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
                ("DB_PASSWORD",      "Sup3rS3cr3t!"),
                ("INTERNAL_API_KEY", "int-api-aabbccdd1122"),
                ("JWT_SECRET",       "my_jwt_signing_secret"),
            ],
        )

    cur.execute("SELECT COUNT(*) FROM products")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO products (name, price) VALUES (?,?)",
            [
                ("Widget A",        9.99),
                ("Widget B",       19.99),
                ("Premium Widget", 99.99),
            ],
        )

    _conn.commit()
    print(f"[evmcp] Database initialised at {DB_PATH}")
