"""
SQL Injection — CWE-89: Improper Neutralization of Special Elements in an SQL Command.

User input is concatenated directly into an SQL query string with no parameterisation,
enabling classic injection and UNION-based data exfiltration.
"""
import sqlite3

from data.db import get_conn


def search_users(name: str) -> str:
    """Search users by name. Returns matching records from the users table.

    VULNERABLE: input is concatenated into the SQL query without parameterisation.

    Bypass (return all rows):
        ' OR '1'='1

    UNION exfiltration (dump secrets table):
        ' UNION SELECT id,label,value,label FROM secrets--

    Error-based probe:
        '
    """
    db = get_conn()
    query = f"SELECT id, name, email, role FROM users WHERE name = '{name}'"
    try:
        cur = db.execute(query)
        rows = cur.fetchall()
        if not rows:
            return f"No users found.\nQuery was: {query}"
        return "\n".join(str(row) for row in rows)
    except sqlite3.Error as exc:
        return f"Database error: {exc}\nQuery was: {query}"
