"""
Insecure Direct Object Reference — CWE-639: Authorization Bypass Through User-Controlled Key.

The query itself is parameterised (not SQLi), but there is no authorisation check —
any caller can retrieve any user record including admin credentials.
"""
import sqlite3

from data.db import get_conn


def get_user(user_id: int) -> str:
    """Retrieve a user record by numeric ID.

    VULNERABLE: no ownership or authorisation check — callers can enumerate all users.

    Retrieve the admin account (id=4, password=Sup3rS3cr3t!):
        user_id=4

    Sequential enumeration:
        user_id=1, 2, 3, 4, 5
    """
    db = get_conn()
    try:
        cur = db.execute(
            "SELECT id, name, email, role, password FROM users WHERE id = ?",
            (user_id,),
        )
        row = cur.fetchone()
        if row is None:
            return f"No user found with id={user_id}"
        return f"id={row[0]} name={row[1]} email={row[2]} role={row[3]} password={row[4]}"
    except sqlite3.Error as exc:
        return f"Database error: {exc}"
