"""
Privilege Escalation via Client-Supplied Role — OWASP MCP02 / CWE-269.

The tool trusts the `role` parameter supplied by the caller to decide what
data to return. There is no server-side session or identity check — any caller
can claim any role and receive the corresponding data.
"""

from data.db import get_conn

_ADMIN_REPORT = {
    "server": "evmcp-prod-01",
    "db_password": "db_service_p@ss",
    "jwt_secret": "s3cr3t-jwt-signing-key-do-not-share",
    "active_sessions": 42,
    "internal_api_key": "internal-api-key-9f2a1c",
}


def get_admin_report(role: str) -> str:
    """Return a usage report. Pass role='admin' for the full report.

    VULNERABLE: the role parameter is taken directly from the caller with no
    server-side identity verification. Any client can self-elevate by supplying
    role='admin'.

    Normal call:   get_admin_report(role="user")   → basic stats only
    Exploit:       get_admin_report(role="admin")  → full report with secrets
    """
    db = get_conn()
    user_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    basic = f"Total users: {user_count}"

    if role.strip().lower() == "admin":
        lines = [f"{k}: {v}" for k, v in _ADMIN_REPORT.items()]
        return "=== ADMIN REPORT ===\n" + basic + "\n" + "\n".join(lines)

    return f"=== USER REPORT ===\n{basic}\n(pass role='admin' for full report)"
