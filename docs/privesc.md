# Privilege Escalation via Client-Supplied Role — OWASP MCP02 / CWE-269

## Description

The `get_admin_report` tool accepts a `role` parameter from the caller and uses it
directly to decide what data to return. There is no server-side session, identity
check, or cryptographic verification — any caller can self-elevate to admin by simply
passing `role=admin` in the request.

This demonstrates **OWASP MCP02: Privilege Escalation via Scope Creep**: MCP tools
that rely on caller-supplied parameters for access control decisions are trivially
bypassed. In agentic systems, this pattern is especially dangerous because the agent
acts autonomously on the escalated privileges.

## CWE

[CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)

## Vulnerable Code

```python
# tools/privesc.py
def get_admin_report(role: str) -> str:
    if role.strip().lower() == "admin":   # trusts caller-supplied value
        return "=== ADMIN REPORT ===\n" + SECRETS   # no identity verification
    return "=== USER REPORT ===\n" + basic_stats
```

## Example MCP Calls

### Normal call — limited data

```bash
curl -s http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_admin_report","arguments":{"role":"user"}},"id":1}'
```

Response:

```
=== USER REPORT ===
Total users: 5
(pass role='admin' for full report)
```

### Exploit — self-elevate to admin

```bash
curl -s http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_admin_report","arguments":{"role":"admin"}},"id":2}'
```

Response:

```
=== ADMIN REPORT ===
Total users: 5
server: evmcp-prod-01
db_password: db_service_p@ss
jwt_secret: s3cr3t-jwt-signing-key-do-not-share
active_sessions: 42
internal_api_key: internal-api-key-9f2a1c
```

## ZAP Detection

ZAP should fuzz the `role` parameter with values including `admin`, `administrator`,
`root`, `superuser`, `ADMIN`, and `Admin`. A successful escalation is indicated by:

- Additional fields in the response (secrets, internal config values)
- A different response structure or header (e.g. `=== ADMIN REPORT ===`)

ZAP can diff the response bodies between `role=user` and `role=admin` to confirm
the privilege boundary is not enforced.

## Secure Fix

Never trust caller-supplied role or privilege claims. Derive the caller's identity and
role from a server-side session or a cryptographically verified token:

```python
from some_auth_lib import verify_token, get_role

def get_admin_report(token: str) -> str:
    identity = verify_token(token)   # raises if invalid/expired
    if get_role(identity) != "admin":
        return "Forbidden"
    return build_admin_report()
```
