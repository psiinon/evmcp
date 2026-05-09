# Server-Side Request Forgery — CWE-918

## Description

The server makes an outbound HTTP request to a caller-supplied URL with no
scheme, host, or IP-range validation. An attacker can use this to:
- Access cloud instance metadata services
- Probe internal services not exposed externally
- Bypass firewall rules (the request originates from the server)
- Pivot into private network segments

## Vulnerable Code

```python
# tools/ssrf.py
resp = requests.get(url, timeout=5, verify=False, allow_redirects=True)
```

No validation of scheme, hostname, or IP address is performed.

## Example MCP Call (benign)

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "fetch_url",
    "arguments": {"url": "http://example.com"}
  },
  "id": 1
}
```

## Attack Payloads

### AWS instance metadata (inside AWS EC2)
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### GCP instance metadata (inside GCP)
```
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

### Self-request (enumerate the MCP server itself)
```
http://localhost:8000/mcp
```

### Internal service probe
```
http://localhost:6379/    (Redis RESP protocol)
http://localhost:5432/    (PostgreSQL)
http://localhost:9200/    (Elasticsearch)
```

### File protocol (if supported by HTTP client)
```
file:///etc/passwd
```
Note: Python's `requests` library does not support `file://` by default.

## Expected Response (metadata, inside AWS)

```
Status: 200
Headers: {'Content-Type': 'text/plain', ...}
Body:
ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/
hostname
iam/
...
```

## ZAP Detection

ZAP's SSRF active scanner should detect:
- Requests to `http://localhost/` returning an unexpected response
- The scanner's own callback URL receiving an inbound request from the server
- Cloud metadata indicators in the response body

## Secure Fix

Validate the URL before making the request:

```python
from urllib.parse import urlparse
import ipaddress

def is_safe_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False
    except ValueError:
        pass  # hostname, not IP — apply DNS rebinding protection separately
    return True
```
