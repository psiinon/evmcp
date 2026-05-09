# Broken Access Control — CWE-285

## Description

The server exposes two MCP endpoints with identical functionality:

| Endpoint | Auth check |
|---|---|
| `POST /mcp` | Checks `Authorization: Bearer <token>` when `--auth-header` is configured |
| `POST /mcp-admin` | **Never checks** — intentionally unprotected |

An attacker who discovers `/mcp-admin` (advertised in the `GET /mcp` discovery response)
can bypass the authorization requirement on `/mcp` entirely. All 10 vulnerable tools
remain accessible.

## Running the Server with Auth Enabled

```bash
docker run --rm -p 8000:8000 evmcp --auth-header mysecrettoken
# or via env var:
docker run --rm -p 8000:8000 -e EVMCP_AUTH_HEADER=mysecrettoken evmcp
```

## Vulnerable Code

```python
# server.py
async def mcp_admin_endpoint(request: Request) -> JSONResponse:
    # VULNERABILITY: auth check is absent — delegates directly to the core handler
    return await _handle(request)
```

Compare with the protected endpoint:

```python
async def mcp_endpoint(request: Request) -> JSONResponse:
    if AUTH_TOKEN is not None and request.method == "POST":
        if request.headers.get("Authorization") != f"Bearer {AUTH_TOKEN}":
            return JSONResponse(..., status_code=401)
    return await _handle(request)
```

## Discovery

The `GET /mcp` endpoint advertises both endpoints:

```bash
curl http://localhost:8000/mcp
```

```json
{
  "endpoints": {
    "/mcp": "Standard MCP endpoint — requires Authorization: Bearer <token>",
    "/mcp-admin": "Admin endpoint — VULNERABLE: does not check Authorization header"
  }
}
```

A scanner that fetches `GET /mcp` will see `/mcp-admin` and can immediately confirm
the auth bypass by calling it without a token.

## Attack Scenario

```bash
# Step 1: discover endpoints
curl http://localhost:8000/mcp

# Step 2: confirm /mcp is protected
curl -s http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}'
# → 401 Unauthorized

# Step 3: bypass via /mcp-admin (no token needed)
curl -s http://localhost:8000/mcp-admin \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}'
# → 200 OK, full tool list

# Step 4: call any tool through the unprotected endpoint
curl -s http://localhost:8000/mcp-admin \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_config","arguments":{}},"id":2}'
# → 200 OK, all credentials exposed
```

## ZAP Detection

With auth configured (`--auth-header mysecrettoken`):

1. ZAP sends `GET /mcp` → discovers `/mcp-admin` in the response
2. ZAP sends `POST /mcp` without auth → receives 401
3. ZAP sends `POST /mcp-admin` without auth → receives 200
4. ZAP flags: unauthenticated access to an endpoint that should be restricted

## Secure Fix

Apply the same auth check in the admin handler, or — better — use Starlette middleware
so the check is impossible to forget:

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
