# evmcp — Extremely Vulnerable MCP Server

> **WARNING: This server contains intentional security vulnerabilities.**
> It is designed for security testing and training only.
> **Never deploy on a network-accessible interface in production or a shared environment.**

evmcp is a purpose-built vulnerable [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server
for testing DAST tools like [ZAP](https://www.zaproxy.org/).
It exposes a suite of deliberately insecure MCP tools over HTTP, providing a realistic target
for scanners that fuzz JSON-RPC parameters.

## Vulnerabilities

| Tool | Vulnerability | CWE |
|---|---|---|
| `search_users` | SQL Injection | CWE-89 |
| `ping_host` | OS Command Injection | CWE-78 |
| `read_file` | Path Traversal | CWE-22 |
| `fetch_url` | SSRF | CWE-918 |
| `parse_xml` | XXE Injection | CWE-611 |
| `load_object` | Insecure Deserialization | CWE-502 |
| `get_user` | IDOR | CWE-639 |
| `greet_user` | Reflected Content / XSS-equivalent | CWE-79 |
| `get_config` | Sensitive Data Exposure | CWE-200 |
| `check_auth` | Weak Authentication | CWE-287 |
| `/mcp-admin` | Broken Access Control | CWE-285 |
| `check_username` | Blind SQL Injection | CWE-89 |
| `write_file` | Arbitrary File Write | CWE-73 |
| `get_weather` (2nd `tools/list`) | Tool Definition Tampering | MCP-specific |
| `prompts/list` / `sampling/createMessage` | Prompt Injection | CWE-1427 |
| `save_note` / `get_notes` | Cross-Session Context Leak | CWE-359 |
| `get_admin_report` | Privilege Escalation (client-supplied role) | CWE-269 |
| `/internal/mcp` | Shadow Endpoint (unadvertised, no auth) | CWE-284 |

See the [docs/](docs/) directory for detailed documentation on each vulnerability.

## Quick Start

```bash
# Build and run (no auth)
docker build -t evmcp .
docker run --rm -p 8000:8000 evmcp

# Run with Authorization header required on /mcp
# /mcp-admin is intentionally left unprotected — that's the vulnerability
docker run --rm -p 8000:8000 evmcp --auth-header mysecrettoken

# Or via environment variable
docker run --rm -p 8000:8000 -e EVMCP_AUTH_HEADER=mysecrettoken evmcp

# Or with Docker Compose
docker compose up --build
```

The MCP endpoint is available at `http://localhost:8000/mcp`.

## Verify it's running

```bash
# List all available tools
curl -s http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}'
```

## Quick exploit checks

```bash
# SQL injection — return all users
curl -s http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"search_users","arguments":{"name":"'"'"' OR '"'"'1'"'"'='"'"'1"}},"id":1}'

# Command injection — run id
curl -s http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"ping_host","arguments":{"host":"127.0.0.1; id"}},"id":2}'

# Path traversal — read flag
curl -s http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{"filename":"../flag.txt"}},"id":3}'

# IDOR — fetch admin account
curl -s http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_user","arguments":{"user_id":4}},"id":4}'
```

## Design Notes

- **Single Docker image** — everything self-contained, no external services required.
- **SQLite database** — recreated fresh on every container start.
- **Plain JSON over HTTP** — no SSE negotiation, no special `Accept` headers required. ZAP and any HTTP client can scan it directly.
- **GET /mcp returns server info** — scanners can discover the endpoint without a POST.
- **Runs as root** — intentional, simplifies file-access vulnerability demonstrations.
- **Verbose errors** — raw exception messages are returned to aid DAST scanner detection.

## Project Structure

```
evmcp/
├── server.py              # FastMCP entry point, tool registration
├── tools/                 # One module per vulnerability class
├── data/                  # SQLite DB, db singleton, target files
├── docs/                  # Vulnerability documentation
├── flag.txt               # Path traversal target (one level above data/)
├── Dockerfile
└── docker-compose.yml
```
