# EVMCP Vulnerability Index

evmcp exposes deliberately vulnerable MCP tools and protocol methods over a single HTTP endpoint (`POST /mcp`).
Each tool's parameters and MCP methods are the attack surface — DAST tools fuzz these JSON-RPC argument values.

## MCP Request Format

All tools are called via:

```
POST http://localhost:8000/mcp
Content-Type: application/json
Accept: application/json, text/event-stream

{"jsonrpc":"2.0","method":"tools/call","params":{"name":"<tool>","arguments":{...}},"id":1}
```

## Quick Reference

| Tool | Vuln Class | CWE | Vulnerable Parameter | Detection Signal |
|---|---|---|---|---|
| `search_users` | SQL Injection | CWE-89 | `name` | DB error in response, unexpected rows |
| `ping_host` | OS Command Injection | CWE-78 | `host` | Command output (uid=, etc.) in response |
| `read_file` | Path Traversal | CWE-22 | `filename` | File contents, absolute path in response |
| `fetch_url` | SSRF | CWE-918 | `url` | Internal service response body |
| `parse_xml` | XXE | CWE-611 | `xml_content` | File/service contents in parsed output |
| `load_object` | Insecure Deserialization | CWE-502 | `data` | RCE side effects, type name in response |
| `get_user` | IDOR | CWE-639 | `user_id` | Password field present for all user IDs |
| `greet_user` | XSS-equivalent | CWE-79 | `name` | Input reflected unescaped in HTML |
| `get_config` | Sensitive Data Exposure | CWE-200 | *(none)* | Credentials/keys in response |
| `check_auth` | Weak Authentication | CWE-287 | `token` | Authenticated response for guessable tokens |
| `/mcp-admin` | Broken Access Control | CWE-285 | endpoint URL | 200 on `/mcp-admin` when `/mcp` returns 401 |
| `check_username` | Blind SQL Injection | CWE-89 | `username` | Boolean flip on `' OR '1'='1' --` payload |
| `write_file` | Arbitrary File Write | CWE-73 | `path`, `content` | `"Written N bytes to ..."` confirmation |
| `get_weather` (2nd call) | Tool Definition Tampering | MCP-specific | `tools/list` response | Description changes between calls |
| `prompts/list` / `sampling/createMessage` | Prompt Injection | CWE-1427 | description fields, `systemPrompt` | Injection payload in response |
| `save_note` / `get_notes` | Cross-Session Context Leak | CWE-359 | `note` | Notes from other sessions visible |
| `get_admin_report` | Privilege Escalation | CWE-269 | `role` | Admin data returned for `role=admin` |
| `/internal/mcp` | Shadow Endpoint | CWE-284 | endpoint URL | 200 on undiscovered path, no auth |

## Detailed Documentation

- [SQL Injection](sqli.md)
- [OS Command Injection](cmdi.md)
- [Path Traversal](path-traversal.md)
- [SSRF](ssrf.md)
- [XXE Injection](xxe.md)
- [Insecure Deserialization](deserial.md)
- [IDOR](idor.md)
- [XSS-equivalent / Sensitive Data / Weak Auth](misc.md)
- [Broken Access Control](broken-access-control.md)
- [Blind SQL Injection](sqli-blind.md)
- [Arbitrary File Write](write-file.md)
- [Tool Definition Tampering (Rug Pull)](rug-pull.md)
- [Prompt Injection](prompt-injection.md)
- [Cross-Session Context Leak](context-leak.md)
- [Privilege Escalation via Client-Supplied Role](privesc.md)
- [Shadow MCP Endpoint](shadow-endpoint.md)
- [ZAP Testing Guide](zap-guide.md)
