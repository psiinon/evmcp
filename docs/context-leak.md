# Cross-Session Context Leak — OWASP MCP10 / CWE-359

## Description

The `save_note` and `get_notes` tools store and retrieve notes in a single global
server-side list. There is no user identity, session token, or access control — any
caller can read every note written by every other caller, across all sessions.

This demonstrates **OWASP MCP10: Context Injection & Over-Sharing**: MCP servers that
store agent context (working memory, notes, intermediate results) without isolation
allow one agent/user's sensitive data to leak to any other caller.

## CWE

[CWE-359: Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)

## Vulnerable Code

```python
# tools/context_leak.py
_NOTES: list[str] = []   # global — shared across every session and caller

def save_note(note: str) -> str:
    _NOTES.append(note)  # no user identity recorded
    return f"Note saved. Total notes stored: {len(_NOTES)}"

def get_notes() -> str:
    lines = [f"[{i + 1}] {n}" for i, n in enumerate(_NOTES)]
    return "\n".join(lines)  # returns ALL notes to ANY caller
```

## Example MCP Calls

### Caller A writes a secret

```bash
curl -s http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"save_note","arguments":{"note":"AWS key: AKIAIOSFODNN7EXAMPLE"}},"id":1}'
```

Response:

```json
{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"Note saved. Total notes stored: 1"}],"isError":false}}
```

### Caller B reads all notes — including Caller A's secret

```bash
curl -s http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_notes","arguments":{}},"id":2}'
```

Response:

```json
{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"[1] AWS key: AKIAIOSFODNN7EXAMPLE"}],"isError":false}}
```

## ZAP Detection

ZAP should:

1. Call `save_note` with a canary value (e.g. a unique UUID or known string).
2. Call `get_notes` in a separate request (different session, no shared cookies/headers).
3. Verify the canary appears in the response.
4. Flag: **Cross-session data leakage / insufficient context isolation**.

## Secure Fix

Scope notes to a verified session or user identity:

```python
import secrets

_SESSIONS: dict[str, list[str]] = {}

def save_note(session_token: str, note: str) -> str:
    if session_token not in _SESSIONS:
        _SESSIONS[session_token] = []
    _SESSIONS[session_token].append(note)
    return "Note saved."

def get_notes(session_token: str) -> str:
    notes = _SESSIONS.get(session_token, [])
    return "\n".join(notes) if notes else "No notes."
```

Better still: store nothing server-side; return data to the client immediately and
let the client manage its own context, or use a proper authenticated store keyed by
a server-verified identity.
