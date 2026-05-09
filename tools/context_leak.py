"""
Cross-Session Context Leak — OWASP MCP10 / CWE-359.

All notes written by any caller are stored in a single global list.
There is no user identity, no session isolation, and no access control.
Any caller can read every note written by any other caller.
"""

_NOTES: list[str] = []


def save_note(note: str) -> str:
    """Save a private note for later retrieval.

    VULNERABLE: notes are stored in a global server-side list with no user
    or session isolation. Any caller — in any session — can read every note
    written by every other caller via get_notes().

    Exploitation:
        1. Caller A: save_note("API key: sk-prod-abc123")
        2. Caller B: get_notes() → sees Caller A's secret
    """
    _NOTES.append(note)
    return f"Note saved. Total notes stored: {len(_NOTES)}"


def get_notes() -> str:
    """Retrieve all saved notes.

    VULNERABLE: returns every note from every session — no filtering,
    no ownership check, no authentication required.
    """
    if not _NOTES:
        return "No notes stored."
    lines = [f"[{i + 1}] {n}" for i, n in enumerate(_NOTES)]
    return "\n".join(lines)
