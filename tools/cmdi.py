"""
OS Command Injection — CWE-78: Improper Neutralization of Special Elements in an OS Command.

User input is passed directly to the shell via shell=True. stdout/stderr are captured
and returned so DAST tools can observe the injected command output.
"""
import subprocess


def ping_host(host: str) -> str:
    """Ping a host and return the command output.

    VULNERABLE: shell=True with unsanitised input enables arbitrary command execution.

    Basic injection:
        127.0.0.1; id

    Chained commands:
        127.0.0.1 && cat /etc/passwd

    Blind (no output returned but side effects occur):
        127.0.0.1; touch /tmp/pwned
    """
    try:
        result = subprocess.run(
            f"ping -c 2 {host}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout + result.stderr
        return output if output else f"ping exited with code {result.returncode}"
    except subprocess.TimeoutExpired:
        return "Command timed out after 10 seconds"
    except Exception as exc:
        return f"Error: {exc}"
