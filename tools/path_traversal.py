"""
Path Traversal — CWE-22: Improper Limitation of a Pathname to a Restricted Directory.

The filename parameter is joined onto the data directory path without checking
whether the resulting path stays within that directory.
"""
import os

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")


def read_file(filename: str) -> str:
    """Read a file from the data directory and return its contents.

    VULNERABLE: no path sanitisation — ../sequences are followed.

    Read the flag one level up:
        ../flag.txt

    Read a Linux system file:
        ../../../etc/passwd

    Read the database file:
        users.db

    Absolute path (replaces the base entirely on most OSes):
        /etc/hostname
    """
    target = os.path.join(DATA_DIR, filename)
    try:
        with open(target) as fh:
            return fh.read()
    except FileNotFoundError:
        return f"File not found: {target}"
    except PermissionError:
        return f"Permission denied: {target}"
    except IsADirectoryError:
        return f"Is a directory: {target}"
    except Exception as exc:
        return f"Error reading {target}: {exc}"
