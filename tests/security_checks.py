"""Leak detection shared by the security tests.

Kept free of Schemathesis and Mininet imports so crafted-input tests can use it
in any environment. fuzz_helpers re-exports these names.
"""
import re

# Signs that a response body exposes internals: tracebacks, source paths and
# the names of backend libraries. Tune after the first real run if a
# legitimate message trips one of these.
LEAK_PATTERNS = {
    "python traceback": re.compile(r"Traceback \(most recent call last\)"),
    "source file and line": re.compile(r'File "[^"]+\.py", line \d+'),
    "python install path": re.compile(
        r"site-packages|/usr/(?:local/)?lib/python|/opt/[\w./-]*venv"),
    "kytos install path": re.compile(r"/var/lib/kytos|/etc/kytos"),
    "backend library name": re.compile(
        r"pymongo|mongodb|starlette|uvicorn|openapi_core|jsonschema",
        re.IGNORECASE),
}


def find_leaks(text):
    """Return the names of the leak patterns found in ``text``."""
    return [name for name, rx in LEAK_PATTERNS.items() if rx.search(text)]
