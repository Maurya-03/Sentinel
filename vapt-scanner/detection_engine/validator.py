# detection_engine/validator.py — Response analysis for vulnerability confirmation

from __future__ import annotations
from detection_engine.payloads import get_sqli_error_signatures


def is_sqli_response(body: str) -> bool:
    """
    Return True if the response body contains SQL error signatures.
    Uses case-insensitive matching against known database error strings.
    """
    lower = body.lower()
    for sig in get_sqli_error_signatures():
        if sig.lower() in lower:
            return True
    return False


def is_xss_reflected(body: str, payload: str) -> bool:
    """
    Return True if the exact payload appears unmodified in the response body.
    A reflected payload means the application is not encoding output.
    """
    # Check for the raw payload appearing in the response
    if payload in body:
        return True

    # Also catch partially-encoded versions of common patterns
    minimal_markers = ["<script>", "onerror=", "onload=", "javascript:", "alert("]
    lower_body = body.lower()
    for marker in minimal_markers:
        if marker in payload.lower() and marker in lower_body:
            return True

    return False


def is_open_redirect(response_url: str, payload: str) -> bool:
    """Check if a redirect landed on the injected domain."""
    try:
        from urllib.parse import urlparse
        redirected = urlparse(response_url).netloc
        injected   = urlparse(payload).netloc
        return bool(injected) and injected in redirected
    except Exception:
        return False
