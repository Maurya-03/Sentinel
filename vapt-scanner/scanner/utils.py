# scanner/utils.py — Shared HTTP session, helpers, and URL utilities

import requests
import urllib.parse
from typing import Optional
from config import DEFAULT_TIMEOUT, USER_AGENT


def build_session() -> requests.Session:
    """Return a configured requests.Session with security-scanner headers."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "close",
    })
    session.verify = False  # allow scanning self-signed certs
    return session


def safe_get(session: requests.Session, url: str,
             params: Optional[dict] = None,
             timeout: int = DEFAULT_TIMEOUT) -> Optional[requests.Response]:
    """GET request that never raises; returns None on error."""
    try:
        return session.get(url, params=params, timeout=timeout, allow_redirects=True)
    except Exception:
        return None


def safe_post(session: requests.Session, url: str,
              data: Optional[dict] = None,
              timeout: int = DEFAULT_TIMEOUT) -> Optional[requests.Response]:
    """POST request that never raises; returns None on error."""
    try:
        return session.post(url, data=data, timeout=timeout, allow_redirects=True)
    except Exception:
        return None


def normalize_url(base: str, href: str) -> Optional[str]:
    """Resolve href relative to base, return None if external or invalid."""
    try:
        joined = urllib.parse.urljoin(base, href)
        base_netloc  = urllib.parse.urlparse(base).netloc
        joined_netloc = urllib.parse.urlparse(joined).netloc
        if joined_netloc != base_netloc:
            return None  # external domain — skip
        # strip fragment
        parsed = urllib.parse.urlparse(joined)._replace(fragment="")
        return urllib.parse.urlunparse(parsed)
    except Exception:
        return None


def extract_base(url: str) -> str:
    """Return scheme://host from a full URL."""
    p = urllib.parse.urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def inject_param(url: str, param: str, payload: str) -> str:
    """Replace or add a query parameter value with the given payload."""
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def truncate(text: str, max_len: int = 200) -> str:
    """Truncate a string for display in reports."""
    return text[:max_len] + "…" if len(text) > max_len else text
