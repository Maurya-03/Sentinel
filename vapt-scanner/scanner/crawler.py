# scanner/crawler.py — BFS web crawler that extracts all in-scope links

from __future__ import annotations
import re
from collections import deque
from typing import Set, List
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from config import MAX_CRAWL_DEPTH, MAX_PAGES, DEFAULT_TIMEOUT
from scanner.utils import build_session, safe_get, normalize_url


def crawl(start_url: str) -> List[str]:
    """
    BFS crawl from start_url.
    Returns a deduplicated list of in-scope URLs discovered.
    Stays within the same scheme+netloc as the start URL.
    """
    session   = build_session()
    visited:  Set[str] = set()
    queue:    deque    = deque([(start_url, 0)])  # (url, depth)
    found:    List[str] = []

    print(f"[CRAWLER] Starting crawl → {start_url}")

    while queue and len(found) < MAX_PAGES:
        url, depth = queue.popleft()

        if url in visited or depth > MAX_CRAWL_DEPTH:
            continue

        visited.add(url)
        response = safe_get(session, url, timeout=DEFAULT_TIMEOUT)

        if response is None or response.status_code >= 400:
            continue

        found.append(url)
        print(f"[CRAWLER] Found ({len(found)}/{MAX_PAGES}): {url}")

        # only parse HTML pages for further links
        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            continue

        soup = BeautifulSoup(response.text, "html.parser")

        for tag in soup.find_all(["a", "form", "link", "script"]):
            href = (
                tag.get("href")
                or tag.get("action")
                or tag.get("src")
            )
            if not href or href.startswith(("mailto:", "tel:", "javascript:")):
                continue

            normalized = normalize_url(start_url, href)
            if normalized and normalized not in visited:
                queue.append((normalized, depth + 1))

    print(f"[CRAWLER] Finished — {len(found)} URLs collected")
    return found


def extract_forms(url: str, session: requests.Session = None) -> List[dict]:
    """
    Extract all HTML forms from a URL.
    Returns list of { action, method, inputs } dicts.
    """
    if session is None:
        session = build_session()

    response = safe_get(session, url)
    if response is None:
        return []

    soup   = BeautifulSoup(response.text, "html.parser")
    forms  = []

    for form in soup.find_all("form"):
        action = form.get("action", url)
        method = form.get("method", "get").lower()

        if not action.startswith("http"):
            action = normalize_url(url, action) or url

        inputs = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name  = inp.get("name")
            value = inp.get("value", "test")
            if name:
                inputs[name] = value

        forms.append({"action": action, "method": method, "inputs": inputs})

    return forms
