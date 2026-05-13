# scanner/crawler.py — BFS web crawler that extracts all in-scope links

from __future__ import annotations
import re
import asyncio
from collections import deque
from typing import Dict, Set, List, Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from config import MAX_CRAWL_DEPTH, MAX_PAGES, DEFAULT_TIMEOUT
from scanner.utils import build_session, safe_get, normalize_url, is_excluded_url
from scanner.async_http import AsyncHTTPClient


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


async def async_crawl(start_url: str, client: Optional[AsyncHTTPClient] = None) -> List[str]:
    """
    Async BFS crawl using a worker pool.
    Returns a deduplicated list of in-scope URLs discovered.
    """
    owns_client = client is None
    client = client or AsyncHTTPClient()
    visited: Set[str] = set()
    queued: Set[str] = {start_url}
    found: List[str] = []
    queue: asyncio.Queue = asyncio.Queue()
    lock = asyncio.Lock()

    await queue.put((start_url, 0))
    print(f"[CRAWLER] Starting async crawl → {start_url}")

    async def worker() -> None:
        while True:
            try:
                url, depth = await queue.get()
            except asyncio.CancelledError:
                break

            if depth > MAX_CRAWL_DEPTH:
                queue.task_done()
                continue

            async with lock:
                if url in visited:
                    queue.task_done()
                    continue
                visited.add(url)

            if is_excluded_url(url):
                queue.task_done()
                continue

            response = await client.get(url)
            if response is None or response.status >= 400:
                if response is None:
                    print(f"[CRAWLER] Fetch failed: {url} ({client.last_error or 'unknown error'})")
                else:
                    print(f"[CRAWLER] Skipping {url}: HTTP {response.status}")
                queue.task_done()
                continue

            async with lock:
                if len(found) < MAX_PAGES:
                    found.append(url)
                    print(f"[CRAWLER] Found ({len(found)}/{MAX_PAGES}): {url}")
                else:
                    queue.task_done()
                    continue

            content_type = response.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                queue.task_done()
                continue

            soup = BeautifulSoup(response.text, "html.parser")

            base_url = response.url or url
            for tag in soup.find_all(["a", "form", "link", "script"]):
                href = tag.get("href") or tag.get("action") or tag.get("src")
                if not href or href.startswith(("mailto:", "tel:", "javascript:")):
                    continue
                normalized = normalize_url(base_url, href)
                if normalized:
                    async with lock:
                        should_queue = (
                            normalized not in visited
                            and normalized not in queued
                            and len(queued) < MAX_PAGES
                        )
                        if should_queue:
                            queued.add(normalized)
                    if should_queue:
                        await queue.put((normalized, depth + 1))

            queue.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(6)]
    await queue.join()

    for task in workers:
        task.cancel()
    if owns_client:
        await client.close()

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


async def async_extract_forms(url: str, client: AsyncHTTPClient) -> List[dict]:
    """Async form extraction for a URL."""
    response = await client.get(url)
    if response is None:
        return []

    soup = BeautifulSoup(response.text, "html.parser")
    forms: List[dict] = []

    for form in soup.find_all("form"):
        action = form.get("action", url)
        method = form.get("method", "get").lower()

        if not action.startswith("http"):
            action = normalize_url(url, action) or url

        inputs = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            value = inp.get("value", "test")
            if name:
                inputs[name] = value

        forms.append({"action": action, "method": method, "inputs": inputs})

    return forms


async def async_collect_forms(urls: List[str], client: AsyncHTTPClient) -> Dict[str, List[dict]]:
    """Fetch forms for crawled URLs once so scanner modules can share them."""
    if not urls:
        return {}

    async def collect(url: str) -> tuple[str, List[dict]]:
        return url, await async_extract_forms(url, client)

    pairs = await asyncio.gather(*(collect(url) for url in urls))
    forms_by_url = {url: forms for url, forms in pairs}
    total = sum(len(forms) for forms in forms_by_url.values())
    print(f"[CRAWLER] Extracted {total} forms from {len(urls)} URLs")
    return forms_by_url
