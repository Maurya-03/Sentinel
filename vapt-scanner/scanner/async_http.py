# scanner/async_http.py — Async HTTP client, retry, rate limiting

from __future__ import annotations
import asyncio
import random
from typing import Optional, Dict, Any

import aiohttp
import requests
from dataclasses import dataclass

from config import (
    DEFAULT_TIMEOUT,
    USER_AGENT,
    HTTP_MAX_CONCURRENCY,
    HTTP_RATE_LIMIT_RPS,
    HTTP_RETRIES,
    HTTP_BACKOFF_BASE,
    DNS_CACHE_TTL,
)


class AsyncRateLimiter:
    """Simple per-target rate limiter based on minimum interval."""

    def __init__(self, rps: float) -> None:
        self._min_interval = 1.0 / rps if rps > 0 else 0.0
        self._lock = asyncio.Lock()
        self._last_call = 0.0

    async def wait(self) -> None:
        if self._min_interval <= 0:
            return
        async with self._lock:
            now = asyncio.get_running_loop().time()
            delta = now - self._last_call
            if delta < self._min_interval:
                await asyncio.sleep(self._min_interval - delta)
            self._last_call = asyncio.get_running_loop().time()


@dataclass
class AsyncResponse:
    status: int
    headers: Dict[str, str]
    text: str
    url: str


class AsyncHTTPClient:
    """Shared aiohttp client with connection pooling, retries, and rate limiting."""

    def __init__(self, base_timeout: int = DEFAULT_TIMEOUT) -> None:
        resolver = aiohttp.DefaultResolver()
        connector = aiohttp.TCPConnector(
            limit=HTTP_MAX_CONCURRENCY,
            ttl_dns_cache=DNS_CACHE_TTL,
            ssl=False,
            enable_cleanup_closed=True,
            resolver=resolver,
        )
        timeout = aiohttp.ClientTimeout(total=base_timeout)
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            },
            raise_for_status=False,
        )
        self._sem = asyncio.Semaphore(HTTP_MAX_CONCURRENCY)
        self._limiter = AsyncRateLimiter(HTTP_RATE_LIMIT_RPS)
        self.last_error: Optional[str] = None

    async def close(self) -> None:
        await self._session.close()

    async def get(self, url: str, params: Optional[dict] = None) -> Optional[AsyncResponse]:
        return await self._request("GET", url, params=params)

    async def post(self, url: str, data: Optional[dict] = None) -> Optional[AsyncResponse]:
        return await self._request("POST", url, data=data)

    async def _request(self, method: str, url: str, **kwargs: Any) -> Optional[AsyncResponse]:
        self.last_error = None
        for attempt in range(HTTP_RETRIES + 1):
            await self._limiter.wait()
            async with self._sem:
                try:
                    async with self._session.request(method, url, **kwargs) as resp:
                        text = await resp.text(errors="ignore")
                        return AsyncResponse(
                            status=resp.status,
                            headers={k: v for k, v in resp.headers.items()},
                            text=text,
                            url=str(resp.url),
                        )
                except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                    self.last_error = f"{type(exc).__name__}: {exc}"
                    if attempt >= HTTP_RETRIES:
                        break
                    backoff = HTTP_BACKOFF_BASE * (2 ** attempt)
                    jitter = random.uniform(0, HTTP_BACKOFF_BASE)
                    await asyncio.sleep(backoff + jitter)
        # Fallback to synchronous requests in a thread for reliability.
        try:
            def _sync_request() -> requests.Response:
                return requests.request(
                    method,
                    url,
                    timeout=DEFAULT_TIMEOUT,
                    allow_redirects=True,
                    verify=False,
                    headers={
                        "User-Agent": USER_AGENT,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.5",
                    },
                    **kwargs,
                )

            resp = await asyncio.to_thread(_sync_request)
            self.last_error = None
            return AsyncResponse(
                status=resp.status_code,
                headers=dict(resp.headers),
                text=resp.text or "",
                url=str(resp.url),
            )
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            return None
