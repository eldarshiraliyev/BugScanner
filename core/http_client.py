"""
Async HTTP Client — Authentication + Rate Limiter + Retry + Cache
v2.1: Added exponential-backoff retry and per-domain request caching.
"""

import asyncio
import hashlib
import json
import time
from typing import Optional

import httpx
import tldextract

from .rate_limiter import AdaptiveRateLimiter
from .logger import get_logger

log = get_logger("http_client")

# Retry configuration
MAX_RETRIES = 3
RETRY_BACKOFF = 1.5
RETRY_STATUS = {500, 502, 503, 504, 429}


class HttpClient:
    def __init__(
        self,
        rate_limiter: AdaptiveRateLimiter,
        timeout: int = 10,
        verify_ssl: bool = False,
        user_agent: str = None,
        max_redirects: int = 5,
        cookies: dict = None,
        headers: dict = None,
        proxy: str = None,
        cache_ttl: int = 300,
        enable_cache: bool = True,
    ):
        self.rate_limiter = rate_limiter
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent or "Mozilla/5.0 (compatible; BugScanner/2.1)"
        self.max_redirects = max_redirects
        self.extra_cookies = cookies or {}
        self.extra_headers = headers or {}
        self.proxy = proxy
        self._client: Optional[httpx.AsyncClient] = None

        # Cache
        self.cache_ttl = cache_ttl
        self.enable_cache = enable_cache
        self._cache: dict[str, tuple[float, httpx.Response]] = {}
        self._cache_hits = 0
        self._cache_misses = 0

    async def __aenter__(self):
        base_headers = {"User-Agent": self.user_agent}
        base_headers.update(self.extra_headers)

        self._client = httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=self.timeout,
            follow_redirects=True,
            max_redirects=self.max_redirects,
            headers=base_headers,
            cookies=self.extra_cookies,
            proxy=self.proxy,
        )
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    # ── helpers ────────────────────────────────────────────────

    def _extract_domain(self, url: str) -> str:
        extracted = tldextract.extract(url)
        return f"{extracted.domain}.{extracted.suffix}"

    def _cache_key(self, method: str, url: str, kwargs: dict) -> str:
        """Stable hash for a request."""
        payload = {
            "m": method.upper(),
            "u": url,
            "h": sorted((kwargs.get("headers") or {}).items()),
            "p": kwargs.get("params"),
            "j": str(kwargs.get("json")),
            "d": str(kwargs.get("data")),
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

    def _cache_get(self, key: str) -> Optional[httpx.Response]:
        if not self.enable_cache:
            return None
        entry = self._cache.get(key)
        if not entry:
            self._cache_misses += 1
            return None
        ts, resp = entry
        if time.monotonic() - ts > self.cache_ttl:
            del self._cache[key]
            self._cache_misses += 1
            return None
        self._cache_hits += 1
        return resp

    def _cache_set(self, key: str, resp: httpx.Response) -> None:
        if not self.enable_cache:
            return
        # Only cache GET requests with successful status
        if resp.status_code >= 400:
            return
        self._cache[key] = (time.monotonic(), resp)

    async def _do_request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> Optional[httpx.Response]:
        """
        Execute a request with retries and rate limiting.

        Returns the response, or None if all attempts fail.
        """
        domain = self._extract_domain(url)

        for attempt in range(1, MAX_RETRIES + 1):
            await self.rate_limiter.acquire(domain)
            try:
                if method == "GET":
                    resp = await self._client.get(url, **kwargs)
                elif method == "POST":
                    resp = await self._client.post(url, **kwargs)
                else:
                    resp = await self._client.request(method, url, **kwargs)

                self.rate_limiter.on_response(domain, resp.status_code)

                # Retry on transient server errors
                if resp.status_code in RETRY_STATUS and attempt < MAX_RETRIES:
                    wait = RETRY_BACKOFF ** attempt
                    log.warning(
                        "retrying_request",
                        url=url,
                        status=resp.status_code,
                        attempt=attempt,
                        wait=wait,
                    )
                    await asyncio.sleep(wait)
                    continue

                return resp

            except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError) as e:
                log.warning(
                    "request_failed",
                    url=url,
                    error=type(e).__name__,
                    attempt=attempt,
                )
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(RETRY_BACKOFF ** attempt)
                continue

        return None

    # ── public API ─────────────────────────────────────────────

    async def get(self, url: str, **kwargs) -> Optional[httpx.Response]:
        key = self._cache_key("GET", url, kwargs)
        cached = self._cache_get(key)
        if cached is not None:
            return cached

        resp = await self._do_request("GET", url, **kwargs)
        if resp is not None:
            self._cache_set(key, resp)
        return resp

    async def post(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self._do_request("POST", url, **kwargs)

    async def request(self, method: str, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self._do_request(method, url, **kwargs)

    def cache_stats(self) -> dict:
        total = self._cache_hits + self._cache_misses
        return {
            "hits": self._cache_hits,
            "misses": self._cache_misses,
            "entries": len(self._cache),
            "hit_rate": round(self._cache_hits / total, 3) if total else 0.0,
        }