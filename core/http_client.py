"""
Async HTTP Client — Authentication + Rate Limiter
"""

import httpx
import tldextract
from typing import Optional
from .rate_limiter import AdaptiveRateLimiter


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
    ):
        self.rate_limiter = rate_limiter
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent or "Mozilla/5.0 (compatible; BugScanner/1.0)"
        self.max_redirects = max_redirects
        self.extra_cookies = cookies or {}
        self.extra_headers = headers or {}
        self.proxy = proxy
        self._client: Optional[httpx.AsyncClient] = None

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

    def _extract_domain(self, url: str) -> str:
        extracted = tldextract.extract(url)
        return f"{extracted.domain}.{extracted.suffix}"

    async def get(self, url: str, **kwargs) -> Optional[httpx.Response]:
        domain = self._extract_domain(url)
        await self.rate_limiter.acquire(domain)
        try:
            response = await self._client.get(url, **kwargs)
            self.rate_limiter.on_response(domain, response.status_code)
            return response
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
            return None

    async def post(self, url: str, **kwargs) -> Optional[httpx.Response]:
        domain = self._extract_domain(url)
        await self.rate_limiter.acquire(domain)
        try:
            response = await self._client.post(url, **kwargs)
            self.rate_limiter.on_response(domain, response.status_code)
            return response
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
            return None

    async def request(self, method: str, url: str, **kwargs) -> Optional[httpx.Response]:
        domain = self._extract_domain(url)
        await self.rate_limiter.acquire(domain)
        try:
            response = await self._client.request(method, url, **kwargs)
            self.rate_limiter.on_response(domain, response.status_code)
            return response
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
            return None