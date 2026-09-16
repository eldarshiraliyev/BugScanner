"""Tests for HttpClient with respx mocking."""

import httpx
import pytest
import respx

from core.http_client import HttpClient
from core.rate_limiter import AdaptiveRateLimiter


@pytest.fixture
def rl():
    return AdaptiveRateLimiter(default_rps=1000, min_rps=1, max_rps=1000)


@pytest.mark.asyncio
@respx.mock
async def test_get_success(rl):
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(200, text="ok")
    )

    async with HttpClient(rl, verify_ssl=False) as client:
        r = await client.get("https://example.com/")
        assert r is not None
        assert r.status_code == 200
        assert r.text == "ok"


@pytest.mark.asyncio
@respx.mock
async def test_get_cache_hit(rl):
    route = respx.get("https://example.com/cached").mock(
        return_value=httpx.Response(200, text="cached")
    )

    async with HttpClient(rl, verify_ssl=False, cache_ttl=60) as client:
        r1 = await client.get("https://example.com/cached")
        r2 = await client.get("https://example.com/cached")

        assert r1 is r2
        assert route.call_count == 1  # Only fetched once
        stats = client.cache_stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 1


@pytest.mark.asyncio
@respx.mock
async def test_retry_on_503(rl):
    attempts = {"n": 0}

    def responder(request):
        attempts["n"] += 1
        if attempts["n"] < 3:
            return httpx.Response(503)
        return httpx.Response(200, text="recovered")

    respx.get("https://example.com/flaky").mock(side_effect=responder)

    async with HttpClient(rl, verify_ssl=False) as client:
        r = await client.get("https://example.com/flaky")
        assert r is not None
        assert r.status_code == 200
        assert r.text == "recovered"
        assert attempts["n"] == 3


@pytest.mark.asyncio
@respx.mock
async def test_error_returns_none_after_retries(rl):
    respx.get("https://example.com/down").mock(
        side_effect=httpx.ConnectError("refused")
    )

    async with HttpClient(rl, verify_ssl=False) as client:
        r = await client.get("https://example.com/down")
        assert r is None


@pytest.mark.asyncio
@respx.mock
async def test_cache_disabled(rl):
    route = respx.get("https://example.com/nocache").mock(
        return_value=httpx.Response(200, text="ok")
    )

    async with HttpClient(rl, verify_ssl=False, enable_cache=False) as client:
        await client.get("https://example.com/nocache")
        await client.get("https://example.com/nocache")
        assert route.call_count == 2