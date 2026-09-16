"""Tests for IDOR SPA-aware false-positive reduction."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from modules.vulns.idor import IDORScanner


def _resp(status: int, text: str = "", content_type: str = "text/html"):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {"content-type": content_type}
    return r


def test_similar_body_identical():
    assert IDORScanner._similar_body("hello world", "hello world") is True


def test_similar_body_length_mismatch():
    a = "a" * 1000
    b = "a" * 100  # 90% shorter
    assert IDORScanner._similar_body(a, b) is False


def test_looks_like_spa_shell_react():
    body = '<html><body><div id="root"></div><script src="/assets/index.js"></script></body></html>'
    assert IDORScanner._looks_like_spa_shell(body, "text/html") is True


def test_looks_like_spa_shell_not_html():
    body = '{"data": []}'
    assert IDORScanner._looks_like_spa_shell(body, "application/json") is False


def test_looks_like_error_page():
    body = "<html><body><h1>404 - Page Not Found</h1></body></html>"
    assert IDORScanner._looks_like_error_page(body) is True


def test_looks_like_error_page_normal():
    body = "<html><body><h1>Welcome</h1></body></html>"
    assert IDORScanner._looks_like_error_page(body) is False


@pytest.mark.asyncio
async def test_spa_detection_true():
    """When a random path returns the same body → SPA detected."""
    http = MagicMock()
    home_body = '<div id="root"></div><script src="/assets/index.js"></script>'

    async def mock_get(url):
        return _resp(200, home_body, "text/html")

    http.get = AsyncMock(side_effect=mock_get)

    scanner = IDORScanner(http)
    is_spa = await scanner._detect_spa_fallback("https://app.example.com/")
    assert is_spa is True

    # Second call should be cached
    is_spa_2 = await scanner._detect_spa_fallback("https://app.example.com/dashboard")
    assert is_spa_2 is True
    # Only 2 real HTTP calls made (baseline + fake)
    assert http.get.call_count == 2


@pytest.mark.asyncio
async def test_spa_detection_false():
    """Non-SPA returns different bodies for existing vs missing paths."""
    http = MagicMock()

    async def mock_get(url):
        if "__bugscanner_nonexistent" in url:
            return _resp(404, "Not found", "text/plain")
        return _resp(200, "Real page content", "text/html")

    http.get = AsyncMock(side_effect=mock_get)

    scanner = IDORScanner(http)
    is_spa = await scanner._detect_spa_fallback("https://api.example.com/")
    assert is_spa is False


@pytest.mark.asyncio
async def test_http_method_skipped_on_spa():
    """On SPA, the HTTP method test should return empty list."""
    http = MagicMock()

    async def mock_get(url):
        return _resp(200, '<div id="root"></div>', "text/html")

    http.get = AsyncMock(side_effect=mock_get)
    http.request = AsyncMock(return_value=_resp(200, '<div id="root"></div>'))

    scanner = IDORScanner(http)
    vulns = await scanner._test_http_method("https://app.example.com/")
    assert vulns == []
    # Should never have issued a method request
    assert http.request.call_count == 0