"""Tests for AdaptiveRateLimiter."""

import asyncio
import time

import pytest

from core.rate_limiter import AdaptiveRateLimiter, TokenBucket


@pytest.mark.asyncio
async def test_token_bucket_initial_state():
    bucket = TokenBucket(rps=10)
    assert bucket.rps == 10
    assert bucket.tokens == 10


@pytest.mark.asyncio
async def test_token_bucket_consumes_token():
    bucket = TokenBucket(rps=100)
    before = bucket.tokens
    await bucket.acquire()
    assert bucket.tokens < before


@pytest.mark.asyncio
async def test_token_bucket_rate_accurate():
    """
    Verify actual RPS matches configured RPS.

    With rps=20, 10 acquisitions should take ~0.5s (±20% tolerance).
    This catches the previous double-refill bug.
    """
    bucket = TokenBucket(rps=20)
    # Consume initial burst
    for _ in range(20):
        await bucket.acquire()

    # Now measure
    start = time.monotonic()
    for _ in range(10):
        await bucket.acquire()
    elapsed = time.monotonic() - start

    # Expected: 10 / 20 = 0.5 seconds
    assert 0.4 < elapsed < 0.7, f"Unexpected elapsed: {elapsed:.3f}s"


def test_429_reduces_rps():
    rl = AdaptiveRateLimiter(default_rps=10, backoff_multiplier=2)
    bucket = rl._get_bucket("example.com")
    assert bucket.rps == 10

    rl.on_response("example.com", 429)
    assert bucket.rps == 5

    rl.on_response("example.com", 429)
    assert bucket.rps == 2.5


def test_429_does_not_go_below_min():
    rl = AdaptiveRateLimiter(default_rps=10, min_rps=2, backoff_multiplier=2)
    bucket = rl._get_bucket("example.com")

    for _ in range(10):
        rl.on_response("example.com", 429)

    assert bucket.rps == 2


def test_503_pauses_domain():
    rl = AdaptiveRateLimiter(pause_on_503=30)
    rl.on_response("example.com", 503)
    assert "example.com" in rl._paused_until


def test_success_increases_rps():
    rl = AdaptiveRateLimiter(default_rps=10, max_rps=50)
    bucket = rl._get_bucket("example.com")

    for _ in range(20):
        rl.on_response("example.com", 200)

    assert bucket.rps == 12  # 10 * 1.2


def test_set_domain_rps_clamped():
    rl = AdaptiveRateLimiter(min_rps=1, max_rps=50)
    rl.set_domain_rps("example.com", 999)
    assert rl._get_bucket("example.com").rps == 50

    rl.set_domain_rps("example.com", -5)
    assert rl._get_bucket("example.com").rps == 1


def test_get_stats():
    rl = AdaptiveRateLimiter(default_rps=10)
    rl._get_bucket("example.com")
    stats = rl.get_stats()
    assert "example.com" in stats
    assert stats["example.com"]["current_rps"] == 10