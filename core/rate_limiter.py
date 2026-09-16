"""
Adaptive Rate Limiter — Token Bucket + 429/503 detection
v2.1: Fixed token bucket refill bug.
"""

import asyncio
import time
from dataclasses import dataclass, field
from collections import defaultdict
from rich.console import Console

console = Console()


@dataclass
class TokenBucket:
    rps: float
    tokens: float = field(init=False)
    last_refill: float = field(init=False)
    lock: asyncio.Lock = field(init=False)

    def __post_init__(self):
        self.tokens = self.rps
        self.last_refill = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self):
        """
        Acquire a token. If none available, sleep and loop.

        FIX: On the previous version, after sleeping we set tokens=0, which
        caused a *double refill* on the next call (elapsed * rps added again).
        The correct approach is to loop until we can consume 1 token.
        """
        async with self.lock:
            while True:
                now = time.monotonic()
                elapsed = now - self.last_refill
                self.tokens = min(self.rps, self.tokens + elapsed * self.rps)
                self.last_refill = now

                if self.tokens >= 1:
                    self.tokens -= 1
                    return

                # Not enough tokens — sleep until the next token is ready
                wait = (1 - self.tokens) / self.rps
                await asyncio.sleep(wait)
                # Loop will re-check tokens on next iteration


class AdaptiveRateLimiter:
    """
    Per-domain token bucket.
    429 → halve RPS
    503 → 30s pause
    Success streak → gradually increase RPS
    """

    def __init__(
        self,
        default_rps: float = 10.0,
        min_rps: float = 1.0,
        max_rps: float = 50.0,
        backoff_multiplier: float = 2.0,
        pause_on_503: int = 30,
    ):
        self.default_rps = default_rps
        self.min_rps = min_rps
        self.max_rps = max_rps
        self.backoff_multiplier = backoff_multiplier
        self.pause_on_503 = pause_on_503

        self._buckets: dict[str, TokenBucket] = {}
        self._success_streak: dict[str, int] = defaultdict(int)
        self._paused_until: dict[str, float] = {}
        self._min_delay: dict[str, float] = defaultdict(float)

    def _get_bucket(self, domain: str) -> TokenBucket:
        if domain not in self._buckets:
            self._buckets[domain] = TokenBucket(rps=self.default_rps)
        return self._buckets[domain]

    def set_domain_rps(self, domain: str, rps: float) -> None:
        """Force a specific RPS for a domain (used by WAF evasion)."""
        rps = max(self.min_rps, min(self.max_rps, rps))
        self._get_bucket(domain).rps = rps

    def set_domain_delay(self, domain: str, delay: float) -> None:
        """Minimum inter-request delay in seconds."""
        self._min_delay[domain] = max(0.0, delay)

    async def acquire(self, domain: str):
        """Call before every request."""
        # 503 pause
        if domain in self._paused_until:
            remaining = self._paused_until[domain] - time.monotonic()
            if remaining > 0:
                console.print(
                    f"[yellow]⏸  {domain} — waiting {remaining:.0f}s (503)[/yellow]"
                )
                await asyncio.sleep(remaining)
            else:
                del self._paused_until[domain]

        await self._get_bucket(domain).acquire()

        # Additional WAF delay
        if self._min_delay[domain] > 0:
            await asyncio.sleep(self._min_delay[domain])

    def on_response(self, domain: str, status_code: int):
        """Call after every response."""
        bucket = self._get_bucket(domain)

        if status_code == 429:
            new_rps = max(self.min_rps, bucket.rps / self.backoff_multiplier)
            console.print(
                f"[red]⚡ 429 — {domain} RPS: {bucket.rps:.1f} → {new_rps:.1f}[/red]"
            )
            bucket.rps = new_rps
            self._success_streak[domain] = 0

        elif status_code == 503:
            console.print(
                f"[red]🛑 503 — {domain} paused for {self.pause_on_503}s[/red]"
            )
            self._paused_until[domain] = time.monotonic() + self.pause_on_503
            self._success_streak[domain] = 0

        elif status_code < 400:
            self._success_streak[domain] += 1
            if self._success_streak[domain] % 20 == 0:
                new_rps = min(self.max_rps, bucket.rps * 1.2)
                if new_rps > bucket.rps:
                    console.print(
                        f"[green]📈 {domain} RPS: {bucket.rps:.1f} → {new_rps:.1f}[/green]"
                    )
                    bucket.rps = new_rps

    def get_stats(self) -> dict:
        return {
            domain: {
                "current_rps": round(bucket.rps, 2),
                "success_streak": self._success_streak.get(domain, 0),
                "paused": domain in self._paused_until,
                "min_delay": self._min_delay.get(domain, 0.0),
            }
            for domain, bucket in self._buckets.items()
        }