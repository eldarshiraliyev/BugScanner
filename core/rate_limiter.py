"""
Adaptive Rate Limiter — Token Bucket + 429/503 detection
"""

import asyncio
import time
from dataclasses import dataclass, field
from collections import defaultdict
from rich.console import Console

console = Console()


@dataclass
class TokenBucket:
    rps: float              # requests per second
    tokens: float = field(init=False)
    last_refill: float = field(init=False)
    lock: asyncio.Lock = field(init=False)

    def __post_init__(self):
        self.tokens = self.rps
        self.last_refill = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self):
        async with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            # Token əlavə et
            self.tokens = min(self.rps, self.tokens + elapsed * self.rps)
            self.last_refill = now

            if self.tokens >= 1:
                self.tokens -= 1
                return
            else:
                # Token olmadıqda gözlə
                wait = (1 - self.tokens) / self.rps
                await asyncio.sleep(wait)
                self.tokens = 0


class AdaptiveRateLimiter:
    """
    Hər domain üçün ayrı token bucket.
    429 → RPS yarıya endir
    503 → 30s pauza
    Success streak → RPS artır
    """

    def __init__(self, default_rps: float = 10.0, min_rps: float = 1.0,
                 max_rps: float = 50.0, backoff_multiplier: float = 2.0,
                 pause_on_503: int = 30):
        self.default_rps = default_rps
        self.min_rps = min_rps
        self.max_rps = max_rps
        self.backoff_multiplier = backoff_multiplier
        self.pause_on_503 = pause_on_503

        self._buckets: dict[str, TokenBucket] = {}
        self._success_streak: dict[str, int] = defaultdict(int)
        self._paused_until: dict[str, float] = {}

    def _get_bucket(self, domain: str) -> TokenBucket:
        if domain not in self._buckets:
            self._buckets[domain] = TokenBucket(rps=self.default_rps)
        return self._buckets[domain]

    async def acquire(self, domain: str):
        """Request göndərməzdən əvvəl çağır"""
        # Pause yoxla
        if domain in self._paused_until:
            remaining = self._paused_until[domain] - time.monotonic()
            if remaining > 0:
                console.print(f"[yellow]⏸  {domain} — {remaining:.0f}s gözlənilir (503)[/yellow]")
                await asyncio.sleep(remaining)
            else:
                del self._paused_until[domain]

        await self._get_bucket(domain).acquire()

    def on_response(self, domain: str, status_code: int):
        """Response aldıqdan sonra çağır"""
        bucket = self._get_bucket(domain)

        if status_code == 429:
            new_rps = max(self.min_rps, bucket.rps / self.backoff_multiplier)
            console.print(f"[red]⚡ 429 — {domain} RPS: {bucket.rps:.1f} → {new_rps:.1f}[/red]")
            bucket.rps = new_rps
            self._success_streak[domain] = 0

        elif status_code == 503:
            console.print(f"[red]🛑 503 — {domain} {self.pause_on_503}s pauzaya alındı[/red]")
            self._paused_until[domain] = time.monotonic() + self.pause_on_503
            self._success_streak[domain] = 0

        elif status_code < 400:
            self._success_streak[domain] += 1
            # 20 uğurlu requestdən sonra RPS artır
            if self._success_streak[domain] % 20 == 0:
                new_rps = min(self.max_rps, bucket.rps * 1.2)
                if new_rps > bucket.rps:
                    console.print(f"[green]📈 {domain} RPS: {bucket.rps:.1f} → {new_rps:.1f}[/green]")
                    bucket.rps = new_rps

    def get_stats(self) -> dict:
        return {
            domain: {
                "current_rps": round(bucket.rps, 2),
                "success_streak": self._success_streak.get(domain, 0),
                "paused": domain in self._paused_until
            }
            for domain, bucket in self._buckets.items()
        }
