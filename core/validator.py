"""
False-Positive Validator
Re-verifies each finding before reporting.
"""

import asyncio
import time
import re
from rich.console import Console
from core.models import Vulnerability, Severity

console = Console()

# SQL markers that indicate a time-based payload
SQLI_TIME_MARKERS = ("SLEEP", "WAITFOR", "PG_SLEEP", "BENCHMARK")


class FalsePositiveValidator:
    def __init__(self, http_client):
        self.http_client = http_client

    async def validate_xss(self, vuln: Vulnerability) -> bool:
        """XSS — 3 re-checks, at least 2 must confirm."""
        if not vuln.payload_used:
            return True

        confirmed = 0
        for _ in range(3):
            resp = await self.http_client.get(vuln.url)
            if resp and vuln.payload_used.lower()[:20] in resp.text.lower():
                confirmed += 1
            await asyncio.sleep(0.5)

        result = confirmed >= 2
        if not result:
            console.print(f"  [dim]FP filtered: XSS {vuln.url[:50]}[/dim]")
        return result

    async def validate_sqli_time(self, vuln: Vulnerability) -> bool:
        """
        Time-based SQLi — 3 repetitions, averaged.

        Supports MySQL (SLEEP), MSSQL (WAITFOR), PostgreSQL (pg_sleep),
        and MySQL (BENCHMARK).
        """
        payload_upper = (vuln.payload_used or "").upper()
        if not vuln.url or not any(m in payload_upper for m in SQLI_TIME_MARKERS):
            return True

        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(vuln.url)
        base_url = urlunparse(parsed._replace(query=""))

        # Baseline — 3 clean requests
        baselines = []
        for _ in range(3):
            t0 = time.monotonic()
            await self.http_client.get(base_url)
            baselines.append(time.monotonic() - t0)
            await asyncio.sleep(0.3)
        baseline_avg = sum(baselines) / len(baselines)

        # Payload — 3 requests
        delays = []
        for _ in range(3):
            t0 = time.monotonic()
            await self.http_client.get(vuln.url)
            delays.append(time.monotonic() - t0)
            await asyncio.sleep(0.5)
        delay_avg = sum(delays) / len(delays)

        all_delayed = all(d > baseline_avg + 2.0 for d in delays)
        significant = delay_avg > baseline_avg + 2.5

        result = all_delayed and significant
        if not result:
            console.print(
                f"  [dim]FP filtered: SQLi time-based "
                f"(baseline={baseline_avg:.2f}s, payload={delay_avg:.2f}s)[/dim]"
            )
        return result

    async def validate_cors(self, vuln: Vulnerability) -> bool:
        """CORS — re-check with a different User-Agent."""
        if not vuln.url:
            return True

        resp = await self.http_client.get(
            vuln.url,
            headers={
                "Origin": "https://evil.com",
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/124.0.0.0",
            },
        )
        if not resp:
            return False

        acao = resp.headers.get("access-control-allow-origin", "")
        result = "evil.com" in acao or acao == "*"
        if not result:
            console.print(f"  [dim]FP filtered: CORS {vuln.url[:50]}[/dim]")
        return result

    async def validate_redirect(self, vuln: Vulnerability) -> bool:
        """Open redirect — re-check with follow_redirects=False."""
        if not vuln.url:
            return True
        try:
            import httpx
            async with httpx.AsyncClient(
                verify=False, timeout=8, follow_redirects=False
            ) as client:
                resp = await client.get(vuln.url)
                location = resp.headers.get("location", "")
                result = (
                    resp.status_code in (301, 302, 303, 307, 308)
                    and "evil.com" in location
                )
                if not result:
                    console.print(
                        f"  [dim]FP filtered: Redirect {vuln.url[:50]}[/dim]"
                    )
                return result
        except Exception:
            return False

    async def validate_disclosure(self, vuln: Vulnerability) -> bool:
        """Disclosure — 200 status stable across re-checks?"""
        if not vuln.url:
            return True

        responses = []
        for _ in range(2):
            resp = await self.http_client.get(vuln.url)
            if resp:
                responses.append(resp.status_code)
            await asyncio.sleep(0.5)

        result = all(s == 200 for s in responses) and len(responses) == 2
        if not result:
            console.print(
                f"  [dim]FP filtered: Disclosure {vuln.url[:50]}[/dim]"
            )
        return result

    async def validate(self, vuln: Vulnerability) -> bool:
        """Dispatch to the appropriate validator based on vuln type."""
        try:
            vtype = vuln.vuln_type.lower()

            if "xss" in vtype:
                return await self.validate_xss(vuln)
            elif "sql" in vtype and "time" in vuln.title.lower():
                return await self.validate_sqli_time(vuln)
            elif "cors" in vtype:
                return await self.validate_cors(vuln)
            elif "redirect" in vtype:
                return await self.validate_redirect(vuln)
            elif "disclosure" in vtype and "git" not in vuln.title.lower():
                return await self.validate_disclosure(vuln)
            return True
        except Exception:
            return True

    async def validate_all(
        self, vulns: list[Vulnerability]
    ) -> tuple[list[Vulnerability], list[Vulnerability]]:
        """
        Validate all vulnerabilities.
        Returns: (confirmed, filtered_as_fp)
        """
        if not vulns:
            return [], []

        console.print(
            f"\n[bold cyan]🔬 False-Positive validation:[/bold cyan] "
            f"verifying {len(vulns)} findings..."
        )

        # Only Medium+ get validated; Low/Info pass through
        to_validate = [
            v for v in vulns
            if v.severity.value in ("critical", "high", "medium")
        ]
        skip = [
            v for v in vulns
            if v.severity.value in ("low", "info")
        ]

        semaphore = asyncio.Semaphore(5)

        async def validate_with_sem(v):
            async with semaphore:
                ok = await self.validate(v)
                return v, ok

        results = await asyncio.gather(
            *[validate_with_sem(v) for v in to_validate],
            return_exceptions=True,
        )

        confirmed = list(skip)
        filtered = []

        for r in results:
            if isinstance(r, tuple):
                vuln, ok = r
                if ok:
                    confirmed.append(vuln)
                else:
                    filtered.append(vuln)

        console.print(
            f"  [green]✓ Confirmed: {len(confirmed)}[/green]  "
            f"[dim]FP filtered: {len(filtered)}[/dim]"
        )

        return confirmed, filtered