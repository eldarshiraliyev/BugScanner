"""
Subdomain Enumeration
- DNS brute force (wordlist)
- Certificate Transparency (crt.sh)
- Passive DNS
"""

import asyncio
import httpx
import dns.resolver
import dns.asyncresolver
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from core.models import SubdomainInfo

console = Console()

# Core subdomain wordlist
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "webdisk", "ns", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap",
    "test", "dev", "staging", "api", "admin", "portal", "blog", "shop", "store",
    "app", "mobile", "vpn", "remote", "secure", "login", "dashboard", "beta",
    "alpha", "demo", "cdn", "static", "assets", "media", "images", "upload",
    "uploads", "files", "backup", "old", "new", "v2", "v1", "prod", "production",
    "development", "qa", "uat", "internal", "intranet", "extranet", "support",
    "help", "forum", "community", "wiki", "docs", "documentation", "status",
    "monitor", "monitoring", "analytics", "metrics", "grafana", "kibana",
    "jenkins", "jira", "confluence", "gitlab", "git", "svn", "ci", "build",
    "docker", "k8s", "kubernetes", "registry", "repo", "nexus", "sonar",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elasticsearch",
    "s3", "storage", "cloud", "aws", "gcp", "azure", "office", "exchange",
]


class SubdomainScanner:
    def __init__(
        self,
        http_client,
        wordlist: list[str] = None,
        check_http: bool = True,
        http_concurrency: int = 20,
        http_timeout: float = 5.0,
    ):
        self.http_client = http_client
        self.wordlist = wordlist or COMMON_SUBDOMAINS
        self.check_http = check_http
        self.http_concurrency = http_concurrency
        self.http_timeout = http_timeout

        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3

    async def _resolve(self, subdomain: str) -> tuple[bool, str | None]:
        """Resolve subdomain to IP."""
        try:
            answers = await self.resolver.resolve(subdomain, "A")
            ip = str(answers[0])
            return True, ip
        except Exception:
            return False, None

    async def _check_http(self, subdomain: str) -> int | None:
        """
        Check HTTP status with a lightweight, isolated client.

        Does NOT go through the shared rate limiter — the shared limiter
        is tuned for the target domain, not for arbitrary subdomains. This
        keeps DNS enumeration from stalling behind the target's RPS bucket.
        """
        for scheme in ("https", "http"):
            try:
                async with httpx.AsyncClient(
                    verify=False,
                    timeout=self.http_timeout,
                    follow_redirects=False,
                ) as client:
                    r = await client.head(f"{scheme}://{subdomain}")
                    return r.status_code
            except Exception:
                continue
        return None

    async def _crtsh(self, domain: str) -> list[str]:
        """Certificate Transparency — crt.sh passive lookup."""
        found: list[str] = []
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    headers={"Accept": "application/json"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data:
                        names = entry.get("name_value", "").split("\n")
                        for name in names:
                            name = name.strip().lstrip("*.")
                            if name.endswith(f".{domain}") and name not in found:
                                found.append(name)
        except Exception:
            pass
        return found

    async def _resolve_only(self, subdomain_full: str) -> SubdomainInfo | None:
        """DNS-only resolve (fast, no HTTP)."""
        resolved, ip = await self._resolve(subdomain_full)
        if not resolved:
            return None
        return SubdomainInfo(subdomain=subdomain_full, ip=ip, status=None)

    async def _enrich_with_http(self, subs: list[SubdomainInfo]) -> None:
        """Fill in HTTP status for each resolved subdomain in parallel."""
        sem = asyncio.Semaphore(self.http_concurrency)

        async def enrich(s: SubdomainInfo):
            async with sem:
                s.status = await self._check_http(s.subdomain)

        await asyncio.gather(*(enrich(s) for s in subs), return_exceptions=True)

    async def scan(self, domain: str) -> list[SubdomainInfo]:
        console.print(f"\n[bold cyan]🔍 Subdomain scan started:[/bold cyan] {domain}")
        results: list[SubdomainInfo] = []
        found_names: set[str] = set()

        # 1. crt.sh passive enumeration
        console.print("[dim]  → Querying crt.sh Certificate Transparency...[/dim]")
        crt_subs = await self._crtsh(domain)
        console.print(f"[dim]  → crt.sh returned {len(crt_subs)} subdomains[/dim]")

        # 2. Wordlist + crt.sh merged
        all_to_check = list(set(
            [f"{sub}.{domain}" for sub in self.wordlist] + crt_subs
        ))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(
                f"[cyan]DNS resolve ({len(all_to_check)} subdomains)...[/cyan]",
                total=len(all_to_check),
            )

            semaphore = asyncio.Semaphore(50)

            async def check_with_semaphore(sub: str):
                async with semaphore:
                    result = await self._resolve_only(sub)
                    progress.advance(task)
                    return result

            raw_results = await asyncio.gather(
                *[check_with_semaphore(s) for s in all_to_check],
                return_exceptions=True,
            )

        for r in raw_results:
            if isinstance(r, SubdomainInfo) and r.subdomain not in found_names:
                found_names.add(r.subdomain)
                results.append(r)

        # 3. Optional HTTP enrichment
        if self.check_http and results:
            console.print(
                f"[dim]  → HTTP probe for {len(results)} subdomains "
                f"(concurrency={self.http_concurrency})...[/dim]"
            )
            await self._enrich_with_http(results)

        # Print results sorted
        for r in sorted(results, key=lambda x: x.subdomain):
            status_str = f"[HTTP {r.status}]" if r.status else "[no HTTP]"
            console.print(f"  [green]✓[/green] {r.subdomain} → {r.ip} {status_str}")

        console.print(
            f"[bold green]  Subdomain scan complete: {len(results)} found[/bold green]"
        )
        return results