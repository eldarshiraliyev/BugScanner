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

# Əsas subdomain wordlist
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
    def __init__(self, http_client, wordlist: list[str] = None):
        self.http_client = http_client
        self.wordlist = wordlist or COMMON_SUBDOMAINS
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3

    async def _resolve(self, subdomain: str) -> tuple[bool, str | None]:
        """DNS resolve et"""
        try:
            answers = await self.resolver.resolve(subdomain, "A")
            ip = str(answers[0])
            return True, ip
        except Exception:
            return False, None

    async def _check_http(self, subdomain: str) -> int | None:
        """HTTP status yoxla"""
        for scheme in ["https", "http"]:
            url = f"{scheme}://{subdomain}"
            response = await self.http_client.get(url)
            if response:
                return response.status_code
        return None

    async def _crtsh(self, domain: str) -> list[str]:
        """Certificate Transparency — crt.sh passiv axtarış"""
        found = []
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    headers={"Accept": "application/json"}
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

    async def _check_single(self, subdomain_full: str) -> SubdomainInfo | None:
        resolved, ip = await self._resolve(subdomain_full)
        if not resolved:
            return None

        status = await self._check_http(subdomain_full)
        return SubdomainInfo(
            subdomain=subdomain_full,
            ip=ip,
            status=status,
        )

    async def scan(self, domain: str) -> list[SubdomainInfo]:
        console.print(f"\n[bold cyan]🔍 Subdomain scan başladı:[/bold cyan] {domain}")
        results = []
        found_names = set()

        # 1. crt.sh passiv
        console.print("[dim]  → crt.sh Certificate Transparency yoxlanılır...[/dim]")
        crt_subs = await self._crtsh(domain)
        console.print(f"[dim]  → crt.sh-dən {len(crt_subs)} subdomain tapıldı[/dim]")

        # 2. Wordlist bruteforce + crt.sh nəticələri birləşdir
        all_to_check = list(set(
            [f"{sub}.{domain}" for sub in self.wordlist] + crt_subs
        ))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(
                f"[cyan]DNS resolve ({len(all_to_check)} subdomain)...[/cyan]",
                total=len(all_to_check)
            )

            semaphore = asyncio.Semaphore(50)  # 50 paralel DNS sorğu

            async def check_with_semaphore(sub):
                async with semaphore:
                    result = await self._check_single(sub)
                    progress.advance(task)
                    return result

            tasks = [check_with_semaphore(sub) for sub in all_to_check]
            raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in raw_results:
            if isinstance(r, SubdomainInfo) and r.subdomain not in found_names:
                found_names.add(r.subdomain)
                results.append(r)
                status_str = f"[HTTP {r.status}]" if r.status else "[no HTTP]"
                console.print(f"  [green]✓[/green] {r.subdomain} → {r.ip} {status_str}")

        console.print(f"[bold green]  Subdomain skanı tamamlandı: {len(results)} tapıldı[/bold green]")
        return results
