"""
Main Scanner Orchestrator — v2.0
WAF Detection + FP Validation + Business Logic + Auth
"""

import asyncio
import yaml
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from core.rate_limiter import AdaptiveRateLimiter
from core.http_client import HttpClient
from core.models import ScanResult, Severity
from core.waf_detector import WAFDetector
from core.validator import FalsePositiveValidator

from modules.recon.subdomain import SubdomainScanner
from modules.recon.portscan import PortScanner
from modules.recon.fingerprint import TechFingerprinter
from modules.recon.discovery import DiscoveryScanner
from modules.vulns.xss import XSSScanner
from modules.vulns.cors import CORSScanner
from modules.vulns.disclosure import DisclosureScanner
from modules.vulns.sqli import SQLiScanner
from modules.vulns.ssrf import SSRFScanner
from modules.vulns.redirect import RedirectScanner
from modules.vulns.jwt import JWTScanner
from modules.vulns.idor import IDORScanner
from modules.vulns.nuclei_wrapper import NucleiWrapper
from modules.vulns.business_logic import BusinessLogicScanner

console = Console()

# settings.yaml sits at the project root; fall back to legacy config/ path
CONFIG_PATH = Path(__file__).parent.parent / "settings.yaml"
_LEGACY_CONFIG_PATH = Path(__file__).parent.parent / "config" / "settings.yaml"


def load_config() -> dict:
    path = CONFIG_PATH if CONFIG_PATH.exists() else _LEGACY_CONFIG_PATH
    with open(path) as f:
        return yaml.safe_load(f)


class BugScanner:
    def __init__(
        self,
        config: dict = None,
        cookies: dict = None,
        headers: dict = None,
        proxy: str = None,
        validate_fp: bool = True,
        run_business_logic: bool = False,
        run_nuclei: bool = True,
    ):
        self.config = config or load_config()
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.proxy = proxy
        self.validate_fp = validate_fp
        self.run_business_logic = run_business_logic
        # Respect both the CLI flag and the global config toggle
        self.run_nuclei = run_nuclei and self.config.get("nuclei", {}).get("enabled", True)

        rl = self.config["rate_limiting"]
        sc = self.config["scanning"]

        self.rate_limiter = AdaptiveRateLimiter(
            default_rps=rl["default_rps"],
            min_rps=rl["min_rps"],
            max_rps=rl["max_rps"],
            backoff_multiplier=rl["backoff_multiplier"],
            pause_on_503=rl["pause_on_503"],
        )

        self.http_config = {
            "timeout":       sc["timeout"],
            "verify_ssl":    sc["verify_ssl"],
            "user_agent":    sc["user_agent"],
            "max_redirects": sc["max_redirects"],
            "cookies":       self.cookies,
            "headers":       self.headers,
            "proxy":         self.proxy,
        }

    def _print_banner(self, target: str):
        auth_status = (
            "[green]Authenticated[/green]"
            if self.cookies or self.headers
            else "[dim]Unauthenticated[/dim]"
        )
        bl_status = "[green]ON[/green]" if self.run_business_logic else "[dim]OFF[/dim]"
        fp_status = "[green]ON[/green]" if self.validate_fp else "[dim]OFF[/dim]"
        nuclei_status = "[green]ON[/green]" if self.run_nuclei else "[dim]OFF[/dim]"

        console.print(Panel.fit(
            f"[bold cyan]BugScanner[/bold cyan] [dim]v2.0[/dim]\n"
            f"[bold]Target:[/bold]         {target}\n"
            f"[bold]Auth:[/bold]           {auth_status}\n"
            f"[bold]Business Logic:[/bold] {bl_status}\n"
            f"[bold]FP Validation:[/bold]  {fp_status}\n"
            f"[bold]Nuclei:[/bold]         {nuclei_status}\n"
            f"[bold]Proxy:[/bold]          {self.proxy or 'none'}\n"
            f"[bold]Time:[/bold]           {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            border_style="cyan"
        ))

    def _print_summary(self, result: ScanResult):
        table = Table(
            title="📊 Scan Summary",
            box=box.ROUNDED,
            border_style="cyan"
        )
        table.add_column("Category", style="bold")
        table.add_column("Count", justify="right")

        table.add_row("Subdomains",     str(len(result.subdomains)))
        table.add_row("Open ports",     str(len(result.open_ports)))
        table.add_row("Endpoints",      str(len(result.endpoints)))
        table.add_row("Vulnerabilities", str(len(result.vulnerabilities)))

        if result.false_positives_filtered:
            table.add_row(
                "[dim]FP filtered[/dim]",
                f"[dim]{result.false_positives_filtered}[/dim]"
            )

        table.add_row("─" * 20, "─" * 5)

        colors = {
            "critical": "bold red",
            "high":     "bold orange3",
            "medium":   "bold yellow",
            "low":      "bold blue",
            "info":     "dim",
        }
        for sev, count in result.vuln_count_by_severity.items():
            if count > 0:
                c = colors.get(sev, "")
                table.add_row(f"  [{c}]{sev.upper()}[/{c}]", f"[{c}]{count}[/{c}]")

        table.add_row("[bold]Risk Score[/bold]", f"[bold]{result.risk_score}/10[/bold]")
        console.print(table)

    async def _apply_waf_evasion(self, http: HttpClient, base_url: str) -> dict:
        """Detect WAF and tune the rate limiter accordingly."""
        console.print("\n[bold cyan]🛡️  WAF Detection...[/bold cyan]")
        detector = WAFDetector(http)
        waf_info = await detector.detect(base_url)

        if waf_info["waf"]:
            evasion = waf_info["evasion"]
            import tldextract
            ext = tldextract.extract(base_url)
            domain = f"{ext.domain}.{ext.suffix}"

            # Use the existing public-ish accessor instead of mutating
            # the private bucket dict directly.
            bucket = self.rate_limiter._get_bucket(domain)
            bucket.rps = max(self.rate_limiter.min_rps, float(evasion["rps"]))

            console.print(
                f"  [yellow]Evasion active:[/yellow] "
                f"RPS→{evasion['rps']}, delay→{evasion['delay']}s"
            )

        return waf_info

    async def scan(
        self,
        target: str,
        modes: list[str] = None,
        port_mode: str = "common",
        skip_subdomains: bool = False,
    ) -> ScanResult:

        if modes is None or "all" in modes:
            modes = ["recon", "vulns"]

        self._print_banner(target)
        result = ScanResult(target=target)
        result.false_positives_filtered = 0

        base_url = target
        if not base_url.startswith(("http://", "https://")):
            base_url = f"https://{target}"

        import tldextract
        ext = tldextract.extract(base_url)
        domain = f"{ext.domain}.{ext.suffix}"

        async with HttpClient(self.rate_limiter, **self.http_config) as http:

            # ── WAF Detection ─────────────────────────────
            await self._apply_waf_evasion(http, base_url)

            # ── RECON ─────────────────────────────────────
            if "recon" in modes:
                console.print(Panel("[bold]RECON PHASE[/bold]", border_style="blue"))

                console.print("\n[bold cyan]🔎 Fingerprinting...[/bold cyan]")
                fp = TechFingerprinter(http)
                techs, header_vulns = await fp.fingerprint(base_url)
                result.technologies = techs
                result.vulnerabilities.extend(header_vulns)

                if not skip_subdomains:
                    sub_scanner = SubdomainScanner(http)
                    result.subdomains = await sub_scanner.scan(domain)

                port_scanner = PortScanner()
                result.open_ports = await port_scanner.scan(domain, mode=port_mode)

                console.print("\n[bold cyan]🗂  Endpoint Discovery...[/bold cyan]")
                disc = DiscoveryScanner(http)
                endpoints, disc_vulns = await disc.scan(base_url)
                result.endpoints = endpoints
                result.vulnerabilities.extend(disc_vulns)

            # ── VULNS ─────────────────────────────────────
            if "vulns" in modes:
                console.print(Panel("[bold]VULNERABILITY SCAN PHASE[/bold]", border_style="red"))

                xss      = XSSScanner(http)
                sqli     = SQLiScanner(http)
                cors     = CORSScanner(http)
                ssrf     = SSRFScanner(http)
                redirect = RedirectScanner(http)
                jwt      = JWTScanner(http)
                idor     = IDORScanner(http)
                disc_sc  = DisclosureScanner(http)

                console.print("\n[bold cyan]📂 Information Disclosure...[/bold cyan]")
                result.vulnerabilities.extend(await disc_sc.scan(base_url))

                console.print("\n[bold cyan]🌐 CORS...[/bold cyan]")
                result.vulnerabilities.extend(await cors.scan(base_url))

                console.print("\n[bold cyan]⚡ XSS...[/bold cyan]")
                result.vulnerabilities.extend(await xss.scan(base_url))

                console.print("\n[bold cyan]💉 SQL Injection...[/bold cyan]")
                result.vulnerabilities.extend(await sqli.scan(base_url))

                console.print("\n[bold cyan]🔄 SSRF...[/bold cyan]")
                result.vulnerabilities.extend(await ssrf.scan(base_url))

                console.print("\n[bold cyan]↪️  Open Redirect...[/bold cyan]")
                result.vulnerabilities.extend(await redirect.scan(base_url))

                console.print("\n[bold cyan]🔑 JWT...[/bold cyan]")
                result.vulnerabilities.extend(await jwt.scan(base_url))

                console.print("\n[bold cyan]🆔 IDOR...[/bold cyan]")
                result.vulnerabilities.extend(await idor.scan(base_url))

                # Discovered endpoints
                if result.endpoints:
                    console.print("\n[bold cyan]🔁 Endpoint scan...[/bold cyan]")
                    for ep_url in result.endpoints[:15]:
                        ep_results = await asyncio.gather(
                            xss.scan(ep_url),
                            sqli.scan(ep_url),
                            cors.scan(ep_url),
                            idor.scan(ep_url),
                            return_exceptions=True,
                        )
                        for r in ep_results:
                            if isinstance(r, list):
                                result.vulnerabilities.extend(r)

                # Live subdomain vuln scan
                live_subs = [s for s in result.subdomains if s.status and s.status < 400]
                if live_subs:
                    console.print("\n[bold cyan]🌐 Subdomain vuln scan...[/bold cyan]")
                    for sub in live_subs[:10]:
                        sub_url = f"https://{sub.subdomain}"
                        sub_results = await asyncio.gather(
                            cors.scan(sub_url),
                            disc_sc.scan(sub_url),
                            return_exceptions=True,
                        )
                        for r in sub_results:
                            if isinstance(r, list):
                                sub.vulnerabilities.extend(r)
                                result.vulnerabilities.extend(r)

                # Business Logic
                if self.run_business_logic:
                    console.print("\n[bold cyan]🧠 Business Logic...[/bold cyan]")
                    bl = BusinessLogicScanner(http)
                    result.vulnerabilities.extend(await bl.scan(base_url))

                # Nuclei
                if self.run_nuclei:
                    console.print("\n[bold cyan]☢️  Nuclei...[/bold cyan]")
                    nuclei = NucleiWrapper()
                    result.vulnerabilities.extend(await nuclei.scan(base_url))

                # False-Positive Validation
                if self.validate_fp and result.vulnerabilities:
                    validator = FalsePositiveValidator(http)
                    confirmed, filtered = await validator.validate_all(result.vulnerabilities)
                    result.vulnerabilities = confirmed
                    result.false_positives_filtered = len(filtered)

        result.end_time = datetime.now()
        console.print()
        self._print_summary(result)
        return result