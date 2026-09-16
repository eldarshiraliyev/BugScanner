"""
Main Scanner Orchestrator — v2.1
WAF Detection + FP Filter + Active Validation + Business Logic + Auth + Cache
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
from core.fp_filter import FPFilter
from core.logger import get_logger

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
log = get_logger("scanner")

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
        enable_cache: bool = True,
    ):
        self.config = config or load_config()
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.proxy = proxy
        self.validate_fp = validate_fp
        self.run_business_logic = run_business_logic
        self.run_nuclei = (
            run_nuclei
            and self.config.get("nuclei", {}).get("enabled", True)
        )
        self.enable_cache = enable_cache

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
            "enable_cache":  self.enable_cache,
        }
        self._http_client: HttpClient | None = None

    # ══════════════════════════════════════════════════════════
    #  Banner
    # ══════════════════════════════════════════════════════════
    def _print_banner(self, target: str):
        auth_status = (
            "[green]Authenticated[/green]"
            if self.cookies or self.headers
            else "[dim]Unauthenticated[/dim]"
        )
        bl_status = (
            "[green]ON[/green]"
            if self.run_business_logic
            else "[dim]OFF[/dim]"
        )
        fp_status = (
            "[green]ON[/green]" if self.validate_fp else "[dim]OFF[/dim]"
        )
        nuclei_status = (
            "[green]ON[/green]" if self.run_nuclei else "[dim]OFF[/dim]"
        )
        cache_status = (
            "[green]ON[/green]" if self.enable_cache else "[dim]OFF[/dim]"
        )

        console.print(Panel.fit(
            f"[bold cyan]BugScanner[/bold cyan] [dim]v2.1[/dim]\n"
            f"[bold]Target:[/bold]         {target}\n"
            f"[bold]Auth:[/bold]           {auth_status}\n"
            f"[bold]Business Logic:[/bold] {bl_status}\n"
            f"[bold]FP Validation:[/bold]  {fp_status}\n"
            f"[bold]Nuclei:[/bold]         {nuclei_status}\n"
            f"[bold]Cache:[/bold]          {cache_status}\n"
            f"[bold]Proxy:[/bold]          {self.proxy or 'none'}\n"
            f"[bold]Time:[/bold]           "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            border_style="cyan",
        ))
        log.info(
            "scan_started",
            target=target,
            proxy=self.proxy,
            authenticated=bool(self.cookies or self.headers),
        )

    # ══════════════════════════════════════════════════════════
    #  Summary table — includes FP stats
    # ══════════════════════════════════════════════════════════
    def _print_summary(self, result: ScanResult):
        table = Table(
            title="📊 Scan Summary",
            box=box.ROUNDED,
            border_style="cyan",
        )
        table.add_column("Category", style="bold")
        table.add_column("Count", justify="right")

        table.add_row("Subdomains",     str(len(result.subdomains)))
        table.add_row("Open ports",     str(len(result.open_ports)))
        table.add_row("Endpoints",      str(len(result.endpoints)))
        table.add_row("Vulnerabilities", str(len(result.vulnerabilities)))

        # ── FP stats breakdown ──
        if result.false_positives_filtered:
            table.add_row(
                "[dim]FP filtered[/dim]",
                f"[dim]{result.false_positives_filtered}[/dim]",
            )
            fp_stats = getattr(result, "fp_stats", {}) or {}
            if fp_stats.get("filtered_spa"):
                table.add_row(
                    "[dim]  ↳ SPA-based[/dim]",
                    f"[dim]{fp_stats['filtered_spa']}[/dim]",
                )
            if fp_stats.get("filtered_no_signature"):
                table.add_row(
                    "[dim]  ↳ No signature[/dim]",
                    f"[dim]{fp_stats['filtered_no_signature']}[/dim]",
                )
            if fp_stats.get("filtered_no_admin_dom"):
                table.add_row(
                    "[dim]  ↳ No admin DOM[/dim]",
                    f"[dim]{fp_stats['filtered_no_admin_dom']}[/dim]",
                )
            if fp_stats.get("filtered_unverified"):
                table.add_row(
                    "[dim]  ↳ No PoC[/dim]",
                    f"[dim]{fp_stats['filtered_unverified']}[/dim]",
                )
            if fp_stats.get("downgraded"):
                table.add_row(
                    "[dim]  ↳ Downgraded[/dim]",
                    f"[dim]{fp_stats['downgraded']}[/dim]",
                )

        # ── Cache stats ──
        if self._http_client:
            stats = self._http_client.cache_stats()
            table.add_row(
                "[dim]Cache hits[/dim]",
                f"[dim]{stats['hits']} ({stats['hit_rate'] * 100:.1f}%)[/dim]",
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
                table.add_row(
                    f"  [{c}]{sev.upper()}[/{c}]",
                    f"[{c}]{count}[/{c}]",
                )

        table.add_row(
            "[bold]Risk Score[/bold]",
            f"[bold]{result.risk_score}/10[/bold]",
        )
        console.print(table)

    # ══════════════════════════════════════════════════════════
    #  WAF evasion
    # ══════════════════════════════════════════════════════════
    async def _apply_waf_evasion(
        self, http: HttpClient, base_url: str
    ) -> dict:
        console.print("\n[bold cyan]🛡️  WAF Detection...[/bold cyan]")
        detector = WAFDetector(http)
        waf_info = await detector.detect(base_url)

        if waf_info["waf"]:
            evasion = waf_info["evasion"]
            import tldextract
            ext = tldextract.extract(base_url)
            domain = f"{ext.domain}.{ext.suffix}"

            self.rate_limiter.set_domain_rps(
                domain, float(evasion["rps"])
            )
            self.rate_limiter.set_domain_delay(
                domain, float(evasion["delay"])
            )

            console.print(
                f"  [yellow]Evasion active:[/yellow] "
                f"RPS→{evasion['rps']}, delay→{evasion['delay']}s"
            )
            log.warning(
                "waf_evasion_applied",
                waf=waf_info["waf"],
                rps=evasion["rps"],
                delay=evasion["delay"],
            )

        return waf_info

    # ══════════════════════════════════════════════════════════
    #  Main scan
    # ══════════════════════════════════════════════════════════
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

        base_url = target
        if not base_url.startswith(("http://", "https://")):
            base_url = f"https://{target}"

        import tldextract
        ext = tldextract.extract(base_url)
        domain = f"{ext.domain}.{ext.suffix}"

        async with HttpClient(self.rate_limiter, **self.http_config) as http:
            self._http_client = http

            # ── WAF Detection ──
            await self._apply_waf_evasion(http, base_url)

            # ══════════════════════════════════════════════════
            #  RECON
            # ══════════════════════════════════════════════════
            if "recon" in modes:
                console.print(
                    Panel("[bold]RECON PHASE[/bold]", border_style="blue")
                )

                console.print("\n[bold cyan]🔎 Fingerprinting...[/bold cyan]")
                fp = TechFingerprinter(http)
                techs, header_vulns = await fp.fingerprint(base_url)
                result.technologies = techs
                result.vulnerabilities.extend(header_vulns)

                if not skip_subdomains:
                    sub_scanner = SubdomainScanner(http)
                    result.subdomains = await sub_scanner.scan(domain)

                port_scanner = PortScanner()
                result.open_ports = await port_scanner.scan(
                    domain, mode=port_mode
                )

                console.print(
                    "\n[bold cyan]🗂  Endpoint Discovery...[/bold cyan]"
                )
                disc = DiscoveryScanner(http)
                endpoints, disc_vulns = await disc.scan(base_url)
                result.endpoints = endpoints
                result.vulnerabilities.extend(disc_vulns)

            # ══════════════════════════════════════════════════
            #  VULNS
            # ══════════════════════════════════════════════════
            if "vulns" in modes:
                console.print(
                    Panel(
                        "[bold]VULNERABILITY SCAN PHASE[/bold]",
                        border_style="red",
                    )
                )

                xss      = XSSScanner(http)
                sqli     = SQLiScanner(http)
                cors     = CORSScanner(http)
                ssrf     = SSRFScanner(http)
                redirect = RedirectScanner(http)
                jwt      = JWTScanner(http)
                idor     = IDORScanner(http)
                disc_sc  = DisclosureScanner(http)

                console.print(
                    "\n[bold cyan]📂 Information Disclosure...[/bold cyan]"
                )
                result.vulnerabilities.extend(await disc_sc.scan(base_url))

                console.print("\n[bold cyan]🌐 CORS...[/bold cyan]")
                result.vulnerabilities.extend(await cors.scan(base_url))

                console.print("\n[bold cyan]⚡ XSS...[/bold cyan]")
                result.vulnerabilities.extend(await xss.scan(base_url))

                console.print(
                    "\n[bold cyan]💉 SQL Injection...[/bold cyan]"
                )
                result.vulnerabilities.extend(await sqli.scan(base_url))

                console.print("\n[bold cyan]🔄 SSRF...[/bold cyan]")
                result.vulnerabilities.extend(await ssrf.scan(base_url))

                console.print(
                    "\n[bold cyan]↪️  Open Redirect...[/bold cyan]"
                )
                result.vulnerabilities.extend(
                    await redirect.scan(base_url)
                )

                console.print("\n[bold cyan]🔑 JWT...[/bold cyan]")
                result.vulnerabilities.extend(await jwt.scan(base_url))

                console.print("\n[bold cyan]🆔 IDOR...[/bold cyan]")
                result.vulnerabilities.extend(await idor.scan(base_url))

                # Discovered endpoints
                if result.endpoints:
                    console.print(
                        "\n[bold cyan]🔁 Endpoint scan...[/bold cyan]"
                    )
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

                # Live subdomains
                live_subs = [
                    s for s in result.subdomains
                    if s.status and s.status < 400
                ]
                if live_subs:
                    console.print(
                        "\n[bold cyan]🌐 Subdomain vuln scan...[/bold cyan]"
                    )
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
                    console.print(
                        "\n[bold cyan]🧠 Business Logic...[/bold cyan]"
                    )
                    bl = BusinessLogicScanner(http)
                    result.vulnerabilities.extend(
                        await bl.scan(base_url)
                    )

                # Nuclei
                if self.run_nuclei:
                    console.print("\n[bold cyan]☢️  Nuclei...[/bold cyan]")
                    nuclei = NucleiWrapper(self.config)
                    result.vulnerabilities.extend(
                        await nuclei.scan(base_url)
                    )

                # ══════════════════════════════════════════════
                #  FALSE-POSITIVE FILTERING (2 stages)
                # ══════════════════════════════════════════════
                if self.validate_fp and result.vulnerabilities:
                    # ── Stage 1: Static FP filter (signatures, SPA, DOM, context)
                    console.print(
                        "\n[bold cyan]🔎 False-positive filter "
                        "(signatures + SPA)...[/bold cyan]"
                    )
                    fp_filter = FPFilter(http)
                    kept, dropped = await fp_filter.filter_all(
                        result.vulnerabilities, base_url
                    )
                    result.vulnerabilities = kept
                    fp_stats = fp_filter.summary()
                    result.fp_stats = fp_stats

                    console.print(
                        f"  [green]✓ Kept: {len(kept)}[/green]  "
                        f"[dim]FP filtered: {dropped}[/dim]"
                    )

                    # ── Stage 2: Active validation (re-request confirmation)
                    if kept:
                        console.print(
                            "\n[bold cyan]🔬 Active verification...[/bold cyan]"
                        )
                        validator = FalsePositiveValidator(http)
                        confirmed, filtered2 = await validator.validate_all(
                            kept
                        )
                        result.vulnerabilities = confirmed
                        result.false_positives_filtered = (
                            dropped + len(filtered2)
                        )
                    else:
                        result.false_positives_filtered = dropped

        # ══════════════════════════════════════════════════════
        #  Finish
        # ══════════════════════════════════════════════════════
        result.end_time = datetime.now()
        console.print()
        self._print_summary(result)

        log.info(
            "scan_completed",
            target=target,
            duration_s=round(
                (result.end_time - result.start_time).total_seconds(), 1
            ),
            vulns=len(result.vulnerabilities),
            risk_score=result.risk_score,
            cache=(
                self._http_client.cache_stats()
                if self._http_client else {}
            ),
            fp_stats=result.fp_stats,
        )

        return result