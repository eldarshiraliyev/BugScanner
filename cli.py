#!/usr/bin/env python3
"""
BugScanner CLI v2.1
"""

import asyncio
import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich import box

sys.path.insert(0, str(Path(__file__).parent))

from core.scanner import BugScanner
from core.reporter import Reporter
from core.logger import get_logger
from core.models import ScanResult, Vulnerability, Severity, SubdomainInfo, PortInfo
from core.differ import diff_scans

console = Console()
log = get_logger("cli")


def print_banner():
    console.print("""
[bold cyan]
  ██████╗ ██╗   ██╗ ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔══██╗██║   ██║██╔════╝ ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██████╔╝██║   ██║██║  ███╗███████╗██║     ███████║██╔██╗ ██║
  ██╔══██╗██║   ██║██║   ██║╚════██║██║     ██╔══██║██║╚██╗██║
  ██████╔╝╚██████╔╝╚██████╔╝███████║╚██████╗██║  ██║██║ ╚████║
  ╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
[/bold cyan]
[dim]  Bug Bounty Automation Tool v2.1 — Authorized use only[/dim]
""")


def parse_cookies(cookie_list: tuple) -> dict:
    result = {}
    for c in cookie_list:
        c = c.strip()
        if '=' in c:
            k, v = c.split('=', 1)
            result[k.strip()] = v.strip()
        else:
            console.print(
                f"[yellow]⚠️  Cookie parse error:[/yellow] '{c}' "
                f"— expected format 'name=value'"
            )
    return result


def parse_headers(header_list: tuple) -> dict:
    result = {}
    for h in header_list:
        h = h.strip()
        if ':' in h:
            k, v = h.split(':', 1)
            result[k.strip()] = v.strip()
        else:
            console.print(
                f"[yellow]⚠️  Header parse error:[/yellow] '{h}' "
                f"— expected format 'Name: Value'"
            )
    return result


def _load_result_from_json(path: str) -> ScanResult:
    """Rehydrate a ScanResult from a JSON file (for diff command)."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    from datetime import datetime
    def _dt(s):
        return datetime.fromisoformat(s) if s else None

    result = ScanResult(target=data["target"])
    result.start_time = _dt(data.get("start_time"))
    result.end_time = _dt(data.get("end_time"))
    result.technologies = data.get("technologies", [])
    result.false_positives_filtered = data.get("summary", {}).get(
        "false_positives_filtered", 0
    )

    result.subdomains = [
        SubdomainInfo(
            subdomain=s["subdomain"],
            ip=s.get("ip"),
            status=s.get("status"),
            technologies=s.get("technologies", []),
        )
        for s in data.get("subdomains", [])
    ]

    result.open_ports = [
        PortInfo(
            port=p["port"],
            protocol=p["protocol"],
            state=p["state"],
            service=p["service"],
            version=p.get("version"),
        )
        for p in data.get("open_ports", [])
    ]

    # endpoints don't have a top-level list in to_dict(); reconstruct from vulns
    result.endpoints = []

    result.vulnerabilities = [
        Vulnerability(
            vuln_type=v["vuln_type"],
            url=v["url"],
            severity=Severity(v["severity"]),
            cvss_score=v["cvss_score"],
            title=v["title"],
            description=v["description"],
            evidence=v["evidence"],
            exploitation=v["exploitation"],
            remediation=v["remediation"],
            parameter=v.get("parameter"),
            method=v.get("method", "GET"),
            payload_used=v.get("payload_used"),
            curl_poc=v.get("curl_poc"),
            cwe_id=v.get("cwe_id"),
            references=v.get("references", []),
        )
        for v in data.get("vulnerabilities", [])
    ]
    return result


@click.group()
def cli():
    """BugScanner v2.1 — Bug Bounty Automation Tool"""
    pass


@cli.command()
@click.argument("url")
@click.option("--mode", "-m", type=click.Choice(["all", "recon", "vulns"]),
              default="all", help="Scan mode (default: all)", show_default=True)
@click.option("--ports", "-p", type=click.Choice(["common", "extended", "full"]),
              default="common", help="Port scan depth (default: common)", show_default=True)
@click.option("--no-subdomains", is_flag=True, default=False,
              help="Skip subdomain enumeration")
@click.option("--output", "-o", default="./reports",
              help="Report directory (default: ./reports)", show_default=True)
@click.option("--format", "-f", type=click.Choice(["all", "json", "html", "sarif"]),
              default="all", help="Output format (default: all)", show_default=True)
@click.option("--rps", type=float, default=10.0,
              help="Max requests per second (default: 10)", show_default=True)
@click.option("--cookie", "-c", multiple=True,
              help='Cookie — "name=value" (repeatable)')
@click.option("--header", "-H", multiple=True,
              help='Custom header — "Name: Value" (repeatable)')
@click.option("--proxy", default=None,
              help="Proxy URL — http://127.0.0.1:8080 (Burp Suite)")
@click.option("--business-logic", is_flag=True, default=False,
              help="Enable business logic scan")
@click.option("--no-fp-validation", is_flag=True, default=False,
              help="Disable false-positive validation")
@click.option("--no-nuclei", is_flag=True, default=False,
              help="Skip Nuclei scan")
@click.option("--no-cache", is_flag=True, default=False,
              help="Disable HTTP request cache")
def scan(url, mode, ports, no_subdomains, output, format,
         rps, cookie, header, proxy, business_logic,
         no_fp_validation, no_nuclei, no_cache):
    """
    Scan a target URL.

    \b
    Examples:
      python cli.py scan https://target.com
      python cli.py scan https://target.com --cookie "session=abc123"
      python cli.py scan https://target.com --proxy http://127.0.0.1:8080
    """
    print_banner()

    parsed_cookies = parse_cookies(cookie)
    parsed_headers = parse_headers(header)

    if parsed_cookies:
        console.print(f"[green]🍪 Cookies:[/green] {', '.join(parsed_cookies.keys())}")
    if parsed_headers:
        console.print(f"[green]📋 Headers:[/green] {', '.join(parsed_headers.keys())}")
    if proxy:
        console.print(f"[green]🔀 Proxy:[/green] {proxy}")
    if business_logic:
        console.print("[green]🧠 Business Logic:[/green] enabled")

    config = None
    if rps != 10.0:
        from core.scanner import load_config
        config = load_config()
        config["rate_limiting"]["default_rps"] = rps

    async def run():
        scanner = BugScanner(
            config=config,
            cookies=parsed_cookies,
            headers=parsed_headers,
            proxy=proxy,
            validate_fp=not no_fp_validation,
            run_business_logic=business_logic,
            run_nuclei=not no_nuclei,
            enable_cache=not no_cache,
        )
        result = await scanner.scan(
            target=url,
            modes=[mode],
            port_mode=ports,
            skip_subdomains=no_subdomains,
        )

        reporter = Reporter(output_dir=output)
        if format == "json":
            await reporter.save_json(result)
        elif format == "html":
            await reporter.save_html(result)
        elif format == "sarif":
            await reporter.save_sarif(result)
        else:
            await reporter.save_all(result)

        console.print(f"\n[bold green]✅ Scan completed![/bold green] Reports: {output}/")
        return result

    asyncio.run(run())


@cli.command()
@click.argument("url")
@click.option("--ports", "-p", type=click.Choice(["common", "extended", "full"]),
              default="common")
@click.option("--no-subdomains", is_flag=True)
@click.option("--output", "-o", default="./reports")
def recon(url, ports, no_subdomains, output):
    """Recon only — subdomains + ports + fingerprint + discovery."""
    print_banner()

    async def run():
        scanner = BugScanner()
        result = await scanner.scan(
            target=url, modes=["recon"],
            port_mode=ports, skip_subdomains=no_subdomains,
        )
        reporter = Reporter(output_dir=output)
        await reporter.save_all(result)

    asyncio.run(run())


@cli.command()
@click.argument("url")
@click.option("--cookie", "-c", multiple=True)
@click.option("--header", "-H", multiple=True)
@click.option("--proxy", default=None)
@click.option("--output", "-o", default="./reports")
@click.option("--no-fp-validation", is_flag=True, default=False)
def vulnscan(url, cookie, header, proxy, output, no_fp_validation):
    """Vulnerability scan only — no recon."""
    print_banner()

    parsed_cookies = parse_cookies(cookie)
    parsed_headers = parse_headers(header)

    async def run():
        scanner = BugScanner(
            cookies=parsed_cookies, headers=parsed_headers,
            proxy=proxy, validate_fp=not no_fp_validation,
        )
        result = await scanner.scan(
            target=url, modes=["vulns"], skip_subdomains=True,
        )
        reporter = Reporter(output_dir=output)
        await reporter.save_all(result)

    asyncio.run(run())


@cli.command()
@click.argument("url")
@click.option("--cookie", "-c", multiple=True)
@click.option("--header", "-H", multiple=True)
@click.option("--proxy", default=None)
@click.option("--output", "-o", default="./reports")
def bizlogic(url, cookie, header, proxy, output):
    """Business logic scan only — authenticated."""
    print_banner()

    parsed_cookies = parse_cookies(cookie)
    parsed_headers = parse_headers(header)

    if not parsed_cookies and not parsed_headers:
        console.print(
            "[yellow]⚠️  Warning:[/yellow] Business logic scan produces limited "
            "results without authentication. Use --cookie to authenticate."
        )

    async def run():
        scanner = BugScanner(
            cookies=parsed_cookies, headers=parsed_headers,
            proxy=proxy, run_business_logic=True, validate_fp=True,
        )
        result = await scanner.scan(
            target=url, modes=["vulns"], skip_subdomains=True,
        )
        reporter = Reporter(output_dir=output)
        await reporter.save_all(result)

    asyncio.run(run())


# ══════════════════════════════════════════════════════════════
#  NEW: diff command
# ══════════════════════════════════════════════════════════════
@cli.command()
@click.argument("old_json", type=click.Path(exists=True))
@click.argument("new_json", type=click.Path(exists=True))
@click.option("--output", "-o", default="./reports",
              help="Where to save diff report", show_default=True)
def diff(old_json, new_json, output):
    """
    Compare two JSON reports and show what changed.

    \b
    Example:
      python cli.py diff reports/old.json reports/new.json
    """
    print_banner()

    console.print(f"[cyan]Loading[/cyan] {old_json}")
    old = _load_result_from_json(old_json)
    console.print(f"[cyan]Loading[/cyan] {new_json}")
    new = _load_result_from_json(new_json)

    result = diff_scans(old, new)

    # ── Print summary table ──
    table = Table(title="🔍 Scan Diff", box=box.ROUNDED, border_style="cyan")
    table.add_column("Category", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Δ", justify="center")

    table.add_row("New vulnerabilities", str(len(result.new_vulnerabilities)),
                  "🟢" if result.new_vulnerabilities else "—")
    table.add_row("Fixed vulnerabilities", str(len(result.fixed_vulnerabilities)),
                  "🔵" if result.fixed_vulnerabilities else "—")
    table.add_row("Unchanged", str(len(result.unchanged_vulnerabilities)), "·")
    table.add_row("", "", "")
    table.add_row("New subdomains", str(len(result.new_subdomains)),
                  "🟢" if result.new_subdomains else "—")
    table.add_row("Removed subdomains", str(len(result.removed_subdomains)),
                  "🔴" if result.removed_subdomains else "—")
    table.add_row("New ports", str(len(result.new_ports)),
                  "🟢" if result.new_ports else "—")
    table.add_row("Closed ports", str(len(result.closed_ports)),
                  "🔵" if result.closed_ports else "—")
    table.add_row("New endpoints", str(len(result.new_endpoints)),
                  "🟢" if result.new_endpoints else "—")
    table.add_row("Removed endpoints", str(len(result.removed_endpoints)),
                  "🔴" if result.removed_endpoints else "—")

    console.print(table)

    # ── Print new vulnerabilities ──
    if result.new_vulnerabilities:
        console.print("\n[bold red]🆕 New Vulnerabilities:[/bold red]")
        for v in result.new_vulnerabilities:
            console.print(f"  {v.severity.emoji} [{v.severity.value.upper()}] "
                          f"{v.title} — {v.url}")

    if result.fixed_vulnerabilities:
        console.print("\n[bold green]✅ Fixed Vulnerabilities:[/bold green]")
        for v in result.fixed_vulnerabilities:
            console.print(f"  {v.severity.emoji} {v.title} — {v.url}")

    # ── Save diff JSON ──
    out_path = Path(output)
    out_path.mkdir(parents=True, exist_ok=True)
    from datetime import datetime
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    diff_file = out_path / f"diff_{ts}.json"
    diff_file.write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    console.print(f"\n[green]💾 Diff report:[/green] {diff_file}")


@cli.command()
def version():
    """Show version information."""
    console.print("[bold cyan]BugScanner[/bold cyan] v2.1")
    console.print("[dim]Bug Bounty Automation Tool[/dim]")
    console.print("[dim]Authorized use only[/dim]")


if __name__ == "__main__":
    cli()