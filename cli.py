#!/usr/bin/env python3
"""
BugScanner CLI v2.0
"""

import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console

sys.path.insert(0, str(Path(__file__).parent))

from core.scanner import BugScanner
from core.reporter import Reporter

console = Console()


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
[dim]  Bug Bounty Automation Tool v2.0 — Authorized use only[/dim]
""")


def parse_cookies(cookie_list: tuple) -> dict:
    """'name=value' formatından dict yarat"""
    result = {}
    for c in cookie_list:
        c = c.strip()
        if '=' in c:
            k, v = c.split('=', 1)
            result[k.strip()] = v.strip()
        else:
            console.print(
                f"[yellow]⚠️  Cookie parse xətası:[/yellow] '{c}' "
                f"— 'name=value' formatında olmalıdır"
            )
    return result


def parse_headers(header_list: tuple) -> dict:
    """'Name: Value' formatından dict yarat"""
    result = {}
    for h in header_list:
        h = h.strip()
        if ':' in h:
            k, v = h.split(':', 1)
            result[k.strip()] = v.strip()
        else:
            console.print(
                f"[yellow]⚠️  Header parse xətası:[/yellow] '{h}' "
                f"— 'Name: Value' formatında olmalıdır"
            )
    return result


@click.group()
def cli():
    """BugScanner v2.0 — Bug Bounty Automation Tool"""
    pass


@cli.command()
@click.argument("url")
@click.option(
    "--mode", "-m",
    type=click.Choice(["all", "recon", "vulns"]),
    default="all",
    help="Scan modu (default: all)",
    show_default=True,
)
@click.option(
    "--ports", "-p",
    type=click.Choice(["common", "extended", "full"]),
    default="common",
    help="Port scan dərinliyi (default: common)",
    show_default=True,
)
@click.option(
    "--no-subdomains",
    is_flag=True,
    default=False,
    help="Subdomain scan-ı atla",
)
@click.option(
    "--output", "-o",
    default="./reports",
    help="Report qovluğu (default: ./reports)",
    show_default=True,
)
@click.option(
    "--format", "-f",
    type=click.Choice(["all", "json", "html"]),
    default="all",
    help="Output format (default: all)",
    show_default=True,
)
@click.option(
    "--rps",
    type=float,
    default=10.0,
    help="Saniyədə max request (default: 10)",
    show_default=True,
)
@click.option(
    "--cookie", "-c",
    multiple=True,
    help='Cookie — "name=value" (bir neçə dəfə istifadə et)',
)
@click.option(
    "--header", "-H",
    multiple=True,
    help='Custom header — "Name: Value"',
)
@click.option(
    "--proxy",
    default=None,
    help="Proxy URL — http://127.0.0.1:8080 (Burp Suite)",
)
@click.option(
    "--business-logic",
    is_flag=True,
    default=False,
    help="Business logic scan (authenticated scan üçün tövsiyə edilir)",
)
@click.option(
    "--no-fp-validation",
    is_flag=True,
    default=False,
    help="False-positive validation-ı söndür (sürətli scan üçün)",
)
@click.option(
    "--no-nuclei",
    is_flag=True,
    default=False,
    help="Nuclei scan-ı atla",
)
def scan(
    url, mode, ports, no_subdomains, output, format,
    rps, cookie, header, proxy,
    business_logic, no_fp_validation, no_nuclei,
):
    """
    Hədəf URL-i skan et.

    \b
    Nümunələr:
      # Sadə scan
      python cli.py scan https://target.com

      # Authenticated scan
      python cli.py scan https://target.com \\
        --cookie "session=abc123" \\
        --cookie "csrf=xyz789"

      # Bearer token ilə
      python cli.py scan https://target.com \\
        --header "Authorization: Bearer eyJ..."

      # Burp Suite proxy + business logic
      python cli.py scan https://target.com \\
        --cookie "session=abc123" \\
        --proxy http://127.0.0.1:8080 \\
        --business-logic

      # Sürətli scan — FP validation söndür
      python cli.py scan https://target.com \\
        --no-subdomains \\
        --no-fp-validation \\
        --rps 20

      # WAF olan hədəf — yavaş, ehtiyatlı
      python cli.py scan https://target.com \\
        --rps 3 \\
        --no-subdomains \\
        --ports common
    """
    print_banner()

    # Cookie + Header parse
    parsed_cookies = parse_cookies(cookie)
    parsed_headers = parse_headers(header)

    if parsed_cookies:
        console.print(
            f"[green]🍪 Cookie:[/green] "
            f"{', '.join(parsed_cookies.keys())}"
        )
    if parsed_headers:
        console.print(
            f"[green]📋 Headers:[/green] "
            f"{', '.join(parsed_headers.keys())}"
        )
    if proxy:
        console.print(f"[green]🔀 Proxy:[/green] {proxy}")
    if business_logic:
        console.print("[green]🧠 Business Logic:[/green] aktiv")

    # Config tənzimlə
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
        else:
            await reporter.save_all(result)

        # Xülasə çap et
        console.print(
            f"\n[bold green]✅ Scan tamamlandı![/bold green] "
            f"Reports: {output}/"
        )

        return result

    asyncio.run(run())


@cli.command()
@click.argument("url")
@click.option(
    "--ports", "-p",
    type=click.Choice(["common", "extended", "full"]),
    default="common",
)
@click.option("--no-subdomains", is_flag=True)
@click.option("--output", "-o", default="./reports")
def recon(url, ports, no_subdomains, output):
    """
    Yalnız recon — subdomain + port + fingerprint + discovery.

    \b
    Nümunə:
      python cli.py recon https://target.com --ports extended
    """
    print_banner()

    async def run():
        scanner = BugScanner()
        result = await scanner.scan(
            target=url,
            modes=["recon"],
            port_mode=ports,
            skip_subdomains=no_subdomains,
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
    """
    Yalnız vulnerability scan — recon-suz.

    \b
    Nümunə:
      python cli.py vulnscan https://target.com \\
        --cookie "session=abc123"
    """
    print_banner()

    parsed_cookies = parse_cookies(cookie)
    parsed_headers = parse_headers(header)

    async def run():
        scanner = BugScanner(
            cookies=parsed_cookies,
            headers=parsed_headers,
            proxy=proxy,
            validate_fp=not no_fp_validation,
        )
        result = await scanner.scan(
            target=url,
            modes=["vulns"],
            skip_subdomains=True,
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
    """
    Yalnız business logic scan — authenticated.

    \b
    Nümunə:
      python cli.py bizlogic https://target.com \\
        --cookie "session=abc123" \\
        --proxy http://127.0.0.1:8080
    """
    print_banner()

    parsed_cookies = parse_cookies(cookie)
    parsed_headers = parse_headers(header)

    if not parsed_cookies and not parsed_headers:
        console.print(
            "[yellow]⚠️  Xəbərdarlıq:[/yellow] "
            "Business logic scan authenticated olmadan "
            "məhdud nəticə verir. --cookie ilə istifadə et."
        )

    async def run():
        scanner = BugScanner(
            cookies=parsed_cookies,
            headers=parsed_headers,
            proxy=proxy,
            run_business_logic=True,
            validate_fp=True,
        )
        result = await scanner.scan(
            target=url,
            modes=["vulns"],
            skip_subdomains=True,
        )
        reporter = Reporter(output_dir=output)
        await reporter.save_all(result)

    asyncio.run(run())


@cli.command()
def version():
    """Versiya məlumatı"""
    console.print("[bold cyan]BugScanner[/bold cyan] v2.0")
    console.print("[dim]Bug Bounty Automation Tool[/dim]")
    console.print("[dim]Authorized use only[/dim]")


if __name__ == "__main__":
    cli()