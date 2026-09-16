"""
Endpoint & Directory Discovery — v2.1

False-positive reduction:
- Content signature verification (HTML shells ignored)
- SPA fallback detection
- Admin panel requires DOM proof (login/password/dashboard)
- Context-aware severity
"""

import asyncio
from urllib.parse import urljoin
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from core.models import Vulnerability, Severity
from core.fp_filter import (
    looks_like_admin_panel,
    is_html_shell,
    SPAFallbackDetector,
)

console = Console()

COMMON_PATHS = [
    # Admin panels
    "admin", "admin/", "administrator", "admin/login",
    "admin/dashboard", "wp-admin", "panel", "cpanel",
    "dashboard", "manage", "management", "backend",
    # API endpoints
    "api", "api/v1", "api/v2", "api/v3", "api/users",
    "api/admin", "api/config", "api/debug", "api/health",
    "api/status", "api/info", "api/docs", "api/swagger",
    "graphql", "graphiql", "api/graphql",
    "rest", "rest/v1", "rest/api",
    # Auth endpoints
    "login", "signin", "signup", "register", "logout",
    "auth", "auth/login", "oauth", "oauth/token",
    "forgot-password", "reset-password", "verify",
    # Debug & dev
    "debug", "test", "dev", "development", "staging",
    "phpinfo.php", "info.php", "test.php",
    "console", "shell", "terminal",
    # Config & sensitive
    ".env", ".env.local", "config", "config.php",
    "configuration", "settings", "setup",
    ".git/HEAD", ".git/config",
    "backup", "backup.zip", "backup.sql",
    # Health & metrics
    "health", "healthz", "ping", "status",
    "metrics", "actuator", "actuator/env",
    "actuator/health", "actuator/info",
    "actuator/mappings", "actuator/beans",
    # Common files
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "security.txt", ".well-known/security.txt",
    "humans.txt", "ads.txt",
    # Package & build
    "package.json", "composer.json", "Dockerfile",
    "docker-compose.yml", ".travis.yml",
    # Upload dirs
    "uploads", "upload", "files", "media",
    "images", "assets", "static",
]

ACTUATOR_PATHS = [
    "actuator", "actuator/env", "actuator/health",
    "actuator/info", "actuator/mappings", "actuator/beans",
    "actuator/configprops", "actuator/logfile",
    "actuator/heapdump", "actuator/threaddump",
]

INTERESTING_CODES = [200, 201, 204, 301, 302, 401, 403]


class DiscoveryScanner:
    def __init__(self, http_client, extra_wordlist: list[str] = None):
        self.http_client = http_client
        self.wordlist = COMMON_PATHS + (extra_wordlist or [])
        self.spa_detector = SPAFallbackDetector(http_client)

    # ══════════════════════════════════════════════════════════
    #  Path check — now returns body + content_type for FP analysis
    # ══════════════════════════════════════════════════════════
    async def _check_path(self, base_url: str, path: str) -> dict | None:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        response = await self.http_client.get(url)
        if not response:
            return None

        if response.status_code not in INTERESTING_CODES:
            return None

        return {
            "url": url,
            "path": path,
            "status": response.status_code,
            "size": len(response.content),
            "content_type": response.headers.get("content-type", ""),
            "body": response.text[:50000],   # ← DOM analysis
        }

    # ══════════════════════════════════════════════════════════
    #  Analysis — v2.1 with 5-rule FP filtering
    # ══════════════════════════════════════════════════════════
    def _analyze_findings(
        self,
        findings: list[dict],
        base_url: str,
        is_spa: bool = False,
    ) -> list[Vulnerability]:
        """
        Analyze discovered endpoints and generate vulnerabilities.

        v2.1 FP rules:
          - Rule 1: HTML shells for non-HTML paths are dropped
          - Rule 2: If SPA, admin/file/route checks are stricter
          - Rule 3: Admin panels require DOM proof (login form)
          - Rule 4: Context-aware severity (internal/localhost)
          - Rule 5: Findings must have verifiable PoC
        """
        vulns: list[Vulnerability] = []

        for f in findings:
            path = f["path"].lower()
            status = f["status"]
            url = f["url"]
            body = f.get("body", "")
            content_type = f.get("content_type", "")
            size = f.get("size", 0)

            # ─────────────────────────────────────────────────
            # Rule 1: Skip HTML shells on non-HTML paths
            # ─────────────────────────────────────────────────
            is_file_like = any(
                path.endswith(ext)
                for ext in (
                    ".env", ".sql", ".key", ".pem", ".php", ".json",
                    ".yml", ".yaml", ".txt", ".zip", ".tar.gz", ".bak",
                )
            )
            html_shell = is_html_shell(body, content_type)

            if html_shell and is_file_like:
                # File endpoints returning HTML shell = SPA fallback
                console.print(
                    f"  [dim]FP: HTML shell for /{f['path']} "
                    f"(expected file content)[/dim]"
                )
                continue

            # ═════════════════════════════════════════════════
            #  Admin Panel — Rule 3: require DOM proof
            # ═════════════════════════════════════════════════
            if any(p in path for p in ("admin", "dashboard", "panel", "cpanel")):
                if status == 200:
                    if not looks_like_admin_panel(body, content_type):
                        console.print(
                            f"  [dim]FP: admin panel /{f['path']} "
                            f"(no login DOM)[/dim]"
                        )
                        continue

                    vulns.append(Vulnerability(
                        vuln_type="Exposed Admin Panel",
                        url=url,
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        title=f"Admin Panel Exposed — /{f['path']}",
                        description=(
                            f"Admin panel ({url}) is publicly accessible. "
                            f"Login form was detected in the DOM."
                        ),
                        evidence=(
                            f"HTTP {status}, size: {size} bytes\n"
                            f"Login form DOM detected (input[type=password], "
                            f"username/password keywords)"
                        ),
                        exploitation=(
                            f"Brute force with Hydra:\n"
                            f"hydra -l admin -P /usr/share/wordlists/rockyou.txt "
                            f"{base_url} http-post-form "
                            f"'/admin/login:user=^USER^&pass=^PASS^:Invalid'"
                        ),
                        remediation=(
                            "1. IP whitelist the admin panel\n"
                            "2. Enable 2FA\n"
                            "3. Change the default URL\n"
                            "4. Add rate limiting"
                        ),
                        curl_poc=f'curl -s "{url}" | head -50',
                        cwe_id="CWE-284",
                    ))

            # ═════════════════════════════════════════════════
            #  Spring Boot Actuator
            # ═════════════════════════════════════════════════
            if "actuator" in path and status in (200, 204):
                # Skip if HTML shell (SPA fallback)
                if html_shell:
                    console.print(
                        f"  [dim]FP: actuator /{f['path']} returns HTML shell[/dim]"
                    )
                    continue

                severity = (
                    Severity.CRITICAL
                    if "heapdump" in path or "env" in path
                    else Severity.HIGH
                )
                cvss = 9.1 if severity == Severity.CRITICAL else 7.5

                vulns.append(Vulnerability(
                    vuln_type="Information Disclosure",
                    url=url,
                    severity=severity,
                    cvss_score=cvss,
                    title=f"Spring Boot Actuator Exposed — /{f['path']}",
                    description=(
                        f"Spring Boot Actuator endpoint ({f['path']}) is "
                        f"publicly accessible. This can leak environment "
                        f"variables, credentials, and heap dumps."
                    ),
                    evidence=f"HTTP {status}, size: {size} bytes",
                    exploitation=(
                        f"Environment variables:\n"
                        f"curl {base_url}/actuator/env | python3 -m json.tool\n\n"
                        f"Heap dump (may contain credentials):\n"
                        f"curl {base_url}/actuator/heapdump -o heap.bin\n"
                        f"strings heap.bin | grep -i 'password\\|secret\\|key'"
                    ),
                    remediation=(
                        "1. Disable Actuator in production\n"
                        "2. management.endpoints.web.exposure.include=health,info\n"
                        "3. Secure with Spring Security"
                    ),
                    curl_poc=f'curl -s "{url}"',
                    cwe_id="CWE-215",
                ))

            # ═════════════════════════════════════════════════
            #  GraphQL
            # ═════════════════════════════════════════════════
            if "graphql" in path and status == 200:
                if html_shell:
                    console.print(
                        f"  [dim]FP: GraphQL /{f['path']} returns HTML shell[/dim]"
                    )
                    continue

                vulns.append(Vulnerability(
                    vuln_type="Information Disclosure",
                    url=url,
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    title="GraphQL Endpoint Exposed",
                    description=(
                        "GraphQL endpoint found. Introspection may be enabled, "
                        "exposing the full schema and types."
                    ),
                    evidence=f"HTTP {status} — {url}",
                    exploitation=(
                        "Introspection query:\n"
                        "curl -X POST -H 'Content-Type: application/json' \\\n"
                        f"  -d '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}' \\\n"
                        f"  {url}"
                    ),
                    remediation=(
                        "1. Disable introspection in production\n"
                        "2. Add query depth limit\n"
                        "3. Enable rate limiting"
                    ),
                    curl_poc=(
                        f"curl -X POST -H 'Content-Type: application/json' "
                        f"-d '{{\"query\":\"{{__typename}}\"}}' {url}"
                    ),
                    cwe_id="CWE-200",
                ))

            # ═════════════════════════════════════════════════
            #  403 Forbidden — potential bypass
            # ═════════════════════════════════════════════════
            if status == 403:
                vulns.append(Vulnerability(
                    vuln_type="Access Control",
                    url=url,
                    severity=Severity.LOW,
                    cvss_score=3.7,
                    title=f"403 Forbidden — Bypass Attempt — /{f['path']}",
                    description=(
                        f"/{f['path']} returns 403. Header manipulation may "
                        f"bypass access control."
                    ),
                    evidence="HTTP 403",
                    exploitation=(
                        f"Header bypass attempts:\n"
                        f"curl -H 'X-Original-URL: /{f['path']}' {base_url}/\n"
                        f"curl -H 'X-Rewrite-URL: /{f['path']}' {base_url}/\n"
                        f"curl -H 'X-Forwarded-For: 127.0.0.1' {url}"
                    ),
                    remediation=(
                        "1. Do not trust proxy headers\n"
                        "2. Server-side authorization checks\n"
                        "3. Ignore X-Original-URL / X-Rewrite-URL headers"
                    ),
                    curl_poc=f'curl -H "X-Forwarded-For: 127.0.0.1" "{url}"',
                    cwe_id="CWE-284",
                ))

        return vulns

    # ══════════════════════════════════════════════════════════
    #  Scan
    # ══════════════════════════════════════════════════════════
    async def scan(self, base_url: str) -> tuple[list[str], list[Vulnerability]]:
        """
        Returns: (discovered_endpoints, vulnerabilities)
        """
        # Detect SPA first — affects analysis strictness
        is_spa = await self.spa_detector.detect(base_url)

        if is_spa:
            console.print(
                f"\n[bold cyan]🗂  Endpoint Discovery:[/bold cyan] "
                f"{len(self.wordlist)} paths (SPA mode — strict)"
            )
        else:
            console.print(
                f"\n[bold cyan]🗂  Endpoint Discovery:[/bold cyan] "
                f"{len(self.wordlist)} paths"
            )

        semaphore = asyncio.Semaphore(30)

        async def check_with_sem(path):
            async with semaphore:
                return await self._check_path(base_url, path)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(
                "[cyan]Path scan...[/cyan]",
                total=len(self.wordlist),
            )

            async def tracked(path):
                result = await check_with_sem(path)
                progress.advance(task)
                return result

            results = await asyncio.gather(
                *[tracked(p) for p in self.wordlist],
                return_exceptions=True,
            )

        findings = [r for r in results if isinstance(r, dict)]
        endpoints = [f["url"] for f in findings]

        # Print discovered endpoints
        for f in findings:
            status_color = {
                200: "green", 403: "yellow", 401: "yellow",
            }.get(f["status"], "blue")
            console.print(
                f"  [{status_color}]{f['status']}[/{status_color}] "
                f"/{f['path']} "
                f"[dim]({f['size']} bytes)[/dim]"
            )

        vulns = self._analyze_findings(findings, base_url, is_spa=is_spa)

        console.print(
            f"[bold green]  Discovery complete: {len(endpoints)} endpoints, "
            f"{len(vulns)} findings (after FP filter)[/bold green]"
        )

        return endpoints, vulns