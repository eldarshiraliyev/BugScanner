"""
Information Disclosure Scanner — v2.1

False-positive reduction:
- Content signature verification (not just HTTP 200)
- SPA fallback detection
- HTML shell filtering
"""

import asyncio
import re
from urllib.parse import urljoin, urlparse
from rich.console import Console

from core.models import Vulnerability, Severity
from core.fp_filter import (
    content_matches_sensitive_signature,
    is_html_shell,
    SPAFallbackDetector,
)

console = Console()

SENSITIVE_PATHS = [
    ".env", ".env.local", ".env.production", ".env.backup",
    ".env.example", "config.env", "env.txt",
    ".git/HEAD", ".git/config", ".git/COMMIT_EDITMSG",
    ".gitignore", ".gitconfig",
    "backup.sql", "backup.zip", "backup.tar.gz", "db_backup.sql",
    "database.sql", "dump.sql", "data.sql",
    "config.php", "config.yml", "config.yaml", "config.json",
    "configuration.php", "settings.php", "wp-config.php",
    "database.php", "db.php", "conn.php", "connection.php",
    "error.log", "access.log", "debug.log", "app.log",
    "logs/error.log", "var/log/error.log",
    "admin/", "administrator/", "phpmyadmin/", "adminer.php",
    "phpinfo.php", "info.php", "test.php", "debug.php",
    "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
    "api/swagger", "api/docs", "api-docs", "api/schema",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
    "server-status", "server-info", "status",
    "package.json", "composer.json", "requirements.txt", "Gemfile",
    "yarn.lock", "package-lock.json", ".npmrc",
    ".travis.yml", ".github/workflows/", "Dockerfile", "docker-compose.yml",
    "Jenkinsfile", ".circleci/config.yml",
    "server.key", "private.key", "ssl.key", "certificate.pem",
]

SENSITIVE_PATTERNS = {
    "API Key (Generic)": (
        r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
        Severity.HIGH, 7.5
    ),
    "AWS Access Key": (
        r'AKIA[0-9A-Z]{16}',
        Severity.CRITICAL, 9.0
    ),
    "AWS Secret Key": (
        r'["\']?aws[_-]?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']',
        Severity.CRITICAL, 9.0
    ),
    "Private Key": (
        r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
        Severity.CRITICAL, 9.5
    ),
    "Database Password": (
        r'(?:DB_PASS|DB_PASSWORD|DATABASE_PASSWORD)\s*=\s*(.+)',
        Severity.CRITICAL, 9.0
    ),
    "GitHub Token": (
        r'ghp_[a-zA-Z0-9]{36}',
        Severity.HIGH, 8.0
    ),
    "JWT Token": (
        r'eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}',
        Severity.MEDIUM, 6.0
    ),
    "SendGrid API Key": (
        r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}',
        Severity.HIGH, 8.0
    ),
    "Slack Token": (
        r'xox[baprs]-[a-zA-Z0-9\-]+',
        Severity.HIGH, 7.5
    ),
    "Google API Key": (
        r'AIza[0-9A-Za-z\-_]{35}',
        Severity.HIGH, 7.5
    ),
    "Stripe Key": (
        r'(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{24,}',
        Severity.HIGH, 8.5
    ),
}


class DisclosureScanner:
    def __init__(self, http_client):
        self.http_client = http_client
        self.spa_detector = SPAFallbackDetector(http_client)

    # ══════════════════════════════════════════════════════════
    #  Helper — sensitive content check
    # ══════════════════════════════════════════════════════════
    def _check_content(self, content: str, url: str) -> list[Vulnerability]:
        vulns = []
        for name, (pattern, severity, cvss) in SENSITIVE_PATTERNS.items():
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                found = match.group(0)
                redacted = found[:8] + "***" if len(found) > 8 else "***"
                vulns.append(Vulnerability(
                    vuln_type="Information Disclosure",
                    url=url,
                    severity=severity,
                    cvss_score=cvss,
                    title=f"Sensitive Data Exposure — {name}",
                    description=f"Response contains a {name} pattern.",
                    evidence=f"Pattern matched: {redacted}",
                    exploitation=(
                        f"This credential can be used directly:\n"
                        f"curl {url} | grep -oE '{pattern[:40]}...'"
                    ),
                    remediation=(
                        f"1. Revoke this credential immediately\n"
                        f"2. Move .env files outside the public web root\n"
                        f"3. Add sensitive files to .gitignore\n"
                        f"4. Use a secret manager (Vault, AWS Secrets Manager)"
                    ),
                    curl_poc=f'curl -s "{url}" | grep -oE "{pattern[:40]}..."',
                    cwe_id="CWE-200",
                    references=[
                        "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"
                    ],
                ))
        return vulns

    # ══════════════════════════════════════════════════════════
    #  Single path check — with FP filtering
    # ══════════════════════════════════════════════════════════
    async def _check_path(self, base_url: str, path: str) -> list[Vulnerability]:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        response = await self.http_client.get(url)

        if not response or response.status_code not in (200, 206):
            return []

        content = response.text
        content_type = response.headers.get("content-type", "")
        vulns = []

        # ══ Rule 1: Content signature verification ══
        # Skip HTML shells — they are almost always SPA fallbacks
        if is_html_shell(content, content_type):
            # Exception: .git and other non-HTML content types
            if ".git" not in path.lower() and "phpinfo" not in path.lower():
                return []

        # ══ Directory listing ══
        if "Index of /" in content or "Directory listing" in content.lower():
            vulns.append(Vulnerability(
                vuln_type="Information Disclosure",
                url=url,
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                title="Directory Listing Enabled",
                description="Web server has directory listing enabled.",
                evidence=f"Directory listing found at '{path}'",
                exploitation=f"curl {url} — enumerate files",
                remediation="Apache: Options -Indexes | nginx: autoindex off;",
                curl_poc=f'curl -s "{url}" | head -20',
                cwe_id="CWE-548",
            ))

        # ══ .git exposure ══
        if ".git" in path and re.search(r"^ref:\s+refs/heads/", content):
            vulns.append(Vulnerability(
                vuln_type="Information Disclosure",
                url=url,
                severity=Severity.HIGH,
                cvss_score=7.5,
                title=".git Directory Exposed",
                description="Git repository is publicly accessible.",
                evidence=f"HEAD file content: {content[:100]}",
                exploitation=(
                    f"Extract full repo:\n"
                    f"git-dumper {base_url}/.git/ ./stolen-repo"
                ),
                remediation=(
                    "Nginx: location ~ /\\.git { deny all; }\n"
                    "Apache: <DirectoryMatch \\.git> Deny from all </DirectoryMatch>"
                ),
                curl_poc=f'curl "{url}"',
                cwe_id="CWE-538",
            ))

        # ══ Sensitive file with signature check ══
        if not vulns and response.status_code == 200:
            # Determine if this is a "sensitive file" candidate
            is_sensitive_candidate = any(
                ext in path.lower()
                for ext in (".env", ".sql", ".key", ".pem", ".php", "backup")
            ) or path.lower() in ("config", "config.php", "config.yml", "config.yaml")

            if is_sensitive_candidate:
                matches, reason = content_matches_sensitive_signature(path, content)

                if matches:
                    # Real sensitive file
                    severity = Severity.HIGH
                    cvss = 7.2
                    if any(ext in path.lower() for ext in (".key", ".pem")):
                        severity = Severity.CRITICAL
                        cvss = 9.5

                    vulns.append(Vulnerability(
                        vuln_type="Information Disclosure",
                        url=url,
                        severity=severity,
                        cvss_score=cvss,
                        title=f"Sensitive File Accessible — {path}",
                        description=(
                            f"'{path}' is publicly accessible and its content "
                            f"matches a sensitive-file signature ({reason})."
                        ),
                        evidence=(
                            f"HTTP 200, content length: {len(content)}\n"
                            f"Signature match: {reason}"
                        ),
                        exploitation=(
                            f'curl -s "{url}" > stolen_{path.replace("/", "_")}'
                        ),
                        remediation=(
                            "Remove this file from the web root, or block it in "
                            "the web server config."
                        ),
                        curl_poc=f'curl -s "{url}" | head -40',
                        cwe_id="CWE-538",
                    ))
                # else: dropped — no signature match → False Positive

        # ══ Sensitive data patterns (only if real content) ══
        content_vulns = self._check_content(content, url)
        vulns.extend(content_vulns)

        for v in vulns:
            console.print(f"  {v.severity.emoji} [bold]Disclosure:[/bold] {v.title} @ {path}")

        return vulns

    # ══════════════════════════════════════════════════════════
    #  Scan
    # ══════════════════════════════════════════════════════════
    async def scan(self, base_url: str) -> list[Vulnerability]:
        # Check if SPA — if yes, be extra strict
        is_spa = await self.spa_detector.detect(base_url)

        if is_spa:
            console.print(
                "  [dim]Disclosure scan: SPA detected — strict mode[/dim]"
            )
        else:
            console.print(
                f"  [dim]Disclosure scan: {len(SENSITIVE_PATHS)} paths...[/dim]"
            )

        semaphore = asyncio.Semaphore(20)

        async def check_with_sem(path):
            async with semaphore:
                return await self._check_path(base_url, path)

        results = await asyncio.gather(
            *[check_with_sem(p) for p in SENSITIVE_PATHS],
            return_exceptions=True,
        )

        vulns = []
        for r in results:
            if isinstance(r, list):
                vulns.extend(r)

        return vulns