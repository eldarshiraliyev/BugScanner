"""
Information Disclosure Scanner
- Exposed sensitive files (.env, .git, backup files)
- Directory listing
- Error page info disclosure
- API key patterns in responses
"""

import re
import asyncio
from urllib.parse import urljoin
from rich.console import Console
from core.models import Vulnerability, Severity

console = Console()

# Sensitive fayllar
SENSITIVE_PATHS = [
    # Environment & Config
    ".env", ".env.local", ".env.production", ".env.backup",
    ".env.example", "config.env", "env.txt",
    # Git
    ".git/HEAD", ".git/config", ".git/COMMIT_EDITMSG",
    ".gitignore", ".gitconfig",
    # Backup fayllar
    "backup.sql", "backup.zip", "backup.tar.gz", "db_backup.sql",
    "database.sql", "dump.sql", "data.sql",
    # Config fayllar
    "config.php", "config.yml", "config.yaml", "config.json",
    "configuration.php", "settings.php", "wp-config.php",
    "database.php", "db.php", "conn.php", "connection.php",
    # Log fayllar
    "error.log", "access.log", "debug.log", "app.log",
    "logs/error.log", "var/log/error.log",
    # Admin paths
    "admin/", "administrator/", "phpmyadmin/", "adminer.php",
    "phpinfo.php", "info.php", "test.php", "debug.php",
    # API docs
    "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
    "api/swagger", "api/docs", "api-docs", "api/schema",
    # Common sensitive
    "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
    "server-status", "server-info", "status",
    # Package files
    "package.json", "composer.json", "requirements.txt", "Gemfile",
    "yarn.lock", "package-lock.json", ".npmrc",
    # CI/CD
    ".travis.yml", ".github/workflows/", "Dockerfile", "docker-compose.yml",
    "Jenkinsfile", ".circleci/config.yml",
    # Certificates
    "server.key", "private.key", "ssl.key", "certificate.pem",
]

# Sensitive məzmun patterns
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

    def _check_content(self, content: str, url: str) -> list[Vulnerability]:
        """Content-i sensitive data üçün yoxla"""
        vulns = []
        for name, (pattern, severity, cvss) in SENSITIVE_PATTERNS.items():
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                # Partial redact (security üçün)
                found = match.group(0)
                redacted = found[:8] + "***" if len(found) > 8 else "***"
                vulns.append(Vulnerability(
                    vuln_type="Information Disclosure",
                    url=url,
                    severity=severity,
                    cvss_score=cvss,
                    title=f"Sensitive Data Exposure — {name}",
                    description=f"Response-da {name} pattern-i aşkar edildi.",
                    evidence=f"Pattern tapıldı: {redacted}",
                    exploitation=(
                        f"Bu credential-dən birbaşa istifadə etmək mümkündür:\n"
                        f"curl {url} | grep -oE '{pattern[:40]}...'"
                    ),
                    remediation=(
                        f"1. Bu credential-i dərhal revoke et\n"
                        f"2. .env fayllarını public directory-dən çıxar\n"
                        f"3. .gitignore-a həssas faylları əlavə et\n"
                        f"4. Secret management tool işlət (HashiCorp Vault, AWS Secrets Manager)"
                    ),
                    cwe_id="CWE-200",
                    references=[
                        "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"
                    ],
                ))
        return vulns

    async def _check_path(self, base_url: str, path: str) -> list[Vulnerability]:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        response = await self.http_client.get(url)

        if not response or response.status_code not in [200, 206]:
            return []

        vulns = []
        content = response.text

        # Directory listing yoxla
        if "Index of /" in content or "Directory listing" in content.lower():
            vulns.append(Vulnerability(
                vuln_type="Information Disclosure",
                url=url,
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                title="Directory Listing Enabled",
                description="Web server directory listing-i aktiv edir. File strukturu görünür.",
                evidence=f"'{path}' üçün directory listing cavabı alındı",
                exploitation=f"curl {url} — bütün faylları siyahıla",
                remediation="Apache: Options -Indexes | nginx: autoindex off;",
                cwe_id="CWE-548",
            ))

        # .git exposure
        if ".git" in path and "ref:" in content:
            vulns.append(Vulnerability(
                vuln_type="Information Disclosure",
                url=url,
                severity=Severity.HIGH,
                cvss_score=7.5,
                title=".git Directory Exposed",
                description="Git repository ictimaən əlçatandır. Source code, credentials, history steal edilə bilər.",
                evidence=f"HEAD faylı oxundu: {content[:100]}",
                exploitation=(
                    "git-dumper aləti ilə tam repo-nu yüklə:\n"
                    f"git-dumper {base_url}/.git/ ./stolen-repo"
                ),
                remediation=(
                    "Nginx: location ~ /\\.git { deny all; }\n"
                    "Apache: <DirectoryMatch \\.git> Deny from all </DirectoryMatch>"
                ),
                curl_poc=f'curl "{url}"',
                cwe_id="CWE-538",
            ))

        # Sensitive content yoxla
        content_vulns = self._check_content(content, url)
        vulns.extend(content_vulns)

        # Sadəcə accessible olan sensitive fayl
        if not vulns and response.status_code == 200:
            for sensitive_ext in [".env", ".sql", ".key", ".pem", "phpinfo"]:
                if sensitive_ext in path.lower():
                    vulns.append(Vulnerability(
                        vuln_type="Information Disclosure",
                        url=url,
                        severity=Severity.HIGH,
                        cvss_score=7.2,
                        title=f"Sensitive File Accessible — {path}",
                        description=f"'{path}' faylı ictimaən əlçatandır.",
                        evidence=f"HTTP 200 cavabı, content length: {len(content)}",
                        exploitation=f'curl "{url}" > stolen_{path.replace("/", "_")}',
                        remediation="Bu faylı web root-dan çıxar və ya web server-də gizlə.",
                        cwe_id="CWE-538",
                    ))
                    break

        for v in vulns:
            console.print(f"  {v.severity.emoji} [bold]Disclosure:[/bold] {v.title} @ {path}")

        return vulns

    async def scan(self, base_url: str) -> list[Vulnerability]:
        console.print(f"  [dim]Info disclosure skan: {len(SENSITIVE_PATHS)} path...[/dim]")

        semaphore = asyncio.Semaphore(20)

        async def check_with_sem(path):
            async with semaphore:
                return await self._check_path(base_url, path)

        results = await asyncio.gather(
            *[check_with_sem(p) for p in SENSITIVE_PATHS],
            return_exceptions=True
        )

        vulns = []
        for r in results:
            if isinstance(r, list):
                vulns.extend(r)

        return vulns
