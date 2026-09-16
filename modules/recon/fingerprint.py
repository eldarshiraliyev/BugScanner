"""
Technology Fingerprinting — v2.1

False-positive reduction:
- Missing security headers on localhost/internal targets downgraded to INFO
- HSTS on localhost skipped (meaningless)
- Server version disclosure severity context-aware
"""

import re
from typing import Optional

import httpx
from rich.console import Console

from core.models import Vulnerability, Severity
from core.fp_filter import is_internal_target

console = Console()

# Technology signatures
TECH_SIGNATURES = {
    "headers": {
        "X-Powered-By": {
            r"PHP/(\d+\.\d+)":          "PHP",
            r"ASP\.NET":                 "ASP.NET",
            r"Express":                  "Express.js",
            r"Next\.js":                 "Next.js",
        },
        "Server": {
            r"nginx/([\d.]+)":           "nginx",
            r"Apache/([\d.]+)":          "Apache",
            r"Microsoft-IIS/([\d.]+)":   "IIS",
            r"cloudflare":               "Cloudflare",
            r"LiteSpeed":                "LiteSpeed",
        },
        "X-Generator":       {".*": "Generator"},
        "X-Drupal-Cache":    {".*": "Drupal"},
        "X-WordPress":       {".*": "WordPress"},
    },
    "html": {
        r'<meta name="generator" content="WordPress ([^"]+)"':  "WordPress",
        r'wp-content/':                                          "WordPress",
        r'wp-includes/':                                         "WordPress",
        r'Drupal\.settings':                                     "Drupal",
        r'Joomla!':                                              "Joomla",
        r'data-reactroot':                                       "React",
        r'ng-version="([^"]+)"':                                 "Angular",
        r'__NUXT__':                                             "Nuxt.js",
        r'__next':                                               "Next.js",
        r'vue\.js':                                              "Vue.js",
        r'bootstrap\.min\.css':                                  "Bootstrap",
        r'jquery\.min\.js':                                      "jQuery",
        r'laravel_session':                                      "Laravel",
        r'_rails_session':                                       "Ruby on Rails",
        r'Django':                                               "Django",
        r'FastAPI':                                              "FastAPI",
        r'Swagger UI':                                           "Swagger/OpenAPI",
        r'graphql':                                              "GraphQL",
    },
    "cookies": {
        r"PHPSESSID":         "PHP",
        r"JSESSIONID":        "Java/Tomcat",
        r"ASP\.NET_SessionId": "ASP.NET",
        r"laravel_session":   "Laravel",
        r"_rails_session":    "Ruby on Rails",
        r"csrftoken":         "Django",
        r"connect\.sid":      "Node.js/Express",
    },
}

VULNERABLE_VERSIONS = {
    "PHP": {
        "< 8.1": "PHP 8.0 and below — EOL, no security updates",
        "5.x":   "PHP 5.x — critical security issues (CVE-2019-11043, etc.)",
    },
    "Apache": {
        "< 2.4.51": "Apache Path Traversal (CVE-2021-41773/CVE-2021-42013)",
    },
    "nginx": {
        "< 1.20": "nginx older version — buffer overflow issues",
    },
}


class TechFingerprinter:
    def __init__(self, http_client):
        self.http_client = http_client

    # ══════════════════════════════════════════════════════════
    #  Signature checks
    # ══════════════════════════════════════════════════════════
    def _check_headers(self, headers: dict) -> list[str]:
        techs = []
        for header, patterns in TECH_SIGNATURES["headers"].items():
            value = headers.get(header, "")
            if not value:
                value = next(
                    (v for k, v in headers.items()
                     if k.lower() == header.lower()),
                    "",
                )
            if value:
                for pattern, tech in patterns.items():
                    match = re.search(pattern, value, re.IGNORECASE)
                    if match:
                        version = match.group(1) if match.lastindex else ""
                        techs.append(f"{tech}{' ' + version if version else ''}")
        return techs

    def _check_html(self, html: str) -> list[str]:
        techs = []
        for pattern, tech in TECH_SIGNATURES["html"].items():
            if re.search(pattern, html, re.IGNORECASE):
                if tech not in techs:
                    techs.append(tech)
        return techs

    def _check_cookies(self, cookies) -> list[str]:
        techs = []
        cookie_str = str(cookies)
        for pattern, tech in TECH_SIGNATURES["cookies"].items():
            if re.search(pattern, cookie_str, re.IGNORECASE):
                if tech not in techs:
                    techs.append(tech)
        return techs

    # ══════════════════════════════════════════════════════════
    #  Security headers — v2.1 context-aware
    # ══════════════════════════════════════════════════════════
    def _check_security_headers(
        self, headers: dict, url: str
    ) -> list[Vulnerability]:
        """
        Check missing security headers with context-aware severity.

        Rule 4 (Context Awareness):
          - On localhost/internal targets, downgrade to INFO
          - Skip HSTS entirely on localhost (HTTPS not enforced)
          - Missing headers on public targets stay at LOW/MEDIUM
        """
        vulns: list[Vulnerability] = []
        headers_lower = {k.lower(): v for k, v in headers.items()}
        internal = is_internal_target(url)

        security_headers = {
            "strict-transport-security": {
                "title": "Missing HSTS Header",
                "desc": (
                    "Strict-Transport-Security header is missing. "
                    "MITM attacks possible on public sites."
                ),
                "cvss": 4.3,
                "remediation": (
                    "Strict-Transport-Security: max-age=31536000; "
                    "includeSubDomains"
                ),
            },
            "x-frame-options": {
                "title": "Missing X-Frame-Options",
                "desc": (
                    "Clickjacking protection missing. Page can be framed."
                ),
                "cvss": 4.3,
                "remediation": "X-Frame-Options: DENY",
            },
            "x-content-type-options": {
                "title": "Missing X-Content-Type-Options",
                "desc": "MIME sniffing protection missing.",
                "cvss": 3.7,
                "remediation": "X-Content-Type-Options: nosniff",
            },
            "content-security-policy": {
                "title": "Missing Content-Security-Policy",
                "desc": (
                    "CSP missing — extra layer of XSS protection unavailable."
                ),
                "cvss": 4.3,
                "remediation": (
                    "Content-Security-Policy: default-src 'self'; "
                    "script-src 'self'"
                ),
            },
            "permissions-policy": {
                "title": "Missing Permissions-Policy",
                "desc": "Browser feature policy not set.",
                "cvss": 2.0,
                "remediation": "Add a Permissions-Policy header",
            },
        }

        for header, info in security_headers.items():
            if header in headers_lower:
                continue

            # ══ Rule 4: Skip HSTS on localhost — meaningless ══
            if internal and header == "strict-transport-security":
                continue

            # ══ Rule 4: Downgrade to INFO on internal targets ══
            if internal:
                severity = Severity.INFO
                cvss = 0.9
            else:
                severity = (
                    Severity.LOW if info["cvss"] < 4 else Severity.MEDIUM
                )
                cvss = info["cvss"]

            vulns.append(Vulnerability(
                vuln_type="Missing Security Header",
                url=url,
                severity=severity,
                cvss_score=cvss,
                title=info["title"],
                description=info["desc"],
                evidence=f"Header '{header}' missing from response",
                exploitation=(
                    f"Example impact for X-Frame-Options:\n"
                    f"<iframe src='{url}'></iframe> → clickjacking"
                ),
                remediation=info["remediation"],
                curl_poc=f'curl -I "{url}" | grep -i "{header}"',
                cwe_id="CWE-693",
            ))

        # ══════════════════════════════════════════════════════════
        #  Server version disclosure — Rule 4: INFO
        # ══════════════════════════════════════════════════════════
        server = headers_lower.get("server", "")
        if server and re.search(r"\d+\.\d+", server):
            severity = Severity.INFO
            cvss = 0.5 if internal else 2.0

            vulns.append(Vulnerability(
                vuln_type="Information Disclosure",
                url=url,
                severity=severity,
                cvss_score=cvss,
                title="Server Version Disclosure",
                description=(
                    f"Server header leaks version info: {server}"
                ),
                evidence=f"Server: {server}",
                exploitation=(
                    "Version information aids targeted exploitation."
                ),
                remediation=(
                    "Hide server version:\n"
                    "  nginx: server_tokens off;\n"
                    "  Apache: ServerTokens Prod"
                ),
                curl_poc=f'curl -I "{url}"',
                cwe_id="CWE-200",
            ))

        return vulns

    # ══════════════════════════════════════════════════════════
    #  Main entry
    # ══════════════════════════════════════════════════════════
    async def fingerprint(
        self, url: str
    ) -> tuple[list[str], list[Vulnerability]]:
        """Fingerprint URL — returns (technologies, vulnerabilities)."""
        response = await self.http_client.get(url)
        if not response:
            return [], []

        techs: list[str] = []
        techs.extend(self._check_headers(dict(response.headers)))
        techs.extend(self._check_html(response.text[:50000]))
        techs.extend(self._check_cookies(response.cookies))
        techs = list(set(techs))

        vulns = self._check_security_headers(dict(response.headers), url)

        if techs:
            console.print(
                f"  [bold]Technologies:[/bold] {', '.join(techs)}"
            )

        return techs, vulns