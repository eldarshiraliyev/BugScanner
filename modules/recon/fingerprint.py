"""
Technology Fingerprinting
- HTTP headers analizi
- HTML content analizi
- Cookie patterns
- JS library detection
"""

import re
from typing import Optional
import httpx
from rich.console import Console
from core.models import Vulnerability, Severity

console = Console()

# Texnologiya imzaları
TECH_SIGNATURES = {
    # Headers
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
    # HTML patterns
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
    # Cookies
    "cookies": {
        r"PHPSESSID":        "PHP",
        r"JSESSIONID":       "Java/Tomcat",
        r"ASP\.NET_SessionId":"ASP.NET",
        r"laravel_session":  "Laravel",
        r"_rails_session":   "Ruby on Rails",
        r"csrftoken":        "Django",
        r"connect\.sid":     "Node.js/Express",
    },
}

# Köhnə/vulnerable versiyalar
VULNERABLE_VERSIONS = {
    "PHP": {
        "< 8.1": "PHP 8.0 və aşağı — EOL, security updates yoxdur",
        "5.x":   "PHP 5.x — kritik security issues (CVE-2019-11043 etc.)",
    },
    "Apache": {
        "< 2.4.51": "Apache Path Traversal (CVE-2021-41773/CVE-2021-42013)",
    },
    "nginx": {
        "< 1.20": "nginx köhnə versiya — buffer overflow issues",
    },
}


class TechFingerprinter:
    def __init__(self, http_client):
        self.http_client = http_client

    def _check_headers(self, headers: dict) -> list[str]:
        techs = []
        for header, patterns in TECH_SIGNATURES["headers"].items():
            value = headers.get(header, "")
            if not value:
                # Case-insensitive yoxla
                value = next((v for k, v in headers.items()
                               if k.lower() == header.lower()), "")
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

    def _check_security_headers(self, headers: dict, url: str) -> list[Vulnerability]:
        """Missing security headers yoxla"""
        vulns = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        security_headers = {
            "strict-transport-security": {
                "title": "Missing HSTS Header",
                "desc": "Strict-Transport-Security header yoxdur. MITM hücumlarına açıqdır.",
                "cvss": 4.3,
                "remediation": "Header əlavə et: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            },
            "x-frame-options": {
                "title": "Missing X-Frame-Options",
                "desc": "Clickjacking hücumlarına qarşı qorunma yoxdur.",
                "cvss": 4.3,
                "remediation": "Header əlavə et: X-Frame-Options: DENY",
            },
            "x-content-type-options": {
                "title": "Missing X-Content-Type-Options",
                "desc": "MIME sniffing hücumlarına açıqdır.",
                "cvss": 3.7,
                "remediation": "Header əlavə et: X-Content-Type-Options: nosniff",
            },
            "content-security-policy": {
                "title": "Missing Content-Security-Policy",
                "desc": "CSP yoxdur. XSS hücumlarına qarşı əlavə qorunma yoxdur.",
                "cvss": 4.3,
                "remediation": "CSP header əlavə et: Content-Security-Policy: default-src 'self'",
            },
            "permissions-policy": {
                "title": "Missing Permissions-Policy",
                "desc": "Browser feature policy təyin edilməyib.",
                "cvss": 2.0,
                "remediation": "Permissions-Policy header əlavə et",
            },
        }

        for header, info in security_headers.items():
            if header not in headers_lower:
                vuln = Vulnerability(
                    vuln_type="Missing Security Header",
                    url=url,
                    severity=Severity.LOW if info["cvss"] < 4 else Severity.MEDIUM,
                    cvss_score=info["cvss"],
                    title=info["title"],
                    description=info["desc"],
                    evidence=f"Header '{header}' response-da yoxdur",
                    exploitation=(
                        f"Attacker bu header-in olmamasından istifadə edə bilər. "
                        f"Məsələn, X-Frame-Options olmadıqda: "
                        f"<iframe src='{url}'></iframe> ilə clickjacking."
                    ),
                    remediation=info["remediation"],
                    cwe_id="CWE-693",
                )
                vulns.append(vuln)

        # Server version disclosure
        server = headers_lower.get("server", "")
        if server and re.search(r"\d+\.\d+", server):
            vulns.append(Vulnerability(
                vuln_type="Information Disclosure",
                url=url,
                severity=Severity.INFO,
                cvss_score=2.0,
                title="Server Version Disclosure",
                description=f"Server header versiya məlumatını açıqlayır: {server}",
                evidence=f"Server: {server}",
                exploitation="Versiya məlumatı targeted exploiting üçün istifadə edilə bilər.",
                remediation="Server header-ini gizlət: nginx-də 'server_tokens off;'",
                cwe_id="CWE-200",
            ))

        return vulns

    async def fingerprint(self, url: str) -> tuple[list[str], list[Vulnerability]]:
        """URL-i fingerprint et, texnologiyaları və header vulnları qaytar"""
        response = await self.http_client.get(url)
        if not response:
            return [], []

        techs = []
        techs.extend(self._check_headers(dict(response.headers)))
        techs.extend(self._check_html(response.text[:50000]))
        techs.extend(self._check_cookies(response.cookies))
        techs = list(set(techs))

        vulns = self._check_security_headers(dict(response.headers), url)

        if techs:
            console.print(f"  [bold]Texnologiyalar:[/bold] {', '.join(techs)}")

        return techs, vulns
