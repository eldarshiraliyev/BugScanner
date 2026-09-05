"""
Open Redirect Scanner
"""

import asyncio
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console
from core.models import Vulnerability, Severity

console = Console()

REDIRECT_PARAM_HINTS = [
    "redirect", "url", "next", "goto", "return", "returnurl",
    "return_url", "redirect_url", "redirect_uri", "continue",
    "destination", "dest", "target", "to", "out", "exit",
    "forward", "location", "link", "ref", "referer",
]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "//evil.com/%2f..",
    r"\/evil.com",
    "/\evil.com",
    "https:evil.com",
    "http://evil.com",
    "//evil%2ecom",
    "%2f%2fevil.com",
    "/%09/evil.com",
    "https://evil.com?trusted.com",
    "https://trusted.com.evil.com",
]


class RedirectScanner:
    def __init__(self, http_client):
        self.http_client = http_client

    def _extract_params(self, url: str) -> list[str]:
        parsed = urlparse(url)
        return list(parse_qs(parsed.query, keep_blank_values=True).keys())

    def _is_redirect_param(self, param: str) -> bool:
        return any(hint in param.lower() for hint in REDIRECT_PARAM_HINTS)

    def _inject(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

    async def _test_param(self, url: str, param: str) -> Vulnerability | None:
        for payload in REDIRECT_PAYLOADS:
            test_url = self._inject(url, param, payload)

            # follow_redirects=False — redirect-i görmək üçün
            try:
                import httpx
                async with httpx.AsyncClient(verify=False, timeout=8,
                                              follow_redirects=False) as client:
                    response = await client.get(test_url)
            except Exception:
                continue

            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get("location", "")
                if "evil.com" in location or location.startswith("//") or location.startswith("https://evil"):
                    return Vulnerability(
                        vuln_type="Open Redirect",
                        url=test_url,
                        severity=Severity.MEDIUM,
                        cvss_score=6.1,
                        title=f"Open Redirect — {param}",
                        description=(
                            f"'{param}' parametri ixtiyari URL-ə redirect etməyə imkan verir. "
                            f"Phishing, credential harvesting üçün istifadə edilə bilər."
                        ),
                        evidence=(
                            f"HTTP {response.status_code}\n"
                            f"Location: {location}"
                        ),
                        exploitation=(
                            f"Victim-ə bu linki göndər:\n"
                            f"{test_url}\n\n"
                            f"Victim trusted domain görüb klikləyər, "
                            f"evil.com-a redirect olar.\n"
                            f"OAuth token theft üçün:\n"
                            f"{self._inject(url, param, 'https://evil.com/steal')}"
                        ),
                        remediation=(
                            "1. Redirect üçün whitelist tətbiq et\n"
                            "2. Relative path-lərdən istifadə et\n"
                            "3. External redirect-ləri tamamilə qadağan et\n"
                            "4. Redirect-dən əvvəl user-ə xəbərdarlıq göstər"
                        ),
                        parameter=param,
                        payload_used=payload,
                        curl_poc=f'curl -v "{test_url}" 2>&1 | grep "Location:"',
                        cwe_id="CWE-601",
                        references=["https://portswigger.net/web-security/dom-based/open-redirection"],
                    )
        return None

    async def scan(self, url: str) -> list[Vulnerability]:
        params = self._extract_params(url)
        redirect_params = [p for p in params if self._is_redirect_param(p)]

        if not redirect_params:
            return []

        console.print(f"  [dim]Open Redirect skan: {len(redirect_params)} parametr[/dim]")

        results = await asyncio.gather(
            *[self._test_param(url, p) for p in redirect_params],
            return_exceptions=True
        )

        vulns = [r for r in results if isinstance(r, Vulnerability)]
        for v in vulns:
            console.print(f"  {v.severity.emoji} [bold]Open Redirect:[/bold] {v.parameter}")
        return vulns