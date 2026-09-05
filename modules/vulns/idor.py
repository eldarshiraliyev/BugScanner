"""
IDOR — Insecure Direct Object Reference Scanner
- Numeric ID manipulation
- UUID/GUID enumeration hints
- Parameter pollution
- HTTP method switching
"""

import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console
from core.models import Vulnerability, Severity

console = Console()

# IDOR-prone parametrlər
IDOR_PARAM_HINTS = [
    "id", "user_id", "userid", "uid", "account", "account_id",
    "order", "order_id", "invoice", "invoice_id", "file", "file_id",
    "doc", "document", "document_id", "record", "record_id",
    "profile", "profile_id", "customer", "customer_id",
    "ticket", "ticket_id", "report", "report_id", "msg", "message_id",
    "pid", "cid", "rid", "num", "number", "ref", "reference",
]

# IDOR-prone URL path patternləri
PATH_ID_PATTERN = re.compile(
    r'/(\d+)(?:/|$)|'
    r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)',
    re.IGNORECASE
)


class IDORScanner:
    def __init__(self, http_client):
        self.http_client = http_client

    def _extract_idor_params(self, url: str) -> list[tuple[str, str]]:
        """IDOR-prone param + dəyər cütlərini çıxar"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        result = []
        for k, v in params.items():
            if any(hint in k.lower() for hint in IDOR_PARAM_HINTS):
                result.append((k, v[0]))
            elif v and re.match(r'^\d+$', v[0]):
                result.append((k, v[0]))
        return result

    def _extract_path_ids(self, url: str) -> list[tuple[int, str, str]]:
        """URL path-dəki ID-ləri tap — (position, original, type)"""
        parsed = urlparse(url)
        path = parsed.path
        results = []

        # Numeric IDs
        for match in re.finditer(r'/(\d+)(?=/|$)', path):
            results.append((match.start(), match.group(1), "numeric"))

        # UUIDs
        uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        for match in re.finditer(uuid_pattern, path, re.IGNORECASE):
            results.append((match.start(), match.group(0), "uuid"))

        return results

    def _inject_param(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

    def _inject_path_id(self, url: str, original_id: str, new_id: str) -> str:
        parsed = urlparse(url)
        new_path = parsed.path.replace(f"/{original_id}", f"/{new_id}", 1)
        return urlunparse(parsed._replace(path=new_path))

    def _generate_test_ids(self, original: str, id_type: str) -> list[str]:
        """Test üçün ID variantları yarat"""
        if id_type == "numeric":
            orig_int = int(original)
            candidates = []
            # Neighbouring IDs
            for delta in [-1, 1, -2, 2, 10, -10, 100]:
                new_id = orig_int + delta
                if new_id > 0:
                    candidates.append(str(new_id))
            # Common admin IDs
            for admin_id in ["1", "2", "0", "admin"]:
                if admin_id != original:
                    candidates.append(admin_id)
            return candidates

        elif id_type == "uuid":
            # UUID manipulation — son character dəyiş
            variants = []
            chars = "0123456789abcdef"
            for i in [-1, -2, -3]:
                for c in chars[:4]:
                    if original[i] != c:
                        new_uuid = original[:i] + c + original[i+1:]
                        variants.append(new_uuid)
                        break
            return variants[:5]

        return []

    def _compare_responses(
        self,
        original_resp,
        test_resp,
        original_id: str,
        test_id: str
    ) -> bool:
        """
        IDOR olub olmadığını müəyyən et:
        - Status 200
        - Content fərqli (başqa user datası)
        - Original ID ilə eyni strukturda cavab
        """
        if not test_resp or test_resp.status_code != 200:
            return False

        if not original_resp or original_resp.status_code != 200:
            return False

        # Eyni content — başqa user datası deyil, redirect ola bilər
        if test_resp.text == original_resp.text:
            return False

        # Content çox kiçikdirsə — error page
        if len(test_resp.text) < 50:
            return False

        # Original ID hələ də görünürsə — öz datamızı görürük
        if original_id in test_resp.text and test_id not in test_resp.text:
            return False

        # Potensial IDOR — fərqli, dolu cavab
        return True

    async def _test_param_idor(
        self, url: str, param: str, original_value: str
    ) -> Vulnerability | None:

        # Baseline al
        original_resp = await self.http_client.get(url)
        if not original_resp or original_resp.status_code != 200:
            return None

        id_type = "numeric" if re.match(r'^\d+$', original_value) else "uuid"
        test_ids = self._generate_test_ids(original_value, id_type)

        for test_id in test_ids:
            test_url = self._inject_param(url, param, test_id)
            test_resp = await self.http_client.get(test_url)

            if self._compare_responses(original_resp, test_resp, original_value, test_id):
                return Vulnerability(
                    vuln_type="IDOR",
                    url=test_url,
                    severity=Severity.HIGH,
                    cvss_score=8.1,
                    title=f"Potensial IDOR — '{param}' parametri",
                    description=(
                        f"'{param}={original_value}' dəyərini '{test_id}' ilə "
                        f"əvəz etdikdə fərqli content alındı. "
                        f"Authorization yoxlanması olmaya bilər."
                    ),
                    evidence=(
                        f"Original: {param}={original_value} → {original_resp.status_code} "
                        f"({len(original_resp.text)} bytes)\n"
                        f"Modified: {param}={test_id} → {test_resp.status_code} "
                        f"({len(test_resp.text)} bytes)"
                    ),
                    exploitation=(
                        f"1. Öz hesabınla login ol\n"
                        f"2. Bu URL-i aç: {test_url}\n"
                        f"3. Başqa user-in datasına baxılıb baxılmadığını yoxla\n\n"
                        f"Avtomatik enumeration:\n"
                        f"for i in $(seq 1 100); do\n"
                        f"  curl -s -b 'session=YOUR_TOKEN' \\\n"
                        f"  '{self._inject_param(url, param, '$i')}' | python3 -m json.tool\n"
                        f"done"
                    ),
                    remediation=(
                        "1. Hər request-də user ownership yoxla\n"
                        "2. Direct object reference əvəzinə indirect reference (mapping) istifadə et\n"
                        "3. UUID işlət — numeric sequential ID əvəzinə\n"
                        "4. Resource-a access-i server-side authorize et"
                    ),
                    parameter=param,
                    payload_used=f"{param}={test_id}",
                    curl_poc=(
                        f'curl -s -H "Cookie: YOUR_SESSION" "{test_url}"'
                    ),
                    cwe_id="CWE-639",
                    references=[
                        "https://portswigger.net/web-security/access-control/idor",
                        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
                    ],
                )

        return None

    async def _test_path_idor(self, url: str) -> list[Vulnerability]:
        vulns = []
        path_ids = self._extract_path_ids(url)

        if not path_ids:
            return vulns

        original_resp = await self.http_client.get(url)
        if not original_resp or original_resp.status_code != 200:
            return vulns

        for _, original_id, id_type in path_ids:
            test_ids = self._generate_test_ids(original_id, id_type)

            for test_id in test_ids:
                test_url = self._inject_path_id(url, original_id, test_id)
                test_resp = await self.http_client.get(test_url)

                if self._compare_responses(original_resp, test_resp, original_id, test_id):
                    vulns.append(Vulnerability(
                        vuln_type="IDOR",
                        url=test_url,
                        severity=Severity.HIGH,
                        cvss_score=8.1,
                        title=f"Potensial IDOR — Path ID ({original_id} → {test_id})",
                        description=(
                            f"URL path-dəki '{original_id}' ID-ni '{test_id}' ilə "
                            f"əvəz etdikdə fərqli authorized content alındı."
                        ),
                        evidence=(
                            f"Original URL: {url} → {original_resp.status_code}\n"
                            f"Modified URL: {test_url} → {test_resp.status_code} "
                            f"({len(test_resp.text)} bytes)"
                        ),
                        exploitation=(
                            f"ID-ləri ardıcıl dəyişərək başqa user datalarına bax:\n"
                            f"for i in $(seq 1 50); do\n"
                            f"  curl -s -b 'session=TOKEN' \\\n"
                            f"  '{self._inject_path_id(url, original_id, '$i')}'\n"
                            f"done"
                        ),
                        remediation=(
                            "1. Path parameter-lərini server-side authorize et\n"
                            "2. Resource ownership yoxla\n"
                            "3. Sequential numeric ID əvəzinə UUID istifadə et"
                        ),
                        payload_used=f"path: {original_id} → {test_id}",
                        curl_poc=f'curl -s "{test_url}"',
                        cwe_id="CWE-639",
                    ))
                    break

        return vulns

    async def _test_http_method(self, url: str) -> list[Vulnerability]:
        """HTTP method switching — GET→POST, POST→PUT"""
        vulns = []
        methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

        original_resp = await self.http_client.get(url)
        if not original_resp:
            return vulns

        for method in methods:
            if method == "GET":
                continue
            resp = await self.http_client.request(method, url)
            if resp and resp.status_code not in [405, 501, 404, 400]:
                if method in ["DELETE", "PUT", "PATCH"]:
                    vulns.append(Vulnerability(
                        vuln_type="IDOR",
                        url=url,
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        title=f"HTTP Method {method} Qəbul Edilir",
                        description=(
                            f"Endpoint {method} metodunu qəbul edir ({resp.status_code}). "
                            f"Authorization yoxlanılmadan data dəyişdirilə/silinə bilər."
                        ),
                        evidence=f"HTTP {method} → {resp.status_code}",
                        exploitation=(
                            f"curl -X {method} \\\n"
                            f"  -H 'Content-Type: application/json' \\\n"
                            f"  -d '{{\"admin\": true}}' \\\n"
                            f"  '{url}'"
                        ),
                        remediation=(
                            f"1. Yalnız lazımlı HTTP metodlarına icazə ver\n"
                            f"2. Hər metod üçün authorization yoxla\n"
                            f"3. {method} üçün CSRF protection tətbiq et"
                        ),
                        method=method,
                        curl_poc=f'curl -X {method} -s "{url}"',
                        cwe_id="CWE-650",
                    ))

        return vulns

    async def scan(self, url: str) -> list[Vulnerability]:
        console.print(f"  [dim]IDOR skan: {url[:60]}[/dim]")
        vulns = []

        # 1. Query param IDOR
        idor_params = self._extract_idor_params(url)
        if idor_params:
            tasks = [
                self._test_param_idor(url, param, value)
                for param, value in idor_params
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Vulnerability):
                    vulns.append(r)
                    console.print(f"  {r.severity.emoji} [bold]IDOR:[/bold] {r.title}")

        # 2. Path ID IDOR
        path_vulns = await self._test_path_idor(url)
        vulns.extend(path_vulns)
        for v in path_vulns:
            console.print(f"  {v.severity.emoji} [bold]IDOR (path):[/bold] {v.title}")

        # 3. HTTP method test
        method_vulns = await self._test_http_method(url)
        vulns.extend(method_vulns)

        return vulns