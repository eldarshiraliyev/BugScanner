"""
IDOR — Insecure Direct Object Reference Scanner
- Numeric ID manipulation
- UUID/GUID enumeration hints
- Parameter pollution
- HTTP method switching (with SPA fallback detection)
"""

import asyncio
import re
import uuid
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console
from core.models import Vulnerability, Severity

console = Console()

# IDOR-prone parameters
IDOR_PARAM_HINTS = [
    "id", "user_id", "userid", "uid", "account", "account_id",
    "order", "order_id", "invoice", "invoice_id", "file", "file_id",
    "doc", "document", "document_id", "record", "record_id",
    "profile", "profile_id", "customer", "customer_id",
    "ticket", "ticket_id", "report", "report_id", "msg", "message_id",
    "pid", "cid", "rid", "num", "number", "ref", "reference",
]

# IDOR-prone URL path patterns
PATH_ID_PATTERN = re.compile(
    r'/(\d+)(?:/|$)|'
    r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)',
    re.IGNORECASE
)

# SPA shell signals — if response contains these, it's likely the SPA index.html
SPA_SHELL_SIGNALS = [
    '<div id="root">',
    '<div id="app">',
    '<div id="__next">',
    '<div id="__nuxt">',
    'window.__NUXT__',
    'window.__INITIAL_STATE__',
    'window.__NEXT_DATA__',
    '__vite_plugin_react_preamble',
    '<script src="/static/js/',
    '<script src="/assets/',
    '<script type="module" src="/src/',
    'you need to enable javascript',
    'please enable javascript',
]

# Generic error signals in body (even with 200 OK)
ERROR_PAGE_SIGNALS = [
    'not found',
    'page not found',
    'does not exist',
    'no such endpoint',
    'cannot find',
    'resource not found',
    'the page you requested',
    '404 error',
]


class IDORScanner:
    def __init__(self, http_client):
        self.http_client = http_client
        # Cache SPA detection per-domain to avoid repeated checks
        self._spa_cache: dict[str, bool] = {}

    # ══════════════════════════════════════════════════════════
    #  Helpers — Body analysis
    # ══════════════════════════════════════════════════════════

    @staticmethod
    def _similar_body(a: str, b: str, tolerance: float = 0.1) -> bool:
        """
        Are two response bodies essentially the same?
        Uses length + first-2000-chars comparison.
        """
        if not a or not b:
            return False
        max_len = max(len(a), len(b))
        if max_len == 0:
            return True
        # If lengths differ by more than `tolerance`, they're different
        if abs(len(a) - len(b)) / max_len > tolerance:
            return False
        # Compare prefix (ignoring dynamic tokens near the end)
        return a[:2000] == b[:2000]

    @staticmethod
    def _looks_like_spa_shell(body: str, content_type: str) -> bool:
        """Detect SPA index.html fallback."""
        if "text/html" not in content_type.lower():
            return False
        body_lower = body.lower()
        return any(sig in body_lower for sig in SPA_SHELL_SIGNALS)

    @staticmethod
    def _looks_like_error_page(body: str) -> bool:
        """Detect soft-404 / generic error pages that return 200."""
        if not body:
            return False
        # Only check first 5KB — error text is usually near the top
        body_lower = body[:5000].lower()
        return any(sig in body_lower for sig in ERROR_PAGE_SIGNALS)

    def _extract_domain(self, url: str) -> str:
        import tldextract
        ext = tldextract.extract(url)
        return f"{ext.domain}.{ext.suffix}"

    async def _detect_spa_fallback(self, url: str) -> bool:
        """
        Detect if the target uses SPA fallback: any random path returns 200
        with the same body as the base URL.

        Result is cached per-domain.
        """
        domain = self._extract_domain(url)
        if domain in self._spa_cache:
            return self._spa_cache[domain]

        # Baseline: fetch the given URL
        base_resp = await self.http_client.get(url)
        if not base_resp or base_resp.status_code != 200:
            self._spa_cache[domain] = False
            return False

        # Request a URL that almost certainly doesn't exist
        parsed = urlparse(url)
        fake_path = (
            parsed.path.rstrip("/")
            + f"/__bugscanner_nonexistent_{uuid.uuid4().hex[:10]}"
        )
        fake_url = urlunparse(parsed._replace(path=fake_path))

        fake_resp = await self.http_client.get(fake_url)
        if not fake_resp:
            self._spa_cache[domain] = False
            return False

        # SPA fallback: fake URL also returns 200 with same body
        is_spa = (
            fake_resp.status_code == 200
            and self._similar_body(base_resp.text, fake_resp.text)
        )

        self._spa_cache[domain] = is_spa
        if is_spa:
            console.print(
                f"  [yellow]⚠ SPA fallback detected on {domain} — "
                f"skipping method-based checks[/yellow]"
            )
        return is_spa

    # ══════════════════════════════════════════════════════════
    #  IDOR — Parameter / Path ID
    # ══════════════════════════════════════════════════════════

    def _extract_idor_params(self, url: str) -> list[tuple[str, str]]:
        """Extract IDOR-prone parameter + value pairs."""
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
        """Find IDs in URL path — (position, original, type)."""
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
        """Generate test IDs."""
        if id_type == "numeric":
            orig_int = int(original)
            candidates = []
            for delta in [-1, 1, -2, 2, 10, -10, 100]:
                new_id = orig_int + delta
                if new_id > 0:
                    candidates.append(str(new_id))
            for admin_id in ["1", "2", "0", "admin"]:
                if admin_id != original:
                    candidates.append(admin_id)
            return candidates

        elif id_type == "uuid":
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
        test_id: str,
    ) -> bool:
        """
        Determine if this is a real IDOR:
        - Status 200
        - Different content (different user data)
        - Not an SPA shell / error page
        """
        if not test_resp or test_resp.status_code != 200:
            return False
        if not original_resp or original_resp.status_code != 200:
            return False

        # Same content → not new data
        if test_resp.text == original_resp.text:
            return False

        # Too small → error page
        if len(test_resp.text) < 50:
            return False

        # Original ID still visible, new ID not → same resource
        if original_id in test_resp.text and test_id not in test_resp.text:
            return False

        # SPA shell / error page check
        ct = test_resp.headers.get("content-type", "")
        if self._looks_like_spa_shell(test_resp.text, ct):
            return False
        if self._looks_like_error_page(test_resp.text):
            return False

        return True

    async def _test_param_idor(
        self, url: str, param: str, original_value: str
    ) -> Vulnerability | None:
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
                    title=f"Potential IDOR — '{param}' parameter",
                    description=(
                        f"Replacing '{param}={original_value}' with '{test_id}' "
                        f"returned different content. "
                        f"Authorization checks may be missing."
                    ),
                    evidence=(
                        f"Original: {param}={original_value} → {original_resp.status_code} "
                        f"({len(original_resp.text)} bytes)\n"
                        f"Modified: {param}={test_id} → {test_resp.status_code} "
                        f"({len(test_resp.text)} bytes)"
                    ),
                    exploitation=(
                        f"1. Log in with your own account\n"
                        f"2. Open this URL: {test_url}\n"
                        f"3. Check if you're viewing another user's data\n\n"
                        f"Automated enumeration:\n"
                        f"for i in $(seq 1 100); do\n"
                        f"  curl -s -b 'session=YOUR_TOKEN' \\\n"
                        f"  '{self._inject_param(url, param, '$i')}' | python3 -m json.tool\n"
                        f"done"
                    ),
                    remediation=(
                        "1. Verify resource ownership on every request\n"
                        "2. Use indirect references (mapping) instead of direct object IDs\n"
                        "3. Use UUIDs instead of sequential numeric IDs\n"
                        "4. Authorize resource access server-side"
                    ),
                    parameter=param,
                    payload_used=f"{param}={test_id}",
                    curl_poc=f'curl -s -H "Cookie: YOUR_SESSION" "{test_url}"',
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
                        title=f"Potential IDOR — Path ID ({original_id} → {test_id})",
                        description=(
                            f"Replacing path ID '{original_id}' with '{test_id}' "
                            f"returned different authorized content."
                        ),
                        evidence=(
                            f"Original URL: {url} → {original_resp.status_code}\n"
                            f"Modified URL: {test_url} → {test_resp.status_code} "
                            f"({len(test_resp.text)} bytes)"
                        ),
                        exploitation=(
                            f"Enumerate sequential IDs to view other users' data:\n"
                            f"for i in $(seq 1 50); do\n"
                            f"  curl -s -b 'session=TOKEN' \\\n"
                            f"  '{self._inject_path_id(url, original_id, '$i')}'\n"
                            f"done"
                        ),
                        remediation=(
                            "1. Authorize path parameters server-side\n"
                            "2. Verify resource ownership\n"
                            "3. Use UUIDs instead of sequential numeric IDs"
                        ),
                        payload_used=f"path: {original_id} → {test_id}",
                        curl_poc=f'curl -s "{test_url}"',
                        cwe_id="CWE-639",
                    ))
                    break

        return vulns

    # ══════════════════════════════════════════════════════════
    #  HTTP Method testing (SPA-aware)
    # ══════════════════════════════════════════════════════════

    async def _test_http_method(self, url: str) -> list[Vulnerability]:
        """
        Test non-GET HTTP methods with false-positive protection:
        1. SPA fallback check → skip if SPA shell returns 200 for everything
        2. Body similarity vs. GET baseline
        3. Content-Type sanity check
        4. Error page detection in body
        """
        vulns: list[Vulnerability] = []

        # ── Skip if SPA fallback detected ──
        if await self._detect_spa_fallback(url):
            return vulns

        # ── Baseline GET ──
        base_resp = await self.http_client.get(url)
        if not base_resp:
            return vulns
        base_body = base_resp.text
        base_ct = base_resp.headers.get("content-type", "").lower()

        # ── Also grab a known-bad URL as an error-page reference ──
        parsed = urlparse(url)
        fake_path = (
            parsed.path.rstrip("/")
            + f"/__bugscanner_404_{uuid.uuid4().hex[:8]}"
        )
        fake_url = urlunparse(parsed._replace(path=fake_path))
        fake_resp = await self.http_client.get(fake_url)
        fake_body = fake_resp.text if fake_resp else ""

        methods = ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
        http_methods_to_report = {"DELETE", "PUT", "PATCH"}

        for method in methods:
            resp = await self.http_client.request(method, url)
            if not resp:
                continue

            status = resp.status_code

            # Obvious rejection → skip
            if status in (400, 401, 403, 404, 405, 406, 415, 501):
                continue

            # Only consider successful responses for write methods
            if not (200 <= status < 300):
                continue

            body = resp.text
            ct = resp.headers.get("content-type", "").lower()

            # ── Filter A: identical to GET baseline → not a new capability ──
            if self._similar_body(body, base_body):
                continue

            # ── Filter B: identical to fake-404 baseline → soft-404 ──
            if fake_body and self._similar_body(body, fake_body):
                continue

            # ── Filter C: SPA shell returned for an API/content endpoint ──
            if self._looks_like_spa_shell(body, ct):
                continue

            # ── Filter D: body contains error-page signals ──
            if self._looks_like_error_page(body):
                continue

            # ── Filter E: OPTIONS — only report if Allow advertises write verbs ──
            if method == "OPTIONS":
                allow = resp.headers.get("allow", "").upper()
                if not any(v in allow for v in ("DELETE", "PUT", "PATCH")):
                    continue
                # If we got here, it's a real Allow header finding
                vulns.append(Vulnerability(
                    vuln_type="IDOR",
                    url=url,
                    severity=Severity.LOW,
                    cvss_score=3.7,
                    title=f"OPTIONS Advertises Write Methods ({allow})",
                    description=(
                        f"OPTIONS response advertises write methods: {allow}. "
                        f"Confirm authorization is enforced per-method."
                    ),
                    evidence=(
                        f"HTTP OPTIONS → {status}\n"
                        f"Allow: {allow}"
                    ),
                    exploitation=(
                        f"curl -X OPTIONS -i '{url}' | grep -i allow"
                    ),
                    remediation=(
                        "1. Restrict Allow to required methods only\n"
                        "2. Enforce authorization per HTTP method"
                    ),
                    method="OPTIONS",
                    curl_poc=f'curl -X OPTIONS -i "{url}"',
                    cwe_id="CWE-650",
                ))
                continue

            # ── Filter F: content-type sanity — if API expected, HTML is suspicious ──
            expects_json = any(
                hint in url.lower()
                for hint in ("/api/", "/v1/", "/v2/", "/graphql", ".json")
            )
            if expects_json and "text/html" in ct:
                # API endpoint returning HTML → fallback page
                continue

            # ── Filter G: empty body for DELETE is actually a good sign, not a finding ──
            # We want *demonstrable* acceptance, not just status 200
            if method == "DELETE" and len(body.strip()) < 5:
                # Empty 200 DELETE is suspicious but could be a soft-accept.
                # Require corroboration: check that GET still works after.
                # For safety, still report but as MEDIUM.
                follow_up = await self.http_client.get(url)
                still_200 = follow_up is not None and follow_up.status_code == 200
                if not still_200:
                    # GET no longer works → DELETE actually succeeded → CRITICAL
                    vulns.append(Vulnerability(
                        vuln_type="IDOR",
                        url=url,
                        severity=Severity.CRITICAL,
                        cvss_score=9.1,
                        title=f"Unauthenticated DELETE — resource destroyed",
                        description=(
                            f"DELETE returned {status} and the resource is no "
                            f"longer accessible via GET. This is a destructive "
                            f"unauthorized write."
                        ),
                        evidence=(
                            f"DELETE → {status}\n"
                            f"GET afterward → {follow_up.status_code if follow_up else 'no response'}"
                        ),
                        exploitation=(
                            f"curl -X DELETE '{url}'"
                        ),
                        remediation=(
                            "1. Enforce authentication and authorization on DELETE\n"
                            "2. Add CSRF protection\n"
                            "3. Use soft-delete with audit logging"
                        ),
                        method="DELETE",
                        curl_poc=f'curl -X DELETE "{url}"',
                        cwe_id="CWE-650",
                    ))
                # else: DELETE was a no-op (200 but resource intact) → not a finding
                continue

            # ── Real write method acceptance ──
            if method in http_methods_to_report:
                vulns.append(Vulnerability(
                    vuln_type="IDOR",
                    url=url,
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    title=f"HTTP Method {method} Accepted",
                    description=(
                        f"Endpoint accepts {method} ({status}) and returns a "
                        f"response distinct from the GET baseline. "
                        f"Data may be modifiable/deletable without authorization."
                    ),
                    evidence=(
                        f"HTTP {method} → {status}\n"
                        f"Content-Type: {ct or 'unknown'}\n"
                        f"Body size: {len(body)} bytes"
                    ),
                    exploitation=(
                        f"curl -X {method} \\\n"
                        f"  -H 'Content-Type: application/json' \\\n"
                        f"  -d '{{\"admin\": true}}' \\\n"
                        f"  '{url}'"
                    ),
                    remediation=(
                        f"1. Allow only necessary HTTP methods\n"
                        f"2. Enforce authorization for each method\n"
                        f"3. Add CSRF protection for {method}"
                    ),
                    method=method,
                    curl_poc=f'curl -X {method} -s "{url}"',
                    cwe_id="CWE-650",
                ))

        return vulns

    # ══════════════════════════════════════════════════════════
    #  Main entry point
    # ══════════════════════════════════════════════════════════

    async def scan(self, url: str) -> list[Vulnerability]:
        console.print(f"  [dim]IDOR scan: {url[:60]}[/dim]")
        vulns: list[Vulnerability] = []

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

        # 3. HTTP method testing (SPA-aware)
        method_vulns = await self._test_http_method(url)
        vulns.extend(method_vulns)
        for v in method_vulns:
            console.print(f"  {v.severity.emoji} [bold]Method:[/bold] {v.title}")

        return vulns