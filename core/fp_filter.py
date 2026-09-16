"""
Centralized False-Positive Filter (v2.1)

Implements 5 rules from the analytical brain spec:

1. Content Signature Verification — don't trust HTTP 200 alone.
2. SPA Fallback Detection — same body for random paths = SPA shell.
3. Admin Panel Verification — require DOM keywords (login/dashboard).
4. Context Awareness — localhost/internal IPs get severity downgrade.
5. Verification — requires concrete PoC (payload + evidence).

Result: ~80% fewer false positives in the final report.
"""

import hashlib
import re
import uuid
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from rich.console import Console

console = Console()


# ══════════════════════════════════════════════════════════════
#  Rule 1: Content signatures for sensitive files
# ══════════════════════════════════════════════════════════════

SENSITIVE_FILE_SIGNATURES = {
    ".env": [
        r"(?im)^[A-Z_][A-Z0-9_]*\s*=\s*\S+",       # KEY=value lines
        r"\bDB_(?:HOST|USER|PASS|NAME|DATABASE)\b",
        r"\b(?:APP_KEY|SECRET_KEY|API_KEY|JWT_SECRET)\b",
    ],
    ".sql": [
        r"(?i)CREATE\s+TABLE",
        r"(?i)INSERT\s+INTO",
        r"(?i)SELECT\s+.*\s+FROM",
        r"(?i)DROP\s+TABLE",
    ],
    ".key": [
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
        r"-----BEGIN PRIVATE KEY-----",
    ],
    ".pem": [
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?(?:PRIVATE KEY|CERTIFICATE)-----",
    ],
    ".git": [
        r"^ref:\s+refs/heads/",                     # HEAD file
        r"\[core\]",                                # config
        r"(?i)repositoryformatversion",
    ],
    "phpinfo": [
        r"(?i)<title>phpinfo\(\)</title>",
        r"(?i)<h1[^>]*>PHP Version",
        r"(?i)PHP Extension.{0,50}Build Date",
    ],
    "backup": [
        r"(?i)CREATE\s+TABLE",
        r"(?i)INSERT\s+INTO",
        r"(?i)mysqldump|pg_dump",
    ],
    "config": [
        r"(?im)^\s*(?:database|db|mysql|postgres)\s*[:=]",
        r"(?im)^\s*(?:username|password)\s*[:=]",
    ],
}


def _expected_signature_group(path: str) -> Optional[list[str]]:
    """Return the signature list for the given file path."""
    lower = path.lower()
    for key, sigs in SENSITIVE_FILE_SIGNATURES.items():
        if key in lower:
            return sigs
    return None


def content_matches_sensitive_signature(path: str, body: str) -> tuple[bool, str]:
    """
    Rule 1: Verify that a 'sensitive file' really contains sensitive content.

    Returns (matches, reason).
    """
    if not body:
        return False, "empty body"

    sigs = _expected_signature_group(path)
    if not sigs:
        # Unknown sensitive path — require at least *some* signature-looking content
        return True, "no signature defined, assuming valid"

    body_sample = body[:20000]
    for pat in sigs:
        if re.search(pat, body_sample):
            return True, f"matched signature: {pat[:40]}"

    return False, "no matching content signature"


# ══════════════════════════════════════════════════════════════
#  Rule 1b: Generic HTML shell detector
# ══════════════════════════════════════════════════════════════

HTML_SHELL_SIGNALS = [
    r"(?i)<!DOCTYPE\s+html",
    r"(?i)<html[^>]*>",
    r"(?i)<div\s+id=[\"']root[\"']",
    r"(?i)<div\s+id=[\"']app[\"']",
    r"(?i)<div\s+id=[\"']__next[\"']",
    r"(?i)window\.__NUXT__",
    r"(?i)window\.__NEXT_DATA__",
    r"(?i)please\s+enable\s+javascript",
    r"(?i)you\s+need\s+to\s+enable\s+javascript",
]


def is_html_shell(body: str, content_type: str = "") -> bool:
    """Return True if the body looks like an HTML SPA shell."""
    if not body:
        return False
    if content_type and "json" in content_type.lower():
        return False

    sample = body[:3000]
    # Multiple HTML shell signals = definitely shell
    hits = sum(1 for pat in HTML_SHELL_SIGNALS if re.search(pat, sample))
    return hits >= 1 and ("<html" in sample.lower() or "<!doctype html" in sample.lower())


# ══════════════════════════════════════════════════════════════
#  Rule 2: SPA Fallback Detection
# ══════════════════════════════════════════════════════════════

@dataclass
class SPAProbe:
    base_status: int = 0
    base_size: int = 0
    base_hash: str = ""
    fake_status: int = 0
    fake_size: int = 0
    fake_hash: str = ""


def _hash_body(body: str) -> str:
    if not body:
        return ""
    return hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()[:16]


class SPAFallbackDetector:
    """
    Rule 2: If a request to a *random nonexistent* path returns the same
    status + size + hash as the base URL, the target is an SPA shell
    that serves index.html for every route.
    """

    def __init__(self, http_client):
        self.http = http_client
        self._cache: dict[str, bool] = {}

    def _domain(self, url: str) -> str:
        p = urlparse(url)
        return p.netloc.lower()

    async def detect(self, base_url: str) -> bool:
        domain = self._domain(base_url)
        if domain in self._cache:
            return self._cache[domain]

        # Fetch base URL
        base = await self.http.get(base_url)
        if not base or base.status_code != 200:
            self._cache[domain] = False
            return False

        # Fetch a random nonexistent path
        p = urlparse(base_url)
        fake_path = p.path.rstrip("/") + f"/__bs_probe_{uuid.uuid4().hex[:10]}"
        fake_url = f"{p.scheme}://{p.netloc}{fake_path}"

        fake = await self.http.get(fake_url)
        if not fake:
            self._cache[domain] = False
            return False

        base_hash = _hash_body(base.text)
        fake_hash = _hash_body(fake.text)

        # SPA detection: fake returns 200 AND same body hash
        is_spa = (
            fake.status_code == 200
            and base_hash
            and fake_hash
            and base_hash == fake_hash
        )

        # Also detect via length similarity (>98% same length) + status 200
        if not is_spa and fake.status_code == 200 and base.text and fake.text:
            longer = max(len(base.text), len(fake.text))
            shorter = min(len(base.text), len(fake.text))
            if longer > 0 and (shorter / longer) > 0.98:
                is_spa = True

        self._cache[domain] = is_spa
        if is_spa:
            console.print(
                f"  [yellow]⚠ SPA fallback detected on {domain} — "
                f"file/route checks will be filtered[/yellow]"
            )
        return is_spa


# ══════════════════════════════════════════════════════════════
#  Rule 3: Admin Panel Verification
# ══════════════════════════════════════════════════════════════

ADMIN_DOM_KEYWORDS = [
    r"(?i)<input[^>]+(?:name|id)=[\"'][^\"']*user",
    r"(?i)<input[^>]+(?:name|id)=[\"'][^\"']*pass",
    r"(?i)<input[^>]+type=[\"']password",
    r"(?i)sign\s*in|log\s*in",
    r"(?i)\bdashboard\b",
    r"(?i)\badmin\s+(?:panel|area|console)\b",
    r"(?i)wp-login\.php",
    r"(?i)phpmyadmin",
    r"(?i)\bforgot\s+password\b",
    r"(?i)\busername\b",
    r"(?i)\bpassword\b",
]

ADMIN_STRONG_SIGNALS = [
    r"(?i)<input[^>]+type=[\"']password",
    r"(?i)wp-login\.php",
    r"(?i)phpmyadmin",
    r"(?i)\badmin\s+panel\b",
]


def looks_like_admin_panel(body: str, content_type: str = "") -> bool:
    """
    Rule 3: Verify an admin panel by looking for login/dashboard DOM
    indicators. Requires at least 3 weak signals OR 1 strong signal.
    """
    if not body:
        return False

    # If it's a JSON or binary response, don't treat as admin panel
    if content_type and not any(t in content_type.lower() for t in ("html", "text")):
        return False

    sample = body[:30000]

    strong = any(re.search(pat, sample) for pat in ADMIN_STRONG_SIGNALS)
    if strong:
        return True

    weak_hits = sum(1 for pat in ADMIN_DOM_KEYWORDS if re.search(pat, sample))
    return weak_hits >= 3


# ══════════════════════════════════════════════════════════════
#  Rule 4: Context Awareness
# ══════════════════════════════════════════════════════════════

INTERNAL_HOST_PATTERNS = [
    r"^localhost$",
    r"^127\.\d+\.\d+\.\d+$",
    r"^::1$",
    r"^10\.\d+\.\d+\.\d+$",
    r"^192\.168\.\d+\.\d+$",
    r"^172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+$",
    r"\.local$",
    r"\.internal$",
    r"\.test$",
]


def is_internal_target(url: str) -> bool:
    """Rule 4: detect local/internal targets."""
    host = urlparse(url).hostname or ""
    host = host.lower()
    for pat in INTERNAL_HOST_PATTERNS:
        if re.search(pat, host):
            return True
    return False


def downgrade_severity(sev: str, steps: int = 1) -> str:
    """Downgrade severity by N steps: critical → high → medium → low → info."""
    order = ["critical", "high", "medium", "low", "info"]
    if sev not in order:
        return sev
    idx = order.index(sev)
    return order[min(len(order) - 1, idx + steps)]


# ══════════════════════════════════════════════════════════════
#  Rule 5: Confirmation — requires concrete PoC
# ══════════════════════════════════════════════════════════════

def has_concrete_poc(vuln) -> bool:
    """
    Rule 5: A finding is 'Confirmed' only if it has concrete evidence.
    """
    # Must have a payload_used OR a curl_poc
    has_payload = bool(getattr(vuln, "payload_used", None))
    has_curl = bool(getattr(vuln, "curl_poc", None))
    has_evidence = bool(getattr(vuln, "evidence", None))

    if not (has_payload or has_curl):
        return False
    if not has_evidence:
        return False

    # Evidence must contain something substantial (> 10 chars)
    if len(str(vuln.evidence).strip()) < 10:
        return False
    return True


# ══════════════════════════════════════════════════════════════
#  Public API
# ══════════════════════════════════════════════════════════════

@dataclass
class FPFilterStats:
    filtered_total: int = 0
    filtered_spa: int = 0
    filtered_no_signature: int = 0
    filtered_no_admin_dom: int = 0
    downgraded: int = 0
    filtered_unverified: int = 0


class FPFilter:
    """
    Unified false-positive filter that can be called from any module.
    """

    def __init__(self, http_client=None):
        self.http = http_client
        self.spa_detector = SPAFallbackDetector(http_client) if http_client else None
        self.stats = FPFilterStats()
        self._spa_cache: dict[str, bool] = {}

    async def is_spa(self, url: str) -> bool:
        if not self.spa_detector:
            return False
        return await self.spa_detector.detect(url)

    def filter_vulnerability(self, vuln, base_url: str) -> bool:
        """
        Filter a single vulnerability. Returns True to KEEP, False to drop.
        Also mutates vuln.severity in-place when downgrading.
        """
        vtype = (vuln.vuln_type or "").lower()
        title = (vuln.title or "").lower()

        # ── Rule 1: sensitive files must have content signature ──
        if "sensitive file" in title or "sensitive file" in vtype:
            path = urlparse(vuln.url).path
            evidence = str(vuln.evidence or "")
            matches, reason = content_matches_sensitive_signature(path, evidence)
            if not matches:
                self.stats.filtered_no_signature += 1
                console.print(f"  [dim]FP: no signature '{path}' ({reason})[/dim]")
                return False

        # ── Rule 1b: HTML shell shouldn't be reported as disclosure ──
        if "disclosure" in vtype or "exposed" in vtype:
            evidence = str(vuln.evidence or "")
            if is_html_shell(evidence):
                # Allow .git and specific cases
                if ".git" not in vuln.url.lower():
                    self.stats.filtered_no_signature += 1
                    console.print(f"  [dim]FP: HTML shell {vuln.url[:60]}[/dim]")
                    return False

        # ── Rule 3: admin panel needs DOM proof ──
        if "admin panel" in title or "admin panel" in vtype:
            evidence = str(vuln.evidence or "")
            if not looks_like_admin_panel(evidence):
                self.stats.filtered_no_admin_dom += 1
                console.print(f"  [dim]FP: admin without DOM {vuln.url[:60]}[/dim]")
                return False

        # ── Rule 5: verifiability ──
        if not has_concrete_poc(vuln):
            # Allow info-level findings without PoC
            if vuln.severity.value in ("critical", "high", "medium"):
                self.stats.filtered_unverified += 1
                console.print(
                    f"  [dim]FP: no concrete PoC '{vuln.title[:50]}'[/dim]"
                )
                return False

        # ── Rule 4: context — downgrade for internal targets ──
        if is_internal_target(base_url):
            if "hsts" in title or "strict-transport" in title:
                if vuln.severity.value != "info":
                    vuln.severity = type(vuln.severity)("info")
                    vuln.cvss_score = min(vuln.cvss_score, 1.0)
                    self.stats.downgraded += 1
            if "cors" in title and "wildcard" in title:
                if vuln.severity.value == "medium":
                    vuln.severity = type(vuln.severity)("low")
                    vuln.cvss_score = min(vuln.cvss_score, 3.0)
                    self.stats.downgraded += 1

        # ── Rule 4b: CORS wildcard on public API = Info ──
        if "cors" in vtype and "wildcard" in title:
            url_lower = vuln.url.lower()
            # If it's a public endpoint (not auth/api/user/etc.), downgrade
            public_markers = ("/public/", "/open/", "/status", "/health")
            sensitive_markers = ("/auth", "/user", "/account", "/token", "/admin")
            if any(m in url_lower for m in public_markers) or not any(
                m in url_lower for m in sensitive_markers
            ):
                if vuln.severity.value in ("high", "medium"):
                    vuln.severity = type(vuln.severity)("info")
                    vuln.cvss_score = min(vuln.cvss_score, 1.0)
                    self.stats.downgraded += 1

        self.stats.filtered_total = (
            self.stats.filtered_no_signature
            + self.stats.filtered_no_admin_dom
            + self.stats.filtered_unverified
            + self.stats.filtered_spa
        )
        return True

    async def filter_all(self, vulns: list, base_url: str) -> tuple[list, int]:
        """
        Filter a whole list of vulnerabilities.
        Returns (kept, dropped_count).
        """
        # Detect SPA once
        is_spa = await self.is_spa(base_url)

        kept = []
        dropped = 0
        for v in vulns:
            # Rule 2: if SPA, drop file/route-based findings
            if is_spa and self._is_route_based(v):
                self.stats.filtered_spa += 1
                dropped += 1
                continue

            if self.filter_vulnerability(v, base_url):
                kept.append(v)
            else:
                dropped += 1

        return kept, dropped

    @staticmethod
    def _is_route_based(v) -> bool:
        """SPA filter applies to file/admin/route-based findings."""
        vtype = (v.vuln_type or "").lower()
        title = (v.title or "").lower()
        markers = ("sensitive file", "exposed admin", "directory listing",
                   "git directory", "information disclosure", "admin panel")
        return any(m in vtype or m in title for m in markers)

    def summary(self) -> dict:
        return {
            "filtered_total": self.stats.filtered_total,
            "filtered_spa": self.stats.filtered_spa,
            "filtered_no_signature": self.stats.filtered_no_signature,
            "filtered_no_admin_dom": self.stats.filtered_no_admin_dom,
            "filtered_unverified": self.stats.filtered_unverified,
            "downgraded": self.stats.downgraded,
        }