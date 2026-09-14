"""
WAF Detection + Evasion Engine
"""

import asyncio
import random
import re
import httpx
from rich.console import Console

console = Console()

# Known WAF signatures
WAF_SIGNATURES = {
    "Cloudflare": [
        "__cfduid", "cf-ray", "cloudflare", "cf-cache-status",
        "attention required", "cf-request-id",
    ],
    "Akamai": [
        "akamai", "ak_bmsc", "bm_sv", "akamaighost",
    ],
    "AWS WAF": [
        "awswaf", "x-amzn-requestid", "x-amz-cf-id",
    ],
    "Imperva / Incapsula": [
        "incap_ses", "visid_incap", "incapsula", "x-iinfo",
    ],
    "Sucuri": [
        "x-sucuri-id", "sucuri", "x-sucuri-cache",
    ],
    "F5 BIG-IP": [
        "bigip", "f5", "ts01", "tspd",
    ],
    "Barracuda": [
        "bni__isessionid", "barracuda",
    ],
    "ModSecurity": [
        "mod_security", "modsecurity", "not acceptable",
    ],
    "Nginx WAF": [
        "nginx", "openresty",
    ],
}

# Evasion strategies per WAF
WAF_EVASION = {
    "Cloudflare": {
        "delay": 2.0,
        "rps": 3,
        "rotate_ua": True,
        "chunked_payloads": True,
    },
    "Akamai": {
        "delay": 1.5,
        "rps": 5,
        "rotate_ua": True,
        "chunked_payloads": True,
    },
    "AWS WAF": {
        "delay": 1.0,
        "rps": 5,
        "rotate_ua": False,
        "chunked_payloads": True,
    },
    "default": {
        "delay": 1.0,
        "rps": 8,
        "rotate_ua": True,
        "chunked_payloads": False,
    },
}

# Realistic browser User-Agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
]

# WAF bypass headers
BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
]


class WAFDetector:
    def __init__(self, http_client):
        self.http_client = http_client
        self.detected_waf = None
        self.evasion_config = WAF_EVASION["default"]

    async def detect(self, url: str) -> dict:
        """Detect WAF and return evasion configuration."""
        result = {
            "waf": None,
            "confidence": 0,
            "evasion": WAF_EVASION["default"],
            "blocked": False,
        }

        response = await self.http_client.get(url)
        if not response:
            return result

        headers_str = " ".join(
            f"{k} {v}" for k, v in response.headers.items()
        ).lower()
        body_lower = response.text[:2000].lower()
        cookies_str = str(response.cookies).lower()
        combined = headers_str + body_lower + cookies_str

        for waf_name, signatures in WAF_SIGNATURES.items():
            hits = sum(1 for sig in signatures if sig.lower() in combined)
            if hits > 0:
                confidence = min(100, hits * 25)
                if confidence > result["confidence"]:
                    result["waf"] = waf_name
                    result["confidence"] = confidence
                    result["evasion"] = WAF_EVASION.get(
                        waf_name, WAF_EVASION["default"]
                    )

        if response.status_code in (403, 406, 429, 503):
            result["blocked"] = True

        if result["waf"]:
            self.detected_waf = result["waf"]
            self.evasion_config = result["evasion"]
            console.print(
                f"  [yellow]⚠️  WAF detected:[/yellow] "
                f"[bold]{result['waf']}[/bold] "
                f"(confidence: {result['confidence']}%)"
            )
            console.print(
                f"  [dim]→ Evasion: RPS={result['evasion']['rps']}, "
                f"delay={result['evasion']['delay']}s, "
                f"UA rotation={result['evasion']['rotate_ua']}[/dim]"
            )
        else:
            console.print("  [green]✓ No WAF detected[/green]")

        return result

    def get_random_ua(self) -> str:
        return random.choice(USER_AGENTS)

    def get_bypass_headers(self) -> dict:
        return random.choice(BYPASS_HEADERS)

    def should_rotate_ua(self) -> bool:
        return self.evasion_config.get("rotate_ua", False)