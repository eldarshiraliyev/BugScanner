"""Tests for FalsePositiveValidator."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from core.validator import FalsePositiveValidator
from core.models import Vulnerability, Severity


def _make_vuln(vtype: str, title: str = "", payload: str = "") -> Vulnerability:
    return Vulnerability(
        vuln_type=vtype, url="https://example.com/",
        severity=Severity.HIGH, cvss_score=7.0,
        title=title or vtype, description="d",
        evidence="e", exploitation="ex", remediation="r",
        payload_used=payload,
    )


@pytest.mark.asyncio
async def test_validate_xss_confirmed():
    http = MagicMock()
    http.get = AsyncMock(return_value=MagicMock(
        text="prefix <script>alert(1)</script> suffix"
    ))
    validator = FalsePositiveValidator(http)
    vuln = _make_vuln("XSS", payload="<script>alert(1)</script>")
    assert await validator.validate_xss(vuln) is True


@pytest.mark.asyncio
async def test_validate_xss_rejected():
    http = MagicMock()
    http.get = AsyncMock(return_value=MagicMock(text="not reflected here"))
    validator = FalsePositiveValidator(http)
    vuln = _make_vuln("XSS", payload="<script>alert(1)</script>")
    assert await validator.validate_xss(vuln) is False


@pytest.mark.asyncio
async def test_validate_sqli_skips_non_time_based():
    http = MagicMock()
    validator = FalsePositiveValidator(http)
    vuln = _make_vuln("SQL Injection", title="Error-Based", payload="' OR 1=1--")
    assert await validator.validate_sqli_time(vuln) is True


@pytest.mark.asyncio
async def test_validate_dispatches_to_correct_validator():
    http = MagicMock()
    http.get = AsyncMock(return_value=MagicMock(text=""))
    validator = FalsePositiveValidator(http)

    # Low-severity or unknown types should pass through (True)
    v = _make_vuln("Unknown Type")
    v.severity = Severity.LOW
    assert await validator.validate(v) is True