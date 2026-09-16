"""Shared pytest fixtures."""

import pytest
from core.models import ScanResult, Vulnerability, Severity, SubdomainInfo, PortInfo


@pytest.fixture
def empty_result():
    return ScanResult(target="https://example.com")


@pytest.fixture
def sample_vuln():
    return Vulnerability(
        vuln_type="XSS",
        url="https://example.com/search?q=x",
        severity=Severity.HIGH,
        cvss_score=7.2,
        title="Reflected XSS",
        description="Test",
        evidence="Test",
        exploitation="Test",
        remediation="Test",
        parameter="q",
    )


@pytest.fixture
def populated_result():
    r = ScanResult(target="https://example.com")
    r.technologies = ["nginx/1.18", "PHP 8.1"]
    r.subdomains = [
        SubdomainInfo(subdomain="api.example.com", ip="1.2.3.4", status=200),
        SubdomainInfo(subdomain="admin.example.com", ip="1.2.3.5", status=403),
    ]
    r.open_ports = [
        PortInfo(port=22, protocol="tcp", state="open", service="ssh"),
        PortInfo(port=443, protocol="tcp", state="open", service="https"),
    ]
    r.endpoints = ["https://example.com/api", "https://example.com/admin"]
    r.vulnerabilities = [
        Vulnerability(
            vuln_type="XSS", url="https://example.com/x?q=1",
            severity=Severity.HIGH, cvss_score=7.2,
            title="XSS", description="d", evidence="e",
            exploitation="ex", remediation="r",
        ),
        Vulnerability(
            vuln_type="CORS", url="https://example.com/api",
            severity=Severity.MEDIUM, cvss_score=5.4,
            title="CORS", description="d", evidence="e",
            exploitation="ex", remediation="r",
        ),
    ]
    return r