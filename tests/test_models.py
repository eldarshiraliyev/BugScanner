"""Tests for core.models."""

from datetime import datetime
from core.models import (
    Severity, calculate_severity, Vulnerability, PortInfo,
    SubdomainInfo, ScanResult,
)


def test_severity_score_ranges():
    assert Severity.CRITICAL.score_range == (9.0, 10.0)
    assert Severity.INFO.score_range == (0.0, 0.9)


def test_calculate_severity_boundaries():
    assert calculate_severity(9.5) == Severity.CRITICAL
    assert calculate_severity(9.0) == Severity.CRITICAL
    assert calculate_severity(8.9) == Severity.HIGH
    assert calculate_severity(7.0) == Severity.HIGH
    assert calculate_severity(6.9) == Severity.MEDIUM
    assert calculate_severity(4.0) == Severity.MEDIUM
    assert calculate_severity(3.9) == Severity.LOW
    assert calculate_severity(1.0) == Severity.LOW
    assert calculate_severity(0.5) == Severity.INFO


def test_vuln_to_dict_roundtrip():
    v = Vulnerability(
        vuln_type="XSS", url="https://x.com/?q=1",
        severity=Severity.HIGH, cvss_score=7.2,
        title="t", description="d", evidence="e",
        exploitation="ex", remediation="r",
        parameter="q", references=["https://owasp.org"],
    )
    d = v.to_dict()
    assert d["vuln_type"] == "XSS"
    assert d["severity"] == "high"
    assert d["cvss_score"] == 7.2
    assert d["parameter"] == "q"
    assert d["references"] == ["https://owasp.org"]


def test_risk_score_empty():
    r = ScanResult(target="https://x.com")
    assert r.risk_score == 0.0


def test_risk_score_weighted(empty_result):
    empty_result.vulnerabilities = [
        Vulnerability("XSS", "u1", Severity.CRITICAL, 9.5, "t", "d", "e", "ex", "r"),
        Vulnerability("LOW", "u2", Severity.LOW, 2.0, "t", "d", "e", "ex", "r"),
    ]
    score = empty_result.risk_score
    assert 0 < score <= 10


def test_vuln_count_by_severity(populated_result):
    counts = populated_result.vuln_count_by_severity
    assert counts["high"] == 1
    assert counts["medium"] == 1
    assert counts["critical"] == 0


def test_to_dict_has_summary(populated_result):
    d = populated_result.to_dict()
    assert "summary" in d
    assert d["summary"]["subdomains_found"] == 2
    assert d["summary"]["open_ports"] == 2
    assert d["summary"]["total_vulnerabilities"] == 2


def test_false_positives_filtered_field():
    r = ScanResult(target="https://x.com")
    assert r.false_positives_filtered == 0
    r.false_positives_filtered = 5
    d = r.to_dict()
    assert d["summary"]["false_positives_filtered"] == 5