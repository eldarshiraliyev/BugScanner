"""
Data models — Vulnerability, ScanResult, Severity
v2.1: Added fp_stats field to ScanResult for false-positive breakdown.
"""

from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from typing import Optional


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score_range(self) -> tuple:
        ranges = {
            "critical": (9.0, 10.0),
            "high":     (7.0, 8.9),
            "medium":   (4.0, 6.9),
            "low":      (1.0, 3.9),
            "info":     (0.0, 0.9),
        }
        return ranges[self.value]

    @property
    def color(self) -> str:
        colors = {
            "critical": "red",
            "high":     "orange3",
            "medium":   "yellow",
            "low":      "blue",
            "info":     "dim",
        }
        return colors[self.value]

    @property
    def emoji(self) -> str:
        emojis = {
            "critical": "🔴",
            "high":     "🟠",
            "medium":   "🟡",
            "low":      "🔵",
            "info":     "⚪",
        }
        return emojis[self.value]


def calculate_severity(cvss_score: float) -> Severity:
    """Calculate severity from CVSS score (CVSS v3.1)."""
    if cvss_score >= 9.0:
        return Severity.CRITICAL
    elif cvss_score >= 7.0:
        return Severity.HIGH
    elif cvss_score >= 4.0:
        return Severity.MEDIUM
    elif cvss_score >= 1.0:
        return Severity.LOW
    return Severity.INFO


@dataclass
class Vulnerability:
    """A single vulnerability finding."""

    vuln_type: str                          # "XSS", "SQLi", "CORS", etc.
    url: str                                # Affected URL
    severity: Severity
    cvss_score: float
    title: str
    description: str
    evidence: str                           # What we observed (response snippet)
    exploitation: str                       # How to exploit
    remediation: str                        # How to fix
    parameter: Optional[str] = None         # Affected parameter
    method: Optional[str] = "GET"
    payload_used: Optional[str] = None      # Successful payload
    curl_poc: Optional[str] = None          # curl PoC command
    cwe_id: Optional[str] = None            # CWE-79, CWE-89, etc.
    references: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type,
            "url": self.url,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "exploitation": self.exploitation,
            "remediation": self.remediation,
            "parameter": self.parameter,
            "method": self.method,
            "payload_used": self.payload_used,
            "curl_poc": self.curl_poc,
            "cwe_id": self.cwe_id,
            "references": self.references,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class PortInfo:
    """An open TCP/UDP port."""

    port: int
    protocol: str           # tcp/udp
    state: str              # open/closed/filtered
    service: str            # http, ssh, mysql, etc.
    version: Optional[str] = None
    banner: Optional[str] = None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)


@dataclass
class SubdomainInfo:
    """A discovered subdomain."""

    subdomain: str
    ip: Optional[str] = None
    status: Optional[int] = None        # HTTP status
    technologies: list[str] = field(default_factory=list)
    open_ports: list[PortInfo] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)


@dataclass
class ScanResult:
    """Complete result of a scan."""

    target: str
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None

    # Recon results
    subdomains: list[SubdomainInfo] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    open_ports: list[PortInfo] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)

    # Vulnerability results
    vulnerabilities: list[Vulnerability] = field(default_factory=list)

    # Statistics
    false_positives_filtered: int = 0
    fp_stats: dict = field(default_factory=dict)   # ← v2.1: FP breakdown

    # ══════════════════════════════════════════════════════════
    #  Computed properties
    # ══════════════════════════════════════════════════════════

    @property
    def vuln_count_by_severity(self) -> dict:
        """Count vulnerabilities grouped by severity level."""
        counts = {s.value: 0 for s in Severity}
        for v in self.vulnerabilities:
            counts[v.severity.value] += 1
        return counts

    @property
    def risk_score(self) -> float:
        """
        Overall risk score — weighted average across all findings.
        Range: 0.0 – 10.0
        """
        if not self.vulnerabilities:
            return 0.0
        weights = {
            "critical": 4,
            "high":     3,
            "medium":   2,
            "low":      1,
            "info":     0,
        }
        total = sum(
            v.cvss_score * weights[v.severity.value]
            for v in self.vulnerabilities
        )
        max_possible = len(self.vulnerabilities) * 10 * 4
        return round((total / max_possible) * 10, 2) if max_possible > 0 else 0.0

    @property
    def duration_seconds(self) -> float:
        """Total scan duration in seconds."""
        if not self.end_time:
            return 0.0
        return (self.end_time - self.start_time).total_seconds()

    # ══════════════════════════════════════════════════════════
    #  Serialization
    # ══════════════════════════════════════════════════════════

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "end_time": (
                self.end_time.isoformat() if self.end_time else None
            ),
            "summary": {
                "subdomains_found": len(self.subdomains),
                "open_ports": len(self.open_ports),
                "endpoints_found": len(self.endpoints),
                "total_vulnerabilities": len(self.vulnerabilities),
                "false_positives_filtered": self.false_positives_filtered,
                "fp_stats": self.fp_stats,
                "by_severity": self.vuln_count_by_severity,
                "risk_score": self.risk_score,
                "duration_seconds": round(self.duration_seconds, 2),
            },
            "technologies": self.technologies,
            "subdomains": [
                {
                    "subdomain": s.subdomain,
                    "ip": s.ip,
                    "status": s.status,
                    "technologies": s.technologies,
                }
                for s in self.subdomains
            ],
            "open_ports": [
                {
                    "port": p.port,
                    "protocol": p.protocol,
                    "state": p.state,
                    "service": p.service,
                    "version": p.version,
                }
                for p in self.open_ports
            ],
            "endpoints": self.endpoints,
            "vulnerabilities": [
                v.to_dict() for v in self.vulnerabilities
            ],
        }