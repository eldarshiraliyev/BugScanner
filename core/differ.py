"""
Scan Differ — compare two ScanResult objects and highlight deltas.

Useful for:
- Re-scanning a target after some time to see what changed
- Verifying that a remediation actually fixed things
- Bug bounty workflows (what's new since last scan?)
"""

from dataclasses import dataclass, field
from core.models import ScanResult, Vulnerability


def _vuln_key(v: Vulnerability) -> str:
    """Stable identity for a vulnerability (URL + type + parameter)."""
    return f"{v.vuln_type}|{v.url}|{v.parameter or ''}"


@dataclass
class ScanDiff:
    old_target: str
    new_target: str

    new_vulnerabilities: list[Vulnerability] = field(default_factory=list)
    fixed_vulnerabilities: list[Vulnerability] = field(default_factory=list)
    unchanged_vulnerabilities: list[Vulnerability] = field(default_factory=list)

    new_subdomains: list[str] = field(default_factory=list)
    removed_subdomains: list[str] = field(default_factory=list)

    new_ports: list[int] = field(default_factory=list)
    closed_ports: list[int] = field(default_factory=list)

    new_endpoints: list[str] = field(default_factory=list)
    removed_endpoints: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.new_vulnerabilities
            or self.fixed_vulnerabilities
            or self.new_subdomains
            or self.removed_subdomains
            or self.new_ports
            or self.closed_ports
            or self.new_endpoints
            or self.removed_endpoints
        )

    @property
    def summary(self) -> dict:
        return {
            "new_vulns": len(self.new_vulnerabilities),
            "fixed_vulns": len(self.fixed_vulnerabilities),
            "unchanged_vulns": len(self.unchanged_vulnerabilities),
            "new_subdomains": len(self.new_subdomains),
            "removed_subdomains": len(self.removed_subdomains),
            "new_ports": len(self.new_ports),
            "closed_ports": len(self.closed_ports),
            "new_endpoints": len(self.new_endpoints),
            "removed_endpoints": len(self.removed_endpoints),
        }

    def to_dict(self) -> dict:
        return {
            "old_target": self.old_target,
            "new_target": self.new_target,
            "summary": self.summary,
            "new_vulnerabilities": [v.to_dict() for v in self.new_vulnerabilities],
            "fixed_vulnerabilities": [v.to_dict() for v in self.fixed_vulnerabilities],
            "new_subdomains": self.new_subdomains,
            "removed_subdomains": self.removed_subdomains,
            "new_ports": self.new_ports,
            "closed_ports": self.closed_ports,
            "new_endpoints": self.new_endpoints,
            "removed_endpoints": self.removed_endpoints,
        }


def diff_scans(old: ScanResult, new: ScanResult) -> ScanDiff:
    """Compute the difference between two ScanResult objects."""
    result = ScanDiff(old_target=old.target, new_target=new.target)

    # ── Vulnerabilities ──
    old_vuln_map = {_vuln_key(v): v for v in old.vulnerabilities}
    new_vuln_map = {_vuln_key(v): v for v in new.vulnerabilities}

    for key, v in new_vuln_map.items():
        if key not in old_vuln_map:
            result.new_vulnerabilities.append(v)
        else:
            result.unchanged_vulnerabilities.append(v)

    for key, v in old_vuln_map.items():
        if key not in new_vuln_map:
            result.fixed_vulnerabilities.append(v)

    # ── Subdomains ──
    old_subs = {s.subdomain for s in old.subdomains}
    new_subs = {s.subdomain for s in new.subdomains}
    result.new_subdomains = sorted(new_subs - old_subs)
    result.removed_subdomains = sorted(old_subs - new_subs)

    # ── Ports ──
    old_ports = {p.port for p in old.open_ports}
    new_ports = {p.port for p in new.open_ports}
    result.new_ports = sorted(new_ports - old_ports)
    result.closed_ports = sorted(old_ports - new_ports)

    # ── Endpoints ──
    old_eps = set(old.endpoints)
    new_eps = set(new.endpoints)
    result.new_endpoints = sorted(new_eps - old_eps)
    result.removed_endpoints = sorted(old_eps - new_eps)

    return result