"""
SARIF 2.1.0 reporter — GitHub Security tab integration.

Drop the generated .sarif file into GitHub Actions:

    - uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: reports/scan.sarif
"""

import json
from pathlib import Path
from core.models import ScanResult, Severity


SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _rule_id(v) -> str:
    if v.cwe_id:
        return v.cwe_id
    # Fallback: slugify vuln_type
    return "BUGSCANNER-" + v.vuln_type.upper().replace(" ", "-")


def to_sarif(result: ScanResult) -> dict:
    """Convert ScanResult to a SARIF 2.1.0 document."""
    rules_map = {}
    sarif_results = []

    for v in result.vulnerabilities:
        rule_id = _rule_id(v)

        # Build rule once per unique id
        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": v.vuln_type,
                "shortDescription": {"text": v.vuln_type},
                "fullDescription": {"text": v.description},
                "helpUri": (v.references[0] if v.references else ""),
                "defaultConfiguration": {
                    "level": SEVERITY_TO_LEVEL.get(v.severity.value, "warning")
                },
                "properties": {
                    "cvss_score": v.cvss_score,
                    "severity": v.severity.value,
                },
            }

        sarif_results.append({
            "ruleId": rule_id,
            "level": SEVERITY_TO_LEVEL.get(v.severity.value, "warning"),
            "message": {
                "text": f"{v.title}\n\n{v.description}"
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": v.url},
                }
            }],
            "properties": {
                "cvss_score": v.cvss_score,
                "severity": v.severity.value,
                "parameter": v.parameter or "",
                "payload_used": v.payload_used or "",
            },
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "BugScanner",
                    "version": "2.1.0",
                    "informationUri": "https://github.com/eldarshiraliyev/BugScanner",
                    "rules": list(rules_map.values()),
                }
            },
            "results": sarif_results,
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": (result.end_time.isoformat() + "Z")
                    if result.end_time else None,
            }],
        }],
    }


async def save_sarif(result: ScanResult, output_dir: str = "./reports") -> Path:
    """Write SARIF file to disk."""
    import aiofiles
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    safe = (result.target
            .replace("https://", "")
            .replace("http://", "")
            .replace("/", "_")
            .replace(":", "_"))
    from datetime import datetime
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = out / f"{safe}_{ts}.sarif"

    sarif = to_sarif(result)
    async with aiofiles.open(path, "w", encoding="utf-8") as f:
        await f.write(json.dumps(sarif, indent=2, ensure_ascii=False))

    return path