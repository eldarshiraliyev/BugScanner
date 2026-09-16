"""
Nuclei Wrapper — run Nuclei scan and parse results.
v2.1: Uses configured template path, adds rate limiting, respects config.
"""

import asyncio
import json
import os
import shutil
from rich.console import Console
from core.models import Vulnerability, Severity

console = Console()

SEVERITY_MAP = {
    "critical": (Severity.CRITICAL, 9.5),
    "high":     (Severity.HIGH,     8.0),
    "medium":   (Severity.MEDIUM,   5.5),
    "low":      (Severity.LOW,      2.5),
    "info":     (Severity.INFO,     0.5),
}


class NucleiWrapper:
    def __init__(self, config: dict = None):
        self.nuclei_path = shutil.which("nuclei")
        self.available = self.nuclei_path is not None

        cfg = (config or {}).get("nuclei", {})
        self.templates_path = os.path.expanduser(
            cfg.get("templates_path", "~/.local/nuclei-templates")
        )
        self.severity_filter = cfg.get(
            "severity", ["critical", "high", "medium", "low"]
        )
        self.rate_limit = cfg.get("rate_limit", 150)

    async def _run(self, cmd: list[str]) -> tuple[int, str, str]:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return proc.returncode, stdout.decode(), stderr.decode()

    async def update_templates(self):
        if not self.available:
            return
        console.print("[dim]Updating Nuclei templates...[/dim]")
        await self._run([self.nuclei_path, "-update-templates", "-silent"])

    def _parse_jsonl(self, output: str) -> list[Vulnerability]:
        vulns = []
        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            sev_str = data.get("info", {}).get("severity", "info").lower()
            severity, cvss = SEVERITY_MAP.get(sev_str, (Severity.INFO, 0.5))

            info = data.get("info", {})
            matched_at = data.get("matched-at", data.get("host", ""))
            template_id = data.get("template-id", "unknown")
            name = info.get("name", template_id)
            description = info.get("description", "Nuclei template finding")
            remediation = info.get("remediation", "See Nuclei template")

            refs = info.get("reference", [])
            if isinstance(refs, str):
                refs = [refs]

            tags = info.get("tags", [])
            tags_str = ", ".join(tags) if isinstance(tags, list) else str(tags)

            vulns.append(Vulnerability(
                vuln_type=f"Nuclei: {template_id}",
                url=matched_at,
                severity=severity,
                cvss_score=cvss,
                title=name,
                description=description,
                evidence=(
                    f"Template: {template_id}\n"
                    f"Tags: {tags_str}\n"
                    f"Matched: {matched_at}"
                ),
                exploitation=(
                    f"Run the Nuclei template manually:\n"
                    f"nuclei -u {matched_at} -t {template_id} -v"
                ),
                remediation=remediation,
                references=refs[:5],
                curl_poc=f"nuclei -u '{matched_at}' -t '{template_id}'",
                cwe_id=None,
            ))

        return vulns

    async def scan(
        self,
        target: str,
        severity: list[str] = None,
        templates: list[str] = None,
        rate_limit: int = None,
    ) -> list[Vulnerability]:

        if not self.available:
            console.print("[yellow]⚠  Nuclei not found — skipping[/yellow]")
            console.print("[dim]  Install: https://github.com/projectdiscovery/nuclei[/dim]")
            return []

        console.print(f"\n[bold cyan]☢️  Nuclei scan:[/bold cyan] {target}")

        cmd = [
            self.nuclei_path,
            "-u", target,
            "-severity", ",".join(severity or self.severity_filter),
            "-rate-limit", str(rate_limit or self.rate_limit),
            "-json",
            "-silent",
            "-no-interactsh",
        ]

        # v2.1 — use configured template path if it exists
        if templates:
            cmd += ["-t", ",".join(templates)]
        elif self.templates_path and os.path.isdir(self.templates_path):
            cmd += ["-t", self.templates_path]
        else:
            console.print(
                f"[yellow]  ⚠ Template path not found ({self.templates_path}), "
                f"using default templates[/yellow]"
            )

        returncode, stdout, stderr = await self._run(cmd)

        if returncode != 0 and not stdout:
            console.print(f"[red]Nuclei error: {stderr[:200]}[/red]")
            return []

        vulns = self._parse_jsonl(stdout)
        console.print(f"[bold green]  Nuclei: {len(vulns)} findings[/bold green]")

        for v in vulns:
            console.print(
                f"  {v.severity.emoji} [bold]{v.severity.value.upper()}[/bold] "
                f"{v.title} — {v.url[:50]}"
            )

        return vulns