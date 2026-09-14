"""
Port Scanner — asyncio-based TCP connect scan + banner grabbing
"""

import asyncio
import socket
from typing import Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from core.models import PortInfo

console = Console()

# Port → Service mapping (fallback when nmap unavailable)
SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "smb",
    993: "imaps", 995: "pop3s", 1723: "pptp", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 8888: "http-alt",
    9200: "elasticsearch", 27017: "mongodb",
}

# Potential vulnerabilities per port
PORT_VULN_HINTS = {
    21:    "FTP — check anonymous login & plaintext credentials",
    22:    "SSH — brute force & outdated version check",
    23:    "Telnet — plaintext protocol, insecure",
    25:    "SMTP — open relay & user enumeration",
    3306:  "MySQL — remote access & weak credentials",
    3389:  "RDP — BlueKeep & brute force",
    5432:  "PostgreSQL — remote access & weak credentials",
    5900:  "VNC — auth bypass & weak password",
    6379:  "Redis — unauthenticated access (CVE-2022-0543)",
    9200:  "Elasticsearch — unauthenticated data exposure",
    27017: "MongoDB — unauthenticated access",
}


class PortScanner:
    def __init__(self, timeout: float = 1.5, max_concurrent: int = 200):
        self.timeout = timeout
        self.max_concurrent = max_concurrent

    async def _tcp_connect(self, host: str, port: int) -> bool:
        """Simple TCP connect scan."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False

    async def _grab_banner(self, host: str, port: int) -> Optional[str]:
        """Fetch service banner."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=2.0,
            )
            if port in (80, 8080, 8888):
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()

            data = await asyncio.wait_for(reader.read(256), timeout=2.0)
            writer.close()
            banner = data.decode("utf-8", errors="ignore").strip()
            return banner[:200] if banner else None
        except Exception:
            return None

    async def _scan_port(
        self, host: str, port: int, semaphore: asyncio.Semaphore
    ) -> Optional[PortInfo]:
        async with semaphore:
            is_open = await self._tcp_connect(host, port)
            if not is_open:
                return None

            service = SERVICE_MAP.get(port, "unknown")
            banner = await self._grab_banner(host, port)

            version = None
            if banner:
                lines = banner.split("\n")
                version = lines[0][:100] if lines else None

            return PortInfo(
                port=port,
                protocol="tcp",
                state="open",
                service=service,
                version=version,
                banner=banner,
            )

    def _resolve_ports(self, mode: str) -> list[int]:
        if mode == "full":
            return list(range(1, 65536))
        if mode == "extended":
            return sorted(set(SERVICE_MAP.keys()) | {8080, 8443, 8888, 9200, 27017})
        return sorted(SERVICE_MAP.keys())

    async def scan(
        self,
        host: str,
        ports: list[int] = None,
        mode: str = "common",
        chunk_size: int = 5000,
    ) -> list[PortInfo]:
        """
        mode: "common" (~19 ports), "extended" (~30 ports), "full" (1-65535)

        Uses chunked processing to keep memory bounded even for full scans —
        never creates more than `chunk_size` coroutines at once.
        """
        if ports is None:
            ports = self._resolve_ports(mode)

        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            console.print(f"[red]❌ Could not resolve {host}[/red]")
            return []

        console.print(
            f"\n[bold cyan]🔌 Port scan:[/bold cyan] {host} ({ip}) — {len(ports)} ports"
        )

        semaphore = asyncio.Semaphore(self.max_concurrent)
        open_ports: list[PortInfo] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Port scan...[/cyan]", total=len(ports))

            # Chunked processing — avoids spawning 65K coroutines at once
            for i in range(0, len(ports), chunk_size):
                chunk = ports[i:i + chunk_size]

                async def scan_one(port):
                    try:
                        return await self._scan_port(ip, port, semaphore)
                    finally:
                        progress.advance(task)

                results = await asyncio.gather(
                    *[scan_one(p) for p in chunk],
                    return_exceptions=True,
                )
                for r in results:
                    if isinstance(r, PortInfo):
                        open_ports.append(r)

        # Print results after progress bar completes
        open_ports.sort(key=lambda p: p.port)
        for r in open_ports:
            hint = PORT_VULN_HINTS.get(r.port, "")
            hint_str = f" [dim]→ {hint}[/dim]" if hint else ""
            console.print(
                f"  [green]OPEN[/green] {r.port}/tcp  "
                f"[yellow]{r.service}[/yellow]"
                f"{' — ' + r.version[:50] if r.version else ''}"
                f"{hint_str}"
            )

        console.print(
            f"[bold green]  Port scan complete: {len(open_ports)} open ports[/bold green]"
        )
        return open_ports