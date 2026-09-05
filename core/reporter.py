"""
Reporter — JSON və HTML report generasiyası
"""

import json
import asyncio
import aiofiles
from pathlib import Path
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from markupsafe import Markup, escape
from rich.console import Console
from core.models import ScanResult

console = Console()

TEMPLATE_DIR = Path(__file__).parent.parent / "reports"
REPORTS_DIR = Path("./reports")


def format_dt(dt) -> str:
    if dt is None:
        return ""
    if isinstance(dt, datetime):
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    return str(dt)[:19].replace("T", " ")


def safe_text(value) -> Markup:
    """HTML escape et amma newline-ları <br>-ə çevir"""
    if value is None:
        return Markup("")
    return Markup(str(escape(str(value))).replace('\n', '<br>'))


def safe_code(value) -> Markup:
    """Kod blokları üçün — escape et, newline saxla"""
    if value is None:
        return Markup("")
    return Markup(str(escape(str(value))))


class Reporter:
    def __init__(self, output_dir: str = None):
        self.output_dir = Path(output_dir or REPORTS_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.jinja = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=True,  # XSS qoruması
        )
        self.jinja.filters["format_dt"]  = format_dt
        self.jinja.filters["safe_text"]  = safe_text
        self.jinja.filters["safe_code"]  = safe_code
        self.jinja.globals["Markup"]     = Markup

    def _filename_base(self, target: str) -> str:
        safe = (target
                .replace("https://", "")
                .replace("http://", "")
                .replace("/", "_")
                .replace(":", "_"))
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{safe}_{ts}"

    async def save_json(self, result: ScanResult) -> Path:
        base = self._filename_base(result.target)
        path = self.output_dir / f"{base}.json"
        data = result.to_dict()
        async with aiofiles.open(path, "w", encoding="utf-8") as f:
            await f.write(json.dumps(data, indent=2, ensure_ascii=False))
        console.print(f"[green]💾 JSON report:[/green] {path}")
        return path

    async def save_html(self, result: ScanResult) -> Path:
        base = self._filename_base(result.target)
        path = self.output_dir / f"{base}.html"
        template = self.jinja.get_template("template.html")
        html = template.render(result=result, format_dt=format_dt)
        async with aiofiles.open(path, "w", encoding="utf-8") as f:
            await f.write(html)
        console.print(f"[green]🌐 HTML report:[/green] {path}")
        return path

    async def save_all(self, result: ScanResult) -> dict[str, Path]:
        json_path, html_path = await asyncio.gather(
            self.save_json(result),
            self.save_html(result),
        )
        return {"json": json_path, "html": html_path}