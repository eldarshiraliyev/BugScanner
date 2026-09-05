"""
FastAPI Backend — WebSocket ilə real-time scan progress
"""

import asyncio
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.scanner import BugScanner
from core.reporter import Reporter

app = FastAPI(title="BugScanner API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Aktiv scan-lar
active_scans: dict[str, dict] = {}


# ── Request modelləri ──────────────────────────────────
class ScanRequest(BaseModel):
    url: str
    mode: str = "all"
    port_mode: str = "common"
    skip_subdomains: bool = False
    rps: float = 10.0
    severity_filter: Optional[list[str]] = None


# ── WebSocket manager ──────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.connections: dict[str, WebSocket] = {}

    async def connect(self, scan_id: str, ws: WebSocket):
        await ws.accept()
        self.connections[scan_id] = ws

    def disconnect(self, scan_id: str):
        self.connections.pop(scan_id, None)

    async def send(self, scan_id: str, data: dict):
        ws = self.connections.get(scan_id)
        if ws:
            try:
                await ws.send_text(json.dumps(data))
            except Exception:
                self.disconnect(scan_id)


manager = ConnectionManager()


# ── Rich console-u WebSocket-ə yönləndir ──────────────
class WSConsole:
    """Rich console əvəzinə — mesajları WS-ə göndər"""
    def __init__(self, scan_id: str, loop: asyncio.AbstractEventLoop):
        self.scan_id = scan_id
        self.loop = loop
        self._buffer = []

    def print(self, *args, **kwargs):
        # Rich markup-ı sil
        import re
        text = " ".join(str(a) for a in args)
        text = re.sub(r'\[/?[^\]]+\]', '', text)
        text = text.strip()
        if text:
            self._buffer.append(text)
            asyncio.run_coroutine_threadsafe(
                manager.send(self.scan_id, {
                    "type": "log",
                    "message": text,
                    "timestamp": datetime.now().isoformat(),
                }),
                self.loop
            )


# ── Endpoints ──────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0"}


@app.post("/api/scan/start")
async def start_scan(req: ScanRequest):
    scan_id = str(uuid.uuid4())[:8]

    active_scans[scan_id] = {
        "id": scan_id,
        "url": req.url,
        "status": "queued",
        "started_at": datetime.now().isoformat(),
        "result": None,
        "error": None,
    }

    # Background-da scan başlat
    asyncio.create_task(_run_scan(scan_id, req))

    return {"scan_id": scan_id, "status": "queued"}


async def _run_scan(scan_id: str, req: ScanRequest):
    active_scans[scan_id]["status"] = "running"

    await manager.send(scan_id, {
        "type": "status",
        "status": "running",
        "message": f"Scan başladı: {req.url}",
    })

    try:
        config = None
        if req.rps != 10.0:
            from core.scanner import load_config
            config = load_config()
            config["rate_limiting"]["default_rps"] = req.rps

        scanner = BugScanner(config=config)
        result = await scanner.scan(
            target=req.url,
            modes=[req.mode],
            port_mode=req.port_mode,
            skip_subdomains=req.skip_subdomains,
        )

        # Report saxla
        reporter = Reporter()
        paths = await reporter.save_all(result)

        result_dict = result.to_dict()
        result_dict["report_paths"] = {
            k: str(v) for k, v in paths.items()
        }

        active_scans[scan_id]["status"] = "completed"
        active_scans[scan_id]["result"] = result_dict

        await manager.send(scan_id, {
            "type": "completed",
            "status": "completed",
            "result": result_dict,
        })

    except Exception as e:
        active_scans[scan_id]["status"] = "error"
        active_scans[scan_id]["error"] = str(e)

        await manager.send(scan_id, {
            "type": "error",
            "status": "error",
            "message": str(e),
        })


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    scan = active_scans.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan tapılmadı")
    return scan


@app.get("/api/scans")
async def list_scans():
    return list(active_scans.values())


@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: str):
    active_scans.pop(scan_id, None)
    return {"deleted": scan_id}


@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(scan_id: str, ws: WebSocket):
    await manager.connect(scan_id, ws)
    try:
        # Əgər scan artıq qurtarıbsa — nəticəni dərhal göndər
        scan = active_scans.get(scan_id)
        if scan and scan["status"] == "completed":
            await ws.send_text(json.dumps({
                "type": "completed",
                "result": scan["result"],
            }))

        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(scan_id)


# Static files — React build
static_dir = Path(__file__).parent / "frontend" / "dist"
if static_dir.exists():
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")
else:
    @app.get("/")
    async def root():
        return JSONResponse({"message": "Frontend build yoxdur. npm run build edin."})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)