"""FastAPI dashboard with Server-Sent Events for real-time scan progress."""
from __future__ import annotations

import asyncio
import dataclasses
import json
import uuid
import webbrowser
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="Skull Flash Dashboard", version="2.0.0")

if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

# In-memory state — fine for a single-user local tool
_queues: Dict[str, asyncio.Queue] = {}
_results: Dict[str, Any] = {}


# ── Models ──────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    ports: str = "1-1000"
    run_osint: bool = False
    run_ssl: bool = False
    run_cve: bool = False
    run_web: bool = False


# ── Helpers ──────────────────────────────────────────────────────────────────

def _to_json(obj: Any) -> Any:
    """JSON-safe conversion for dataclasses and Enums."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _to_json(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, list):
        return [_to_json(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _to_json(v) for k, v in obj.items()}
    return obj


async def _push(scan_id: str, payload: dict) -> None:
    q = _queues.get(scan_id)
    if q:
        await q.put(payload)


async def _run_scan(scan_id: str, req: ScanRequest) -> None:
    """Background task: run all requested modules and push SSE events."""
    try:
        from skullflash.config import load_config
        from skullflash.core.correlation import CorrelationEngine
        from skullflash.core.scanner import scan_target

        cfg = load_config()
        scan_result = None
        cve_results = None
        web_result = None

        # ── Port scan ────────────────────────────────────────────────────────
        await _push(scan_id, {"type": "status", "message": f"Iniciando scan em {req.target}…"})
        try:
            scan_result = await scan_target(req.target, ports=req.ports, timeout=cfg.scan_timeout)
            for host in scan_result.hosts:
                await _push(scan_id, {
                    "type": "host_discovered",
                    "host": {"ip": host.ip, "hostname": host.hostname, "state": host.state},
                })
                for svc in host.services:
                    if svc.state == "open":
                        await _push(scan_id, {
                            "type": "port_open",
                            "port": svc.port,
                            "service": svc.name,
                            "product": svc.product,
                            "version": svc.version,
                            "host": host.ip,
                        })
        except FileNotFoundError:
            await _push(scan_id, {"type": "error", "message": "nmap não encontrado."})

        # ── CVE correlation ──────────────────────────────────────────────────
        if req.run_cve and scan_result:
            await _push(scan_id, {"type": "status", "message": "Buscando CVEs…"})
            from skullflash.core.cve import correlate_cves
            cve_results = await correlate_cves(scan_result, api_key=cfg.nvd_api_key)
            total = sum(len(r.cves) for r in cve_results)
            await _push(scan_id, {"type": "status", "message": f"{total} CVEs encontrados"})

        # ── Web / SSL analysis ───────────────────────────────────────────────
        if req.run_web or req.run_ssl:
            url = req.target if req.target.startswith("http") else f"https://{req.target}"
            await _push(scan_id, {"type": "status", "message": "Analisando web…"})
            from skullflash.core.web import analyze_web
            web_result = await analyze_web(
                url,
                check_headers=req.run_web,
                check_ssl=req.run_ssl,
            )
            await _push(scan_id, {"type": "ssl_analyzed", "score": web_result.security_score})

        # ── OSINT ─────────────────────────────────────────────────────────────
        if req.run_osint:
            await _push(scan_id, {"type": "status", "message": "Coletando OSINT…"})
            from skullflash.core.osint import run_osint
            osint = await run_osint(req.target)
            if osint.dns and osint.dns.records:
                await _push(scan_id, {"type": "dns_records", "count": len(osint.dns.records)})

        # ── Correlation ──────────────────────────────────────────────────────
        await _push(scan_id, {"type": "status", "message": "Calculando risco…"})
        engine = CorrelationEngine()
        report = engine.analyze(
            target=req.target,
            scan_result=scan_result,
            cve_results=cve_results,
            web_result=web_result,
        )

        for finding in report.findings:
            await _push(scan_id, {
                "type": "finding",
                "finding": _to_json(finding),
            })

        await _push(scan_id, {"type": "risk_score", "score": report.risk_score})
        await _push(scan_id, {"type": "summary", "text": report.executive_summary})

        _results[scan_id] = {"scan": scan_result, "report": report, "cves": cve_results}

    except Exception as exc:
        await _push(scan_id, {"type": "error", "message": str(exc)})
    finally:
        await _push(scan_id, None)  # SSE sentinel


# ── Routes ───────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    html_path = _TEMPLATES_DIR / "index.html"
    if html_path.exists():
        return HTMLResponse(html_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Skull Flash — template not found</h1>", status_code=500)


@app.post("/api/scan")
async def start_scan(request: ScanRequest) -> Dict[str, str]:
    """Start an async scan and return a scan_id for the SSE stream."""
    scan_id = str(uuid.uuid4())
    _queues[scan_id] = asyncio.Queue()
    asyncio.create_task(_run_scan(scan_id, request))
    return {"scan_id": scan_id}


@app.get("/api/scan/{scan_id}/stream")
async def stream_results(scan_id: str) -> StreamingResponse:
    """SSE stream — yields events as the scan progresses."""
    if scan_id not in _queues:
        raise HTTPException(status_code=404, detail="Scan not found")

    async def _generator():
        q = _queues[scan_id]
        try:
            while True:
                event = await q.get()
                if event is None:
                    yield 'data: {"type":"done"}\n\n'
                    break
                yield f"data: {json.dumps(event)}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            _queues.pop(scan_id, None)

    return StreamingResponse(
        _generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/scan/{scan_id}/report")
async def download_report(scan_id: str, format: str = "json") -> Any:
    """Return the final report for a completed scan."""
    if scan_id not in _results:
        raise HTTPException(status_code=404, detail="Scan result not available yet")

    data = _results[scan_id]

    if format == "json":
        from fastapi.responses import JSONResponse
        return JSONResponse(content=_to_json(data))

    raise HTTPException(status_code=400, detail=f"Format {format!r} not supported via API (use CLI for HTML/PDF)")
