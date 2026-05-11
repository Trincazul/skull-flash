"""Tests for the FastAPI web dashboard — routes, SSE stream, and report endpoint."""
from __future__ import annotations

import asyncio
import json

import pytest

fastapi = pytest.importorskip("fastapi", reason="fastapi not installed — skip web UI tests")
httpx = pytest.importorskip("httpx", reason="httpx not installed")

from httpx import ASGITransport, AsyncClient  # noqa: E402

from skullflash.web_ui.server import app, _queues, _results  # noqa: E402


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _clear_state():
    """Isolate server state between tests."""
    _queues.clear()
    _results.clear()
    yield
    _queues.clear()
    _results.clear()


@pytest.fixture
def client_transport():
    return ASGITransport(app=app)


# ── GET / ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dashboard_returns_html(client_transport) -> None:
    async with AsyncClient(transport=client_transport, base_url="http://test") as client:
        resp = await client.get("/")

    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "Skull Flash" in resp.text


# ── POST /api/scan ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_start_scan_returns_scan_id(client_transport) -> None:
    async with AsyncClient(transport=client_transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/scan",
            json={"target": "127.0.0.1", "ports": "80"},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert "scan_id" in data
    assert isinstance(data["scan_id"], str)
    assert len(data["scan_id"]) > 0


@pytest.mark.asyncio
async def test_start_scan_creates_queue(client_transport) -> None:
    async with AsyncClient(transport=client_transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/scan",
            json={"target": "127.0.0.1"},
        )

    scan_id = resp.json()["scan_id"]
    assert scan_id in _queues


@pytest.mark.asyncio
async def test_start_scan_all_modules_off(client_transport) -> None:
    payload = {
        "target": "127.0.0.1",
        "ports": "80",
        "run_osint": False,
        "run_ssl": False,
        "run_cve": False,
        "run_web": False,
    }
    async with AsyncClient(transport=client_transport, base_url="http://test") as client:
        resp = await client.post("/api/scan", json=payload)

    assert resp.status_code == 200


# ── GET /api/scan/{id}/stream ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_stream_not_found(client_transport) -> None:
    async with AsyncClient(transport=client_transport, base_url="http://test") as client:
        resp = await client.get("/api/scan/does-not-exist/stream")

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_stream_yields_done_event(client_transport) -> None:
    """Manually push None sentinel to the queue and verify the stream closes."""
    async with AsyncClient(transport=client_transport, base_url="http://test") as client:
        # Start scan to create queue
        resp = await client.post("/api/scan", json={"target": "127.0.0.1"})
        scan_id = resp.json()["scan_id"]

    # Drain the background task's events and push a sentinel
    q = _queues.get(scan_id) or asyncio.Queue()
    _queues[scan_id] = q
    await q.put({"type": "status", "message": "test"})
    await q.put(None)  # sentinel

    chunks = []
    async with AsyncClient(transport=client_transport, base_url="http://test") as client:
        async with client.stream("GET", f"/api/scan/{scan_id}/stream") as stream:
            async for line in stream.aiter_lines():
                if line.startswith("data:"):
                    chunks.append(json.loads(line[5:].strip()))
                    if chunks and chunks[-1].get("type") == "done":
                        break

    assert any(c.get("type") == "done" for c in chunks)


@pytest.mark.asyncio
async def test_stream_passes_through_finding_event(client_transport) -> None:
    import uuid
    scan_id = str(uuid.uuid4())
    q: asyncio.Queue = asyncio.Queue()
    _queues[scan_id] = q

    finding_payload = {
        "type": "finding",
        "finding": {
            "id": "FIND-001",
            "title": "Test finding",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "description": "desc",
            "evidence": [],
            "remediation": "fix it",
            "references": [],
            "affected_assets": ["10.0.0.1:80"],
        },
    }
    await q.put(finding_payload)
    await q.put(None)

    chunks = []
    async with AsyncClient(transport=client_transport, base_url="http://test") as client:
        async with client.stream("GET", f"/api/scan/{scan_id}/stream") as stream:
            async for line in stream.aiter_lines():
                if line.startswith("data:"):
                    event = json.loads(line[5:].strip())
                    chunks.append(event)
                    if event.get("type") == "done":
                        break

    finding_events = [c for c in chunks if c.get("type") == "finding"]
    assert finding_events
    assert finding_events[0]["finding"]["id"] == "FIND-001"


# ── GET /api/scan/{id}/report ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_report_not_ready_returns_404(client_transport) -> None:
    async with AsyncClient(transport=client_transport, base_url="http://test") as client:
        resp = await client.get("/api/scan/unknown-id/report")

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_report_returns_json_when_available(client_transport) -> None:
    import uuid
    scan_id = str(uuid.uuid4())
    _results[scan_id] = {"scan": None, "report": None, "cves": None}

    async with AsyncClient(transport=client_transport, base_url="http://test") as client:
        resp = await client.get(f"/api/scan/{scan_id}/report?format=json")

    assert resp.status_code == 200
    data = resp.json()
    assert "scan" in data


@pytest.mark.asyncio
async def test_report_unsupported_format_returns_400(client_transport) -> None:
    import uuid
    scan_id = str(uuid.uuid4())
    _results[scan_id] = {"data": "ok"}

    async with AsyncClient(transport=client_transport, base_url="http://test") as client:
        resp = await client.get(f"/api/scan/{scan_id}/report?format=pdf")

    assert resp.status_code == 400
