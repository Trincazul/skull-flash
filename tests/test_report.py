"""Tests for skullflash.output.report."""
from __future__ import annotations

import json
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from skullflash.core.scanner import HostResult, ScanResult, ServiceResult
from skullflash.output.report import _to_dict, export_json


def _make_scan() -> ScanResult:
    svc = ServiceResult(port=443, protocol="tcp", state="open", name="https", version="1.1", product="nginx")
    host = HostResult(ip="10.0.0.1", hostname="server.local", state="up", services=[svc])
    return ScanResult(
        target="10.0.0.1",
        timestamp=datetime(2024, 6, 1, 12, 0, 0),
        hosts=[host],
        duration_seconds=2.5,
    )


# ---------------------------------------------------------------------------
# _to_dict
# ---------------------------------------------------------------------------

def test_to_dict_scan():
    d = _to_dict(_make_scan())
    assert d["target"] == "10.0.0.1"
    assert d["duration_seconds"] == 2.5
    assert len(d["hosts"]) == 1


def test_to_dict_nested_service():
    d = _to_dict(_make_scan())
    svc = d["hosts"][0]["services"][0]
    assert svc["port"] == 443
    assert svc["product"] == "nginx"


def test_to_dict_datetime_as_string():
    d = _to_dict(_make_scan())
    assert isinstance(d["timestamp"], str)
    assert "2024" in d["timestamp"]


def test_to_dict_list():
    result = _to_dict([_make_scan(), _make_scan()])
    assert isinstance(result, list)
    assert len(result) == 2


# ---------------------------------------------------------------------------
# export_json
# ---------------------------------------------------------------------------

def test_export_json_creates_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "result.json"
        export_json(_make_scan(), out)
        assert out.exists()


def test_export_json_valid_content():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "result.json"
        export_json(_make_scan(), out)
        data = json.loads(out.read_text())
        assert data["target"] == "10.0.0.1"
        assert data["hosts"][0]["ip"] == "10.0.0.1"


def test_export_json_creates_parent_dirs():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "deep" / "nested" / "result.json"
        export_json(_make_scan(), out)
        assert out.exists()
