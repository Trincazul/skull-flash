"""Tests for passive technology and OS fingerprinting."""
from __future__ import annotations

from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from skullflash.core.fingerprint import TechFingerprint, detect_technologies, os_fingerprint_passive


# ── Helpers ───────────────────────────────────────────────────────────────────

def _mock_response(headers: Dict[str, str], body: str = "", cookies: list | None = None) -> MagicMock:
    response = MagicMock(spec=httpx.Response)
    response.headers = httpx.Headers(headers)
    response.text = body
    return response


# ── detect_technologies ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detect_nginx_from_server_header() -> None:
    mock_resp = _mock_response({"Server": "nginx/1.24.0"})

    with patch("skullflash.core.fingerprint.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_client

        result = await detect_technologies("http://example.com")

    assert isinstance(result, TechFingerprint)
    assert result.server is not None
    assert "nginx" in result.server.lower()


@pytest.mark.asyncio
async def test_detect_php_from_x_powered_by() -> None:
    mock_resp = _mock_response({"X-Powered-By": "PHP/8.2.0", "Server": "Apache"})

    with patch("skullflash.core.fingerprint.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_client

        result = await detect_technologies("http://example.com")

    assert result.language == "PHP"


@pytest.mark.asyncio
async def test_detect_returns_empty_on_network_error() -> None:
    with patch("skullflash.core.fingerprint.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("connection refused"))
        mock_client_cls.return_value = mock_client

        result = await detect_technologies("http://unreachable.local")

    assert isinstance(result, TechFingerprint)
    assert result.url == "http://unreachable.local"
    assert result.technologies == []


@pytest.mark.asyncio
async def test_detect_windows_hint_from_iis() -> None:
    mock_resp = _mock_response({"Server": "Microsoft-IIS/10.0", "X-Powered-By": "ASP.NET"})

    with patch("skullflash.core.fingerprint.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_client

        result = await detect_technologies("http://example.com")

    assert result.os_hint is not None
    assert "Windows" in result.os_hint


@pytest.mark.asyncio
async def test_confidence_scores_are_bounded() -> None:
    mock_resp = _mock_response({"Server": "nginx", "X-Generator": "WordPress 6.5"})

    with patch("skullflash.core.fingerprint.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_client

        result = await detect_technologies("http://example.com")

    for score in result.confidence.values():
        assert 0 <= score <= 100


@pytest.mark.asyncio
async def test_technologies_list_matches_confidence_keys() -> None:
    mock_resp = _mock_response({"Server": "nginx/1.18"})

    with patch("skullflash.core.fingerprint.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_client

        result = await detect_technologies("http://example.com")

    assert set(result.technologies) == set(result.confidence.keys())


# ── os_fingerprint_passive ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_os_fingerprint_windows_smb() -> None:
    result = await os_fingerprint_passive("10.0.0.1", [445, 139, 80])
    assert result is not None
    assert "Windows" in result


@pytest.mark.asyncio
async def test_os_fingerprint_windows_smb_rdp() -> None:
    result = await os_fingerprint_passive("10.0.0.1", [445, 139, 3389])
    assert result is not None
    assert "Windows" in result
    assert "RDP" in result


@pytest.mark.asyncio
async def test_os_fingerprint_windows_rdp_no_ssh() -> None:
    result = await os_fingerprint_passive("10.0.0.1", [3389, 80])
    assert result is not None
    assert "Windows" in result


@pytest.mark.asyncio
async def test_os_fingerprint_web_only_inconclusive() -> None:
    result = await os_fingerprint_passive("10.0.0.1", [80, 443])
    assert result is None


@pytest.mark.asyncio
async def test_os_fingerprint_ssh_fallback_on_error() -> None:
    with patch("skullflash.core.fingerprint.asyncio.get_running_loop") as mock_loop:
        mock_loop_obj = MagicMock()
        mock_loop_obj.run_in_executor = AsyncMock(side_effect=OSError("connection refused"))
        mock_loop.return_value = mock_loop_obj

        result = await os_fingerprint_passive("192.168.1.1", [22])

    assert result is not None
    assert "Linux" in result or "Unix" in result


@pytest.mark.asyncio
async def test_os_fingerprint_empty_ports() -> None:
    result = await os_fingerprint_passive("10.0.0.1", [])
    assert result is None
