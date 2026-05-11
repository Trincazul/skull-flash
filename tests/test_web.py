"""Tests for skullflash.core.web."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from skullflash.core.web import HeaderAnalysis, _check_http_headers, _SECURITY_HEADERS


def _make_mock_client(headers: dict) -> tuple:
    """Return (MockClass, mock_response) for patching httpx.AsyncClient."""
    mock_response = MagicMock()
    mock_response.headers = headers

    mock_instance = AsyncMock()
    mock_instance.get = AsyncMock(return_value=mock_response)
    mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
    mock_instance.__aexit__ = AsyncMock(return_value=False)

    mock_cls = MagicMock(return_value=mock_instance)
    return mock_cls, mock_response


# ---------------------------------------------------------------------------
# _check_http_headers
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_all_headers_present():
    headers = {h: "value" for h in _SECURITY_HEADERS}
    mock_cls, _ = _make_mock_client(headers)

    with patch("skullflash.core.web.httpx.AsyncClient", mock_cls):
        result = await _check_http_headers("https://example.com")

    assert result.score == 100
    assert len(result.missing) == 0
    assert len(result.present) == len(_SECURITY_HEADERS)


@pytest.mark.asyncio
async def test_no_headers_present():
    mock_cls, _ = _make_mock_client({})

    with patch("skullflash.core.web.httpx.AsyncClient", mock_cls):
        result = await _check_http_headers("https://example.com")

    assert result.score == 0
    assert len(result.missing) == len(_SECURITY_HEADERS)
    assert len(result.present) == 0


@pytest.mark.asyncio
async def test_partial_headers():
    present = _SECURITY_HEADERS[:3]
    mock_cls, _ = _make_mock_client({h: "x" for h in present})

    with patch("skullflash.core.web.httpx.AsyncClient", mock_cls):
        result = await _check_http_headers("https://example.com")

    assert len(result.present) == 3
    assert len(result.missing) == len(_SECURITY_HEADERS) - 3


@pytest.mark.asyncio
async def test_network_error_returns_zero_score():
    mock_instance = AsyncMock()
    mock_instance.get = AsyncMock(side_effect=Exception("connection refused"))
    mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
    mock_instance.__aexit__ = AsyncMock(return_value=False)
    mock_cls = MagicMock(return_value=mock_instance)

    with patch("skullflash.core.web.httpx.AsyncClient", mock_cls):
        result = await _check_http_headers("https://unreachable.invalid")

    assert result.score == 0
    assert isinstance(result, HeaderAnalysis)
