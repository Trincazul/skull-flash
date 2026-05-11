"""Tests for skullflash.core.osint."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import dns.resolver

from skullflash.core.osint import DnsResult, WhoisResult, _dns_lookup, _whois_lookup, run_osint


# ---------------------------------------------------------------------------
# _whois_lookup
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_whois_lookup_success():
    mock_w = MagicMock()
    mock_w.registrar = "Example Registrar LLC"
    mock_w.creation_date = "2000-01-01"
    mock_w.expiration_date = "2030-01-01"
    mock_w.name_servers = ["ns1.example.com", "ns2.example.com"]

    with patch("skullflash.core.osint.whois.whois", return_value=mock_w):
        result = await _whois_lookup("example.com")

    assert isinstance(result, WhoisResult)
    assert result.domain == "example.com"
    assert result.registrar == "Example Registrar LLC"
    assert len(result.name_servers) == 2


@pytest.mark.asyncio
async def test_whois_lookup_list_fields():
    mock_w = MagicMock()
    mock_w.registrar = ["Registrar A", "Registrar B"]
    mock_w.creation_date = None
    mock_w.expiration_date = None
    mock_w.name_servers = []

    with patch("skullflash.core.osint.whois.whois", return_value=mock_w):
        result = await _whois_lookup("example.com")

    assert "Registrar A" in result.registrar


@pytest.mark.asyncio
async def test_whois_lookup_exception_propagates():
    with patch("skullflash.core.osint.whois.whois", side_effect=Exception("Timeout")):
        with pytest.raises(Exception, match="Timeout"):
            await _whois_lookup("bad.example")


# ---------------------------------------------------------------------------
# _dns_lookup
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_dns_lookup_returns_records():
    mock_rdata = MagicMock()
    mock_rdata.to_text.return_value = "93.184.216.34"
    mock_answers = [mock_rdata]

    with patch("dns.asyncresolver.Resolver") as MockResolver:
        instance = MockResolver.return_value
        instance.resolve = AsyncMock(return_value=mock_answers)
        result = await _dns_lookup("example.com")

    assert isinstance(result, DnsResult)
    assert result.domain == "example.com"


@pytest.mark.asyncio
async def test_dns_lookup_no_records():
    with patch("dns.asyncresolver.Resolver") as MockResolver:
        instance = MockResolver.return_value
        instance.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN)
        result = await _dns_lookup("nonexistent.invalid")

    assert result.records == {}


# ---------------------------------------------------------------------------
# run_osint
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_osint_tolerates_whois_failure():
    mock_rdata = MagicMock()
    mock_rdata.to_text.return_value = "1.2.3.4"

    with patch("skullflash.core.osint.whois.whois", side_effect=Exception("Timeout")), \
         patch("dns.asyncresolver.Resolver") as MockResolver:
        MockResolver.return_value.resolve = AsyncMock(return_value=[mock_rdata])
        result = await run_osint("example.com")

    assert result.whois is None
    assert result.dns is not None
