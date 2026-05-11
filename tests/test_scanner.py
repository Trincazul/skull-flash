"""Tests for skullflash.core.scanner."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from skullflash.core.scanner import ScanResult, _parse_nmap_xml, scan_target

_SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="localhost"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


# ---------------------------------------------------------------------------
# _parse_nmap_xml unit tests
# ---------------------------------------------------------------------------

def test_parse_basic_host():
    hosts = _parse_nmap_xml(_SAMPLE_XML)
    assert len(hosts) == 1
    assert hosts[0].ip == "127.0.0.1"
    assert hosts[0].hostname == "localhost"
    assert hosts[0].state == "up"


def test_parse_services():
    hosts = _parse_nmap_xml(_SAMPLE_XML)
    services = hosts[0].services
    assert len(services) == 2
    ssh = services[0]
    assert ssh.port == 22
    assert ssh.protocol == "tcp"
    assert ssh.name == "ssh"
    assert ssh.product == "OpenSSH"
    assert ssh.version == "8.9"


def test_parse_empty_xml():
    assert _parse_nmap_xml("<nmaprun></nmaprun>") == []


def test_parse_invalid_xml():
    assert _parse_nmap_xml("not xml at all <<<") == []


def test_parse_host_without_services():
    xml = """<nmaprun>
      <host>
        <status state="down"/>
        <address addr="10.0.0.1" addrtype="ipv4"/>
        <hostnames/>
        <ports/>
      </host>
    </nmaprun>"""
    hosts = _parse_nmap_xml(xml)
    assert len(hosts) == 1
    assert hosts[0].state == "down"
    assert hosts[0].services == []


# ---------------------------------------------------------------------------
# scan_target integration (mocked subprocess)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scan_target_success():
    mock_proc = AsyncMock()
    mock_proc.returncode = 0
    mock_proc.communicate = AsyncMock(return_value=(_SAMPLE_XML.encode(), b""))

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scan_target("127.0.0.1", ports="22-80")

    assert isinstance(result, ScanResult)
    assert result.target == "127.0.0.1"
    assert len(result.hosts) == 1
    assert result.duration_seconds >= 0


@pytest.mark.asyncio
async def test_scan_target_nmap_missing():
    with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError):
        with pytest.raises(FileNotFoundError):
            await scan_target("127.0.0.1")


@pytest.mark.asyncio
async def test_scan_target_returns_empty_on_nmap_error():
    mock_proc = AsyncMock()
    mock_proc.returncode = 1
    mock_proc.communicate = AsyncMock(return_value=(b"", b"nmap: error"))

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scan_target("127.0.0.1")

    assert result.hosts == []
