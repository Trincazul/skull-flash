"""Async nmap wrapper that returns typed dataclasses."""
from __future__ import annotations

import asyncio
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from typing import List

from loguru import logger


@dataclass
class ServiceResult:
    port: int
    protocol: str
    state: str
    name: str
    version: str
    product: str


@dataclass
class HostResult:
    ip: str
    hostname: str
    state: str
    services: List[ServiceResult] = field(default_factory=list)


@dataclass
class ScanResult:
    target: str
    timestamp: datetime
    hosts: List[HostResult] = field(default_factory=list)
    duration_seconds: float = 0.0


async def scan_target(
    target: str,
    ports: str = "1-1000",
    timeout: int = 30,
) -> ScanResult:
    """Run an nmap service scan asynchronously and return structured results.

    Args:
        target: IP address, hostname, or CIDR range to scan.
        ports: Port range string (e.g. "1-1000" or "22,80,443").
        timeout: Per-host timeout in seconds passed to nmap --host-timeout.

    Returns:
        ScanResult with parsed host and service information.

    Raises:
        FileNotFoundError: If nmap is not installed.
        asyncio.TimeoutError: If the scan exceeds timeout + 10 seconds.
    """
    start = datetime.now()
    logger.info(f"Scanning {target} ports {ports}")

    cmd = [
        "nmap", "-sV", "-oX", "-",
        "--host-timeout", f"{timeout}s",
        "-p", ports,
        target,
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout + 10,
        )
    except FileNotFoundError:
        logger.error("nmap not found — install it with: apt install nmap / brew install nmap")
        raise
    except asyncio.TimeoutError:
        proc.kill()
        logger.error(f"Scan of {target} exceeded timeout")
        raise

    duration = (datetime.now() - start).total_seconds()
    result = ScanResult(target=target, timestamp=start, duration_seconds=duration)

    if proc.returncode == 0 and stdout:
        result.hosts = _parse_nmap_xml(stdout.decode(errors="replace"))
    elif stderr:
        logger.warning(f"nmap stderr: {stderr.decode(errors='replace')[:300]}")

    logger.info(f"Scan done: {len(result.hosts)} host(s) in {duration:.1f}s")
    return result


def _parse_nmap_xml(xml_output: str) -> List[HostResult]:
    """Parse nmap -oX output into HostResult objects."""
    hosts: List[HostResult] = []
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        logger.warning(f"nmap XML parse error: {exc}")
        return hosts

    for host_elem in root.findall("host"):
        status = host_elem.find("status")
        state = status.attrib.get("state", "unknown") if status is not None else "unknown"

        addr = host_elem.find("address[@addrtype='ipv4']")
        ip = addr.attrib.get("addr", "") if addr is not None else ""

        hostname = ""
        hostnames = host_elem.find("hostnames")
        if hostnames is not None:
            first = hostnames.find("hostname")
            if first is not None:
                hostname = first.attrib.get("name", "")

        host = HostResult(ip=ip, hostname=hostname, state=state)

        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                port_state = port_elem.find("state")
                svc = port_elem.find("service")
                host.services.append(ServiceResult(
                    port=int(port_elem.attrib.get("portid", 0)),
                    protocol=port_elem.attrib.get("protocol", "tcp"),
                    state=port_state.attrib.get("state", "") if port_state is not None else "",
                    name=svc.attrib.get("name", "") if svc is not None else "",
                    version=svc.attrib.get("version", "") if svc is not None else "",
                    product=svc.attrib.get("product", "") if svc is not None else "",
                ))

        hosts.append(host)

    return hosts
