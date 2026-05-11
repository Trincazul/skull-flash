"""Passive technology and OS fingerprinting via HTTP headers and response analysis."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import httpx
from loguru import logger


_SIGNATURES_FILE = Path(__file__).parent.parent / "data" / "signatures.json"

# Typical SSH banner fragments and their OS mappings
_SSH_OS_HINTS: List[tuple] = [
    (r"Ubuntu", "Ubuntu Linux"),
    (r"Debian", "Debian Linux"),
    (r"CentOS", "CentOS Linux"),
    (r"Red Hat|RedHat|RHEL", "Red Hat Enterprise Linux"),
    (r"Fedora", "Fedora Linux"),
    (r"FreeBSD", "FreeBSD"),
    (r"OpenBSD", "OpenBSD"),
    (r"Windows", "Windows"),
]


@dataclass
class TechFingerprint:
    url: str
    server: Optional[str] = None
    language: Optional[str] = None
    framework: Optional[str] = None
    cms: Optional[str] = None
    cdn: Optional[str] = None
    waf: Optional[str] = None
    os_hint: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    confidence: Dict[str, int] = field(default_factory=dict)
    raw_headers: Dict[str, str] = field(default_factory=dict)


def _load_signatures() -> Dict:
    try:
        return json.loads(_SIGNATURES_FILE.read_text())
    except Exception as exc:
        logger.warning(f"Could not load signatures: {exc}")
        return {}


async def detect_technologies(url: str, timeout: int = 10) -> TechFingerprint:
    """Identify web technologies via passive HTTP response analysis.

    This function only performs a single GET request — no attack payloads,
    no active port probing. Analysis is based solely on the response.

    Args:
        url: Target URL (include scheme).
        timeout: HTTP timeout in seconds.

    Returns:
        TechFingerprint with detected technologies and confidence scores.
    """
    result = TechFingerprint(url=url)
    sigs = _load_signatures()

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; SkullFlash/2.0)"},
        ) as client:
            response = await client.get(url)
    except Exception as exc:
        logger.warning(f"Tech fingerprint request failed for {url}: {exc}")
        return result

    headers = {k.lower(): v for k, v in response.headers.items()}
    result.raw_headers = dict(response.headers)
    body = response.text[:50_000]  # cap memory usage

    # ── Direct header hints ──────────────────────────────────────────────────
    result.server = response.headers.get("Server", "").split("/")[0] or None
    powered_by = response.headers.get("X-Powered-By", "")
    if powered_by:
        result.language = powered_by.split("/")[0]

    # ── Signature matching ───────────────────────────────────────────────────
    cookies_str = " ".join(response.headers.getlist("set-cookie"))

    for tech_name, sig in sigs.items():
        score = 0
        base = int(sig.get("confidence_base", 80))

        # Header matching
        for header, pattern in (sig.get("headers") or {}).items():
            value = response.headers.get(header, "")
            if value and re.search(pattern, value, re.IGNORECASE):
                score += base

        # Cookie matching
        for cookie_pattern in (sig.get("cookies") or []):
            if re.search(cookie_pattern, cookies_str, re.IGNORECASE):
                score += 20

        # Meta tag matching
        for attr, pattern in (sig.get("meta") or {}).items():
            meta_pattern = rf'<meta[^>]+name=["\']?{attr}["\']?[^>]+content=["\']?([^"\'>\s]+)'
            match = re.search(meta_pattern, body, re.IGNORECASE)
            if match and re.search(pattern, match.group(1), re.IGNORECASE):
                score += 40

        if score > 0:
            result.confidence[tech_name] = min(100, score)
            result.technologies.append(tech_name)

    # ── Classify detections into categories ─────────────────────────────────
    _CMS = {"WordPress", "Drupal", "Joomla", "Magento", "Shopify", "Wix"}
    _CDN = {"Cloudflare", "AWS CloudFront", "Akamai", "Fastly", "Imperva", "Varnish", "Squid"}
    _FRAMEWORK = {"Laravel", "Django", "Ruby on Rails", "Spring Boot", "Express.js", "ASP.NET", "Next.js", "Nuxt.js"}
    _SERVERS = {"nginx", "Apache", "IIS", "LiteSpeed", "Caddy", "OpenResty", "Traefik"}

    by_conf = sorted(result.technologies, key=lambda t: result.confidence.get(t, 0), reverse=True)

    for tech in by_conf:
        if tech in _CMS and not result.cms:
            result.cms = tech
        if tech in _CDN and not result.cdn:
            result.cdn = tech
        if tech in _FRAMEWORK and not result.framework:
            result.framework = tech
        if tech in _SERVERS and not result.server:
            result.server = tech

    # ── OS hint from Server header ───────────────────────────────────────────
    server_full = response.headers.get("Server", "")
    for pattern, os_name in _SSH_OS_HINTS:
        if re.search(pattern, server_full, re.IGNORECASE):
            result.os_hint = os_name
            break

    # Windows / IIS hint
    if "IIS" in server_full or "ASP.NET" in response.headers.get("X-Powered-By", ""):
        result.os_hint = result.os_hint or "Windows Server"

    return result


async def os_fingerprint_passive(ip: str, open_ports: List[int]) -> Optional[str]:
    """Infer OS from port presence and service banners without sending special packets.

    This is a passive inference function — it only looks at already-collected
    scan data and does not initiate new connections.

    Args:
        ip: Target IP address.
        open_ports: List of open TCP ports from a prior nmap scan.

    Returns:
        Human-readable OS guess string, or None if inconclusive.
    """
    ports_set = set(open_ports)

    # Windows-specific ports
    if {445, 139} & ports_set:
        if 3389 in ports_set:
            return "Windows (SMB + RDP)"
        return "Windows (SMB)"
    if 3389 in ports_set and not ({22} & ports_set):
        return "Windows (RDP, no SSH)"

    # Linux / Unix hints
    if 22 in ports_set:
        try:
            import asyncio
            import socket
            loop = asyncio.get_running_loop()

            def _grab_banner() -> str:
                with socket.create_connection((ip, 22), timeout=5) as s:
                    return s.recv(256).decode(errors="replace")

            banner = await loop.run_in_executor(None, _grab_banner)
            for pattern, os_name in _SSH_OS_HINTS:
                if re.search(pattern, banner, re.IGNORECASE):
                    return os_name
            return "Linux/Unix (SSH banner inconclusive)"
        except Exception:
            return "Linux/Unix (SSH open, banner unavailable)"

    # Port 80/443 only — no strong OS signal
    if ports_set & {80, 443, 8080, 8443}:
        return None

    return None
