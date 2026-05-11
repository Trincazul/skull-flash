"""HTTP security headers analysis and SSL/TLS certificate inspection."""
from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import httpx
from cryptography import x509
from loguru import logger


_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]


@dataclass
class HeaderAnalysis:
    url: str
    present: Dict[str, str] = field(default_factory=dict)
    missing: List[str] = field(default_factory=list)
    score: int = 0  # 0-100 based on percentage of headers present


@dataclass
class SslAnalysis:
    domain: str
    valid: bool = False
    expiry: Optional[str] = None       # ISO format UTC string
    days_remaining: int = 0
    issuer: str = ""
    subject: str = ""
    protocol: str = ""
    cipher: str = ""
    san: List[str] = field(default_factory=list)
    score: int = 0  # 0-100


@dataclass
class WebResult:
    target: str
    headers: Optional[HeaderAnalysis] = None
    ssl: Optional[SslAnalysis] = None
    security_score: int = 0  # average of sub-scores


async def analyze_web(
    url: str,
    check_headers: bool = True,
    check_ssl: bool = True,
    timeout: int = 10,
) -> WebResult:
    """Perform HTTP and SSL/TLS security analysis on a URL.

    Args:
        url: Full URL including scheme (e.g. https://example.com).
        check_headers: Analyze HTTP security response headers.
        check_ssl: Inspect TLS certificate (only for https:// targets).
        timeout: HTTP request timeout in seconds.

    Returns:
        WebResult with header and SSL findings and a composite security score.
    """
    result = WebResult(target=url)
    tasks = []

    if check_headers:
        tasks.append(_check_http_headers(url, timeout))
    if check_ssl and url.startswith("https://"):
        domain = url.split("//", 1)[1].split("/")[0].split(":")[0]
        tasks.append(_check_ssl_cert(domain))

    gathered = await asyncio.gather(*tasks, return_exceptions=True)

    idx = 0
    if check_headers:
        result.headers = gathered[idx] if not isinstance(gathered[idx], Exception) else HeaderAnalysis(url=url)
        idx += 1
    if check_ssl and url.startswith("https://"):
        result.ssl = gathered[idx] if not isinstance(gathered[idx], Exception) else None

    scores = [x.score for x in [result.headers, result.ssl] if x is not None]
    result.security_score = int(sum(scores) / len(scores)) if scores else 0

    return result


async def _check_http_headers(url: str, timeout: int = 10) -> HeaderAnalysis:
    analysis = HeaderAnalysis(url=url)
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.get(url)
        for header in _SECURITY_HEADERS:
            if header in response.headers:
                analysis.present[header] = response.headers[header][:100]
            else:
                analysis.missing.append(header)
        analysis.score = int(len(analysis.present) / len(_SECURITY_HEADERS) * 100)
    except Exception as exc:
        logger.warning(f"HTTP headers check failed for {url}: {exc}")
    return analysis


async def _check_ssl_cert(domain: str, port: int = 443) -> SslAnalysis:
    analysis = SslAnalysis(domain=domain)
    try:
        ctx = ssl.create_default_context()
        der_cert, protocol, cipher = await _fetch_cert(domain, port, ctx)

        cert = x509.load_der_x509_certificate(der_cert)

        expiry_aware = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)
        days_remaining = (expiry_aware - now).days

        analysis.valid = True
        analysis.expiry = expiry_aware.isoformat()
        analysis.days_remaining = days_remaining
        analysis.issuer = _get_cn(cert.issuer) or cert.issuer.rfc4514_string()[:80]
        analysis.subject = _get_cn(cert.subject) or cert.subject.rfc4514_string()[:80]
        analysis.protocol = protocol
        analysis.cipher = cipher[0] if cipher else ""

        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            analysis.san = [str(name.value) for name in san_ext.value][:10]
        except x509.extensions.ExtensionNotFound:
            pass

        if days_remaining > 30:
            analysis.score = 100
        elif days_remaining > 7:
            analysis.score = 60
        else:
            analysis.score = 20

    except ssl.SSLCertVerificationError as exc:
        logger.warning(f"Invalid certificate for {domain}: {exc}")
        analysis.valid = False
        analysis.score = 0
    except (socket.gaierror, socket.timeout, OSError) as exc:
        logger.warning(f"Connection failed for {domain}: {exc}")
    except Exception as exc:
        logger.warning(f"SSL check error for {domain}: {exc}")

    return analysis


async def _fetch_cert(
    domain: str, port: int, ctx: ssl.SSLContext
) -> Tuple[bytes, str, Tuple]:
    """Connect via TLS and return the raw DER certificate, protocol, and cipher."""
    loop = asyncio.get_running_loop()

    def _connect() -> Tuple[bytes, str, Tuple]:
        with socket.create_connection((domain, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                der = tls.getpeercert(binary_form=True)
                return der, tls.version() or "", tls.cipher() or ("", "", 0)

    return await loop.run_in_executor(None, _connect)


def _get_cn(name: x509.Name) -> str:
    try:
        return name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    except (IndexError, Exception):
        return ""
