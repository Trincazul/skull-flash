"""CVE correlation via the NVD API v2 with local 24-hour cache."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

import httpx
from loguru import logger

from skullflash.core.scanner import ScanResult, ServiceResult
from skullflash.utils.rate_limit import RateLimiter


_CACHE_FILE = Path.home() / ".skullflash" / "cve_cache.json"
_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class CveEntry:
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    published: str


@dataclass
class CveResult:
    service: str
    version: str
    cves: List[CveEntry] = field(default_factory=list)


async def correlate_cves(
    scan_result: ScanResult,
    api_key: Optional[str] = None,
) -> List[CveResult]:
    """Look up CVEs in NVD for each service/version found in a ScanResult.

    Without an API key NVD allows 5 requests per 30 s; with a key, 50/30 s.
    Results are cached in ~/.skullflash/cve_cache.json for 24 hours.

    Args:
        scan_result: Completed port scan.
        api_key: Optional NVD API key for higher rate limits.

    Returns:
        List of CveResult ordered by first appearance in the scan.
    """
    rate = (50 / 30) if api_key else (5 / 30)
    limiter = RateLimiter(rate)
    cache = _load_cache()
    results: List[CveResult] = []
    seen: set[str] = set()

    for host in scan_result.hosts:
        for svc in host.services:
            if not svc.product and not svc.name:
                continue
            cache_key = f"{(svc.product or svc.name).lower()}:{svc.version.lower()}"
            if cache_key in seen:
                continue
            seen.add(cache_key)

            cve_result = CveResult(service=svc.product or svc.name, version=svc.version)

            if cache_key in cache and _is_fresh(cache[cache_key].get("timestamp", "")):
                cve_result.cves = [CveEntry(**e) for e in cache[cache_key]["cves"]]
                logger.debug(f"CVE cache hit for {cache_key}")
            else:
                await limiter.acquire()
                cve_result.cves = await _fetch_cves(svc, api_key)
                cache[cache_key] = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "cves": [vars(c) for c in cve_result.cves],
                }

            results.append(cve_result)

    _save_cache(cache)
    return results


async def _fetch_cves(svc: ServiceResult, api_key: Optional[str]) -> List[CveEntry]:
    keyword = f"{svc.product} {svc.version}".strip() if svc.product else svc.name
    if not keyword:
        return []

    params: dict = {"keywordSearch": keyword, "resultsPerPage": 10}
    headers = {"apiKey": api_key} if api_key else {}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(_NVD_URL, params=params, headers=headers)
            response.raise_for_status()
            data = response.json()
    except Exception as exc:
        logger.warning(f"NVD API error for {keyword!r}: {exc}")
        return []

    entries: List[CveEntry] = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        descs = cve.get("descriptions", [])
        description = next((d["value"] for d in descs if d.get("lang") == "en"), "")[:200]

        score, severity = 0.0, "UNKNOWN"
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve.get("metrics", {}).get(metric_key, [])
            if metrics:
                cvss_data = metrics[0].get("cvssData", {})
                score = float(cvss_data.get("baseScore", 0.0))
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
                break

        entries.append(CveEntry(
            cve_id=cve_id,
            description=description,
            cvss_score=score,
            severity=severity,
            published=cve.get("published", ""),
        ))

    return sorted(entries, key=lambda x: x.cvss_score, reverse=True)


def _load_cache() -> dict:
    try:
        if _CACHE_FILE.exists():
            return json.loads(_CACHE_FILE.read_text())
    except Exception as exc:
        logger.debug(f"Could not load CVE cache: {exc}")
    return {}


def _save_cache(cache: dict) -> None:
    _CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        _CACHE_FILE.write_text(json.dumps(cache, indent=2))
    except Exception as exc:
        logger.warning(f"Could not save CVE cache: {exc}")


def _is_fresh(timestamp: str) -> bool:
    try:
        dt = datetime.fromisoformat(timestamp)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - dt < timedelta(hours=24)
    except Exception:
        return False
