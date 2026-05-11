"""Faraday CE integration — push findings via the Faraday REST API."""
from __future__ import annotations

import os
from typing import Any, Dict, List

import httpx
from loguru import logger

from skullflash.core.correlation import Finding, Severity
from skullflash.integrations.base import IntegrationBase


_SEVERITY_MAP = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "med",
    Severity.LOW: "low",
    Severity.INFO: "info",
}


class FaradayIntegration(IntegrationBase):
    """Push skull-flash findings to Faraday CE via its bulk_create API.

    Required environment variables:
      SKULLFLASH_FARADAY_URL      — e.g. http://localhost:5985
      SKULLFLASH_FARADAY_TOKEN    — API token from Faraday settings
      SKULLFLASH_FARADAY_WORKSPACE — workspace slug (e.g. "mypentest")
    """

    def __init__(self, workspace: str = "") -> None:
        self._base = os.environ.get("SKULLFLASH_FARADAY_URL", "http://localhost:5985").rstrip("/")
        self._token = os.environ.get("SKULLFLASH_FARADAY_TOKEN", "")
        self._workspace = workspace or os.environ.get("SKULLFLASH_FARADAY_WORKSPACE", "")

    async def push_findings(
        self, findings: List[Finding], target: str
    ) -> Dict[str, Any]:
        """Bulk-create vulnerabilities in Faraday.

        Args:
            findings: Correlation engine findings to push.
            target: Scan target (used as Faraday host label).

        Returns:
            Dict with 'created' count and server response.
        """
        if not self._workspace:
            raise ValueError("Set SKULLFLASH_FARADAY_WORKSPACE env var or pass workspace=.")

        headers = {"Authorization": f"Token {self._token}", "Content-Type": "application/json"}
        url = f"{self._base}/api/v3/ws/{self._workspace}/bulk_create"

        payload = self._build_payload(findings, target)

        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()

        logger.info(f"Pushed {len(findings)} findings to Faraday workspace {self._workspace!r}")
        return {"created": len(findings), "response": data}

    def _build_payload(self, findings: List[Finding], target: str) -> Dict[str, Any]:
        ip = target.split(":")[0] if ":" in target else target
        vulnerabilities = []

        for finding in findings:
            vulnerabilities.append({
                "name": finding.title,
                "description": finding.description,
                "severity": _SEVERITY_MAP.get(finding.severity, "info"),
                "cvss2": {"base_score": finding.cvss_score} if finding.cvss_score else {},
                "refs": finding.references,
                "custom_fields": {
                    "finding_id": finding.id,
                    "remediation": finding.remediation,
                    "evidence": "\n".join(finding.evidence),
                },
                "status": "open",
                "type": "VulnerabilityWeb" if "https://" in target or "http://" in target else "Vulnerability",
            })

        return {
            "hosts": [{
                "ip": ip,
                "description": f"Skull Flash scan target: {target}",
                "hostnames": [target] if target != ip else [],
                "services": [],
                "vulnerabilities": vulnerabilities,
            }]
        }
