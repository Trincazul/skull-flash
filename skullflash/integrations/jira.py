"""Jira integration — create one issue per finding above the severity threshold."""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from loguru import logger

from skullflash.core.correlation import Finding, Severity
from skullflash.integrations.base import IntegrationBase


_PRIORITY_MAP = {
    Severity.CRITICAL: "Highest",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Lowest",
}

_THRESHOLD_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


class JiraIntegration(IntegrationBase):
    """Create Jira issues for skull-flash findings.

    Required environment variables:
      SKULLFLASH_JIRA_URL      — e.g. https://company.atlassian.net
      SKULLFLASH_JIRA_TOKEN    — API token (user:token for basic auth, or PAT)
      SKULLFLASH_JIRA_PROJECT  — Project key, e.g. SEC
      SKULLFLASH_JIRA_USER     — User email (required for Jira Cloud basic auth)

    Optional:
      SKULLFLASH_JIRA_SEVERITY_THRESHOLD — Minimum severity to create issues for (default: HIGH)
    """

    def __init__(self) -> None:
        self._url = os.environ.get("SKULLFLASH_JIRA_URL", "")
        self._token = os.environ.get("SKULLFLASH_JIRA_TOKEN", "")
        self._project = os.environ.get("SKULLFLASH_JIRA_PROJECT", "")
        self._user = os.environ.get("SKULLFLASH_JIRA_USER", "")
        threshold_str = os.environ.get("SKULLFLASH_JIRA_SEVERITY_THRESHOLD", "HIGH")
        try:
            self._threshold = Severity[threshold_str.upper()]
        except KeyError:
            self._threshold = Severity.HIGH

    def _above_threshold(self, sev: Severity) -> bool:
        return _THRESHOLD_ORDER.index(sev) <= _THRESHOLD_ORDER.index(self._threshold)

    async def push_findings(
        self, findings: List[Finding], target: str
    ) -> Dict[str, Any]:
        """Create Jira issues for all findings at or above the severity threshold.

        Args:
            findings: Findings from the correlation engine.
            target: Scan target identifier.

        Returns:
            Dict with 'created' (list of issue keys) and 'skipped' (count).
        """
        try:
            from jira import JIRA
        except ImportError as exc:
            raise ImportError(
                "jira package required: pip install 'skull-flash[integrations]'"
            ) from exc

        if not all([self._url, self._token, self._project]):
            raise ValueError(
                "Set SKULLFLASH_JIRA_URL, SKULLFLASH_JIRA_TOKEN, "
                "SKULLFLASH_JIRA_PROJECT env vars."
            )

        auth = (self._user, self._token) if self._user else (self._token,)
        try:
            client = JIRA(server=self._url, basic_auth=auth)
        except Exception as exc:
            raise ConnectionError(f"Could not connect to Jira at {self._url}: {exc}") from exc

        created: List[str] = []
        skipped = 0

        for finding in findings:
            if not self._above_threshold(finding.severity):
                skipped += 1
                continue

            description = self._format_description(finding, target)
            try:
                issue = client.create_issue(fields={
                    "project": {"key": self._project},
                    "summary": f"[Skull Flash] {finding.title}",
                    "description": description,
                    "issuetype": {"name": "Bug"},
                    "priority": {"name": _PRIORITY_MAP[finding.severity]},
                    "labels": ["skull-flash", "security", finding.severity.value.lower()],
                })
                created.append(issue.key)
                logger.info(f"Created Jira issue {issue.key} for {finding.id}")
            except Exception as exc:
                logger.warning(f"Failed to create issue for {finding.id}: {exc}")

        return {"created": created, "skipped": skipped, "total": len(findings)}

    @staticmethod
    def _format_description(finding: Finding, target: str) -> str:
        evidence = "\n".join(f"* {e}" for e in finding.evidence)
        refs = "\n".join(f"* {r}" for r in finding.references) if finding.references else "N/A"
        assets = ", ".join(finding.affected_assets)
        cvss = f"*CVSS Score:* {finding.cvss_score}" if finding.cvss_score else ""

        return (
            f"h2. Finding ID: {finding.id}\n"
            f"*Target:* {target}\n"
            f"*Affected Assets:* {assets}\n"
            f"*Severity:* {finding.severity.value}\n"
            f"{cvss}\n\n"
            f"h3. Description\n{finding.description}\n\n"
            f"h3. Evidence\n{evidence}\n\n"
            f"h3. Remediation\n{finding.remediation}\n\n"
            f"h3. References\n{refs}\n"
        )
