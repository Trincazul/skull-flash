"""Base interface for all export integrations."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List

from skullflash.core.correlation import Finding


class IntegrationBase(ABC):
    """Abstract base for platforms that receive skull-flash findings."""

    @abstractmethod
    async def push_findings(
        self, findings: List[Finding], target: str
    ) -> Dict[str, Any]:
        """Send findings to the external platform.

        Args:
            findings: List of Finding objects to push.
            target: Human-readable scan target string.

        Returns:
            Summary dict describing what was created/updated.
        """
        ...
