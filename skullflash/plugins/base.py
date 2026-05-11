"""Plugin interface — all skull-flash plugins must implement BasePlugin."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class PluginMeta:
    name: str
    version: str = "1.0.0"
    author: str = "unknown"
    description: str = ""
    category: str = "recon"   # recon | scan | report
    requires: List[str] = field(default_factory=list)


class BasePlugin(ABC):
    """Base class for all skull-flash plugins.

    Subclasses must:
    - Set the class-level `meta` attribute to a PluginMeta instance.
    - Implement `run()` and `get_options()`.
    """

    meta: PluginMeta

    @abstractmethod
    async def run(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the plugin against the given target.

        Args:
            target: IP, domain, or URL to probe.
            options: Key-value options (see get_options() for defaults).

        Returns:
            Dict with plugin-specific results.
        """
        ...

    @abstractmethod
    def get_options(self) -> Dict[str, Any]:
        """Return configurable options and their default values.

        Returns:
            Dict mapping option name to default value.
        """
        ...
