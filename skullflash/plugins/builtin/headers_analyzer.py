"""Builtin plugin: detailed HTTP security header analysis with scoring."""
from __future__ import annotations

from typing import Any, Dict, List

import httpx

from skullflash.plugins.base import BasePlugin, PluginMeta


_HEADERS_DB: Dict[str, Dict[str, Any]] = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "Forces HTTPS. Missing means downgrade attacks are possible.",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "Mitigates XSS and data injection attacks.",
        "recommendation": "Define a restrictive CSP policy matching your application's needs.",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Prevents clickjacking attacks.",
        "recommendation": "Add: X-Frame-Options: DENY",
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "Prevents MIME sniffing.",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Controls Referer header information leakage.",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "Controls browser feature access.",
        "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
    "X-XSS-Protection": {
        "severity": "LOW",
        "description": "Legacy XSS filter hint for older browsers.",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block (or rely on CSP instead)",
    },
}


class HeadersAnalyzerPlugin(BasePlugin):
    """Detailed HTTP security header analysis with per-header scoring."""

    meta = PluginMeta(
        name="headers_analyzer",
        version="1.0.0",
        author="skull-flash",
        description="Análise detalhada de security headers com scoring por header",
        category="scan",
        requires=["httpx"],
    )

    def get_options(self) -> Dict[str, Any]:
        return {"timeout": 10, "follow_redirects": True}

    async def run(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze HTTP security headers for the given URL.

        Args:
            target: URL to analyze (include scheme).
            options: 'timeout' and 'follow_redirects' supported.

        Returns:
            Dict with 'present', 'missing', 'score', and 'details'.
        """
        timeout = int(options.get("timeout", 10))
        follow = bool(options.get("follow_redirects", True))
        result: Dict[str, Any] = {
            "target": target,
            "present": {},
            "missing": [],
            "details": {},
            "score": 0,
        }

        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=follow) as client:
                response = await client.get(target)
        except Exception as exc:
            result["error"] = str(exc)
            return result

        present: Dict[str, str] = {}
        missing: List[str] = []

        for header, meta in _HEADERS_DB.items():
            if header in response.headers:
                present[header] = response.headers[header]
            else:
                missing.append(header)
                result["details"][header] = meta

        result["present"] = present
        result["missing"] = missing
        result["score"] = int(len(present) / len(_HEADERS_DB) * 100)

        return result
