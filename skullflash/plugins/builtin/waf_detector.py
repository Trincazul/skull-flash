"""Builtin plugin: WAF detection via HTTP header and response fingerprinting."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

import httpx

from skullflash.plugins.base import BasePlugin, PluginMeta


# (display_name, [(header, pattern), ...], [cookie_pattern, ...])
_WAF_SIGNATURES: List[Tuple[str, List[Tuple[str, str]], List[str]]] = [
    ("Cloudflare", [
        ("Server", r"cloudflare"),
        ("CF-RAY", r".+"),
    ], ["__cflb", "__cfuid", "cf_clearance"]),
    ("AWS WAF / CloudFront", [
        ("X-Cache", r"(Hit|Miss) from cloudfront"),
        ("Via", r"CloudFront"),
        ("X-Amz-Cf-Pop", r".+"),
    ], ["AWSALB", "AWSALBCORS"]),
    ("Imperva / Incapsula", [
        ("X-Iinfo", r".+"),
        ("X-CDN", r"Incapsula"),
    ], ["incap_ses", "visid_incap"]),
    ("Akamai", [
        ("X-Check-Cacheable", r".+"),
        ("X-Akamai-Transformed", r".+"),
        ("Server", r"AkamaiGHost"),
    ], ["ak_bmsc", "bm_sz"]),
    ("F5 BIG-IP ASM", [
        ("X-WA-Info", r".+"),
        ("Server", r"BigIP"),
        ("Set-Cookie", r"TS[0-9a-f]{8}"),
    ], ["TS", "BIGipServer"]),
    ("ModSecurity", [
        ("Server", r"mod_security"),
        ("X-Mod-Security", r".+"),
    ], []),
    ("Sucuri", [
        ("X-Sucuri-ID", r".+"),
        ("Server", r"Sucuri"),
        ("X-Sucuri-Cache", r".+"),
    ], []),
    ("Barracuda", [
        ("X-Barracuda-URL", r".+"),
    ], ["barra_counter_session"]),
    ("Wallarm", [
        ("X-Wallarm-Node", r".+"),
    ], []),
    ("Nginx ModSecurity", [
        ("Server", r"nginx"),
        ("X-Content-Type-Options", r"nosniff"),
    ], []),
]


class WafDetectorPlugin(BasePlugin):
    """Detects presence and type of WAF by HTTP response fingerprinting.

    This plugin is passive — it only analyzes normal HTTP responses
    and does not send attack payloads.
    """

    meta = PluginMeta(
        name="waf_detector",
        version="1.0.0",
        author="skull-flash",
        description="Detecta WAF por fingerprinting passivo de headers e cookies",
        category="recon",
        requires=["httpx"],
    )

    def get_options(self) -> Dict[str, Any]:
        return {"timeout": 10}

    async def run(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Probe the target URL and identify any WAF in front of it.

        Args:
            target: URL to analyze (include scheme).
            options: 'timeout' supported.

        Returns:
            Dict with 'waf_detected' (bool), 'waf_name' (str), 'confidence' (int),
            'matched_signatures', and 'response_headers'.
        """
        timeout = int(options.get("timeout", 10))
        result: Dict[str, Any] = {
            "target": target,
            "waf_detected": False,
            "waf_name": None,
            "confidence": 0,
            "matched_signatures": [],
            "response_headers": {},
        }

        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=True,
            ) as client:
                response = await client.get(target)
        except Exception as exc:
            result["error"] = str(exc)
            return result

        result["response_headers"] = dict(response.headers)

        # Collect all Set-Cookie header values
        cookies_str = " ".join(response.headers.getlist("set-cookie"))

        best_name: Optional[str] = None
        best_score = 0

        for waf_name, header_sigs, cookie_patterns in _WAF_SIGNATURES:
            score = 0
            matched: List[str] = []

            for header, pattern in header_sigs:
                value = response.headers.get(header, "")
                if value and re.search(pattern, value, re.IGNORECASE):
                    score += 30
                    matched.append(f"header {header}: {value[:60]}")

            for cookie_pat in cookie_patterns:
                if re.search(cookie_pat, cookies_str, re.IGNORECASE):
                    score += 20
                    matched.append(f"cookie matches {cookie_pat!r}")

            if score > best_score:
                best_score = score
                best_name = waf_name
                result["matched_signatures"] = matched

        if best_score >= 30:
            result["waf_detected"] = True
            result["waf_name"] = best_name
            result["confidence"] = min(100, best_score)

        return result
