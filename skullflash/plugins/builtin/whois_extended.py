"""Builtin plugin: WHOIS + IP geolocation via ip-api.com (free, no key required)."""
from __future__ import annotations

from typing import Any, Dict

import httpx
import whois

from skullflash.plugins.base import BasePlugin, PluginMeta


class WhoisExtendedPlugin(BasePlugin):
    """WHOIS lookup enriched with IP geolocation data from ip-api.com."""

    meta = PluginMeta(
        name="whois_extended",
        version="1.0.0",
        author="skull-flash",
        description="WHOIS + geolocalização do IP via ip-api.com (sem chave de API)",
        category="recon",
        requires=["python-whois", "httpx"],
    )

    def get_options(self) -> Dict[str, Any]:
        return {"timeout": 10}

    async def run(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Run WHOIS and geolocation for a domain or IP.

        Args:
            target: Domain or IP address.
            options: Supports 'timeout' (int, seconds).

        Returns:
            Dict with 'whois' and 'geo' keys.
        """
        timeout = int(options.get("timeout", self.get_options()["timeout"]))
        result: Dict[str, Any] = {"target": target, "whois": {}, "geo": {}}

        # WHOIS
        try:
            import asyncio
            loop = asyncio.get_running_loop()
            w = await loop.run_in_executor(None, whois.whois, target)

            def _fmt(val: object) -> str:
                if isinstance(val, list):
                    return ", ".join(str(v) for v in val[:3])
                return str(val) if val else "N/A"

            result["whois"] = {
                "registrar": _fmt(getattr(w, "registrar", None)),
                "creation_date": _fmt(getattr(w, "creation_date", None)),
                "expiration_date": _fmt(getattr(w, "expiration_date", None)),
                "name_servers": [str(ns).lower() for ns in (getattr(w, "name_servers", None) or [])],
                "emails": _fmt(getattr(w, "emails", None)),
                "org": _fmt(getattr(w, "org", None)),
            }
        except Exception as exc:
            result["whois"]["error"] = str(exc)

        # Geolocation — resolving domain to IP first if needed
        ip = target
        try:
            import socket
            ip = socket.gethostbyname(target)
        except Exception:
            pass

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(
                    f"http://ip-api.com/json/{ip}",
                    params={"fields": "status,country,regionName,city,isp,org,lat,lon,query"},
                )
                data = response.json()
                if data.get("status") == "success":
                    result["geo"] = {
                        "ip": data.get("query"),
                        "country": data.get("country"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                    }
        except Exception as exc:
            result["geo"]["error"] = str(exc)

        return result
