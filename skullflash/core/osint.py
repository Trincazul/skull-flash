"""OSINT: WHOIS, DNS records, and subdomain enumeration."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import dns.asyncresolver
import dns.resolver
import whois
from loguru import logger


# Top-500 most common subdomains (condensed to ~60 for built-in use)
_SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2", "webmail",
    "server", "remote", "blog", "web", "email", "portal", "api", "admin",
    "dev", "stage", "staging", "test", "vpn", "m", "shop", "forum",
    "support", "app", "beta", "news", "cdn", "cloud", "secure", "login",
    "dashboard", "static", "img", "images", "media", "docs", "status",
    "help", "intranet", "gateway", "auth", "sso", "monitor", "monitoring",
    "git", "gitlab", "github", "jenkins", "jira", "confluence", "wiki",
    "mysql", "db", "database", "redis", "elastic", "kibana", "grafana",
    "prometheus", "k8s", "docker", "registry", "backup", "archive",
    "old", "new", "v1", "v2", "internal", "cpanel", "whm", "mx",
    "autodiscover", "autoconfig", "api2", "api-v2", "staging2",
]


@dataclass
class WhoisResult:
    domain: str
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    name_servers: List[str] = field(default_factory=list)


@dataclass
class DnsResult:
    domain: str
    records: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class OsintResult:
    target: str
    whois: Optional[WhoisResult] = None
    dns: Optional[DnsResult] = None
    subdomains: List[str] = field(default_factory=list)


async def run_osint(target: str, include_subdomains: bool = False) -> OsintResult:
    """Run full OSINT reconnaissance on a domain or IP.

    Args:
        target: Domain name or IP address.
        include_subdomains: Whether to enumerate subdomains via DNS brute-force.

    Returns:
        OsintResult aggregating all gathered information.
    """
    result = OsintResult(target=target)
    tasks: list = [_whois_lookup(target), _dns_lookup(target)]
    if include_subdomains:
        tasks.append(_subdomain_enum(target))

    gathered = await asyncio.gather(*tasks, return_exceptions=True)

    result.whois = gathered[0] if not isinstance(gathered[0], Exception) else None
    result.dns = gathered[1] if not isinstance(gathered[1], Exception) else None
    if include_subdomains and len(gathered) > 2:
        result.subdomains = gathered[2] if not isinstance(gathered[2], Exception) else []

    if isinstance(gathered[0], Exception):
        logger.warning(f"WHOIS failed: {gathered[0]}")
    if isinstance(gathered[1], Exception):
        logger.warning(f"DNS lookup failed: {gathered[1]}")

    return result


async def _whois_lookup(domain: str) -> WhoisResult:
    """Perform WHOIS lookup in a thread executor to avoid blocking the event loop."""
    loop = asyncio.get_running_loop()
    w = await loop.run_in_executor(None, whois.whois, domain)

    def _fmt(val: object) -> str:
        if isinstance(val, list):
            return ", ".join(str(v) for v in val[:3])
        return str(val) if val else "N/A"

    return WhoisResult(
        domain=domain,
        registrar=_fmt(getattr(w, "registrar", None)),
        creation_date=_fmt(getattr(w, "creation_date", None)),
        expiration_date=_fmt(getattr(w, "expiration_date", None)),
        name_servers=[str(ns).lower() for ns in (getattr(w, "name_servers", None) or [])],
    )


async def _dns_lookup(domain: str) -> DnsResult:
    """Resolve A, MX, NS, TXT, and CNAME records for a domain."""
    result = DnsResult(domain=domain)
    resolver = dns.asyncresolver.Resolver()

    for rtype in ("A", "MX", "NS", "TXT", "CNAME"):
        try:
            answers = await resolver.resolve(domain, rtype)
            result.records[rtype] = [rdata.to_text() for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as exc:
            logger.debug(f"DNS {rtype} query failed for {domain}: {exc}")

    return result


async def _subdomain_enum(domain: str, concurrency: int = 50) -> List[str]:
    """Enumerate subdomains via DNS brute-force using the built-in wordlist.

    Args:
        domain: Base domain to probe (e.g. "example.com").
        concurrency: Maximum parallel DNS queries.

    Returns:
        Sorted list of discovered FQDNs.
    """
    found: List[str] = []
    resolver = dns.asyncresolver.Resolver()
    sem = asyncio.Semaphore(concurrency)

    async def _check(sub: str) -> None:
        fqdn = f"{sub}.{domain}"
        async with sem:
            try:
                await resolver.resolve(fqdn, "A")
                found.append(fqdn)
                logger.info(f"Subdomain found: {fqdn}")
            except Exception:
                pass

    await asyncio.gather(*[_check(s) for s in _SUBDOMAIN_WORDLIST])
    return sorted(found)
