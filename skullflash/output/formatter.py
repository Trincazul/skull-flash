"""Rich-based terminal output for all scan result types."""
from __future__ import annotations

from typing import List, Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from skullflash.core.cve import CveResult
from skullflash.core.fingerprint import TechFingerprint
from skullflash.core.osint import OsintResult
from skullflash.core.phone import PhoneResult
from skullflash.core.scanner import ScanResult
from skullflash.core.web import WebResult


console = Console()

_SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "white",
    "UNKNOWN": "dim",
    "NONE": "dim",
}


def make_progress() -> Progress:
    """Return a pre-configured Rich progress bar."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )


def print_scan_result(result: ScanResult, cve_results: Optional[List[CveResult]] = None) -> None:
    """Render a ScanResult to the console."""
    console.print(Panel(
        f"[bold]Target:[/] {result.target}   "
        f"[bold]Hosts:[/] {len(result.hosts)}   "
        f"[bold]Duration:[/] {result.duration_seconds:.1f}s",
        title="[bold cyan]Port Scan[/]",
        border_style="cyan",
    ))

    for host in result.hosts:
        tbl = Table(
            title=f"[bold]{host.ip}[/]  {host.hostname or ''}  — {host.state}",
            box=box.ROUNDED,
        )
        tbl.add_column("Port", style="cyan", width=7)
        tbl.add_column("Proto", width=5)
        tbl.add_column("State", width=8)
        tbl.add_column("Service", width=14)
        tbl.add_column("Product / Version")

        for svc in host.services:
            state_style = "green" if svc.state == "open" else "red"
            tbl.add_row(
                str(svc.port),
                svc.protocol,
                f"[{state_style}]{svc.state}[/]",
                svc.name,
                f"{svc.product} {svc.version}".strip(),
            )
        console.print(tbl)

    if cve_results:
        print_cve_results(cve_results)


def print_osint_result(result: OsintResult) -> None:
    """Render an OsintResult to the console."""
    console.print(Panel(
        f"[bold]Target:[/] {result.target}",
        title="[bold cyan]OSINT[/]",
        border_style="cyan",
    ))

    if result.whois:
        w = result.whois
        tbl = Table(title="WHOIS", box=box.ROUNDED)
        tbl.add_column("Field", style="bold", width=18)
        tbl.add_column("Value")
        tbl.add_row("Domain", w.domain)
        tbl.add_row("Registrar", w.registrar)
        tbl.add_row("Created", w.creation_date)
        tbl.add_row("Expires", w.expiration_date)
        tbl.add_row("Name Servers", "\n".join(w.name_servers[:5]))
        console.print(tbl)

    if result.dns and result.dns.records:
        tbl = Table(title="DNS Records", box=box.ROUNDED)
        tbl.add_column("Type", style="cyan", width=7)
        tbl.add_column("Value")
        for rtype, values in result.dns.records.items():
            for val in values:
                tbl.add_row(rtype, val)
        console.print(tbl)

    if result.subdomains:
        tbl = Table(title=f"Subdomains ({len(result.subdomains)} found)", box=box.ROUNDED)
        tbl.add_column("FQDN", style="green")
        for sub in result.subdomains:
            tbl.add_row(sub)
        console.print(tbl)


def print_web_result(result: WebResult) -> None:
    """Render a WebResult to the console."""
    score_color = "green" if result.security_score >= 70 else ("yellow" if result.security_score >= 40 else "red")
    console.print(Panel(
        f"[bold]Target:[/] {result.target}   "
        f"[bold]Security Score:[/] [{score_color}]{result.security_score}/100[/]",
        title="[bold cyan]Web Security[/]",
        border_style="cyan",
    ))

    if result.headers:
        h = result.headers
        tbl = Table(title=f"HTTP Security Headers  (score {h.score}/100)", box=box.ROUNDED)
        tbl.add_column("Header", width=32)
        tbl.add_column("Status", width=12)
        tbl.add_column("Value")
        for header, value in h.present.items():
            tbl.add_row(header, "[green]✓ Present[/]", value[:60])
        for header in h.missing:
            tbl.add_row(header, "[red]✗ Absent[/]", "—")
        console.print(tbl)

    if result.ssl:
        s = result.ssl
        score_col = "green" if s.score == 100 else ("yellow" if s.score >= 60 else "red")
        tbl = Table(title=f"SSL/TLS Certificate  (score {s.score}/100)", box=box.ROUNDED)
        tbl.add_column("Field", style="bold", width=20)
        tbl.add_column("Value")
        tbl.add_row("Valid", "[green]Yes[/]" if s.valid else "[red]No[/]")
        tbl.add_row("Subject", s.subject[:70])
        tbl.add_row("Issuer", s.issuer[:70])
        tbl.add_row("Expires", s.expiry or "—")
        tbl.add_row("Days Remaining", f"[{score_col}]{s.days_remaining}[/]")
        tbl.add_row("Protocol", s.protocol)
        tbl.add_row("Cipher", s.cipher)
        tbl.add_row("SANs", "\n".join(s.san[:5]))
        console.print(tbl)


def print_phone_result(result: PhoneResult) -> None:
    """Render a PhoneResult to the console."""
    status = "[green]Valid[/]" if result.valid else "[red]Invalid[/]"
    tbl = Table(title=f"Phone Lookup  {status}", box=box.ROUNDED)
    tbl.add_column("Field", style="bold", width=24)
    tbl.add_column("Value")
    tbl.add_row("Number", result.number)
    tbl.add_row("Location", result.location)
    tbl.add_row("Carrier", result.carrier_name)
    tbl.add_row("Type", result.number_type)
    tbl.add_row("Country", result.country)
    tbl.add_row("National Format", result.national_format)
    tbl.add_row("International Format", result.international_format)
    console.print(tbl)


def print_fingerprint(fp: TechFingerprint) -> None:
    """Render technology fingerprint results to the console."""
    tbl = Table(title=f"Technology Fingerprint — {fp.url}", box=box.ROUNDED)
    tbl.add_column("Category", style="bold cyan", width=14)
    tbl.add_column("Detected", width=22)
    tbl.add_column("Confidence")

    for label, value in [
        ("Server", fp.server),
        ("Language", fp.language),
        ("Framework", fp.framework),
        ("CMS", fp.cms),
        ("CDN / WAF", fp.cdn),
        ("OS Hint", fp.os_hint),
    ]:
        if value:
            tbl.add_row(label, value, "—")

    by_conf = sorted(fp.technologies, key=lambda t: fp.confidence.get(t, 0), reverse=True)
    for tech in by_conf:
        tbl.add_row("", tech, f"{fp.confidence.get(tech, 0)}%")

    console.print(tbl)


def print_risk_report(report: "Any") -> None:
    """Render a RiskReport (from correlation engine) to the console."""
    score = report.risk_score
    score_color = "red" if score >= 70 else ("yellow" if score >= 40 else "green")
    console.print(Panel(
        f"[bold]Target:[/] {report.target}   "
        f"[bold]Risk Score:[/] [{score_color}]{score:.0f}/100[/]   "
        f"[bold]Findings:[/] {len(report.findings)}\n\n"
        f"{report.executive_summary}",
        title="[bold red]Risk Report[/]",
        border_style="red" if score >= 70 else ("yellow" if score >= 40 else "green"),
    ))

    if not report.findings:
        return

    tbl = Table(title="Findings", box=box.ROUNDED)
    tbl.add_column("ID", style="dim", width=9)
    tbl.add_column("Title")
    tbl.add_column("Severity", width=10)
    tbl.add_column("CVSS", width=6)
    tbl.add_column("Assets")

    for finding in report.findings:
        sev = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        style = _SEVERITY_STYLE.get(sev, "white")
        cvss = f"{finding.cvss_score:.1f}" if finding.cvss_score is not None else "—"
        tbl.add_row(
            finding.id,
            finding.title[:60],
            f"[{style}]{sev}[/]",
            cvss,
            ", ".join(finding.affected_assets[:2]),
        )

    console.print(tbl)


def print_cve_results(results: List[CveResult]) -> None:
    """Render CVE findings sorted by CVSS score."""
    all_entries = [
        (cve, r.service, r.version)
        for r in results
        for cve in r.cves
    ]
    all_entries.sort(key=lambda x: x[0].cvss_score, reverse=True)

    tbl = Table(title=f"CVEs ({len(all_entries)} found)", box=box.ROUNDED)
    tbl.add_column("CVE ID", style="bold cyan", width=18)
    tbl.add_column("Service", width=14)
    tbl.add_column("CVSS", width=6)
    tbl.add_column("Severity", width=10)
    tbl.add_column("Description")

    for cve, service, version in all_entries:
        style = _SEVERITY_STYLE.get(cve.severity.upper(), "white")
        tbl.add_row(
            cve.cve_id,
            f"{service} {version}".strip(),
            str(cve.cvss_score),
            f"[{style}]{cve.severity}[/]",
            cve.description[:65],
        )
    console.print(tbl)
