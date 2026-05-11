"""Click entry point — all skull-flash sub-commands."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Optional

import click

from skullflash import __version__
from skullflash.config import load_config
from skullflash.output.formatter import (
    console,
    make_progress,
    print_fingerprint,
    print_osint_result,
    print_phone_result,
    print_risk_report,
    print_scan_result,
    print_web_result,
)
from skullflash.utils.ethics import require_authorization
from skullflash.utils.logger import setup_logger


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(version=__version__, prog_name="skull-flash")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Show DEBUG output.")
@click.option("--quiet", "-q", is_flag=True, default=False, help="Suppress all but errors.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool, quiet: bool) -> None:
    """Skull Flash — Professional security auditing tool."""
    cfg = load_config()
    setup_logger(level=cfg.log_level, verbose=verbose, quiet=quiet)
    ctx.ensure_object(dict)
    ctx.obj["config"] = cfg


# ---------------------------------------------------------------------------
# skull-flash scan
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--target", "-t", required=True, help="IP address, hostname, or CIDR range.")
@click.option("--ports", "-p", default="1-1000", show_default=True, help="Port range or list.")
@click.option("--output", "-o", type=click.Path(), default=None, help="Save report to this path.")
@click.option("--format", "fmt", type=click.Choice(["json", "html", "pdf"]), default="json", show_default=True)
@click.option("--cve", "run_cve", is_flag=True, default=False, help="Correlate services with CVEs.")
@click.pass_context
def scan(ctx: click.Context, target: str, ports: str, output: Optional[str], fmt: str, run_cve: bool) -> None:
    """Scan ports and identify services on a target host or network."""
    cfg = ctx.obj["config"]
    require_authorization(target, cfg.allowed_targets, cfg.blocked_targets)

    async def _run() -> None:
        from skullflash.core.scanner import scan_target
        from skullflash.core.cve import correlate_cves
        from skullflash.output.report import export_json, export_html, export_pdf

        with make_progress() as prog:
            tid = prog.add_task(f"Scanning {target}…", total=None)
            result = await scan_target(target, ports=ports, timeout=cfg.scan_timeout)
            prog.update(tid, completed=True)

        cve_results = None
        if run_cve:
            with make_progress() as prog:
                tid = prog.add_task("Correlating CVEs…", total=None)
                cve_results = await correlate_cves(result, api_key=cfg.nvd_api_key)
                prog.update(tid, completed=True)

        print_scan_result(result, cve_results)

        if output:
            out = Path(output)
            payload = {"scan": result, "cves": cve_results or []}
            {"json": export_json, "html": export_html, "pdf": export_pdf}[fmt](payload, out)
            console.print(f"[green]✓ Report saved to {out}[/]")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# skull-flash osint
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--target", "-t", required=True, help="Domain name or IP address.")
@click.option("--subdomains", is_flag=True, default=False, help="Enumerate subdomains via DNS brute-force.")
@click.option("--output", "-o", type=click.Path(), default=None)
@click.option("--format", "fmt", type=click.Choice(["json", "html", "pdf"]), default="json", show_default=True)
@click.pass_context
def osint(ctx: click.Context, target: str, subdomains: bool, output: Optional[str], fmt: str) -> None:
    """Gather OSINT: WHOIS, DNS records, and optional subdomain enumeration."""
    async def _run() -> None:
        from skullflash.core.osint import run_osint
        from skullflash.output.report import export_json, export_html, export_pdf

        with make_progress() as prog:
            tid = prog.add_task(f"Running OSINT on {target}…", total=None)
            result = await run_osint(target, include_subdomains=subdomains)
            prog.update(tid, completed=True)

        print_osint_result(result)

        if output:
            out = Path(output)
            payload = {"osint": result}
            {"json": export_json, "html": export_html, "pdf": export_pdf}[fmt](payload, out)
            console.print(f"[green]✓ Report saved to {out}[/]")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# skull-flash web
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--target", "-t", required=True, help="URL including scheme (e.g. https://example.com).")
@click.option("--no-ssl", "skip_ssl", is_flag=True, default=False, help="Skip SSL/TLS certificate check.")
@click.option("--no-headers", "skip_headers", is_flag=True, default=False, help="Skip HTTP security headers check.")
@click.option("--fingerprint", "do_fingerprint", is_flag=True, default=False, help="Detect technologies via HTTP fingerprinting.")
@click.option("--output", "-o", type=click.Path(), default=None)
@click.option("--format", "fmt", type=click.Choice(["json", "html", "pdf"]), default="json", show_default=True)
@click.pass_context
def web(ctx: click.Context, target: str, skip_ssl: bool, skip_headers: bool, do_fingerprint: bool, output: Optional[str], fmt: str) -> None:
    """Analyze HTTP security headers and SSL/TLS certificate of a URL."""
    async def _run() -> None:
        from skullflash.core.web import analyze_web
        from skullflash.output.report import export_json, export_html, export_pdf

        with make_progress() as prog:
            tid = prog.add_task(f"Analyzing {target}…", total=None)
            result = await analyze_web(
                target,
                check_headers=not skip_headers,
                check_ssl=not skip_ssl,
            )
            prog.update(tid, completed=True)

        print_web_result(result)

        if do_fingerprint:
            from skullflash.core.fingerprint import detect_technologies
            with make_progress() as prog:
                tid = prog.add_task("Fingerprinting technologies…", total=None)
                fp = await detect_technologies(target)
                prog.update(tid, completed=True)
            print_fingerprint(fp)

        if output:
            out = Path(output)
            payload = {"web": result}
            {"json": export_json, "html": export_html, "pdf": export_pdf}[fmt](payload, out)
            console.print(f"[green]✓ Report saved to {out}[/]")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# skull-flash phone
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--number", "-n", required=True, help="Phone number in E.164 format (e.g. +5511999990000).")
@click.pass_context
def phone(ctx: click.Context, number: str) -> None:
    """Look up carrier, location, and type for a phone number."""
    from skullflash.core.phone import lookup_phone
    result = lookup_phone(number)
    print_phone_result(result)


# ---------------------------------------------------------------------------
# skull-flash cve
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--target", "-t", required=True, help="Host or CIDR to scan and correlate with CVEs.")
@click.option("--ports", "-p", default="1-1000", show_default=True)
@click.option("--output", "-o", type=click.Path(), default=None)
@click.option("--format", "fmt", type=click.Choice(["json", "html", "pdf"]), default="json", show_default=True)
@click.pass_context
def cve(ctx: click.Context, target: str, ports: str, output: Optional[str], fmt: str) -> None:
    """Scan target and correlate open services with CVEs from NVD."""
    cfg = ctx.obj["config"]
    require_authorization(target, cfg.allowed_targets, cfg.blocked_targets)

    async def _run() -> None:
        from skullflash.core.scanner import scan_target
        from skullflash.core.cve import correlate_cves
        from skullflash.output.report import export_json, export_html, export_pdf

        with make_progress() as prog:
            t1 = prog.add_task(f"Scanning {target}…", total=None)
            scan_result = await scan_target(target, ports=ports, timeout=cfg.scan_timeout)
            prog.update(t1, completed=True)
            t2 = prog.add_task("Looking up CVEs in NVD…", total=None)
            cve_results = await correlate_cves(scan_result, api_key=cfg.nvd_api_key)
            prog.update(t2, completed=True)

        print_scan_result(scan_result, cve_results)

        if output:
            out = Path(output)
            payload = {"scan": scan_result, "cves": cve_results}
            {"json": export_json, "html": export_html, "pdf": export_pdf}[fmt](payload, out)
            console.print(f"[green]✓ Report saved to {out}[/]")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# skull-flash report
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--input", "-i", "input_path", required=True, type=click.Path(exists=True), help="JSON result file.")
@click.option("--format", "fmt", required=True, type=click.Choice(["html", "pdf"]))
@click.option("--output", "-o", required=True, type=click.Path())
@click.pass_context
def report(ctx: click.Context, input_path: str, fmt: str, output: str) -> None:
    """Render a report from a previously saved JSON result file."""
    import json as _json
    from skullflash.output.report import export_html, export_pdf

    data = _json.loads(Path(input_path).read_text())
    out = Path(output)
    {"html": export_html, "pdf": export_pdf}[fmt](data, out)
    console.print(f"[green]✓ Report saved to {out}[/]")


# ---------------------------------------------------------------------------
# skull-flash interactive  (backward compatibility)
# ---------------------------------------------------------------------------

@cli.command()
def interactive() -> None:
    """Launch the original interactive menu (v1 backward compatibility)."""
    try:
        from sample import menu
        menu.image()
        menu.menuindex()
    except ImportError:
        console.print("[red]Interactive mode requires the sample/ directory from v1.[/]")
        sys.exit(1)


# ---------------------------------------------------------------------------
# skull-flash analyze
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--target", "-t", required=True, help="IP, hostname, or CIDR to analyze.")
@click.option("--ports", "-p", default="1-1000", show_default=True, help="Port range.")
@click.option("--cve", "run_cve", is_flag=True, default=False, help="Correlate services with NVD CVEs.")
@click.option("--web", "run_web", is_flag=True, default=False, help="Analyze HTTP headers and SSL.")
@click.option("--osint", "run_osint", is_flag=True, default=False, help="Collect WHOIS and DNS data.")
@click.option("--output", "-o", type=click.Path(), default=None, help="Save full report to file.")
@click.option("--format", "fmt", type=click.Choice(["json", "html", "pdf"]), default="json", show_default=True)
@click.pass_context
def analyze(
    ctx: click.Context,
    target: str,
    ports: str,
    run_cve: bool,
    run_web: bool,
    run_osint: bool,
    output: Optional[str],
    fmt: str,
) -> None:
    """Run full scan + correlation engine and display a risk-scored report."""
    cfg = ctx.obj["config"]
    require_authorization(target, cfg.allowed_targets, cfg.blocked_targets)

    async def _run() -> None:
        from skullflash.core.scanner import scan_target
        from skullflash.core.correlation import CorrelationEngine
        from skullflash.output.report import export_json, export_html, export_pdf

        scan_result = None
        cve_results = None
        web_result = None
        osint_result = None

        with make_progress() as prog:
            tid = prog.add_task(f"Scanning {target}…", total=None)
            try:
                scan_result = await scan_target(target, ports=ports, timeout=cfg.scan_timeout)
            except FileNotFoundError:
                console.print("[red]nmap not found — install nmap and retry.[/]")
            prog.update(tid, completed=True)

        if run_cve and scan_result:
            from skullflash.core.cve import correlate_cves
            with make_progress() as prog:
                tid = prog.add_task("Correlating CVEs…", total=None)
                cve_results = await correlate_cves(scan_result, api_key=cfg.nvd_api_key)
                prog.update(tid, completed=True)

        if run_web:
            from skullflash.core.web import analyze_web
            url = target if target.startswith("http") else f"https://{target}"
            with make_progress() as prog:
                tid = prog.add_task("Analyzing web/SSL…", total=None)
                web_result = await analyze_web(url)
                prog.update(tid, completed=True)

        if run_osint:
            from skullflash.core.osint import run_osint as _run_osint
            with make_progress() as prog:
                tid = prog.add_task("Running OSINT…", total=None)
                osint_result = await _run_osint(target)
                prog.update(tid, completed=True)

        engine = CorrelationEngine()
        report = engine.analyze(
            target=target,
            scan_result=scan_result,
            cve_results=cve_results,
            web_result=web_result,
        )

        if scan_result:
            print_scan_result(scan_result, cve_results)
        if osint_result:
            print_osint_result(osint_result)
        if web_result:
            print_web_result(web_result)

        print_risk_report(report)

        if output:
            out = Path(output)
            payload = {
                "scan": scan_result,
                "cves": cve_results or [],
                "web": web_result,
                "osint": osint_result,
                "report": report,
            }
            {"json": export_json, "html": export_html, "pdf": export_pdf}[fmt](payload, out)
            console.print(f"[green]✓ Report saved to {out}[/]")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# skull-flash serve
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind host.")
@click.option("--port", default=8080, show_default=True, help="Bind port.")
@click.option("--reload", is_flag=True, default=False, help="Enable auto-reload (development only).")
def serve(host: str, port: int, reload: bool) -> None:
    """Launch the Skull Flash web dashboard (FastAPI + SSE)."""
    try:
        import uvicorn
    except ImportError:
        console.print("[red]uvicorn is required: pip install 'skull-flash[web]'[/]")
        sys.exit(1)

    console.print(f"[bold green]Starting Skull Flash Dashboard at http://{host}:{port}[/]")
    uvicorn.run(
        "skullflash.web_ui.server:app",
        host=host,
        port=port,
        reload=reload,
        log_level="warning",
    )


# ---------------------------------------------------------------------------
# skull-flash plugin
# ---------------------------------------------------------------------------

@cli.group()
def plugin() -> None:
    """Manage and run skull-flash plugins."""


@plugin.command("list")
def plugin_list() -> None:
    """List all discovered plugins (builtin + user)."""
    from skullflash.plugins.loader import discover_plugins

    plugins = discover_plugins()
    if not plugins:
        console.print("[dim]No plugins found.[/]")
        return

    from rich.table import Table
    from rich import box
    tbl = Table(title=f"Plugins ({len(plugins)} found)", box=box.ROUNDED)
    tbl.add_column("Name", style="bold cyan", width=22)
    tbl.add_column("Version", width=8)
    tbl.add_column("Description")

    for p in plugins.values():
        tbl.add_row(p.meta.name, p.meta.version, p.meta.description)
    console.print(tbl)


@plugin.command("info")
@click.argument("name")
def plugin_info(name: str) -> None:
    """Show detailed information about a plugin."""
    from skullflash.plugins.loader import discover_plugins

    plugins = discover_plugins()
    p = plugins.get(name)
    if not p:
        console.print(f"[red]Plugin {name!r} not found.[/]")
        sys.exit(1)

    from rich.panel import Panel
    opts = p.get_options()
    opts_str = "\n".join(f"  {k}: {v}" for k, v in opts.items()) or "  (none)"
    console.print(Panel(
        f"[bold]Name:[/]        {p.meta.name}\n"
        f"[bold]Version:[/]     {p.meta.version}\n"
        f"[bold]Description:[/] {p.meta.description}\n"
        f"[bold]Options:[/]\n{opts_str}",
        title=f"Plugin — {p.meta.name}",
        border_style="cyan",
    ))


@plugin.command("run")
@click.argument("name")
@click.option("--target", "-t", required=True, help="Target for the plugin.")
@click.option("--option", "-O", "options", multiple=True, metavar="KEY=VALUE", help="Plugin options.")
def plugin_run(name: str, target: str, options: tuple) -> None:
    """Run a plugin against a target."""
    from skullflash.plugins.loader import discover_plugins

    plugins = discover_plugins()
    p = plugins.get(name)
    if not p:
        console.print(f"[red]Plugin {name!r} not found.[/]")
        sys.exit(1)

    parsed_opts = {}
    for opt in options:
        if "=" in opt:
            k, _, v = opt.partition("=")
            parsed_opts[k.strip()] = v.strip()

    async def _run() -> None:
        result = await p.run(target, parsed_opts or None)
        import json as _json
        console.print_json(_json.dumps(result, default=str))

    asyncio.run(_run())


@plugin.command("install")
@click.argument("source")
def plugin_install(source: str) -> None:
    """Install a plugin from a local file path or HTTPS URL."""
    from skullflash.plugins.loader import install_plugin, PluginSecurityError

    try:
        dest = install_plugin(source)
        console.print(f"[green]✓ Plugin installed to {dest}[/]")
    except PluginSecurityError as exc:
        console.print(f"[red]Security check failed: {exc}[/]")
        sys.exit(1)
    except Exception as exc:
        console.print(f"[red]Install failed: {exc}[/]")
        sys.exit(1)


# ---------------------------------------------------------------------------
# skull-flash export
# ---------------------------------------------------------------------------

@cli.group()
def export() -> None:
    """Export scan findings to external platforms."""


def _load_findings_from_report(report_path: str):
    """Read a JSON report file and reconstruct Finding objects."""
    import json as _json
    from skullflash.core.correlation import Finding, Severity

    data = _json.loads(Path(report_path).read_text())
    findings_raw = data.get("report", {}).get("findings", [])
    target = data.get("report", {}).get("target", report_path)

    findings = []
    for f in findings_raw:
        findings.append(Finding(
            id=f["id"],
            title=f["title"],
            severity=Severity(f["severity"]),
            cvss_score=f.get("cvss_score"),
            description=f["description"],
            evidence=f.get("evidence", []),
            remediation=f.get("remediation", ""),
            references=f.get("references", []),
            affected_assets=f.get("affected_assets", []),
        ))
    return findings, target


@export.command("jira")
@click.option("--report", "-r", "report_path", required=True, type=click.Path(exists=True), help="JSON report file.")
@click.option("--threshold", default="MEDIUM", show_default=True, type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]), help="Minimum severity to export.")
@click.pass_context
def export_jira(ctx: click.Context, report_path: str, threshold: str) -> None:
    """Push findings to Jira as issues."""
    try:
        from skullflash.integrations.jira import JiraIntegration
    except ImportError:
        console.print("[red]jira package required: pip install 'skull-flash[integrations]'[/]")
        sys.exit(1)

    findings, target = _load_findings_from_report(report_path)
    integration = JiraIntegration(severity_threshold=threshold)

    async def _run() -> None:
        result = await integration.push_findings(findings, target)
        console.print(f"[green]✓ Created {result['created']} Jira issues.[/]")

    asyncio.run(_run())


@export.command("dradis")
@click.option("--report", "-r", "report_path", required=True, type=click.Path(exists=True), help="JSON report file.")
@click.option("--output", "-o", required=True, type=click.Path(), help="Destination .xml file.")
def export_dradis(report_path: str, output: str) -> None:
    """Export findings as Dradis-compatible XML."""
    from skullflash.integrations.dradis import DradisIntegration

    findings, target = _load_findings_from_report(report_path)
    integration = DradisIntegration()
    integration.export_xml(findings, target, Path(output))
    console.print(f"[green]✓ Dradis XML saved to {output}[/]")


@export.command("faraday")
@click.option("--report", "-r", "report_path", required=True, type=click.Path(exists=True), help="JSON report file.")
@click.option("--workspace", "-w", default="", help="Faraday workspace slug (overrides env var).")
def export_faraday(report_path: str, workspace: str) -> None:
    """Push findings to Faraday CE via bulk_create API."""
    from skullflash.integrations.faraday import FaradayIntegration

    findings, target = _load_findings_from_report(report_path)
    integration = FaradayIntegration(workspace=workspace)

    async def _run() -> None:
        result = await integration.push_findings(findings, target)
        console.print(f"[green]✓ Pushed {result['created']} findings to Faraday.[/]")

    asyncio.run(_run())


if __name__ == "__main__":
    cli()
