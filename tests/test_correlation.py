"""Tests for the correlation engine — all 6 rules, scoring, and summary."""
from __future__ import annotations

from datetime import datetime

import pytest

from skullflash.core.correlation import (
    CorrelationEngine,
    Finding,
    RiskReport,
    Severity,
    _calculate_risk_score,
    _generate_summary,
)
from skullflash.core.cve import CveEntry, CveResult
from skullflash.core.scanner import HostResult, ScanResult, ServiceResult
from skullflash.core.web import HeaderAnalysis, SslAnalysis, WebResult


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _service(port: int, state: str = "open", name: str = "http", product: str = "", version: str = "") -> ServiceResult:
    return ServiceResult(port=port, protocol="tcp", state=state, name=name, product=product, version=version)


def _host(ip: str = "10.0.0.1", *services: ServiceResult) -> HostResult:
    return HostResult(ip=ip, hostname="", state="up", services=list(services))


def _scan(*hosts: HostResult) -> ScanResult:
    return ScanResult(target="10.0.0.1", timestamp=datetime.utcnow(), hosts=list(hosts), duration_seconds=1.0)


def _cve_entry(cve_id: str, cvss: float) -> CveEntry:
    return CveEntry(
        cve_id=cve_id,
        description=f"Test vulnerability {cve_id}",
        cvss_score=cvss,
        severity="CRITICAL" if cvss >= 9.0 else "HIGH",
        published="2024-01-01",
    )


def _cve_result(service: str, version: str, *entries: CveEntry) -> CveResult:
    return CveResult(service=service, version=version, cves=list(entries))


def _ssl(valid: bool = True, protocol: str = "TLSv1.3", cipher: str = "ECDHE-RSA-AES256-GCM-SHA384") -> SslAnalysis:
    return SslAnalysis(
        domain="example.com",
        valid=valid,
        expiry="2026-01-01T00:00:00",
        days_remaining=365,
        issuer="Let's Encrypt",
        subject="CN=example.com",
        protocol=protocol,
        cipher=cipher,
        san=["example.com"],
        score=100 if valid else 20,
    )


def _headers(missing: list | None = None) -> HeaderAnalysis:
    all_headers = [
        "Strict-Transport-Security", "Content-Security-Policy",
        "X-Frame-Options", "X-Content-Type-Options",
        "X-XSS-Protection", "Referrer-Policy", "Permissions-Policy",
    ]
    missing = missing or []
    present = {h: "value" for h in all_headers if h not in missing}
    return HeaderAnalysis(url="https://example.com", present=present, missing=missing, score=100)


# ── RULE-001 ─────────────────────────────────────────────────────────────────

def test_rule001_critical_cve_generates_finding() -> None:
    scan = _scan(_host("10.0.0.1", _service(80, name="http", product="Apache", version="2.4")))
    cves = [_cve_result("Apache", "2.4", _cve_entry("CVE-2024-9999", 9.8))]

    engine = CorrelationEngine()
    report = engine.analyze("10.0.0.1", scan_result=scan, cve_results=cves)

    critical = [f for f in report.findings if f.severity == Severity.CRITICAL]
    assert critical, "Expected at least one CRITICAL finding for CVSS 9.8 CVE"
    assert "CVE-2024-9999" in critical[0].title


def test_rule001_skips_low_cvss() -> None:
    scan = _scan(_host("10.0.0.1", _service(80)))
    cves = [_cve_result("http", "", _cve_entry("CVE-2024-0001", 5.0))]

    engine = CorrelationEngine()
    report = engine.analyze("10.0.0.1", scan_result=scan, cve_results=cves)

    assert not any(f.severity == Severity.CRITICAL for f in report.findings)


# ── RULE-002 ─────────────────────────────────────────────────────────────────

def test_rule002_weak_protocol_generates_high() -> None:
    ssl = _ssl(protocol="TLSv1.0")
    web = WebResult(target="https://example.com", ssl=ssl, security_score=40)

    engine = CorrelationEngine()
    report = engine.analyze("example.com", web_result=web)

    high = [f for f in report.findings if f.severity == Severity.HIGH and "SSL" in f.title]
    assert high, "Expected HIGH finding for weak TLS protocol"


def test_rule002_expired_cert_generates_high() -> None:
    ssl = _ssl(valid=False)
    web = WebResult(target="https://example.com", ssl=ssl, security_score=20)

    engine = CorrelationEngine()
    report = engine.analyze("example.com", web_result=web)

    ssl_findings = [f for f in report.findings if "SSL" in f.title and f.severity == Severity.HIGH]
    assert ssl_findings


def test_rule002_good_ssl_no_finding() -> None:
    ssl = _ssl(valid=True, protocol="TLSv1.3", cipher="ECDHE-RSA-AES256-GCM-SHA384")
    web = WebResult(target="https://example.com", ssl=ssl, security_score=100)

    engine = CorrelationEngine()
    report = engine.analyze("example.com", web_result=web)

    assert not any("SSL" in f.title for f in report.findings)


# ── RULE-003 ─────────────────────────────────────────────────────────────────

def test_rule003_missing_hsts_generates_medium() -> None:
    web = WebResult(
        target="https://example.com",
        headers=_headers(missing=["Strict-Transport-Security"]),
        security_score=80,
    )

    engine = CorrelationEngine()
    report = engine.analyze("example.com", web_result=web)

    medium = [f for f in report.findings if f.severity == Severity.MEDIUM and "Strict-Transport-Security" in f.title]
    assert medium


def test_rule003_missing_csp_generates_medium() -> None:
    web = WebResult(
        target="https://example.com",
        headers=_headers(missing=["Content-Security-Policy"]),
        security_score=80,
    )

    engine = CorrelationEngine()
    report = engine.analyze("example.com", web_result=web)

    assert any("Content-Security-Policy" in f.title for f in report.findings)


def test_rule003_all_headers_present_no_finding() -> None:
    web = WebResult(target="https://example.com", headers=_headers(missing=[]), security_score=100)

    engine = CorrelationEngine()
    report = engine.analyze("example.com", web_result=web)

    assert not any(f.severity == Severity.MEDIUM for f in report.findings)


# ── RULE-004 ─────────────────────────────────────────────────────────────────

def test_rule004_ftp_generates_high() -> None:
    scan = _scan(_host("10.0.0.1", _service(21, name="ftp")))

    engine = CorrelationEngine()
    report = engine.analyze("10.0.0.1", scan_result=scan)

    ftp_findings = [f for f in report.findings if f.severity == Severity.HIGH and "FTP" in f.title]
    assert ftp_findings


def test_rule004_telnet_generates_high() -> None:
    scan = _scan(_host("10.0.0.1", _service(23, name="telnet")))

    engine = CorrelationEngine()
    report = engine.analyze("10.0.0.1", scan_result=scan)

    assert any("Telnet" in f.title and f.severity == Severity.HIGH for f in report.findings)


def test_rule004_rdp_generates_medium() -> None:
    scan = _scan(_host("10.0.0.1", _service(3389, name="ms-wbt-server")))

    engine = CorrelationEngine()
    report = engine.analyze("10.0.0.1", scan_result=scan)

    assert any("RDP" in f.title and f.severity == Severity.MEDIUM for f in report.findings)


def test_rule004_ignored_for_closed_port() -> None:
    scan = _scan(_host("10.0.0.1", _service(21, state="closed")))

    engine = CorrelationEngine()
    report = engine.analyze("10.0.0.1", scan_result=scan)

    assert not any("FTP" in f.title for f in report.findings)


# ── RULE-005 ─────────────────────────────────────────────────────────────────

def test_rule005_three_or_more_cves_generates_high() -> None:
    scan = _scan(_host("10.0.0.1", _service(80)))
    cves = [_cve_result("http", "", _cve_entry(f"CVE-2024-{i:04d}", 5.0) for i in range(3))]  # type: ignore[arg-type]
    # Build properly
    entries = [_cve_entry(f"CVE-2024-{i:04d}", 5.0) for i in range(3)]
    cves = [CveResult(service="http", version="", cves=entries)]

    engine = CorrelationEngine()
    report = engine.analyze("10.0.0.1", scan_result=scan, cve_results=cves)

    assert any("Superfície" in f.title and f.severity == Severity.HIGH for f in report.findings)


def test_rule005_fewer_than_three_cves_no_attack_surface() -> None:
    scan = _scan(_host("10.0.0.1", _service(80)))
    cves = [CveResult(service="http", version="", cves=[_cve_entry("CVE-2024-0001", 5.0)])]

    engine = CorrelationEngine()
    report = engine.analyze("10.0.0.1", scan_result=scan, cve_results=cves)

    assert not any("Superfície" in f.title for f in report.findings)


# ── RULE-006 ─────────────────────────────────────────────────────────────────

def test_rule006_unknown_version_generates_info() -> None:
    scan = _scan(_host("10.0.0.1", _service(9999, name="unknown", product="", version="")))

    engine = CorrelationEngine()
    report = engine.analyze("10.0.0.1", scan_result=scan)

    info = [f for f in report.findings if f.severity == Severity.INFO and "9999" in f.title]
    assert info


def test_rule006_known_product_no_info_finding() -> None:
    scan = _scan(_host("10.0.0.1", _service(80, name="http", product="nginx", version="1.18")))

    engine = CorrelationEngine()
    report = engine.analyze("10.0.0.1", scan_result=scan)

    assert not any(f.severity == Severity.INFO and "80" in f.title for f in report.findings)


# ── Risk score ────────────────────────────────────────────────────────────────

def test_calculate_risk_score_empty() -> None:
    assert _calculate_risk_score([]) == 0.0


def test_calculate_risk_score_all_critical(tmp_path) -> None:
    def _f(sev):
        return Finding(
            id="F-001", title="t", severity=sev, cvss_score=None,
            description="d", evidence=[], remediation="r", references=[], affected_assets=[],
        )

    findings = [_f(Severity.CRITICAL)] * 5
    score = _calculate_risk_score(findings)
    assert score == 100.0


def test_calculate_risk_score_all_info() -> None:
    def _f():
        return Finding(
            id="F-001", title="t", severity=Severity.INFO, cvss_score=None,
            description="d", evidence=[], remediation="r", references=[], affected_assets=[],
        )

    score = _calculate_risk_score([_f(), _f()])
    assert score == 0.0


def test_calculate_risk_score_mixed() -> None:
    findings = [
        Finding(id="F-001", title="t", severity=Severity.HIGH, cvss_score=None,
                description="d", evidence=[], remediation="r", references=[], affected_assets=[]),
        Finding(id="F-002", title="t", severity=Severity.LOW, cvss_score=None,
                description="d", evidence=[], remediation="r", references=[], affected_assets=[]),
    ]
    score = _calculate_risk_score(findings)
    assert 0.0 < score < 100.0


# ── Summary ───────────────────────────────────────────────────────────────────

def test_generate_summary_no_findings() -> None:
    summary = _generate_summary("10.0.0.1", [], 0.0)
    assert "10.0.0.1" in summary
    assert "BAIXO" in summary


def test_generate_summary_with_critical() -> None:
    f = Finding(
        id="F-001", title="Critical vuln", severity=Severity.CRITICAL, cvss_score=9.8,
        description="d", evidence=[], remediation="r", references=[], affected_assets=[],
    )
    summary = _generate_summary("10.0.0.1", [f], 100.0)
    assert "ALTO" in summary
    assert "imediata" in summary


def test_analyze_resets_counter_between_calls() -> None:
    scan = _scan(_host("10.0.0.1", _service(21)))
    engine = CorrelationEngine()
    r1 = engine.analyze("10.0.0.1", scan_result=scan)
    r2 = engine.analyze("10.0.0.1", scan_result=scan)

    ids1 = [f.id for f in r1.findings]
    ids2 = [f.id for f in r2.findings]
    assert ids1 == ids2, "Counter must reset between analyze() calls"
