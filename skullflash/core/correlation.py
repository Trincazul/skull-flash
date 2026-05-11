"""Correlation engine — consolidates scan artefacts into scored findings."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from skullflash.core.cve import CveResult
from skullflash.core.scanner import ScanResult
from skullflash.core.web import SslAnalysis, WebResult


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


_WEIGHTS: Dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

_SENSITIVE_PORTS: Dict[int, tuple] = {
    21:    ("FTP",     Severity.HIGH,   "Protocolo em texto plano — credenciais não criptografadas"),
    23:    ("Telnet",  Severity.HIGH,   "Protocolo em texto plano — sessão inteiramente exposta"),
    3389:  ("RDP",    Severity.MEDIUM, "Remote Desktop Protocol exposto à rede"),
    5900:  ("VNC",    Severity.MEDIUM, "Acesso remoto à área de trabalho exposto"),
    27017: ("MongoDB", Severity.MEDIUM, "MongoDB pode estar sem autenticação"),
}

_WEAK_PROTOS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLS 1.0", "TLS 1.1"}

_WEAK_CIPHER_FRAGMENTS = {"RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "ANON"}

_REQUIRED_HEADERS: Dict[str, str] = {
    "Strict-Transport-Security":  "Adicionar HSTS para forçar conexões HTTPS",
    "Content-Security-Policy":    "Adicionar CSP para mitigar XSS e injeção de conteúdo",
    "X-Frame-Options":            "Adicionar X-Frame-Options: DENY para prevenir clickjacking",
    "X-Content-Type-Options":     "Adicionar X-Content-Type-Options: nosniff",
}


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    cvss_score: Optional[float]
    description: str
    evidence: List[str]
    remediation: str
    references: List[str]
    affected_assets: List[str]


@dataclass
class RiskReport:
    target: str
    timestamp: datetime
    findings: List[Finding] = field(default_factory=list)
    risk_score: float = 0.0
    executive_summary: str = ""


class CorrelationEngine:
    """Apply deterministic rules to generate a consolidated RiskReport.

    Instantiate once and call analyze() for each target — the counter
    resets automatically on each call.
    """

    def __init__(self) -> None:
        self._counter = 0

    def _next_id(self) -> str:
        self._counter += 1
        return f"FIND-{self._counter:03d}"

    def analyze(
        self,
        target: str,
        scan_result: Optional[ScanResult] = None,
        cve_results: Optional[List[CveResult]] = None,
        web_result: Optional[WebResult] = None,
    ) -> RiskReport:
        """Run all correlation rules and return a scored RiskReport.

        Args:
            target: Human-readable target identifier (IP, domain, URL).
            scan_result: Nmap scan output.
            cve_results: CVE lookups from NVD.
            web_result: HTTP headers and SSL analysis.

        Returns:
            RiskReport with all generated findings and computed scores.
        """
        self._counter = 0
        findings: List[Finding] = []

        if scan_result:
            findings += self._rule_004_sensitive_ports(scan_result)
            findings += self._rule_006_unknown_versions(scan_result)

        if scan_result and cve_results:
            findings += self._rule_001_critical_cves(scan_result, cve_results)
            findings += self._rule_005_attack_surface(scan_result, cve_results)

        if web_result and web_result.ssl:
            findings += self._rule_002_weak_ssl(web_result.ssl, target)

        if web_result and web_result.headers:
            findings += self._rule_003_missing_headers(web_result.headers, target)

        risk = _calculate_risk_score(findings)
        summary = _generate_summary(target, findings, risk)

        return RiskReport(
            target=target,
            timestamp=datetime.utcnow(),
            findings=findings,
            risk_score=risk,
            executive_summary=summary,
        )

    # ── RULE-001 ──────────────────────────────────────────────────────────────

    def _rule_001_critical_cves(
        self, scan: ScanResult, cve_results: List[CveResult]
    ) -> List[Finding]:
        out: List[Finding] = []
        for host in scan.hosts:
            for svc in host.services:
                if svc.state != "open":
                    continue
                for cve_res in cve_results:
                    for cve in cve_res.cves:
                        if cve.cvss_score >= 9.0:
                            out.append(Finding(
                                id=self._next_id(),
                                title=f"CVE crítico {cve.cve_id} em {svc.product or svc.name}",
                                severity=Severity.CRITICAL,
                                cvss_score=cve.cvss_score,
                                description=cve.description,
                                evidence=[
                                    f"Host: {host.ip}:{svc.port}",
                                    f"Serviço: {svc.product} {svc.version}".strip(),
                                    f"CVE: {cve.cve_id} (CVSS {cve.cvss_score})",
                                ],
                                remediation=(
                                    f"Atualizar {svc.product or svc.name} para a versão mais recente "
                                    f"que corrige {cve.cve_id}."
                                ),
                                references=[
                                    f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}"
                                ],
                                affected_assets=[f"{host.ip}:{svc.port}"],
                            ))
        return out

    # ── RULE-002 ──────────────────────────────────────────────────────────────

    def _rule_002_weak_ssl(self, ssl: SslAnalysis, target: str) -> List[Finding]:
        issues: List[str] = []
        if ssl.protocol in _WEAK_PROTOS:
            issues.append(f"Protocolo fraco habilitado: {ssl.protocol}")
        cipher = (ssl.cipher or "").upper()
        for frag in _WEAK_CIPHER_FRAGMENTS:
            if frag in cipher:
                issues.append(f"Cipher suite fraca: {ssl.cipher}")
                break
        if not ssl.valid:
            issues.append("Certificado inválido ou expirado")

        if not issues:
            return []

        return [Finding(
            id=self._next_id(),
            title="Configuração SSL/TLS fraca ou insegura",
            severity=Severity.HIGH,
            cvss_score=None,
            description="A configuração SSL/TLS apresenta problemas que podem expor a comunicação.",
            evidence=issues,
            remediation=(
                "Desabilitar TLS < 1.2, remover ciphers RC4/DES/3DES/MD5, "
                "e garantir que o certificado esteja válido e renovado."
            ),
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cipher_String_Cheat_Sheet.html"
            ],
            affected_assets=[target],
        )]

    # ── RULE-003 ──────────────────────────────────────────────────────────────

    def _rule_003_missing_headers(self, headers, target: str) -> List[Finding]:
        out: List[Finding] = []
        for header in headers.missing:
            if header in _REQUIRED_HEADERS:
                out.append(Finding(
                    id=self._next_id(),
                    title=f"Header de segurança ausente: {header}",
                    severity=Severity.MEDIUM,
                    cvss_score=None,
                    description=f"O response header '{header}' não está presente, reduzindo a postura de segurança.",
                    evidence=[f"Header ausente: {header}", f"URL analisada: {target}"],
                    remediation=_REQUIRED_HEADERS[header],
                    references=["https://owasp.org/www-project-secure-headers/"],
                    affected_assets=[target],
                ))
        return out

    # ── RULE-004 ──────────────────────────────────────────────────────────────

    def _rule_004_sensitive_ports(self, scan: ScanResult) -> List[Finding]:
        out: List[Finding] = []
        for host in scan.hosts:
            for svc in host.services:
                if svc.state != "open":
                    continue
                if svc.port not in _SENSITIVE_PORTS:
                    continue
                name, severity, reason = _SENSITIVE_PORTS[svc.port]
                out.append(Finding(
                    id=self._next_id(),
                    title=f"Serviço sensível exposto: {name} (porta {svc.port})",
                    severity=severity,
                    cvss_score=None,
                    description=f"{reason}.",
                    evidence=[
                        f"Host: {host.ip}",
                        f"Porta: {svc.port}/tcp ({svc.state})",
                        f"Serviço identificado: {name}",
                    ],
                    remediation=(
                        f"Restringir acesso à porta {svc.port} via firewall ou "
                        f"substituir {name} por alternativa segura."
                    ),
                    references=["https://www.cisa.gov/uscert/ncas/alerts"],
                    affected_assets=[f"{host.ip}:{svc.port}"],
                ))
        return out

    # ── RULE-005 ──────────────────────────────────────────────────────────────

    def _rule_005_attack_surface(
        self, scan: ScanResult, cve_results: List[CveResult]
    ) -> List[Finding]:
        total_cves = sum(len(r.cves) for r in cve_results)
        if total_cves < 3:
            return []

        out: List[Finding] = []
        for host in scan.hosts:
            out.append(Finding(
                id=self._next_id(),
                title="Superfície de ataque elevada — múltiplos CVEs identificados",
                severity=Severity.HIGH,
                cvss_score=None,
                description=(
                    f"{total_cves} CVEs foram encontrados nos serviços expostos em {host.ip}, "
                    f"indicando uma superfície de ataque ampla que requer patch management urgente."
                ),
                evidence=[
                    f"Total de CVEs identificados: {total_cves}",
                    f"Host afetado: {host.ip}",
                    f"Serviços com CVEs: {', '.join(r.service for r in cve_results if r.cves)}",
                ],
                remediation=(
                    "Aplicar patches de segurança em todos os serviços afetados, "
                    "desabilitar serviços desnecessários e implementar segmentação de rede."
                ),
                references=["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
                affected_assets=[host.ip],
            ))
        return out

    # ── RULE-006 ──────────────────────────────────────────────────────────────

    def _rule_006_unknown_versions(self, scan: ScanResult) -> List[Finding]:
        out: List[Finding] = []
        for host in scan.hosts:
            for svc in host.services:
                if svc.state == "open" and not svc.version and not svc.product:
                    out.append(Finding(
                        id=self._next_id(),
                        title=f"Versão não identificada na porta {svc.port}",
                        severity=Severity.INFO,
                        cvss_score=None,
                        description=(
                            f"O serviço na porta {svc.port} está aberto, mas produto/versão "
                            f"não foram identificados — impossibilitando correlação automática de CVEs."
                        ),
                        evidence=[
                            f"Host: {host.ip}:{svc.port}",
                            f"Serviço: {svc.name or 'unknown'}",
                        ],
                        remediation="Investigar manualmente via banner grabbing ou análise do protocolo.",
                        references=[],
                        affected_assets=[f"{host.ip}:{svc.port}"],
                    ))
        return out


# ── Helpers ────────────────────────────────────────────────────────────────────

def _calculate_risk_score(findings: List[Finding]) -> float:
    """Weighted normalised risk score in [0, 100].

    Args:
        findings: List of generated findings.

    Returns:
        Float between 0.0 and 100.0.
    """
    if not findings:
        return 0.0
    raw = sum(_WEIGHTS[f.severity] for f in findings)
    return min(100.0, (raw / (len(findings) * 10)) * 100)


def _generate_summary(target: str, findings: List[Finding], risk: float) -> str:
    """Generate a human-readable executive summary string."""
    by_sev = {s: 0 for s in Severity}
    for f in findings:
        by_sev[f.severity] += 1

    risk_label = "ALTO" if risk >= 70 else ("MÉDIO" if risk >= 40 else "BAIXO")

    parts: List[str] = []
    for sev, label in [
        (Severity.CRITICAL, "crítico(s)"),
        (Severity.HIGH, "alto(s)"),
        (Severity.MEDIUM, "médio(s)"),
        (Severity.LOW, "baixo(s)"),
        (Severity.INFO, "informacional(is)"),
    ]:
        if by_sev[sev]:
            parts.append(f"{by_sev[sev]} {label}")

    severity_str = ", ".join(parts) if parts else "nenhum finding"

    critical_list = [f for f in findings if f.severity == Severity.CRITICAL]
    critical_str = ""
    if critical_list:
        titles = [f.title[:50] for f in critical_list[:2]]
        critical_str = f" Principais vetores: {'; '.join(titles)}."

    action = " Recomenda-se ação imediata nos findings críticos." if by_sev[Severity.CRITICAL] else ""

    return (
        f"Foram identificados {len(findings)} finding(s) no alvo {target}: {severity_str}. "
        f"O risco geral é {risk_label} (score {risk:.0f}/100).{critical_str}{action}"
    )
