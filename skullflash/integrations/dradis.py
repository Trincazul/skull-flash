"""Dradis integration — export findings as Dradis-compatible XML."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List

from skullflash.core.correlation import Finding
from skullflash.integrations.base import IntegrationBase


class DradisIntegration(IntegrationBase):
    """Generate Dradis CE / Pro import XML from skull-flash findings."""

    async def push_findings(
        self, findings: List[Finding], target: str
    ) -> Dict[str, Any]:
        """Build an in-memory Dradis XML document and return it as a string.

        Call export_xml() to write to a file directly.

        Args:
            findings: Correlation engine findings.
            target: Scan target label.

        Returns:
            Dict with 'xml' key containing the serialized XML string.
        """
        xml_str = self._build_xml(findings, target)
        return {"xml": xml_str, "findings": len(findings)}

    def export_xml(self, findings: List[Finding], target: str, output_path: Path) -> None:
        """Write a Dradis-compatible XML import file.

        Args:
            findings: Correlation engine findings.
            target: Scan target label.
            output_path: Destination .xml file path.
        """
        xml_str = self._build_xml(findings, target)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(xml_str, encoding="utf-8")

    @staticmethod
    def _build_xml(findings: List[Finding], target: str) -> str:
        root = ET.Element("dradis-template")
        nodes = ET.SubElement(root, "nodes")
        node = ET.SubElement(nodes, "node")

        ET.SubElement(node, "label").text = target
        ET.SubElement(node, "type-id").text = "1"

        notes = ET.SubElement(node, "notes")
        for finding in findings:
            note = ET.SubElement(notes, "note")
            fields = ET.SubElement(note, "fields")

            evidence_str = "\n".join(finding.evidence)
            refs_str = "\n".join(finding.references) if finding.references else "N/A"
            assets_str = ", ".join(finding.affected_assets)

            _field(fields, "Title", finding.title)
            _field(fields, "Risk", finding.severity.value)
            _field(fields, "CVSS Score", str(finding.cvss_score) if finding.cvss_score else "N/A")
            _field(fields, "Description", finding.description)
            _field(fields, "Evidence", evidence_str)
            _field(fields, "Affected Assets", assets_str)
            _field(fields, "Remediation", finding.remediation)
            _field(fields, "References", refs_str)
            _field(fields, "Finding ID", finding.id)

        ET.indent(root, space="  ")
        return ET.tostring(root, encoding="unicode", xml_declaration=True)


def _field(parent: ET.Element, tag: str, text: str) -> ET.Element:
    f = ET.SubElement(parent, "field")
    f.set("tag", tag)
    f.text = text
    return f
