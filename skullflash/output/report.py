"""Export scan results as JSON, HTML, or PDF."""
from __future__ import annotations

import dataclasses
import json
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape
from loguru import logger

from skullflash import __version__


def _to_dict(obj: Any) -> Any:
    """Recursively convert dataclasses, datetimes, and Paths to JSON-safe types."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _to_dict(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, list):
        return [_to_dict(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    return obj


def export_json(data: Any, output_path: Path) -> None:
    """Serialize data to a pretty-printed JSON file.

    Args:
        data: Any dataclass, dict, or list to export.
        output_path: Destination file path (created if missing).
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(_to_dict(data), indent=2, default=str), encoding="utf-8")
    logger.info(f"JSON report → {output_path}")


def export_html(
    data: Dict[str, Any],
    output_path: Path,
    template_dir: Optional[Path] = None,
) -> None:
    """Render data through the Jinja2 report template and write an HTML file.

    Args:
        data: Mapping of section names to result objects.
        output_path: Destination .html file.
        template_dir: Override default templates/ directory.
    """
    tdir = template_dir or Path(__file__).parent.parent.parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(tdir)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html.j2")
    html = template.render(
        data=_to_dict(data),
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        version=__version__,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    logger.info(f"HTML report → {output_path}")


def export_pdf(
    data: Dict[str, Any],
    output_path: Path,
    template_dir: Optional[Path] = None,
) -> None:
    """Generate a PDF by rendering the HTML template and converting with WeasyPrint.

    Args:
        data: Mapping of section names to result objects.
        output_path: Destination .pdf file.
        template_dir: Override default templates/ directory.
    """
    try:
        from weasyprint import HTML as WeasyHTML
    except ImportError as exc:
        raise ImportError("weasyprint is required for PDF export: pip install weasyprint") from exc

    html_path = output_path.with_suffix(".html")
    export_html(data, html_path, template_dir)
    WeasyHTML(filename=str(html_path)).write_pdf(str(output_path))
    html_path.unlink(missing_ok=True)
    logger.info(f"PDF report → {output_path}")
