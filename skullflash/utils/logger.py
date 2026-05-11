"""Loguru logger configuration."""
from __future__ import annotations

import sys
from pathlib import Path

from loguru import logger


def setup_logger(level: str = "INFO", verbose: bool = False, quiet: bool = False) -> None:
    """Configure console and file handlers.

    Args:
        level: Minimum level for the file sink.
        verbose: Show DEBUG+ on console.
        quiet: Show only ERROR+ on console.
    """
    logger.remove()

    console_level = "DEBUG" if verbose else ("ERROR" if quiet else "WARNING")
    logger.add(
        sys.stderr,
        level=console_level,
        colorize=True,
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | {message}",
    )

    log_dir = Path.home() / ".skullflash" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    logger.add(
        log_dir / "skull-flash-{time:YYYY-MM-DD}.log",
        level=level,
        rotation="00:00",
        retention="30 days",
        serialize=True,  # JSON format for SIEM ingestion
    )
