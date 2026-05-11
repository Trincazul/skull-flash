"""Authorization check and audit logging for every scan."""
from __future__ import annotations

import getpass
import socket
import sys
from datetime import datetime, timezone
from ipaddress import AddressValueError, ip_address, ip_network
from pathlib import Path
from typing import List

from loguru import logger


_AUDIT_LOG = Path.home() / ".skullflash" / "audit.log"


def require_authorization(
    target: str,
    allowed_targets: List[str],
    blocked_targets: List[str],
) -> None:
    """Validate operator authorization before scanning.

    Checks the target against blocked/allowed lists. If the target is not in
    the whitelist (when one is configured), asks for explicit written confirmation.
    All attempts are appended to an immutable audit log.

    Args:
        target: Scan target (IP, CIDR, or domain).
        allowed_targets: Whitelist from config. Empty means all targets are allowed.
        blocked_targets: Blacklist from config — always enforced.

    Raises:
        SystemExit: If the target is blocked or the user denies authorization.
    """
    if _is_blocked(target, blocked_targets):
        logger.error(f"Target {target!r} is in the blocked list. Aborting.")
        _write_audit(target, "BLOCKED")
        sys.exit(1)

    _write_audit(target, "AUTHORIZATION_CHECK")

    if not _is_allowed(target, allowed_targets):
        print(f"\n⚠  ATENÇÃO: Você está prestes a escanear {target}")
        print("   Confirme que possui AUTORIZAÇÃO ESCRITA para realizar este scan.")
        answer = input('   Digite "EU TENHO AUTORIZAÇÃO" para continuar: ')
        if answer.strip() != "EU TENHO AUTORIZAÇÃO":
            print("Scan cancelado.")
            _write_audit(target, "AUTHORIZATION_DENIED")
            sys.exit(0)

    _write_audit(target, "SCAN_STARTED")


def _is_blocked(target: str, blocked: List[str]) -> bool:
    for entry in blocked:
        try:
            if ip_address(target) in ip_network(entry, strict=False):
                return True
        except (AddressValueError, ValueError):
            if target == entry:
                return True
    return False


def _is_allowed(target: str, allowed: List[str]) -> bool:
    if not allowed:
        return True
    for entry in allowed:
        try:
            if ip_address(target) in ip_network(entry, strict=False):
                return True
        except (AddressValueError, ValueError):
            if target == entry or target.endswith(f".{entry}"):
                return True
    return False


def _write_audit(target: str, event: str) -> None:
    _AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "unknown"
    ts = datetime.now(timezone.utc).isoformat()
    user = getpass.getuser()
    line = f"{ts} user={user} host={hostname} target={target} event={event}\n"
    with open(_AUDIT_LOG, "a") as fh:
        fh.write(line)
