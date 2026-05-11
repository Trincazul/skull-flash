"""Plugin loader with AST-based security validation."""
from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Dict, Optional

from loguru import logger

from skullflash.plugins.base import BasePlugin


_BUILTIN_DIR = Path(__file__).parent / "builtin"
_USER_DIR = Path.home() / ".skullflash" / "plugins"

# Hard-blocked AST patterns: calling these from a plugin is not allowed.
_BLOCKED_CALLS = {
    ("os", "system"),
    ("os", "popen"),
    ("os", "execvp"),
    ("os", "execve"),
}
_BLOCKED_BUILTINS = {"eval", "exec", "__import__"}


class PluginSecurityError(Exception):
    """Raised when a plugin fails the static security check."""


def discover_plugins() -> Dict[str, BasePlugin]:
    """Discover plugins from the builtin and user directories.

    Returns:
        Dict mapping plugin name to loaded BasePlugin instance.
    """
    plugins: Dict[str, BasePlugin] = {}

    for directory in (_BUILTIN_DIR, _USER_DIR):
        if not directory.exists():
            continue
        for path in sorted(directory.glob("*.py")):
            if path.name.startswith("_"):
                continue
            plugin = load_plugin(path)
            if plugin is not None:
                plugins[plugin.meta.name] = plugin
                logger.debug(f"Loaded plugin: {plugin.meta.name} from {path}")

    return plugins


def load_plugin(path: Path) -> Optional[BasePlugin]:
    """Load a single .py file as a plugin after security validation.

    Args:
        path: Path to the plugin .py file.

    Returns:
        BasePlugin instance, or None if loading fails.

    Raises:
        PluginSecurityError: If the plugin contains blocked code patterns.
    """
    try:
        source = path.read_text(encoding="utf-8")
        _security_check(source, path.name)
    except PluginSecurityError:
        raise
    except Exception as exc:
        logger.warning(f"Could not read plugin {path}: {exc}")
        return None

    try:
        spec = importlib.util.spec_from_file_location(path.stem, path)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        sys.modules[f"_skullflash_plugin_{path.stem}"] = module
        spec.loader.exec_module(module)  # type: ignore[attr-defined]
    except Exception as exc:
        logger.warning(f"Failed to load plugin {path.name}: {exc}")
        return None

    for attr in vars(module).values():
        if (
            isinstance(attr, type)
            and issubclass(attr, BasePlugin)
            and attr is not BasePlugin
        ):
            try:
                return attr()
            except Exception as exc:
                logger.warning(f"Could not instantiate plugin from {path.name}: {exc}")
                return None

    logger.warning(f"No BasePlugin subclass found in {path.name}")
    return None


def install_plugin(source: str) -> Path:
    """Copy or download a plugin file into the user plugins directory.

    Args:
        source: Local file path or HTTPS URL.

    Returns:
        Path to the installed plugin file.
    """
    _USER_DIR.mkdir(parents=True, exist_ok=True)

    if source.startswith("https://") or source.startswith("http://"):
        import httpx
        logger.warning(f"Downloading plugin from remote URL: {source}")
        response = httpx.get(source, follow_redirects=True, timeout=30)
        response.raise_for_status()
        content = response.text
        name = source.rstrip("/").split("/")[-1]
        if not name.endswith(".py"):
            name += ".py"
        dest = _USER_DIR / name
        _security_check(content, name)
        dest.write_text(content, encoding="utf-8")
    else:
        src_path = Path(source)
        if not src_path.exists():
            raise FileNotFoundError(f"Plugin file not found: {source}")
        content = src_path.read_text(encoding="utf-8")
        _security_check(content, src_path.name)
        dest = _USER_DIR / src_path.name
        dest.write_text(content, encoding="utf-8")

    logger.info(f"Plugin installed to {dest}")
    return dest


# ── Internal security checker ──────────────────────────────────────────────────

def _security_check(source: str, filename: str) -> None:
    """Parse source with AST and raise PluginSecurityError for dangerous patterns.

    Blocked patterns:
    - os.system(), os.popen(), os.exec*() calls
    - eval() / exec() built-in calls
    - __import__() calls
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise PluginSecurityError(f"Syntax error in {filename}: {exc}") from exc

    for node in ast.walk(tree):
        # Check attribute calls like os.system(...)
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                pair = (func.value.id, func.attr)
                if pair in _BLOCKED_CALLS:
                    raise PluginSecurityError(
                        f"Plugin {filename!r} calls blocked function {func.value.id}.{func.attr}(). "
                        f"Plugins may not use os.system/popen/exec variants."
                    )
            # Check bare built-in calls like eval(...) / exec(...)
            if isinstance(func, ast.Name) and func.id in _BLOCKED_BUILTINS:
                raise PluginSecurityError(
                    f"Plugin {filename!r} uses blocked built-in '{func.id}()'. "
                    f"Dynamic code execution is not permitted in plugins."
                )
