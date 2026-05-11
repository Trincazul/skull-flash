"""Tests for the plugin system — security checker, loader, and discovery."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from skullflash.plugins.loader import (
    PluginSecurityError,
    _security_check,
    discover_plugins,
    load_plugin,
)


# ── _security_check ───────────────────────────────────────────────────────────

def test_security_check_passes_clean_code() -> None:
    source = "def add(a, b): return a + b"
    _security_check(source, "clean.py")  # must not raise


def test_security_check_passes_import_statement() -> None:
    source = "import os\nprint(os.getcwd())"
    _security_check(source, "safe_import.py")  # os.getcwd is fine; only os.system etc. blocked


def test_security_check_blocks_os_system() -> None:
    source = "import os; os.system('rm -rf /')"
    with pytest.raises(PluginSecurityError, match="os.system"):
        _security_check(source, "bad.py")


def test_security_check_blocks_os_popen() -> None:
    source = "import os\nos.popen('whoami')"
    with pytest.raises(PluginSecurityError, match="os.popen"):
        _security_check(source, "bad.py")


def test_security_check_blocks_os_execvp() -> None:
    source = "import os\nos.execvp('sh', ['sh', '-c', 'id'])"
    with pytest.raises(PluginSecurityError, match="os.execvp"):
        _security_check(source, "bad.py")


def test_security_check_blocks_eval() -> None:
    source = "result = eval('1 + 1')"
    with pytest.raises(PluginSecurityError, match="eval"):
        _security_check(source, "bad.py")


def test_security_check_blocks_exec() -> None:
    source = "exec('import os; os.system(\"ls\")')"
    with pytest.raises(PluginSecurityError, match="exec"):
        _security_check(source, "bad.py")


def test_security_check_blocks_dunder_import() -> None:
    source = "__import__('subprocess').call(['ls'])"
    with pytest.raises(PluginSecurityError, match="__import__"):
        _security_check(source, "bad.py")


def test_security_check_raises_on_syntax_error() -> None:
    source = "def broken(:"
    with pytest.raises(PluginSecurityError, match="Syntax error"):
        _security_check(source, "broken.py")


# ── load_plugin ───────────────────────────────────────────────────────────────

_VALID_PLUGIN = textwrap.dedent("""\
    from skullflash.plugins.base import BasePlugin, PluginMeta

    class DemoPlugin(BasePlugin):
        meta = PluginMeta(name="demo", version="0.1", description="demo plugin")

        async def run(self, target, options=None):
            return {"ping": target}

        def get_options(self):
            return {}
""")

_NO_SUBCLASS_PLUGIN = textwrap.dedent("""\
    def helper():
        return 42
""")


def test_load_plugin_valid(tmp_path: Path) -> None:
    p = tmp_path / "demo.py"
    p.write_text(_VALID_PLUGIN)

    plugin = load_plugin(p)

    assert plugin is not None
    assert plugin.meta.name == "demo"
    assert plugin.meta.version == "0.1"


def test_load_plugin_no_subclass_returns_none(tmp_path: Path) -> None:
    p = tmp_path / "noclass.py"
    p.write_text(_NO_SUBCLASS_PLUGIN)

    plugin = load_plugin(p)

    assert plugin is None


def test_load_plugin_raises_security_error_for_blocked_code(tmp_path: Path) -> None:
    p = tmp_path / "evil.py"
    p.write_text("import os\nos.system('bad')")

    with pytest.raises(PluginSecurityError):
        load_plugin(p)


def test_load_plugin_nonexistent_file(tmp_path: Path) -> None:
    p = tmp_path / "ghost.py"

    plugin = load_plugin(p)

    assert plugin is None


# ── discover_plugins ──────────────────────────────────────────────────────────

def test_discover_plugins_returns_dict() -> None:
    plugins = discover_plugins()
    assert isinstance(plugins, dict)


def test_discover_plugins_keys_are_strings() -> None:
    plugins = discover_plugins()
    for key in plugins:
        assert isinstance(key, str)


def test_discover_plugins_values_are_base_plugin() -> None:
    from skullflash.plugins.base import BasePlugin
    plugins = discover_plugins()
    for plugin in plugins.values():
        assert isinstance(plugin, BasePlugin)


def test_builtin_plugins_loaded() -> None:
    plugins = discover_plugins()
    # At least one builtin plugin should always be available
    assert len(plugins) >= 1, "Expected at least one builtin plugin"


# ── Plugin run (integration) ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_valid_plugin_run(tmp_path: Path) -> None:
    p = tmp_path / "runner.py"
    p.write_text(_VALID_PLUGIN)

    plugin = load_plugin(p)
    assert plugin is not None

    result = await plugin.run("127.0.0.1")

    assert result == {"ping": "127.0.0.1"}
