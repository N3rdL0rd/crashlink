"""Tests for the plugin-optimizer system."""

import sys

import pytest

import crashlink.plugins as plugins
from crashlink import Bytecode
from crashlink.decomp import IRFunction, TraversingIROptimizer
from crashlink.pseudo import pseudo

_CLAZZ = "tests/haxe/Clazz.hl"

# Records which IRFunctions a plugin optimizer ran on, so tests can assert gating.
_ran: list = []


class _MarkerOptimizer(TraversingIROptimizer):
    def optimize(self) -> None:
        _ran.append(id(self.func))


def _fresh():
    """Load a fresh Bytecode so the per-image plugin cache doesn't carry over."""
    return Bytecode.from_path(_CLAZZ)


def setup_function(_fn):
    plugins.clear()
    _ran.clear()


def teardown_function(_fn):
    plugins.clear()


def test_sha_is_computed():
    code = _fresh()
    assert code.sha256 and len(code.sha256) == 64


def test_gate_by_matching_sha_runs():
    code = _fresh()
    plugins.register_optimizer(_MarkerOptimizer, sha=code.sha256)
    IRFunction(code, code.functions[0])
    assert _ran, "optimizer gated to this sha should have run"


def test_gate_by_wrong_sha_skips():
    code = _fresh()
    plugins.register_optimizer(_MarkerOptimizer, sha="00" * 32)
    IRFunction(code, code.functions[0])
    assert not _ran, "optimizer gated to a different sha must not run"


def test_gate_by_predicate():
    code = _fresh()
    plugins.register_optimizer(_MarkerOptimizer, when=lambda c: True)
    IRFunction(code, code.functions[0])
    assert _ran


def test_no_gate_applies_always():
    code = _fresh()
    plugins.register_optimizer(_MarkerOptimizer)
    IRFunction(code, code.functions[0])
    assert _ran


def test_optimizers_for_filters_position():
    code = _fresh()
    plugins.register_optimizer(_MarkerOptimizer, position="start")
    assert plugins.optimizers_for(code, "start") == [_MarkerOptimizer]
    assert plugins.optimizers_for(code, "end") == []


def test_plugin_can_mutate_decompilation():
    # An optimizer that empties the block should visibly change output.
    class Emptier(TraversingIROptimizer):
        def optimize(self) -> None:
            if hasattr(self.func, "block"):
                self.func.block.statements = []

    base = _fresh()
    before = pseudo(IRFunction(base, base.functions[0]))

    active = _fresh()
    plugins.register_optimizer(Emptier, sha=active.sha256)
    after = pseudo(IRFunction(active, active.functions[0]))

    assert before != after


def test_raising_plugin_optimizer_is_skipped_with_warning():
    class Boom(TraversingIROptimizer):
        def optimize(self) -> None:
            raise RuntimeError("boom")

    base = _fresh()
    expected = pseudo(IRFunction(base, base.functions[0]))

    code = _fresh()
    plugins.register_optimizer(Boom)
    with pytest.warns(RuntimeWarning, match="Boom raised RuntimeError: boom"):
        got = pseudo(IRFunction(code, code.functions[0]))
    assert got == expected


def test_raising_gate_is_skipped_with_warning():
    def broken_gate(_code: Bytecode) -> bool:
        raise ZeroDivisionError("gate bug")

    code = _fresh()
    plugins.register_optimizer(_MarkerOptimizer, when=broken_gate)
    with pytest.warns(RuntimeWarning, match="gate for optimizer _MarkerOptimizer"):
        IRFunction(code, code.functions[0])
    assert not _ran


def test_plugin_registered_after_first_decompile_applies():
    code = _fresh()
    IRFunction(code, code.functions[0])
    plugins.register_optimizer(_MarkerOptimizer)
    IRFunction(code, code.functions[0])
    assert _ran, "a plugin registered mid-session must apply to later functions of an already-used image"


def test_broken_plugin_file_leaves_no_registrations_or_module(tmp_path, monkeypatch):
    monkeypatch.setattr(plugins, "plugin_dirs", lambda: [])  # ignore any plugins installed on this machine
    path = tmp_path / "half_broken.py"
    path.write_text(
        "from crashlink.plugins import optimizer\n"
        "from crashlink.decomp import TraversingIROptimizer\n"
        "@optimizer()\n"
        "class Early(TraversingIROptimizer):\n"
        "    pass\n"
        "raise SystemExit(3)\n"
    )
    with pytest.warns(RuntimeWarning, match="failed to load plugin .*half_broken.py: SystemExit"):
        plugins.load_file(str(path))
    assert plugins.registered() == []
    assert "crashlink_plugin_half_broken" not in sys.modules


def _plugin_in(directory, marker):
    directory.mkdir(parents=True)
    (directory / "marker_plugin.py").write_text(f"open({str(marker)!r}, 'w').close()\n")


def test_current_directory_plugins_are_not_executed(tmp_path, monkeypatch):
    marker = tmp_path / "ran"
    work = tmp_path / "work"
    _plugin_in(work / ".crashlink" / "plugins", marker)
    monkeypatch.chdir(work)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("CRASHLINK_PLUGINS", raising=False)

    plugins.registered()

    assert not marker.exists()


def test_env_var_opts_a_project_directory_in(tmp_path, monkeypatch):
    marker = tmp_path / "ran"
    work = tmp_path / "work"
    _plugin_in(work / ".crashlink" / "plugins", marker)
    monkeypatch.chdir(work)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CRASHLINK_PLUGINS", ".crashlink/plugins")

    plugins.registered()

    assert marker.exists()
