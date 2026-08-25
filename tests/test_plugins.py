"""Tests for the plugin-optimizer system."""

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
