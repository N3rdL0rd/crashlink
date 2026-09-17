"""Enum and typed-catch regressions compiled from current fixture sources."""

import os
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from crashlink import Bytecode
from crashlink.core import Enum, F64, Function, tIndex
from crashlink.decomp.function import IRClass, IRFunction
from crashlink.decomp.ir import (
    IRAssign,
    IRBlock,
    IRBoolExpr,
    IRConditional,
    IRConst,
    IREnumConstruct,
    IRLocal,
    IRPrimitiveLoop,
    IRReturn,
    IRWhileLoop,
)
from crashlink.decomp.opt.clean import IRLoopConditionOptimizer
from crashtest.behavior import compare_programs, compile_haxe, execute


@pytest.mark.parametrize(
    "name",
    [
        "EnumDestruct",
        "RecursiveEnumChain",
        "EnumMixedSwitch",
        "TypedCatch",
        "TryLoopContinue",
        "CatchClosureCaptureExc",
        "CatchNameReuse",
        "UnrolledLoopCatch",
    ],
)
def test_enum_and_catch_execution_survives_roundtrip(tmp_path, name):
    if not shutil.which("haxe") or not (os.environ.get("HL_RUNTIME") or shutil.which("hl")):
        pytest.skip("runtime regressions require Haxe and HashLink")
    source = (Path(__file__).parent / "haxe" / f"{name}.hx").read_text()
    original, error = compile_haxe(source, name, tmp_path / "original")
    assert error is None, error
    code = Bytecode.from_path(str(original))
    recovered = IRClass(code, code.get_test_obj(name), capture_layers=True).pseudo()
    recompiled, error = compile_haxe(recovered, name, tmp_path / "recompiled")
    assert error is None, error
    result = compare_programs(original, recompiled, name)
    assert result.passed, result.to_json()


def test_unmatched_typed_catch_does_not_swallow_exception(tmp_path):
    runtime = os.environ.get("HL_RUNTIME") or shutil.which("hl")
    if not shutil.which("haxe") or not runtime:
        pytest.skip("runtime regressions require Haxe and HashLink")
    name = "UnusedCatchType"
    source = (Path(__file__).parent / "haxe" / f"{name}.hx").read_text()
    for version in ("original", "recompiled"):
        target, error = compile_haxe(source, name, tmp_path / version)
        assert error is None, error
        result = execute([runtime, str(target)], str(target.parent))
        assert result.error is None, result.error
        assert result.returncode == 1
        assert result.stdout.splitlines()[0] == "Uncaught exception: x"
        if version == "original":
            code = Bytecode.from_path(str(target))
            source = IRClass(code, code.get_test_obj(name), capture_layers=True).pseudo()


def test_typed_catch_rethrows_original_payload(tmp_path):
    runtime = os.environ.get("HL_RUNTIME") or shutil.which("hl")
    if not shutil.which("haxe") or not runtime:
        pytest.skip("runtime regressions require Haxe and HashLink")
    name = "TypedCatchRethrow"
    source = (Path(__file__).parent / "haxe" / f"{name}.hx").read_text()
    for version in ("original", "recompiled"):
        target, error = compile_haxe(source, name, tmp_path / version)
        assert error is None, error
        result = execute([runtime, str(target)], str(target.parent))
        assert result.error is None, result.error
        assert result.returncode == 1
        assert result.stdout.splitlines()[0] == "Uncaught exception: deep"
        if version == "original":
            code = Bytecode.from_path(str(target))
            source = IRClass(code, code.get_test_obj(name)).pseudo()


def test_loop_setup_value_remains_available_to_enum_argument():
    code = Bytecode.from_path(str(Path(__file__).parent / "haxe" / "EnumMixedSwitch.hl"))
    float_type = tIndex(next(i for i, t in enumerate(code.types) if isinstance(t.definition, F64)))
    enum_type = tIndex(
        next(
            i
            for i, t in enumerate(code.types)
            if isinstance(t.definition, Enum) and t.definition.name.resolve(code) == "Shape"
        )
    )
    radius = IRLocal("var0", float_type, code)
    setup, body, root = IRBlock(code), IRBlock(code), IRBlock(code)
    setup.statements = [
        IRAssign(code, radius, IRConst(code, IRConst.ConstType.INT, value=2)),
        IRBoolExpr(code, IRBoolExpr.CompareType.GTE, radius, IRConst(code, IRConst.ConstType.INT, value=10)),
    ]
    body.statements = [IRReturn(code, IREnumConstruct(code, "Circle", [radius], enum_type))]
    root.statements = [IRPrimitiveLoop(code, setup, body)]
    function = cast(
        IRFunction, SimpleNamespace(code=code, func=Function(), ops=[], block=root, locals=[radius])
    )
    IRLoopConditionOptimizer(function).optimize()

    # Execute the first iteration, which returns immediately. Losing the loop
    # setup assignment makes the constructor read an undefined local here.
    values = {}

    def evaluate(node):
        if isinstance(node, IRConst):
            return node.value
        if isinstance(node, IRLocal):
            return values[node.name]
        if isinstance(node, IRAssign):
            values[node.target.name] = evaluate(node.expr)
        elif isinstance(node, IRBoolExpr):
            if node.op == IRBoolExpr.CompareType.TRUE:
                return True
            if node.op == IRBoolExpr.CompareType.GTE:
                return evaluate(node.left) >= evaluate(node.right)
            if node.op == IRBoolExpr.CompareType.LT:
                return evaluate(node.left) < evaluate(node.right)
            raise AssertionError(node.op)
        elif isinstance(node, IRBlock):
            for statement in node.statements:
                result = evaluate(statement)
                if result is not None:
                    return result
        elif isinstance(node, IRConditional):
            return evaluate(node.true_block if evaluate(node.condition) else node.false_block)
        elif isinstance(node, IRWhileLoop):
            assert evaluate(node.condition)
            return evaluate(node.body)
        elif isinstance(node, IRReturn):
            return evaluate(node.value)
        elif isinstance(node, IREnumConstruct):
            return node.construct_name, tuple(evaluate(arg) for arg in node.args)
        else:
            raise AssertionError(type(node))

    assert evaluate(root) == ("Circle", (2,))
