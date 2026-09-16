"""Array recovery must preserve captured values, effects, and declaration types."""

from types import SimpleNamespace
from typing import cast

import os
import shutil

import pytest

from crashlink.core import Array, Bool, Bytecode, Dyn, F64, I32, Type, Void, tIndex
from crashlink.decomp.function import IRFunction
from crashlink.decomp.ir import (
    IRArrayAccess,
    IRArrayLiteral,
    IRAssign,
    IRBlock,
    IRConditional,
    IRConst,
    IRExpression,
    IRLocal,
    IRNativeArrayNew,
    IRReturn,
)
from crashlink.decomp.opt.arrays import IRArrayObjWrapperOptimizer
from crashlink.decomp.opt.arraytypes import _recover_native_local_types, _uniform_element_type
from crashlink.pseudo import _collect_locals


def _code():
    code = Bytecode()
    code.types = []
    for definition in (Void, I32, Dyn, Array, Bool, F64):
        typ = Type()
        typ.kind.value = Type.TYPEDEFS.index(definition)
        typ.definition = definition()
        code.types.append(typ)
    return code


def _block(code, *statements):
    block = IRBlock(code)
    block.statements = list(statements)
    return block


def _int(code, value):
    return IRConst(code, IRConst.ConstType.INT, value=value)


class _Observe(IRExpression):
    def __init__(self, code, label):
        super().__init__(code)
        self.label = label

    def get_type(self):
        return self.code.types[1]

    def __repr__(self):
        return f"Observe({self.label})"


def _evaluate(node, values, events):
    if isinstance(node, IRBlock):
        for stmt in node.statements:
            result = _evaluate(stmt, values, events)
        return result
    if isinstance(node, IRAssign):
        value = _evaluate(node.expr, values, events)
        if isinstance(node.target, IRArrayAccess):
            values[node.target.array.name][_evaluate(node.target.index, values, events)] = value
        else:
            values[node.target.name] = value
        return value
    if isinstance(node, IRConst):
        return node.value
    if isinstance(node, IRLocal):
        return values[node.name]
    if isinstance(node, IRConditional):
        return _evaluate(
            node.true_block if _evaluate(node.condition, values, events) else node.false_block, values, events
        )
    if isinstance(node, IRNativeArrayNew):
        return [None] * _evaluate(node.size, values, events)
    if isinstance(node, IRArrayLiteral):
        return [_evaluate(elem, values, events) for elem in node.elements]
    if isinstance(node, IRReturn):
        return _evaluate(node.value, values, events)
    if isinstance(node, _Observe):
        events.append(node.label)
        return len(events)
    raise AssertionError(type(node))


def _fold(code, block, array):
    optimizer = IRArrayObjWrapperOptimizer(cast(IRFunction, SimpleNamespace(code=code)))
    match = optimizer._try_fold_array_literal(block.statements, len(block.statements) - 1, array)
    if match is not None:
        elements, consumed = match
        block.statements[-1] = IRReturn(code, IRArrayLiteral(code, elements))
        block.statements = [stmt for index, stmt in enumerate(block.statements) if index not in consumed]


def test_literal_preserves_value_stored_before_nested_register_reuse():
    code = _code()
    array = IRLocal("array", tIndex(3), code)
    value = IRLocal("value", tIndex(2), code)
    block = _block(
        code,
        IRAssign(code, array, IRNativeArrayNew(code, tIndex(3), code.types[2], _int(code, 2))),
        IRAssign(code, value, _int(code, 11)),
        IRAssign(code, IRArrayAccess(code, array, _int(code, 0)), value),
        IRConditional(
            code,
            IRConst(code, IRConst.ConstType.BOOL, value=True),
            _block(code, IRAssign(code, value, _int(code, 22))),
            _block(code),
        ),
        IRAssign(code, IRArrayAccess(code, array, _int(code, 1)), value),
        IRReturn(code, array),
    )
    _fold(code, block, array)
    assert _evaluate(block, {}, []) == [11, 22]


def test_literal_keeps_store_effect_before_intervening_effect():
    code = _code()
    array = IRLocal("array", tIndex(3), code)
    block = _block(
        code,
        IRAssign(code, array, IRNativeArrayNew(code, tIndex(3), code.types[1], _int(code, 1))),
        IRAssign(code, IRArrayAccess(code, array, _int(code, 0)), _Observe(code, "element")),
        _Observe(code, "between"),
        IRReturn(code, array),
    )
    _fold(code, block, array)
    events = []
    assert _evaluate(block, {}, events) == [1]
    assert events == ["element", "between"]


def test_mixed_primitive_elements_do_not_infer_first_primitive_type():
    code = _code()
    integer = IRLocal("integer", tIndex(1), code)
    floating = IRLocal("floating", tIndex(5), code)
    assert _uniform_element_type([integer, floating], code) is None
    assert _uniform_element_type([integer, integer], code) == code.types[1]


def test_reused_native_register_declaration_covers_all_allocations():
    code = _code()
    array = IRLocal("array", tIndex(3), code)
    block = _block(
        code,
        IRAssign(code, array, IRNativeArrayNew(code, tIndex(3), code.types[1], _int(code, 1))),
        IRAssign(code, array, IRNativeArrayNew(code, tIndex(3), code.types[5], _int(code, 1))),
    )
    _recover_native_local_types(cast(IRFunction, SimpleNamespace(block=block)), code)
    assert _collect_locals(block)["array"] == "hl.NativeArray<Dynamic>"


def test_empty_array_roundtrip_preserves_allocation_count(tmp_path):
    from crashlink.decomp.function import IRClass
    from crashtest.behavior import compare_programs, compile_haxe

    if not shutil.which("haxe") or not (os.environ.get("HL_RUNTIME") or shutil.which("hl")):
        pytest.skip("roundtrip regression requires Haxe and HashLink")
    source = """
class EmptyArrayRoundtrip {
    static function make():Array<String> { return []; }
    static function main() {
        var a = make();
        var b = make();
        a.push("kept");
        Sys.println(a.join(","));
        Sys.println(b.length);
        Sys.println(a == b);
    }
}
"""
    name = "EmptyArrayRoundtrip"
    original, error = compile_haxe(source, name, tmp_path / "original")
    assert error is None, error
    before = Bytecode.from_path(str(original))
    recovered = IRClass(before, before.get_test_obj(name)).pseudo()
    recompiled, error = compile_haxe(recovered, name, tmp_path / "recompiled")
    assert error is None, error
    after = Bytecode.from_path(str(recompiled))

    def allocations(code):
        make = next(f for f in code.functions if code.full_func_name(f) == f"${name}.make")
        return sum(
            op.op == "Call2" and code.full_func_name(op.df["fun"].resolve(code)) == "std.alloc_array"
            for op in make.ops
        )

    assert allocations(before) == 1
    assert allocations(after) == allocations(before)
    behavior = compare_programs(original, recompiled, name)
    assert behavior.passed, behavior.to_json()
    assert behavior.recompiled.stdout == "kept\n0\nfalse\n"


def test_empty_dynamic_array_roundtrip_preserves_allocation_pair(tmp_path):
    from crashlink.decomp.function import IRClass
    from crashtest.behavior import compare_programs, compile_haxe

    if not shutil.which("haxe") or not (os.environ.get("HL_RUNTIME") or shutil.which("hl")):
        pytest.skip("roundtrip regression requires Haxe and HashLink")
    source = """
class EmptyDynamicArrayRoundtrip {
    static function make():Array<Dynamic> { return []; }
    static function main() {
        var a = make();
        var b = make();
        a.push("kept");
        Sys.println(a.join(","));
        Sys.println(b.length);
        Sys.println(a == b);
    }
}
"""
    name = "EmptyDynamicArrayRoundtrip"
    original, error = compile_haxe(source, name, tmp_path / "original")
    assert error is None, error
    before = Bytecode.from_path(str(original))
    recovered = IRClass(before, before.get_test_obj(name)).pseudo()
    recompiled, error = compile_haxe(recovered, name, tmp_path / "recompiled")
    assert error is None, error
    after = Bytecode.from_path(str(recompiled))

    def allocation_pair(code):
        make = next(f for f in code.functions if code.full_func_name(f) == f"${name}.make")
        return (
            sum(
                op.op == "Call2" and code.full_func_name(op.df["fun"].resolve(code)) == "std.alloc_array"
                for op in make.ops
            ),
            sum(
                op.op == "Call2"
                and code.full_func_name(op.df["fun"].resolve(code)) == "hl.types.$ArrayDyn.alloc"
                for op in make.ops
            ),
        )

    assert allocation_pair(before) == (1, 1)
    assert allocation_pair(after) == allocation_pair(before)
    behavior = compare_programs(original, recompiled, name)
    assert behavior.passed, behavior.to_json()
    assert behavior.recompiled.stdout == "kept\n0\nfalse\n"
