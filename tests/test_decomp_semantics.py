"""Behavioral regressions for control-flow, numeric and discarded-result semantics."""

import math
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import List, cast

import pytest

from crashlink.core import Bytecode, Function, I64, Opcode, Reg, Type, tIndex
from crashlink.decomp.cfg import CFGraph, CFJumpThreader
from crashlink.decomp.function import IRClass, IRFunction
from crashlink.decomp.ir import (
    IRArithmetic,
    IRArrayAccess,
    IRAssign,
    IRBlock,
    IRBoolExpr,
    IRBreak,
    IRCall,
    IRCast,
    IRConditional,
    IRConst,
    IRContinue,
    IRExpression,
    IRField,
    IRLocal,
    IRPrimitiveLoop,
    IRReturn,
    IRStatement,
    IRWhileLoop,
)
from crashlink.decomp.opt.clean import (
    IRDeadAssignmentEliminator,
    IRDeadStoreEliminator,
    IRDeadTempEliminator,
    IRLoopConditionOptimizer,
    IRSequentialTempFolder,
)
from crashlink.decomp.opt.inliner import IRConditionInliner, IRTempAssignmentInliner
from crashlink.pseudo import _expression_to_haxe, _generate_statements


def _function(code, statements, locals=()):
    block = IRBlock(code)
    block.statements = statements
    return SimpleNamespace(code=code, func=Function(), ops=[], block=block, locals=list(locals))


def test_jump_self_loop_terminates():
    # Isolate the former infinite append-to-predecessors loop so a regression
    # fails with a timeout instead of hanging the whole test runner.
    subprocess.run(
        [
            sys.executable,
            "-c",
            """
from crashlink.core import Function, Opcode, VarInt
from crashlink.decomp.cfg import CFGraph
function = Function()
function.ops = [Opcode('JAlways', {'offset': VarInt(-1)})]
graph = CFGraph(function)
graph.build()
assert graph.nodes == [graph.entry]
assert graph.entry.branches == [(graph.entry, 'unconditional')]
assert graph.entry in graph.loops
""",
        ],
        check=True,
        capture_output=True,
        timeout=5,
    )


def test_jump_cycle_and_entry_survive_threading():
    graph = CFGraph(Function())
    prefix, a, b = [graph.add_node([Opcode("JAlways")]) for _ in range(3)]
    graph.entry = prefix
    graph.add_branch(prefix, a, "unconditional")
    graph.add_branch(a, b, "unconditional")
    graph.add_branch(b, a, "unconditional")
    CFJumpThreader(graph).optimize()
    assert graph.entry is a
    assert set(graph.nodes) == {a, b}
    assert a.branches == [(b, "unconditional")]
    assert b.branches == [(a, "unconditional")]
    CFJumpThreader(graph).optimize()
    assert set(graph.nodes) == {a, b}
    assert graph.entry is a


def test_jump_chain_preserves_branch_labels_and_entry():
    graph = CFGraph(Function())
    start, middle = [graph.add_node([Opcode("JAlways")]) for _ in range(2)]
    branch = graph.add_node([Opcode("JTrue")])
    end = graph.add_node([Opcode("Ret")])
    graph.entry = start
    graph.add_branch(start, middle, "unconditional")
    graph.add_branch(middle, branch, "unconditional")
    graph.add_branch(branch, start, "true")
    graph.add_branch(branch, end, "false")
    CFJumpThreader(graph).optimize()
    assert graph.entry is branch
    assert graph.nodes == [branch, end]
    assert branch.branches == [(branch, "true"), (end, "false")]


class _UnknownThrowingExpression(IRExpression):
    def get_type(self):
        return self.code.types[1]

    def __repr__(self):
        return "unknown_throwing_expression"


def _evaluate(node, values, events):
    """Small independent observer for evaluation count, order and exceptions."""
    if isinstance(node, IRBlock):
        for stmt in node.statements:
            _evaluate(stmt, values, events)
    elif isinstance(node, IRAssign):
        values[node.target.name] = _evaluate(node.expr, values, events)
    elif isinstance(node, IRLocal):
        return values[node.name]
    elif isinstance(node, IRConst):
        return node.value
    elif isinstance(node, IRCall):
        for arg in node.args:
            _evaluate(arg, values, events)
        events.append(node.call_type.value)
        return 7
    elif isinstance(node, IRArithmetic):
        left = _evaluate(node.left, values, events)
        right = _evaluate(node.right, values, events)
        if node.op == IRArithmetic.ArithmeticType.ADD:
            return left + right
        raise AssertionError(node.op)
    elif isinstance(node, IRArrayAccess):
        return _evaluate(node.array, values, events)[_evaluate(node.index, values, events)]
    elif isinstance(node, IRCast):
        value = _evaluate(node.expr, values, events)
        if not isinstance(value, int):
            raise TypeError("checked cast")
        return value
    elif isinstance(node, _UnknownThrowingExpression):
        raise ValueError("unknown expression")
    elif isinstance(node, IRConditional):
        condition = _evaluate(node.condition, values, events)
        _evaluate(node.true_block if condition else node.false_block, values, events)
    elif isinstance(node, IRReturn):
        return _evaluate(node.value, values, events)
    else:
        raise AssertionError(type(node))


def _observe(block):
    events = []
    try:
        _evaluate(block, {"input": None, "closure": None, "flag": False}, events)
    except (TypeError, ValueError) as exc:
        events.append(type(exc).__name__)
    return events


@pytest.mark.parametrize(
    "optimizer", [IRDeadTempEliminator, IRDeadStoreEliminator, IRDeadAssignmentEliminator]
)
@pytest.mark.parametrize(
    "kind", ["func", "native", "closure", "method", "this", "nested", "read", "cast", "unknown"]
)
def test_discarded_results_preserve_calls_and_exceptions(optimizer, kind):
    code = Bytecode.create_empty()
    temp = IRLocal("var0", tIndex(1), code)
    input = IRLocal("input", tIndex(1), code)
    one = IRConst(code, IRConst.ConstType.INT, value=1)
    if kind in ("func", "native", "closure", "method", "this"):
        target = IRLocal("closure", tIndex(1), code) if kind == "closure" else None
        expr = IRCall(code, IRCall.CallType(kind), target, [])
        expected = [kind]
    elif kind == "nested":
        expr = IRArithmetic(
            code, one, IRCall(code, IRCall.CallType.NATIVE, None, []), IRArithmetic.ArithmeticType.ADD
        )
        expected = ["native"]
    elif kind == "read":
        expr = IRArrayAccess(code, input, one, tIndex(1))
        expected = ["TypeError"]
    elif kind == "cast":
        expr = IRCast(code, tIndex(1), input)
        expected = ["TypeError"]
    else:
        expr = _UnknownThrowingExpression(code)
        expected = ["ValueError"]
    function = _function(code, [IRAssign(code, temp, expr), IRAssign(code, temp, one)])
    assert _observe(function.block) == expected
    optimizer(function).optimize()
    assert _observe(function.block) == expected


@pytest.mark.parametrize("optimizer", [IRConditionInliner, IRTempAssignmentInliner])
def test_throwing_read_is_not_moved_into_unexecuted_branch(optimizer):
    code = Bytecode.create_empty()
    temp = IRLocal("var0", tIndex(1), code)
    source = IRLocal("input", tIndex(1), code)
    flag = IRLocal("flag", tIndex(3), code)
    read = IRArrayAccess(code, source, IRConst(code, IRConst.ConstType.INT, value=0), tIndex(1))
    yes, no = IRBlock(code), IRBlock(code)
    yes.statements = [IRReturn(code, temp)]
    function = _function(code, [IRAssign(code, temp, read), IRConditional(code, flag, yes, no)])
    assert _observe(function.block) == ["TypeError"]
    optimizer(function).optimize()
    assert _observe(function.block) == ["TypeError"]
    if optimizer is IRTempAssignmentInliner:
        optimizer(function, aggressive=True).optimize()
        assert _observe(function.block) == ["TypeError"]


@pytest.mark.parametrize("next_target", ["var0", "var1"])
def test_condition_inliner_preserves_self_referential_assignment_value(next_target):
    code = Bytecode.create_empty()
    source = IRLocal("var0", tIndex(1), code)
    target = IRLocal(next_target, tIndex(1), code)
    result = IRLocal("result", tIndex(1), code)
    two = IRConst(code, IRConst.ConstType.INT, value=2)
    four = IRConst(code, IRConst.ConstType.INT, value=4)
    function = _function(
        code,
        [
            IRAssign(code, source, IRArithmetic(code, source, two, IRArithmetic.ArithmeticType.ADD)),
            IRAssign(code, target, IRArithmetic(code, source, four, IRArithmetic.ArithmeticType.ADD)),
            IRAssign(code, result, source),
        ],
    )
    before = {"var0": 3}
    _evaluate(function.block, before, [])
    IRConditionInliner(function).optimize()
    after = {"var0": 3}
    _evaluate(function.block, after, [])
    assert after["result"] == before["result"]
    assert after[next_target] == before[next_target]


def test_sequential_folding_does_not_delay_throwing_read_past_call():
    code = Bytecode.create_empty()
    temp = IRLocal("var0", tIndex(1), code)
    source = IRLocal("input", tIndex(1), code)
    read = IRArrayAccess(code, source, IRConst(code, IRConst.ConstType.INT, value=0), tIndex(1))
    call = IRCall(code, IRCall.CallType.NATIVE, None, [])
    result = IRArithmetic(code, call, temp, IRArithmetic.ArithmeticType.ADD)
    function = _function(code, [IRAssign(code, temp, read), IRAssign(code, temp, result)])
    IRSequentialTempFolder(function).optimize()
    assert _observe(function.block) == ["TypeError"]


@pytest.fixture(scope="module")
def compiled_numeric_program(tmp_path_factory):
    haxe, hl = shutil.which("haxe"), shutil.which("hl")
    if not haxe or not hl:
        pytest.skip("numeric recompilation regressions require haxe and hl")
    path = tmp_path_factory.mktemp("numeric-semantics")
    code = Bytecode.create_empty()
    a, b = [IRLocal(name, tIndex(1), code) for name in ("a", "b")]
    x, y = [IRLocal(name, tIndex(2), code) for name in ("x", "y")]
    functions, checks, expected = [], [], []
    # A conversion's Float binding must remain the operand. Substituting its
    # integer source while retaining the declaration both repeats conversions
    # and lets integer multiplication overflow before the result is widened.
    converted = [IRLocal(name, tIndex(2), code) for name in ("var8", "var9")]
    bindings = [IRAssign(code, dst, IRCast(code, tIndex(2), src)) for dst, src in zip(converted, (a, b))]
    body: List[IRStatement] = [
        *bindings,
        IRReturn(code, IRArithmetic(code, converted[0], converted[1], IRArithmetic.ArithmeticType.MUL)),
    ]
    context = _function(code, body, [a, b, *converted])
    rendered = _generate_statements(
        body,
        code,
        context,
        1,
        {"a", "b"},
        inline_declarations={stmt: (cast(IRLocal, stmt.target).name, "Float") for stmt in bindings},
    )
    functions.append("static function widenedProduct(a:Int, b:Int):Float {\n" + "\n".join(rendered) + "\n}")
    checks.append("Sys.println(widenedProduct(2147483647, 2));")
    expected.append("4294967294")
    for op in ("SDIV", "UDIV", "SMOD", "UMOD"):
        expr = IRArithmetic(code, a, b, IRArithmetic.ArithmeticType[op])
        functions.append(
            f"static function {op.lower()}(a:Int, b:Int):Int return {_expression_to_haxe(expr, code)};"
        )
    for left, right in [
        (-1, 2),
        (-2147483648, 2),
        (7, -3),
        (-7, 3),
        (-1, 1),
        (-1, -1),
        (-2147483647, -2147483648),
        (-1, 0),
    ]:
        for op in ("SDIV", "UDIV", "SMOD", "UMOD"):
            lhs, rhs = (left & 0xFFFFFFFF, right & 0xFFFFFFFF) if op.startswith("U") else (left, right)
            quotient = math.trunc(lhs / rhs) if rhs else 0
            result = quotient if op.endswith("DIV") else (lhs - quotient * rhs if rhs else 0)
            result = ((result + 0x80000000) & 0xFFFFFFFF) - 0x80000000
            checks.append(f"Sys.println({op.lower()}({left}, {right}));")
            expected.append(str(result))
    wide_type = Type()
    wide_type.kind.value = Type.Kind.I64.value
    wide_type.definition = I64()
    code.types.append(wide_type)
    wa, wb = [IRLocal(name, tIndex(len(code.types) - 1), code) for name in ("a", "b")]
    functions.extend(
        [
            "static function wide(h:Int, l:Int):hl.I64 return ((h : hl.I64) << 32) | (((l : hl.I64) << 32) >>> 32);",
            'static function report(v:hl.I64):Void Sys.println((v >>> 32).toInt() + "," + v.toInt());',
        ]
    )
    for op in ("SDIV", "UDIV", "SMOD", "UMOD"):
        expr = IRArithmetic(code, wa, wb, IRArithmetic.ArithmeticType[op])
        functions.append(
            f"static function {op.lower()}64(a:hl.I64, b:hl.I64):hl.I64 return {_expression_to_haxe(expr, code)};"
        )
    for op in ("ULT", "UGTE"):
        expr = IRBoolExpr(code, IRBoolExpr.CompareType[op], wa, wb)
        functions.append(
            f"static function {op.lower()}64(a:hl.I64, b:hl.I64):Bool return {_expression_to_haxe(expr, code)};"
        )

    def words(value):
        return [((word + 0x80000000) & 0xFFFFFFFF) - 0x80000000 for word in (value >> 32, value)]

    for left, right in [
        ((1 << 40) + 7, 3),
        ((1 << 63) - 1, (1 << 32) + 1),
        (-1, 1),
        (-1, 3),
        (-2, (1 << 32) + 1),
        (-(1 << 63), -1),
        (-(1 << 63), 3),
        (-(1 << 63), -(1 << 63)),
        (-(1 << 63), -(1 << 63) + 1),
        (0, -1),
        (-7, -3),
        (-1, 0),
        ((1 << 63) - 1, -(1 << 63)),
    ]:
        lsrc, rsrc = [f"wide({words(v)[0]}, {words(v)[1]})" for v in (left, right)]
        for op in ("SDIV", "UDIV", "SMOD", "UMOD"):
            lhs, rhs = (
                (left & ((1 << 64) - 1), right & ((1 << 64) - 1)) if op.startswith("U") else (left, right)
            )
            quotient = abs(lhs) // abs(rhs) if rhs else 0
            if (lhs < 0) != (rhs < 0):
                quotient = -quotient
            result = quotient if op.endswith("DIV") else (lhs - quotient * rhs if rhs else 0)
            checks.append(f"report({op.lower()}64({lsrc}, {rsrc}));")
            expected.append(",".join(map(str, words(result))))
        for op in ("ULT", "UGTE"):
            less = (left & ((1 << 64) - 1)) < (right & ((1 << 64) - 1))
            checks.append(f"Sys.println({op.lower()}64({lsrc}, {rsrc}));")
            expected.append(str(less if op == "ULT" else not less).lower())

    functions.extend(
        [
            "static var order:Int = 0;",
            "static function nextA():hl.I64 { order = order * 10 + 1; return wide(-1, -1); }",
            "static function nextB():hl.I64 { order = order * 10 + 2; return 3; }",
        ]
    )
    # Render-time substitutions can introduce real calls as operands. Neither
    # unsigned lowering may duplicate them or reverse their evaluation order.
    substitutions = IRFunction(code, Function(), do_optimize=False, no_lift=True)
    substitutions._render_subs = {wa: ("nextA()", None), wb: ("nextB()", None)}
    for op, result in (("UDIV", ((1 << 64) - 1) // 3), ("UMOD", 0)):
        expr = IRArithmetic(code, wa, wb, IRArithmetic.ArithmeticType[op])
        functions.append(
            f"static function once{op}():hl.I64 return {_expression_to_haxe(expr, code, substitutions)};"
        )
        checks.extend(["order = 0;", f"report(once{op}());", "Sys.println(order);"])
        expected.extend([",".join(map(str, words(result))), "12"])
    ordered = {
        "JSLt": lambda a, b: a < b,
        "JSGte": lambda a, b: a >= b,
        "JSGt": lambda a, b: a > b,
        "JSLte": lambda a, b: a <= b,
        "JNotLt": lambda a, b: not a < b,
        "JNotGte": lambda a, b: not a >= b,
    }
    context = _function(code, [], [x, y])
    for opcode, compare in ordered.items():
        for inverted in (False, True):
            expr = IRFunction._build_bool_expr_from_op(context, Opcode(opcode, {"a": Reg(0), "b": Reg(1)}))
            if inverted:
                expr.invert()
            name = opcode.lower() + ("_inverted" if inverted else "")
            functions.append(
                f"static function {name}(x:Float, y:Float):Bool return {_expression_to_haxe(expr, code)};"
            )
            for left, right, lsrc, rsrc in [
                (math.nan, 1.0, "Math.NaN", "1.0"),
                (1.0, math.nan, "1.0", "Math.NaN"),
                (math.inf, math.inf, "Math.POSITIVE_INFINITY", "Math.POSITIVE_INFINITY"),
                (-0.0, 0.0, "-0.0", "0.0"),
                (-math.inf, 1.0, "Math.NEGATIVE_INFINITY", "1.0"),
            ]:
                value = compare(left, right)
                checks.append(f"Sys.println({name}({lsrc}, {rsrc}));")
                expected.append(str(not value if inverted else value).lower())
    source = (
        "class Numeric {\n"
        + "\n".join(functions)
        + "\nstatic function main() {\n"
        + "\n".join(checks)
        + "\n}\n}\n"
    )
    (path / "Numeric.hx").write_text(source)
    subprocess.run(
        [haxe, "-cp", str(path), "-main", "Numeric", "-hl", str(path / "numeric.hl")],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return hl, path / "numeric.hl", expected


def test_numeric_boundaries_and_nan_survive_execution(compiled_numeric_program):
    hl, path, expected = compiled_numeric_program
    result = subprocess.run([hl, str(path)], check=True, capture_output=True, text=True, timeout=15)
    assert result.stdout.splitlines() == expected


@pytest.mark.parametrize(
    "name,body,expected",
    [
        (
            "ArrayIndexingCase",
            'var a = [1,2,3]; ArrayIndexingCase.swap(a,0,2); Sys.println(a.join(",")); '
            "Sys.println(ArrayIndexingCase.sum(a)); Sys.println(ArrayIndexingCase.sum([]));",
            ["3,2,1", "6", "0"],
        ),
        (
            "LoopControlCase",
            "for (a in [[],[1,2,3],[1,-2,3],[-1,2],[-3,-2]]) { "
            "Sys.println(LoopControlCase.sumUntilNegative(a)); "
            "Sys.println(LoopControlCase.findLastPositive(a)); }",
            ["0", "-1", "6", "3", "1", "3", "0", "2", "0", "-1"],
        ),
        (
            "DoWhileBreakCase",
            "Sys.println(DoWhileBreakCase.firstMultipleOfThree(10)); "
            "Sys.println(DoWhileBreakCase.firstMultipleOfThree(2)); "
            "Sys.println(DoWhileBreakCase.firstMultipleOfThree(1));",
            ["3", "2", "1"],
        ),
        (
            "ForLoopRegisterReuseCase",
            "Sys.println(ForLoopRegisterReuseCase.sumRange(5)); "
            "Sys.println(ForLoopRegisterReuseCase.sumRange(3)); "
            "Sys.println(ForLoopRegisterReuseCase.sumRange(2));",
            ["11", "4", "2"],
        ),
    ],
)
def test_array_mutation_and_loop_exits_survive_roundtrip(tmp_path, name, body, expected):
    haxe, hl = shutil.which("haxe"), shutil.which("hl")
    if not haxe or not hl:
        pytest.skip("behavioral lifting regressions require haxe and hl")
    for version in ("original", "recompiled"):
        directory = tmp_path / version
        directory.mkdir()
        if version == "original":
            source = (Path(__file__).parent / "haxe" / f"{name}.hx").read_text()
        else:
            bytecode = Bytecode.from_path(str(tmp_path / "original" / "program.hl"))
            source = IRClass(bytecode, bytecode.get_test_obj(name)).pseudo()
            if name == "ForLoopRegisterReuseCase":
                # Regression guard for #26: a debug-named local elsewhere in
                # the function that happens to reuse the loop index's raw
                # register must not stop the for-loop from being recovered.
                assert "for (i in 0" in source, source
        (directory / f"{name}.hx").write_text(source)
        # The fixture mains discard their results. A separate caller observes
        # mutations, empty input, early returns and normal loop termination.
        (directory / "Probe.hx").write_text(
            f"@:access({name}) class Probe {{ static function main() {{ {body} }} }}"
        )
        compiled = subprocess.run(
            [haxe, "-cp", str(directory), "-main", "Probe", "-hl", str(directory / "program.hl")],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert compiled.returncode == 0, compiled.stderr
        result = subprocess.run(
            [hl, str(directory / "program.hl")],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.splitlines() == expected


@pytest.mark.parametrize("tail_form", ["break", "continue_break"])
def test_loop_recovery_preserves_condition_skipped_by_continue(tmp_path, tail_form):
    haxe = shutil.which("haxe")
    if not haxe:
        pytest.skip("loop rendering regression requires Haxe")
    code = Bytecode.create_empty()
    i = IRLocal("i", tIndex(1), code)
    check = IRLocal("check", tIndex(1), code)

    def block(*statements):
        result = IRBlock(code)
        result.statements = list(statements)
        return result

    def number(value):
        return IRConst(code, IRConst.ConstType.INT, value=value)

    condition = IRBoolExpr(
        code, IRBoolExpr.CompareType.ISTRUE, IRCall(code, IRCall.CallType.CLOSURE, check, [])
    )
    if tail_form == "break":
        condition.invert()
        tail = [IRConditional(code, condition, block(IRBreak(code)), block())]
    else:
        tail = [IRConditional(code, condition, block(IRContinue(code)), block()), IRBreak(code)]
    body = block(
        IRAssign(code, i, IRArithmetic(code, i, number(1), IRArithmetic.ArithmeticType.ADD)),
        IRConditional(
            code,
            IRBoolExpr(code, IRBoolExpr.CompareType.LT, i, number(3)),
            block(IRContinue(code)),
            block(),
        ),
        *tail,
    )
    loop = IRWhileLoop(code, IRBoolExpr(code, IRBoolExpr.CompareType.TRUE), body)
    function = _function(code, [loop], [i, check])
    rendered = "\n".join(_generate_statements([loop], code, function, 2, {"i", "check"}))
    (tmp_path / "Probe.hx").write_text(
        "class Probe { static function main() { var i = 0; var checks = 0; "
        "function check():Bool { checks++; return false; }\n"
        + rendered
        + "\nSys.println(i); Sys.println(checks); } }"
    )
    result = subprocess.run(
        [haxe, "-cp", str(tmp_path), "-main", "Probe", "--interp"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    # The first two iterations continue without evaluating the side-effectful
    # tail condition; changing their target to a do-while test would stop at 1.
    assert result.stdout.splitlines() == ["3", "1"]


@pytest.mark.parametrize(
    "scenario,expected",
    [
        ("continue", ["3", "4"]),
        ("empty", ["0", "1"]),
        ("live_exit", ["0", "1"]),
        ("live_body", ["3", "1"]),
        ("null_before_call", ["caught", "0"]),
        ("read_order", ["RL"]),
        ("null_read", ["caught", "0"]),
        ("null_final_test", ["caught", "1"]),
        ("overwrite_operand", ["1", "1"]),
        ("overwrite_chain", ["1", "2"]),
    ],
)
def test_loop_condition_setup_preserves_evaluation(tmp_path, scenario, expected):
    haxe = shutil.which("haxe")
    if not haxe:
        pytest.skip("loop condition regression requires Haxe")
    code = Bytecode.create_empty()
    i, scratch, other, box, check = [
        IRLocal(name, tIndex(1), code) for name in ("i", "scratch", "other", "box", "check")
    ]

    def number(value):
        return IRConst(code, IRConst.ConstType.INT, value=value)

    def block(*statements):
        result = IRBlock(code)
        result.statements = list(statements)
        return result

    def field(name):
        return IRField(code, box, name, tIndex(1))

    setup = [IRAssign(code, scratch, field("limit"))]
    condition = IRBoolExpr(code, IRBoolExpr.CompareType.GTE, i, scratch)
    body: List[IRStatement] = [
        IRAssign(code, i, IRArithmetic(code, i, number(1), IRArithmetic.ArithmeticType.ADD)),
    ]
    suffix = "Sys.println(i); Sys.println(box.reads);"
    bound = 3
    if scenario == "continue":
        # The scratch is killed before the continue; the test still runs on
        # the backedge and once more on the final failed iteration.
        body += [IRAssign(code, scratch, number(-1)), IRContinue(code)]
    elif scenario == "empty":
        bound = 0
    elif scenario == "live_exit":
        bound = 0
        suffix = "Sys.println(scratch); Sys.println(box.reads);"
    elif scenario == "live_body":
        body = [IRAssign(code, i, scratch), IRBreak(code)]
    elif scenario == "null_before_call":
        setup.append(IRAssign(code, other, IRCall(code, IRCall.CallType.CLOSURE, check, [])))
        suffix = "Sys.println(calls);"
    elif scenario == "null_read":
        suffix = "Sys.println(i);"
    elif scenario == "null_final_test":
        body.append(IRAssign(code, box, IRConst(code, IRConst.ConstType.NULL, value=None)))
        suffix = "Sys.println(i);"
    elif scenario == "read_order":
        setup = [IRAssign(code, scratch, field("right")), IRAssign(code, other, field("left"))]
        # Folding in operand order would reverse the throwing reads.
        condition = IRBoolExpr(code, IRBoolExpr.CompareType.GTE, other, scratch)
        suffix = "Sys.println(box.order);"
    elif scenario == "overwrite_operand":
        setup = [IRAssign(code, scratch, i), IRAssign(code, i, field("limit"))]
        body = [IRAssign(code, other, scratch), IRBreak(code)]
        suffix = "Sys.println(i); Sys.println(box.reads);"
        bound = 1
    elif scenario == "overwrite_chain":
        setup.append(
            IRAssign(code, scratch, IRArithmetic(code, scratch, number(1), IRArithmetic.ArithmeticType.ADD))
        )
        bound = 0

    loop = IRPrimitiveLoop(code, block(*setup, condition), block(*body))
    statements = [loop]
    if scenario == "live_exit":
        # This is an actual IR consumer, not an invisible renderer-only read.
        statements.append(IRAssign(code, other, scratch))
        suffix = "Sys.println(other); Sys.println(box.reads);"
    function = _function(code, statements, [i, scratch, other, box, check])
    IRLoopConditionOptimizer(function).optimize()
    rendered = "\n".join(
        _generate_statements(
            function.block.statements, code, function, 2, {"i", "scratch", "other", "box", "check"}
        )
    )
    if scenario in ("null_before_call", "null_read", "null_final_test"):
        prefix = "" if scenario == "null_final_test" else "box = null; "
        rendered = prefix + "try {\n" + rendered + '\n} catch (e:Dynamic) { Sys.println("caught"); }'
    (tmp_path / "Probe.hx").write_text(
        "class Box { public var reads = 0; public var order = ''; var bound:Int; "
        "public function new(n:Int) { bound = n; } "
        "public var limit(get,never):Int; function get_limit():Int { reads++; return bound; } "
        "public var left(get,never):Int; function get_left():Int { order += 'L'; return 1; } "
        "public var right(get,never):Int; function get_right():Int { order += 'R'; return 0; } } "
        "class Probe { static function main() { var i = 0; var scratch = -10; var other = -20; "
        f"var box = new Box({bound}); var calls = 0; "
        "function check():Int { calls++; return 0; }\n" + rendered + "\n" + suffix + " } }"
    )
    result = subprocess.run(
        [haxe, "-cp", str(tmp_path), "-main", "Probe", "--interp"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == expected


def test_switch_roundtrip_preserves_arithmetic_count(tmp_path):
    from collections import Counter

    from crashtest.behavior import compile_haxe

    if not shutil.which("haxe"):
        pytest.skip("opcode regression requires Haxe")
    name = "SwitchRegisterReuse"
    source = (Path(__file__).parent / "haxe" / f"{name}.hx").read_text()
    original, error = compile_haxe(source, name, tmp_path / "original")
    assert error is None, error
    before = Bytecode.from_path(str(original))
    recovered = IRClass(before, before.get_test_obj(name)).pseudo()
    recompiled, error = compile_haxe(recovered, name, tmp_path / "recompiled")
    assert error is None, error
    after = Bytecode.from_path(str(recompiled))

    def arithmetic(code):
        method = next(f for f in code.functions if code.full_func_name(f) == f"${name}.pick")
        return Counter(op.op for op in method.ops if op.op in ("Add", "Sub", "Mul"))

    assert arithmetic(before) == {"Add": 2, "Sub": 1, "Mul": 3}
    assert arithmetic(after) == arithmetic(before)
    for code in (before, after):
        method = next(f for f in code.functions if code.full_func_name(f) == f"${name}.pick")
        assert not any(op.op == "Mov" for op in method.ops)


def test_loop_condition_recovers_after_array_guard_collapse(tmp_path):
    from crashtest.behavior import compare_programs, compile_haxe, resolve_hl_runtime

    if not shutil.which("haxe") or not resolve_hl_runtime():
        pytest.skip("loop condition regression requires Haxe and HashLink")
    name = "LoopElementCondition"
    source = """class LoopElementCondition {
    static function bump(a:Array<Int>) { a[0] = a[0] + 1; }
    static function main() {
        var box = [0];
        var seen = 0;
        while (box[0] < 3) {
            seen += box[0];
            bump(box);
        }
        Sys.println(seen);
    }
}"""
    original, error = compile_haxe(source, name, tmp_path / "original")
    assert error is None, error
    code = Bytecode.from_path(str(original))
    recovered = IRClass(code, code.get_test_obj(name)).pseudo()
    # The element read is a branch until the bounds guard collapses, which is
    # what used to leave the loop as `while (true) { ... else break; }`.
    assert "while (box[0] < 3)" in recovered
    assert "while (true)" not in recovered
    recompiled, error = compile_haxe(recovered, name, tmp_path / "recompiled")
    assert error is None, error
    result = compare_programs(original, recompiled, name)
    assert result.passed, result.to_json()
    assert result.original.stdout == "3\n"
