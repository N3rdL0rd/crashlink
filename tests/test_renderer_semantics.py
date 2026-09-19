"""Rendering must preserve values and real native-call ABI behavior."""

import os
import re
import shutil
from pathlib import Path

import pytest

from crashtest.behavior import compile_haxe
from crashtest.run import run_case
from crashlink.core import Bytecode, tIndex
from crashlink.decomp import IRClass
from crashlink.decomp.ir import (
    IRArrayAccess,
    IRAssign,
    IRBlock,
    IRBoolExpr,
    IRBreak,
    IRConditional,
    IRConst,
    IRContinue,
    IRLocal,
    IRReturn,
    IRTryCatch,
    IRWhileLoop,
)
from crashlink.pseudo import _is_definitely_assigned_before_use


@pytest.mark.parametrize(
    "name,source",
    [
        (
            "ClassAliases",
            """class ClassAliases {
    static var count = 0;
    static function log(v:Int):Void { trace(v); count += v; }
    static function main():Void { log(2); log(3); Sys.println(count); }
}""",
        ),
        (
            "NativeBoundary",
            """@:hlNative("std") extern class RawNative {
    static function itos(value:Int, count:hl.Ref<Int>):hl.Bytes;
    static function string_compare(a:hl.Bytes, b:hl.Bytes, count:Int):Int;
}
class NativeBoundary {
    static function main():Void {
        var count = 0;
        var bytes = RawNative.itos(123, new hl.Ref(count));
        var text = @:privateAccess String.__alloc__(bytes, count);
        Sys.println(text);
        Sys.println(count);
        Sys.println(RawNative.string_compare(bytes, @:privateAccess "123".bytes, count));
    }
}""",
        ),
        (
            "NestedCallable",
            """class SignatureOnly {
    public var value:Int;
}
enum CallableBox { Wrap(f:(Int->Int)->(Int->Int)); }
class NestedCallable {
    public static var unused:SignatureOnly->SignatureOnly;
    var base:Int;
    public var fn:Int->Int;
    public function new(base:Int) { this.base = base; fn = add; }
    function add(value:Int):Int { return base + value; }
    static function compose(f:Int->Int):(Int->Int)->(Int->Int) {
        return function(g:Int->Int):Int->Int { return function(v:Int):Int { return f(g(v)); }; };
    }
    static function main():Void {
        var owner = new NestedCallable(7);
        var f = owner.fn;
        var box = Wrap(compose(f));
        switch box { case Wrap(make): Sys.println(make(f)(3)); }
    }
}""",
        ),
        (
            "TraceSnapshot",
            """class TraceSnapshot {
    static function original(v:Dynamic, ?infos:haxe.PosInfos):Void {
        if (infos == null) { Sys.println("missing:" + v); return; }
        Sys.println(v + ":" + infos.fileName + ":" + infos.lineNumber + ":" + infos.className + ":" + infos.methodName);
        Sys.println(infos.customParams == null ? "no extras" : infos.customParams.join(","));
    }
    static function replacement(v:Dynamic, ?infos:haxe.PosInfos):Void { Sys.println("replacement:" + v); }
    static function main():Void {
        haxe.Log.trace = original;
        var saved = haxe.Log.trace;
        haxe.Log.trace = replacement;
        var pos:haxe.PosInfos = {fileName:"original/path.hx",lineNumber:123,className:"Original",methodName:"emit"};
        saved("captured", pos);
        saved("optional");
        haxe.Log.trace("new", pos);
        pos.customParams = ["extra", 9];
        saved("extras", pos);
    }
}""",
        ),
        (
            "HeapsSkinSplit",
            (Path(__file__).parent / "haxe" / "HeapsSkinSplit.hx").read_text(),
        ),
        (
            "TerminalAssignment",
            """class TerminalAssignment {
    static function choose(mode:Int):Int {
        var values:Array<Int>;
        if (mode < 0) return -1;
        if (mode == 0) values = [2, 3]; else values = [5];
        var sum = 0;
        var i = 0;
        while (i < values.length) {
            var part:Int;
            if (i == 0) part = values[i]; else part = values[i] * 2;
            sum += part;
            i++;
        }
        var last:Int = 0;
        while (true) {
            if (mode == 3) return sum;
            last = sum + 7;
            break;
        }
        return last;
    }
    static function main():Void {
        for (mode in [-1, 0, 1, 3]) Sys.println(choose(mode));
    }
}""",
        ),
        (
            "AssignmentExitPaths",
            """class AssignmentExitPaths {
    static var events = "";
    static function value(fail:Bool):Int {
        events += "v";
        if (fail) throw "failed";
        return 7;
    }
    static function choose(n:Int, fail:Bool):Int {
        var carried = 4;
        var i = 0;
        while (i < n) {
            i++;
            if (i == 1) continue;
            if (i == 3) break;
            carried = carried + i;
        }
        var result = 11;
        try {
            result = value(fail);
            events += "t";
        } catch (e:Dynamic) {
            events += "c";
            carried += result;
        }
        return carried + result;
    }
    static function main():Void {
        for (n in [0, 1, 2, 4]) {
            Sys.println(choose(n, false));
            Sys.println(choose(n, true));
        }
        Sys.println(events);
    }
}""",
        ),
    ],
)
def test_renderer_roundtrip_preserves_observations(tmp_path, name, source):
    if not shutil.which("haxe") or not (os.environ.get("HL_RUNTIME") or shutil.which("hl")):
        pytest.skip("Haxe and HashLink required for renderer execution")
    artifact, error = compile_haxe(source, name, tmp_path)
    assert error is None, error
    artifact.rename(tmp_path / f"{name}.hl")
    result = run_case(str(tmp_path / f"{name}.hx"), 0)
    assert not result.failed, result.error or result.behavioral_comparison


def test_static_alias_roundtrip_preserves_initialization_and_escapes(tmp_path):
    if not shutil.which("haxe") or not (os.environ.get("HL_RUNTIME") or shutil.which("hl")):
        pytest.skip("Haxe and HashLink required for renderer execution")
    name = "StaticAliasLifetime"
    source = """class StaticAliasLifetime {
    static var log:String = init();
    static function init():String { Sys.println("initialized"); return "I"; }
    static function sideT():Bool { log += "T"; return true; }
    static function owner():Class<StaticAliasLifetime> {
        var result = StaticAliasLifetime;
        sideT();
        return result;
    }
    static function main():Void {
        Sys.println(log);
        Sys.println(owner() == StaticAliasLifetime);
        Sys.println(log);
    }
}"""
    artifact, error = compile_haxe(source, name, tmp_path)
    assert error is None, error
    artifact.rename(tmp_path / f"{name}.hl")
    result = run_case(str(tmp_path / f"{name}.hx"), 0)
    assert not result.failed, result.error or result.behavioral_comparison
    assert result.opcode_comparison is not None
    method = next(m for m in result.opcode_comparison.methods if m.name.endswith(".sideT"))
    # Qualified read/write sites each need a receiver load. A third load is an
    # unconsumed class alias, not part of either static-field operation.
    loads = [
        line
        for line in method.recomp_disasm.splitlines()
        if line.startswith("GetGlobal.") and f"global[${name}]" in line
    ]
    assert len(loads) <= 2, method.recomp_disasm


@pytest.mark.parametrize(
    "scenario,safe",
    [
        ("terminal_branch", True),
        ("zero_trip", False),
        ("loop_local", True),
        ("loop_carried_read", False),
        ("continue_skips_read", True),
        ("break_before_write", False),
        ("break_after_write", False),
        ("catch_entry", False),
        ("catch_write", True),
        ("store_receiver", False),
    ],
)
def test_default_omission_requires_assignment_on_reachable_read_paths(scenario, safe):
    code = Bytecode.create_empty()
    value = IRLocal("value", tIndex(1), code)
    flag = IRLocal("flag", tIndex(3), code)
    one = IRConst(code, IRConst.ConstType.INT, value=1)
    write = IRAssign(code, value, one)
    read = IRReturn(code, value)

    def block(*statements):
        result = IRBlock(code)
        result.statements = list(statements)
        return result

    if scenario == "terminal_branch":
        root = block(IRConditional(code, flag, block(IRReturn(code, one)), block(write)), read)
    elif scenario == "zero_trip":
        root = block(IRWhileLoop(code, flag, block(write)), read)
    elif scenario == "loop_local":
        root = block(IRWhileLoop(code, flag, block(write, read)))
    elif scenario == "loop_carried_read":
        root = block(IRWhileLoop(code, flag, block(value, write)))
    elif scenario == "continue_skips_read":
        root = block(
            IRWhileLoop(
                code, flag, block(IRConditional(code, flag, block(IRContinue(code)), block(write)), read)
            )
        )
    elif scenario in ("break_before_write", "break_after_write"):
        body = block(IRConditional(code, flag, block(IRBreak(code)), block()), write, IRBreak(code))
        if scenario == "break_after_write":
            body = block(write, IRBreak(code))
        root = block(IRWhileLoop(code, IRBoolExpr(code, IRBoolExpr.CompareType.TRUE), body), read)
    elif scenario in ("catch_entry", "catch_write"):
        catch_body = block(read) if scenario == "catch_entry" else block(write)
        root = block(IRTryCatch(code, block(write), catch_body), read)
    else:
        root = block(IRAssign(code, IRArrayAccess(code, value, one, tIndex(1)), one), write)

    assert _is_definitely_assigned_before_use("value", root) is safe


def test_private_access_marks_only_hidden_std_members():
    code = Bytecode.from_path("tests/haxe/CatchOrder.hl")
    out = IRClass(code, code.get_test_obj("CatchOrder")).pseudo()
    # try/catch lowers to the private `haxe.Exception.caught`, which only
    # recompiles inside @:privateAccess.
    assert "@:privateAccess haxe.Exception.caught(" in out
    # Public std API is reachable as written; annotating it is noise.
    assert "Sys.println(" in out
    assert "@:privateAccess Sys.println" not in out


def _decompile_source(tmp_path, name: str, source: str) -> str:
    """Compile one Haxe module and return the decompiled class pseudocode."""
    artifact, error = compile_haxe(source, name, tmp_path)
    assert error is None, error
    code = Bytecode.from_path(str(artifact))
    return IRClass(code, code.get_test_obj(name)).pseudo()


def test_trace_collapses_compiler_lowering():
    code = Bytecode.from_path("tests/haxe/ArrayMethodCallTypeCase.hl")
    out = IRClass(code, code.get_test_obj("ArrayMethodCallTypeCase")).pseudo()
    # The dynamic-function load, the PosInfos object and the closure call are
    # all scaffolding for one source-level `trace(a)`.
    assert "trace(a); //" in out
    assert "haxe.Log.trace" not in out
    assert "PosInfos" not in out


def test_trace_recovers_extra_arguments(tmp_path):
    if not shutil.which("haxe"):
        pytest.skip("Haxe required to build the fixture")
    out = _decompile_source(
        tmp_path,
        "TraceExtras",
        """class TraceExtras {
    static function main():Void {
        var a = 1;
        var b = "x";
        trace(a);
        trace(a, b);
        trace("lit", a, b);
    }
}""",
    )
    # Extra arguments travel in the position object's customParams array; they
    # are real arguments and must come back as arguments.
    assert "trace(a); //" in out
    assert "trace(a, b); //" in out
    assert 'trace("lit", a, b); //' in out
    assert "customParams" not in out


def test_trace_is_not_collapsed_across_a_rebound_log(tmp_path):
    if not shutil.which("haxe"):
        pytest.skip("Haxe required to build the fixture")
    out = _decompile_source(
        tmp_path,
        "TraceRebind",
        """class TraceRebind {
    static function replacement(v:Dynamic, ?infos:haxe.PosInfos):Void { Sys.println("replacement:" + v); }
    static function main():Void {
        var saved = haxe.Log.trace;
        haxe.Log.trace = replacement;
        var pos:haxe.PosInfos = {fileName:"kept.hx", lineNumber:1, className:"TraceRebind", methodName:"main"};
        saved("snapshot", pos);
        trace("live");
    }
}""",
    )
    # `trace(...)` reads haxe.Log.trace at the call site, so a call through a
    # snapshot taken before the rebind is a different function: collapsing it
    # would print through `replacement` instead.
    assert "= haxe.Log.trace;" in out
    assert "haxe.Log.trace = TraceRebind.replacement;" in out
    assert 'saved("snapshot", pos);' in out
    # The unrebound call site is still ordinary lowering and does collapse.
    assert 'trace("live"); //' in out


def test_single_expression_closures_render_inline(tmp_path):
    if not shutil.which("haxe"):
        pytest.skip("Haxe required to build the fixture")
    out = _decompile_source(
        tmp_path,
        "InlineClosures",
        """class InlineClosures {
    static function main():Void {
        var greet = () -> "hello";
        var add = (a:Int, b:Int) -> a + b;
        var counter = 0;
        var bump = () -> { counter++; Sys.println(counter); };
        Sys.println(greet());
        Sys.println(add(1, 2));
        bump();
    }
}""",
    )
    # A closure whose body is one expression belongs at its creation site.
    assert '() -> "hello"' in out
    assert ") -> " in out
    # A multi-statement body cannot stand in expression position, so it stays
    # a lifted helper rather than being mangled into one line.
    assert "__anon_" in out
    assert "function __anon_" in out


def test_boxing_temporaries_and_dead_markers_are_dropped():
    code = Bytecode.from_path("tests/haxe/AbstractOps.hl")
    out = IRClass(code, code.get_test_obj("AbstractOps")).pseudo()
    # Boxing a value into a Dynamic temp one statement before its only use is
    # a representation change, not work worth naming.
    assert "Sys.println(total);" in out
    assert ": Dynamic = total" not in out

    code = Bytecode.from_path("tests/haxe/ArrayDynamicLiteral.hl")
    out = IRClass(code, code.get_test_obj("ArrayDynamicLiteral")).pseudo()
    # The element-type marker an array allocation consumed leaves a constant
    # evaluated for nothing behind.
    assert not re.search(r"(?m)^\s*null;\s*$", out)
