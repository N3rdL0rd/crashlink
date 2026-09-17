"""Rendering must preserve values and real native-call ABI behavior."""

import os
import shutil
from pathlib import Path

import pytest

from crashtest.behavior import compile_haxe
from crashtest.run import run_case


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
        line for line in method.recomp_disasm.splitlines()
        if line.startswith("GetGlobal.") and f"global[${name}]" in line
    ]
    assert len(loads) <= 2, method.recomp_disasm
