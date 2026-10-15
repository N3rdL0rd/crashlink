"""Null-check placement: a value read inside a loop, a trace or an array store keeps its evaluation order."""

import re
import shutil
from pathlib import Path

import pytest

from crashtest.behavior import resolve_hl_runtime

from .test_ops_arrays13 import _same_signature, roundtrip


@pytest.fixture(autouse=True)
def _tools() -> None:
    if not shutil.which("haxe") or resolve_hl_runtime() is None:
        pytest.skip("project round trips require Haxe and HashLink")


def _untraced(output: str) -> str:
    return re.sub(r"^(?:src/)?Main\.hx:\d+: ", "", output, flags=re.M)


def _check(tmp_path: Path, source: str, *functions: str) -> str:
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    # The decompiled project has its own layout: only the position a trace prints differs.
    assert _untraced(actual) == _untraced(expected)
    for name in functions:
        assert _same_signature(original, recompiled, name), name
    return files["src/Main.hx"]


def test_virtual_call_in_a_loop_is_folded_into_the_trace(tmp_path: Path) -> None:
    # `s` is written in the loop body; that write comes before the call, so the call may still move into the trace.
    source = """
class S { public function new() {} public function area():Float return 2.5; }
class T extends S { override public function area():Float return 3.5; }
class Main {
    static function mk(k:String):S return k == "a" ? new S() : new T();
    static function main() {
        var kinds = ["a", "b"];
        for (k in kinds) {
            var s = mk(k);
            trace(s.area());
        }
    }
}
"""
    text = _check(tmp_path, source, "Main.main")
    assert "trace(s.area())" in text


def test_string_concat_in_a_loop_is_folded_into_the_trace(tmp_path: Path) -> None:
    source = """
class S { public function new() {} public function nm():String return "n"; }
class T extends S { override public function nm():String return "t"; }
class Main {
    static function main() {
        var kinds = ["a", "b"];
        var a:Array<S> = [];
        for (k in kinds) a.push(new T());
        for (s in a) trace(s.nm() + ":" + s.nm());
    }
}
"""
    text = _check(tmp_path, source, "Main.main")
    assert 'trace(s.nm() + ":" + s.nm())' in text


def test_array_store_checks_the_array_before_evaluating_the_index(tmp_path: Path) -> None:
    source = """
class Main {
    static function side(n:String, v:Int):Int { Sys.println(n); return v; }
    static function main() {
        var arr = [10, 20, 30];
        arr[side("idx", 1)] = side("val", 99);
        Sys.println(arr.join(","));
    }
}
"""
    text = _check(tmp_path, source, "Main.main")
    assert 'arr[Main.side("idx", 1)] = Main.side("val", 99)' in text


def test_closure_read_from_a_static_array_in_a_trace_keeps_the_element_type(tmp_path: Path) -> None:
    source = """
class Main {
    static var handlers:Array<Int->Int> = [null, null];
    static function register():Void {
        handlers[0] = function(x:Int):Int return x + 1;
        handlers[1] = function(x:Int):Int return x * 2;
    }
    static function main() {
        register();
        trace(handlers[0](5));
        trace(handlers[1](5));
    }
}
"""
    text = _check(tmp_path, source, "Main.main", "Main.register")
    assert "Array<((Int) -> Int)>" in text
    assert "trace(Main.handlers[0](5))" in text


def test_float_concat_arms_sharing_a_length_cell_fold_back_to_concatenation(tmp_path: Path) -> None:
    # Every `"x" + float` conversion writes its length into one register, which the arms also reuse for
    # the trace's line number: the conversions of the other arms are not readers of the cell.
    source = """
enum Shape {
    None;
    Circle(r:Float);
    Rect(w:Float, h:Float);
}

class Main {
    static function main() {
        var a = None;
        var b = None;
        trace(a == b);
        var c = Circle(1.0);
        switch (a) {
            case None: trace("none");
            case Circle(r): trace("circle " + r);
            case Rect(w, h): trace("rect " + w + " " + h);
        }
        switch (c) {
            case None: trace("none2");
            case Circle(r): trace("circle2 " + r);
            case Rect(w, h): trace("rect2 " + w + " " + h);
        }
    }
}
"""
    # The cell also leaks the trace line numbers into the function's behaviour: compare the output only.
    text = _check(tmp_path, source)
    assert "__alloc__" not in text


def test_bytes_buffer_growth_guard_is_kept(tmp_path: Path) -> None:
    # `BytesBuffer.__expand` is the inline method's own source, not the array guard HL puts before a bracket write.
    source = """
class Main {
    static function main() {
        var buf = new haxe.io.BytesBuffer();
        buf.addDouble(9007199254740991.0);
        Sys.println(buf.getBytes().length);
    }
}
"""
    _check(tmp_path, source, "Main.main")


def test_unused_field_read_keeps_its_null_check(tmp_path: Path) -> None:
    # `field++` through an inline abstract operator reads the field and drops the value; a bare
    # `this.field;` statement would not compile back to the read.
    source = """
private abstract MyInt(Int) from Int to Int {
    @:op(A++)
    public inline function increment():MyInt {
        Main.count++;
        return this;
    }
}

class Main {
    public static var count = 0;
    final field:MyInt = 1;

    public function new() {}

    function t():Void {
        field++;
        Sys.println(count);
    }

    static function main() {
        new Main().t();
    }
}
"""
    _check(tmp_path, source, "Main.t")
