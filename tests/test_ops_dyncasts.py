"""Casts at Dynamic boundaries: the decompiled source must compile back to the same checked casts."""

import shutil
import subprocess
from pathlib import Path
from typing import Dict, Tuple

import pytest

from crashlink import Bytecode, project
from crashlink.core import Function
from crashlink.equivalence import signature
from crashtest.behavior import resolve_hl_runtime


@pytest.fixture(autouse=True)
def _tools() -> None:
    if not shutil.which("haxe") or resolve_hl_runtime() is None:
        pytest.skip("project round trips require Haxe and HashLink")


def _run(program: Path) -> str:
    runtime = resolve_hl_runtime()
    assert runtime is not None
    result = subprocess.run([runtime, str(program)], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    return result.stdout


def roundtrip(tmp_path: Path, source: str) -> Tuple[Dict[str, str], str, str, Bytecode, Bytecode]:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Main.hx").write_text(source)
    target = tmp_path / "original.hl"
    result = subprocess.run(
        ["haxe", "-cp", str(tmp_path / "src"), "-main", "Main", "-hl", str(target)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    files = project.export(Bytecode.from_path(str(target)))
    folder = tmp_path / "project"
    project.write(str(folder), files)
    result = subprocess.run(["haxe", "build.hxml"], cwd=folder, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return (
        files,
        _run(target),
        _run(folder / "out.hl"),
        Bytecode.from_path(str(target)),
        Bytecode.from_path(str(folder / "out.hl")),
    )


def _function(code: Bytecode, name: str) -> Function:
    return next(f for f in code.functions if code.full_func_name(f).endswith(name))


def _same_signature(original: Bytecode, recompiled: Bytecode, name: str) -> bool:
    a = signature(original, _function(original, name))
    b = signature(recompiled, _function(recompiled, name))
    assert a and b, (a.reason, b.reason)
    return a.digest == b.digest


def test_checked_cast_out_of_dynamic_into_a_dynamic_slot_is_spelled_out(tmp_path: Path) -> None:
    # A value read out of Dynamic at a type (a property of a generic base class, a field of
    # `Dynamic<Array<Dynamic>>`, a generic field holding a function, an iterable's `iterator`) is
    # SafeCast to it even where it is passed on as Dynamic: an erased or `Dynamic` parameter, a
    # null test, a comparison, a `throw`, a call of the function it holds.
    source = """
import haxe.ds.Option;

abstract class Base<T> {
    public function new(v:T) this.value = v;
    public var value(get, set):T;
    abstract public function get_value():T;
    abstract public function set_value(v:T):T;
}

class Ints extends Base<Array<Int>> {
    var w:Array<Int> = [];
    public function new(v:Array<Int>) super(v);
    public function get_value():Array<Int> return w;
    public function set_value(v:Array<Int>):Array<Int> return w = v;
}

class Holder<T> {
    public var value:T;
    public function new() {}
}

private abstract Items<T>(Iterator<T>) from Iterator<T> to Iterator<T> {
    @:from public static inline function fromIterable<T>(i:Iterable<T>) return (i.iterator() : Items<T>);
    public inline function hasNext() return this.hasNext();
    public inline function next() return this.next();
}

@:forward @:transitive private abstract Refs(Array<String>) from Array<String> to Array<String> {}

class Main {
    static function eq<T>(a:T, b:T, ?pos:haxe.PosInfos) Sys.println(Std.string(a) + " " + Std.string(b));
    static function same(a:Dynamic, b:Dynamic) Sys.println(Std.string(a) + " " + Std.string(b));
    static function getNull():Dynamic return null;
    static function deNull<T>(value:T, def:T):T return value != null ? value : def;

    static function run(f:Dynamic->Void) {
        var t = new Ints([1, 2]);
        same([1, 2], t.value);
        eq(null, cast(getNull(), Option<Dynamic>));
        var m:Dynamic<Array<Dynamic>> = {a: [1]};
        eq(m.a, null);
        Sys.println(m.a != null);
        var h = new Holder<Dynamic->Void>();
        h.value = f;
        Sys.println(h.value == f);
        var x:Float = deNull(null, 0.5);
        Sys.println(x);
        try throw (getNull() : String) catch (e:String) Sys.println("caught") catch (e:Dynamic) Sys.println("other");
        var refs:Refs = ["1"];
        var items:Items<String> = refs;
        Sys.println(items.hasNext() + " " + items.next());
    }

    static function main() run(function(v) {});
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert actual == expected
    assert _same_signature(original, recompiled, "Main.run")


def test_boxed_number_converted_back_out_of_dynamic_stays_dynamic(tmp_path: Path) -> None:
    # The compiler folds a Dynamic holding a constant into the constant, typed Dynamic: boxed,
    # then cast to the `Null<Int>` the other argument fixes the type parameter at.
    source = """
class Main {
    static function eq<T>(a:T, b:T) Sys.println(Std.string(a) + " " + Std.string(b));

    static function run() {
        var d:Dynamic = {a: [0]};
        eq(d.a[0], 0);
        eq((1.5 : Dynamic), 0.5);
    }

    static function main() run();
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "(1.5 : Dynamic)" in files["src/Main.hx"]
    assert actual == expected
    assert _same_signature(original, recompiled, "Main.run")


def test_int_stored_into_nullable_int64_is_one_unchecked_cast(tmp_path: Path) -> None:
    source = """
class Main {
    static var n:Null<haxe.Int64>;

    static function run(i:Int) {
        n = 29;
        var m:Null<haxe.Int64> = i;
        Sys.println(n != null && m != null);
    }

    static function main() run(Std.random(1) + 3);
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert actual == expected
    assert _same_signature(original, recompiled, "Main.run")


def test_boxed_number_converted_to_another_boxed_number_through_dynamic(tmp_path: Path) -> None:
    # `x` aliases `v`, so the conversion is one SafeCast; a direct one unboxes and reboxes.
    source = """
class Main {
    static function widen(v:Null<Int>):Null<Float> {
        var x:Dynamic = v;
        return x;
    }

    static function main() {
        Sys.println(widen(3));
        Sys.println(widen(null));
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert actual == expected
    assert _same_signature(original, recompiled, "Main.widen")


def test_closure_called_through_dynamic_returns_dynamic(tmp_path: Path) -> None:
    source = """
class Main {
    static function eq<T>(a:T, b:T) Sys.println(Std.string(a) + " " + Std.string(b));

    static function run() {
        var f:haxe.Constraints.Function = function() return 12;
        eq(12, f());
    }

    static function main() run();
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert actual == expected
    assert _same_signature(original, recompiled, "Main.run")
