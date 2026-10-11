"""Erased class type parameters: a generic class must be declared generic again, or its reads lose
the unchecked casts the compiler gives a type parameter (see `crashlink.classgenerics`)."""

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
    assert result.returncode == 0, result.stderr + files["src/Main.hx"]
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


def test_field_of_a_generic_class_is_read_at_its_type_argument(tmp_path: Path) -> None:
    # `b.v` is a `Dyn` field read cast unchecked to String: `Box<String>`. Declared `Dynamic`, the
    # read would be converted to String with a checked cast.
    source = """
class Box<T> {
    public var v:T;
    public function new(v:T) {
        this.v = v;
    }
}

class Main {
    static function main() {
        var b = new Box<String>("abc");
        var s = b.v;
        Sys.println(s.length);
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "class Box<T>" in files["src/Main.hx"]
    assert actual == expected
    assert _same_signature(original, recompiled, "Main.main")


def test_subclass_closes_the_type_parameter_of_its_super_class(tmp_path: Path) -> None:
    # `B extends A<String>`: B's own call to the inherited `f():T` is cast unchecked to String.
    source = """
class A<T> {
    public function f():T return null;
}

class B extends A<String> {
    public function new() {}
    public function f2() {
        var v = f();
        return v;
    }
}

class Main {
    static function main() {
        Sys.println(new B().f2());
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "extends A<String>" in files["src/Main.hx"]
    assert actual == expected
    assert _same_signature(original, recompiled, "B.f2")


def test_override_takes_the_parameter_type_its_super_class_was_closed_with(tmp_path: Path) -> None:
    # `onItem(item:T)` overridden in `Sub extends Base<String>` as `onItem(item:String)`: declared
    # `Dynamic` the override's parameter would be Dynamic and `toUpperCase` a dynamic call.
    source = """
class Base<T> {
    public var received:T;
    public function new(item:T) {
        onItem(item);
    }
    public dynamic function onItem(item:T):Void {
        received = item;
    }
}

class Sub extends Base<String> {
    public function new() {
        super("ctor");
    }
    override function onItem(item:String) {
        received = item.toUpperCase();
    }
}

class Main {
    static function main() {
        var s = new Sub();
        Sys.println(s.received);
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "onItem(item: String)" in files["src/Main.hx"]
    assert actual == expected
    assert _same_signature(original, recompiled, "Sub.onItem")
    assert _same_signature(original, recompiled, "Main.main")


def test_class_instantiated_two_ways_stays_erased(tmp_path: Path) -> None:
    # `Holder<Int>` reads `value` with a checked cast, `Holder<String>` with an unchecked one: one
    # declaration can't give both, so the class keeps its erased `Dynamic` field.
    source = """
class Holder<T> {
    public var value:T;
    public function new(value:T) {
        this.value = value;
    }
}

class Main {
    static function asInt(h:Holder<Int>):Int return h.value;
    static function asString(h:Holder<String>):String return h.value;

    static function main() {
        Sys.println(asInt(new Holder(12)) + asString(new Holder("x")).length);
    }
}
"""
    files, expected, actual, _, _ = roundtrip(tmp_path, source)
    assert "class Holder<" not in files["src/Main.hx"]
    assert actual == expected


def test_parameter_slot_stored_from_an_array_element_stays_erased(tmp_path: Path) -> None:
    # The class stores an element of its `Array<T>` into the `T` field; the array is rendered with the
    # element type its callers pass, which a `T` field couldn't take.
    source = """
class Iter<T> {
    var data:Array<T>;
    var x = 0;
    public var cur:T;
    public function new(data:Array<T>) {
        this.data = data;
    }
    public function step() {
        cur = data[x++];
    }
}

class Main {
    static function main() {
        var it = new Iter(["a", "bc"]);
        it.step();
        it.step();
        var s:String = it.cur;
        Sys.println(s.length);
    }
}
"""
    files, expected, actual, _, _ = roundtrip(tmp_path, source)
    assert "class Iter<" not in files["src/Main.hx"]
    assert actual == expected
