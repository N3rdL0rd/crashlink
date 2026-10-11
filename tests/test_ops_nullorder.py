"""Evaluation order around null checks: the recompiled code must check and evaluate in the original order."""

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


def test_loop_body_temp_feeding_a_closure_call_is_inlined_after_the_callee_check(tmp_path: Path) -> None:
    # `append(arr[i].foo)` checks `append` before reading `arr[i]`. Keeping the element and field
    # reads as temps ahead of the call in the loop body reads them before the check instead.
    source = """
class Main {
    static function main() {
        var arr = [{foo: 1, bar: 2}, {foo: 3, bar: 4}];
        var buf = new StringBuf();
        var append = function(s:Int) buf.add(s);
        if (Std.random(1) == 1) append = null;
        for (i in 0...arr.length) {
            append(arr[i].foo);
            append(arr[i].bar);
        }
        Sys.println(buf.toString());
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert expected == actual
    assert "append(arr[i].foo);" in files["src/Main.hx"]
    assert _same_signature(original, recompiled, "Main.main")


def test_argument_built_after_the_receiver_check_is_passed_inline(tmp_path: Path) -> None:
    # `hs.remove(new Item())` checks `hs` before allocating the argument; hoisting the
    # allocation into a temp ahead of the call allocates before the check.
    source = """
interface Coll<T> { function remove(v:T):Bool; }
class Item { public function new() {} }
class HS<T> implements Coll<T> {
    public function new() {}
    public function remove(v:T):Bool return true;
}
class Main {
    static function main() {
        var hs:Coll<Item> = new HS();
        if (Std.random(1) == 1) hs = null;
        Sys.println(hs.remove(new Item()));
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert expected == actual
    assert "hs.remove(new Item())" in files["src/Main.hx"]
    assert _same_signature(original, recompiled, "Main.main")


def test_class_viewed_as_its_interface_to_call_a_method_is_converted_to_the_interface(tmp_path: Path) -> None:
    # The map field is converted to `IMap` through the class's interface cache; once the
    # conversion is a receiver rather than a temp, it still has to name the interface.
    source = """
class C { public static var TYPE = "type"; public function new() {} }
class Main {
    var comps:Map<String, C>;
    function new() {
        comps = new Map();
        comps.set(C.TYPE, new C());
    }
    @:generic function has<T:C>(cls:Class<T>):Bool {
        return comps.exists(Reflect.field(cls, "TYPE"));
    }
    static function main() {
        Sys.println(new Main().has(C));
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert expected == actual
    assert _same_signature(original, recompiled, "Main.has_C")


def test_function_field_read_out_of_a_structure_is_a_read_only_var(tmp_path: Path) -> None:
    # A structure's method is called with `CallMethod`; a function-typed var's closure is read
    # out of its slot and called. A class's method still satisfies a read-only var.
    source = """
class A {
    var a:String;
    public function new(a) this.a = a;
    public function test() return a;
}
class Main {
    static function main() {
        var x:{ var test(default, never):() -> String; } = new A("foo");
        Sys.println(x.test());
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert expected == actual
    assert "var test(default, never)" in files["src/Main.hx"]
    assert _same_signature(original, recompiled, "Main.main")
