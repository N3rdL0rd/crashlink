"""Closures the compiler adapts or captures must decompile into source that compiles and behaves the same."""

import shutil
import subprocess
from pathlib import Path
from typing import Dict, Tuple

import pytest

from crashlink import Bytecode, project
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


def roundtrip(tmp_path: Path, source: str) -> Tuple[Dict[str, str], str, str]:
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
    return files, _run(target), _run(folder / "out.hl")


def test_function_assigned_to_an_optional_function_type(tmp_path: Path) -> None:
    # HL passes an optional basic argument through a function type as an hl.Ref, so the
    # compiler wraps the function in a helper that unboxes it; source never wrote the helper.
    source = """
class Main {
    static var f:?Int->Int;
    static var g:?Int->String->Int;
    static function main() {
        f = function(?a:Int) return a == null ? -1 : a;
        Sys.println(f());
        Sys.println(f(5));
        g = (?a:Int = 1, b:String) -> a + b.length;
        Sys.println(g("--"));
        Sys.println(g(4, "--"));
    }
}
"""
    files, expected, actual = roundtrip(tmp_path, source)
    assert ".bind(" not in files["src/Main.hx"]
    assert actual == expected


def test_closure_capturing_a_closure_context_built_after_other_work(tmp_path: Path) -> None:
    # The capture context is allocated and then filled; the value of one field comes from a
    # switch over the outer context, which sits between the allocation and the stores.
    source = """
class Main {
    static function nested(a:Int):Int->(Int->String) {
        return (b:Int) -> {
            return (c:Int) -> "" + a + b + c;
        }
    }
    static function main() {
        var n = nested(1);
        Sys.println(n(2)(3));
    }
}
"""
    files, expected, actual = roundtrip(tmp_path, source)
    assert actual == expected


def test_nullable_passed_to_an_optional_basic_parameter(tmp_path: Path) -> None:
    # `get(inull)` compiles to `r = inull == null ? null : new hl.Ref(inull)` then `get(r)`.
    source = """
class Main {
    var inull:Null<Int> = null;
    var five:Null<Int> = 5;
    function new() {}
    function get(a = 2, b = 4.25) return a + "/" + b;
    function run() {
        Sys.println(get(inull));
        Sys.println(get(five));
        Sys.println(get(five, five));
    }
    static function main() new Main().run();
}
"""
    files, expected, actual = roundtrip(tmp_path, source)
    assert actual == expected


def test_dynamic_catch_variable_keeps_its_type(tmp_path: Path) -> None:
    # `catch (e)` is `catch (e:haxe.Exception)`, so a Dynamic catch must be written out.
    source = """
class Main {
    static function main() {
        try {
            throw 123;
        } catch (e:Dynamic) {
            var n:Int = e;
            Sys.println(n + 1);
        }
        try {
            throw "x";
        } catch (e:Dynamic) {
            Sys.println(Std.string(e) + "!");
        }
    }
}
"""
    files, expected, actual = roundtrip(tmp_path, source)
    assert "catch (" in files["src/Main.hx"] and ":Dynamic)" in files["src/Main.hx"]
    assert actual == expected


def test_exception_stack_and_thrown_wrapper(tmp_path: Path) -> None:
    # `stack` is a CallStack (an abstract over an array) and `Exception.thrown` returns Any.
    source = """
import haxe.CallStack;
class Main {
    static function stacks():Array<CallStack> {
        var result:Array<CallStack> = [];
        result.push(new haxe.Exception("a").stack);
        result.push(@:privateAccess (haxe.Exception.thrown("b"):haxe.Exception).stack);
        return result;
    }
    static function main() Sys.println(stacks().length);
}
"""
    files, expected, actual = roundtrip(tmp_path, source)
    assert actual == expected


def test_catch_of_an_interface_keeps_its_type(tmp_path: Path) -> None:
    # The interface is caught by its class object; losing it makes a later `catch (e:Dynamic)` unreachable.
    source = """
interface Marker {}
class Main {
    static function main() {
        var i = try {
            throw (null : Marker);
        } catch (s:Marker) {
            1;
        } catch (e:Dynamic) {
            2;
        }
        Sys.println(i);
    }
}
"""
    files, expected, actual = roundtrip(tmp_path, source)
    assert "catch (e:Marker)" in files["src/Main.hx"]
    assert "catch (e:Dynamic)" in files["src/Main.hx"]
    assert actual == expected
