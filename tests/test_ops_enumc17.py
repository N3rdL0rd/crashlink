"""Enum patterns and closure capture contexts: the decompiled source must compile back to the same code."""

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


def test_literal_payload_pattern_is_written_as_match(tmp_path: Path) -> None:
    # `case Bar(0)` tests the constructor and compares the payload read straight from the value;
    # `Type.enumParameters(x)[0]` is a call and a null check the original does not have.
    source = """
private enum FooBar {
    Foo;
    Bar(value:Any);
}

class Main {
    static function test(bar:FooBar):Bool {
        return switch (bar) {
            case Bar(0): true;
            case _: false;
        }
    }

    static function main() {
        Sys.println(test(Bar(0)) + " " + test(Bar(1)) + " " + test(Foo));
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert expected == actual
    assert _same_signature(original, recompiled, "Main.test")


def test_closure_body_locals_do_not_hide_captured_variables(tmp_path: Path) -> None:
    # The closure's own temporaries and the captured variables share register names; inlined as a
    # lambda, a declaration in the body must not shadow the variable it is meant to read.
    source = """
private class Point {
    public var x:Float = 1;
    public var y:Float = 2;
    extern inline public function new() {}
}

class Main {
    public function new() {}

    function test() {
        var pt = new Point();
        function closure() {
            pt.x = pt.x + pt.y;
        }
        closure();
        Sys.println(pt.x);
        Sys.println(pt.y);
    }

    static function main() {
        new Main().test();
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "__ClosureCtx" not in files["src/Main.hx"]
    assert expected == actual


def test_enum_parameter_built_from_a_structure_field_keeps_the_array_element_type(tmp_path: Path) -> None:
    # `Album(d.tracks)`: no `alloc_array` builds the array, it comes out of the structure's field,
    # whose element type the other functions' literals give. `Array<Dynamic>` would be an ArrayDyn.
    source = """
private typedef Data = {year:Int, ?tracks:Array<String>, ?side:String}

private enum Kind {
    Album(tracks:Array<String>);
    Single(side:String);
}

class Main {
    static function kind(d:Data):Kind {
        return d.tracks != null ? Album(d.tracks) : Single(d.side);
    }

    static function main() {
        var data:Data = {year: 1967, tracks: ["a", "b"]};
        Sys.println(Std.string(kind(data)));
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert expected == actual
    assert _same_signature(original, recompiled, "Main.kind")


def test_closure_returning_a_structure_is_inlined_with_its_return_type(tmp_path: Path) -> None:
    # The lifted helper's header ends in `{ var then: ... } {`: the parameter and return type
    # have to be told apart from the body's brace, or the closure stays a `.bind` of a helper.
    source = """
class Main {
    static function main() {
        var k = [];
        var f = function() {
            k.push(1);
            return {then: function(x) k.push(x)};
        }
        f().then(2);
        Sys.println(k.length);
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert ".bind(" not in files["src/Main.hx"]
    assert expected == actual
    assert _same_signature(original, recompiled, "Main.main")


def test_bind_of_a_method_stays_a_bind(tmp_path: Path) -> None:
    # `c.process.bind(42)` travels the receiver and the value in one capture context; spelled
    # `.bind(Ctx(...))` of a lifted helper it builds another context type.
    source = """
class C {
    public function new() {}

    public function process(value:Int):Int {
        return value;
    }
}

class Main {
    static var timestamp = 1.0;

    static function main() {
        var c = new C();
        var c2 = new C();
        var f = c.process.bind(42);
        c = null;
        Sys.println(f());
        timestamp = 2.0;
        var g = c2.process.bind(Std.int(timestamp));
        Sys.println(g());
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "__ClosureCtx" not in files["src/Main.hx"]
    assert expected == actual
    assert _same_signature(original, recompiled, "Main.main")


def test_function_returning_void_passed_where_dynamic_is_expected_is_not_adapted_in_source(
    tmp_path: Path,
) -> None:
    # `Reflect.makeVarArgs(f)` with `f:Array<Dynamic>->Void`: the compiler wraps `f` in a helper that
    # returns null, guarded by a null test. The source passed `f` itself to the public extern.
    source = """
class Main {
    static function main() {
        var f = function(args:Array<Dynamic>) {
            Sys.println(args.length);
        };
        var g:Dynamic = Reflect.makeVarArgs(f);
        g(1, 2, 3);
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert ".bind(" not in files["src/Main.hx"]
    assert expected == actual
    assert _same_signature(original, recompiled, "Main.main")
