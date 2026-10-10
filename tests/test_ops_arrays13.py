"""Erased `Array<T>` element types: the decompiled source must compile back to the same typed arrays."""

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


def test_structure_array_field_keeps_the_element_type_of_the_arrays_stored_into_it(tmp_path: Path) -> None:
    # HL types the structure's field `ArrayObj` with no element type; only the `alloc_array` of the
    # array stored into it says `T`. Declared `Array<Dynamic>`, it would be an ArrayDyn and cast.
    source = """
class Main {
    static function make(n:Int) {
        return {arr: [{foo: n, bar: 42}], name: "x"};
    }

    static function main() {
        var o = make(Std.random(1) + 1);
        Sys.println(o.arr.length + o.arr[0].bar + o.arr[0].foo);
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "var arr: Array<{ var bar: Int; var foo: Int; }>" in files["src/Main.hx"]
    assert actual == expected
    assert _same_signature(original, recompiled, "Main.make")
    assert _same_signature(original, recompiled, "Main.main")


def test_enum_array_parameter_keeps_the_element_type_of_the_arrays_built_into_it(tmp_path: Path) -> None:
    # An enum constructor's `Array<T>` parameter is an `ArrayObj`; only the arrays it's built with say `T`.
    source = """
enum E {
    A(a:Array<String>);
    B(v:Int, cs:Array<E>);
}

class Main {
    static function size(e:E):Int {
        return switch e {
            case A(a): a.length;
            case B(v, cs):
                var n = v;
                for (c in cs) n += size(c);
                n;
        }
    }

    static function main() {
        var a = [];
        var b = [];
        Sys.println(Type.enumEq(A(a), A(b)));
        Sys.println(size(B(1, [A(["x"]), B(2, [A([])])])));
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert actual == expected
    assert _same_signature(original, recompiled, "Main.size")
    assert _same_signature(original, recompiled, "Main.main")


def test_closure_array_parameter_keeps_the_element_type_calls_through_its_function_type_pass(
    tmp_path: Path,
) -> None:
    # `Array<String>->Void` is `fun(ArrayObj)->Void`: the field, and the closure stored into it, are typed
    # by the arrays passed when calling through the field.
    source = """
class Main {
    var foo:Array<String>->Void;
    var result:Array<String>;

    function new() {}

    function setup() {
        result = [];
        foo = function(args:Array<String>) {
            result.push(args.join(","));
            args.push("foo");
            result.push(args.join(","));
        }
    }

    static function main() {
        var m = new Main();
        m.setup();
        var args:Array<String> = [];
        args.push("bar");
        m.foo(args);
        Sys.println(m.result);
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "var foo: ((Array<String>) -> Void);" in files["src/Main.hx"]
    assert "function(args: Array<String>)" in files["src/Main.hx"]
    assert actual == expected
    assert _same_signature(original, recompiled, "Main.setup")
    assert _same_signature(original, recompiled, "Main.main")


def test_abstract_over_an_erased_array_wraps_the_element_type_its_members_are_called_with(
    tmp_path: Path,
) -> None:
    # The `_Impl_` members take the value as an `ArrayObj`; the arrays callers pass them say `T`.
    source = """
abstract Words(Array<String>) from Array<String> {
    public var length(get, never):Int;

    function get_length() return this.length;

    @:arrayAccess function get(i:Int) return this[i];

    public function joined() return this.join("+");
}

class Main {
    static function main() {
        var a:Words = ['hello', 'world'];
        Sys.println(a.joined() + a.length + a[1]);
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "abstract Words(Array<String>)" in files["src/Main.hx"]
    assert actual == expected
    assert _same_signature(original, recompiled, "Main.main")
    assert _same_signature(original, recompiled, "Words_Impl_.joined")


def test_class_field_of_dynamic_arrays_keeps_its_array_dyn_element_type(tmp_path: Path) -> None:
    # `Array<Array<Dynamic>>` is an ArrayObj of ArrayDyn: the element type is fully known, not erased.
    source = """
class Box {
    public var rows:haxe.ds.Vector<Array<Dynamic>>;

    public function new(n:Int) {
        rows = new haxe.ds.Vector(n);
    }
}

class Main {
    static function main() {
        var b = new Box(Std.random(1) + 3);
        var row:Array<Dynamic> = [1, "a"];
        b.rows[1] = row;
        Sys.println(b.rows.length + b.rows[1].length);
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "public var rows: Array<Array<Dynamic>>;" in files["src/Main.hx"]
    assert actual == expected
    assert _same_signature(original, recompiled, "Box.__constructor__")


def test_structure_built_field_by_field_keeps_the_element_type_of_its_array_fields(tmp_path: Path) -> None:
    # A literal leaving an optional field out is built as `{}` with each field set by name, then made the
    # structure: the arrays set on it type the structure's fields.
    source = """
typedef Path = {name:String, pack:Array<String>, ?sub:String};

class Main {
    static function show(p:Path) {
        return p.name + p.pack.length + p.pack[0];
    }

    static function main() {
        var p:Path = {name: "x", pack: ["a", "b"]};
        Sys.println(show(p));
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "var pack: Array<String>;" in files["src/Main.hx"]
    assert actual == expected
    assert _same_signature(original, recompiled, "Main.show")
    assert _same_signature(original, recompiled, "Main.main")


def test_closure_bound_to_a_captured_array_takes_its_element_type(tmp_path: Path) -> None:
    # A local a closure writes is boxed in a one-element array the closure is bound to.
    source = """
class Main {
    static function once(f:Void->Void):Void->Void {
        return function() {
            f();
            f = () -> Sys.println("again");
        };
    }

    static function main() {
        var g = once(() -> Sys.println("first"));
        g();
        g();
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert actual == expected
    once = _function(original, "Main.once")
    closure = next(op.df["fun"].resolve(original) for op in once.ops if op.op == "InstanceClosure")
    lifted = next(f for f in recompiled.functions if "__anon_" in recompiled.full_func_name(f))
    assert signature(original, closure).digest == signature(recompiled, lifted).digest
