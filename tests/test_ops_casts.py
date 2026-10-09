"""The decompiled source makes the compiler emit the same casts, boxings and null checks."""

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


def _ops(code: Bytecode, name: str) -> list:
    func = next(f for f in code.functions if code.full_func_name(f).endswith(name))
    return [str(op.op) for op in func.ops]


def test_a_type_variable_parameter_is_declared_generic(tmp_path: Path) -> None:
    # `same<T>` and `same(a:Dynamic, ...)` compile to the same signature; only a call tells them
    # apart: with T fixed to Int, a Dynamic argument is cast to it.
    source = """
class Main {
    static function same<T>(a:T, b:T) {
        Sys.println(a == b);
    }
    static function run(d:Dynamic) {
        same(0, d.length);
        same(1, d.length);
    }
    static function main() {
        run([1]);
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "function same<T>(a: T, b: T)" in files["src/Main.hx"]
    assert actual == expected
    assert _ops(original, "Main.run") == _ops(recompiled, "Main.run")
    assert "SafeCast" in _ops(recompiled, "Main.run")


def test_a_map_declares_the_value_type_its_uses_show(tmp_path: Path) -> None:
    # HL erases a map's value type; `get` is an UnsafeCast to it where the map has one, a SafeCast
    # out of a Dynamic read where it was left out.
    source = """
class Main {
    static final flags:Map<Int, Int> = [0 => 1010];
    static function bits() return flags;
    static function run(names:Map<String, String>) {
        var local = new Map<Int, Float>();
        local.set(1, 2.5);
        var value = bits().get(0);
        var name = names.get("a");
        var list = local.get(1);
        Sys.println(value);
        Sys.println(name);
        Sys.println(list);
    }
    static function main() {
        var names = new Map<String, String>();
        names.set("a", "b");
        run(names);
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    text = files["src/Main.hx"]
    assert (
        "haxe.ds.IntMap<Int>" in text
        and "haxe.ds.StringMap<String>" in text
        and "haxe.ds.IntMap<Float>" in text
    )
    assert actual == expected
    for name in ("Main.run", "Main.main"):
        assert _ops(original, name) == _ops(recompiled, name)


def test_an_array_of_type_variable_parameter_is_declared_generic(tmp_path: Path) -> None:
    # `Array<T>` is an ArrayDyn once erased; a typed array passed for it is cast.
    source = """
class Main {
    static function sameArrays<T>(a:Array<T>, b:Array<T>) {
        Sys.println(a.length == b.length);
    }
    static function run() {
        var names = ["a", "b"];
        sameArrays(names, names);
    }
    static function main() {
        run();
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "function sameArrays<T>(a: Array<T>, b: Array<T>)" in files["src/Main.hx"]
    assert actual == expected
    assert _ops(original, "Main.run") == _ops(recompiled, "Main.run")
    assert "SafeCast" in _ops(recompiled, "Main.run")


def test_arrays_of_one_type_variable_share_their_element_type(tmp_path: Path) -> None:
    # An array of unknown element type next to typed ones for `Array<T>` parameters would not unify.
    source = """
class Main {
    static function sameArrays<T>(a:Array<T>, b:Array<T>) {
        Sys.println(a.length == b.length);
    }
    static function pick(from:Array<String>, other:Array<String>) {
        return from.length > 1 ? from : other;
    }
    static function run() {
        var names = ["a", "b"];
        sameArrays(names, pick(names, ["c"]));
        sameArrays(["d"], names);
    }
    static function main() {
        run();
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "cast (Main.pick(" in files["src/Main.hx"]
    assert actual == expected


def test_an_int_read_from_an_array_is_widened_where_a_float_is_wanted(tmp_path: Path) -> None:
    # The element read has the array's element type, so the Int to Float conversion is the
    # implicit one (ToSFloat), not a `cast`.
    source = """
class Main {
    static function run(i:Int) {
        var ints = [1, 2];
        var total = ints[i] + 1.5;
        Sys.println(total);
    }
    static function main() {
        run(0);
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "cast(" not in files["src/Main.hx"]
    assert actual == expected
    assert _ops(original, "Main.run") == _ops(recompiled, "Main.run")


def test_null_read_as_a_basic_type_stays_a_cast(tmp_path: Path) -> None:
    # `new Vector<Int>(n)` fills the last slot with `cast null`: a Null and a SafeCast.
    source = """
class Main {
    static function run() {
        var v = new haxe.ds.Vector<Int>(3);
        v[0] = 1;
        var f = new haxe.ds.Vector<Float>(2);
        f[0] = 1.5;
        Sys.println(v[0]);
        Sys.println(f[0]);
    }
    static function main() {
        run();
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "cast(null, Int)" in files["src/Main.hx"]
    assert actual == expected
    assert _ops(original, "Main.run") == _ops(recompiled, "Main.run")


def test_an_int_literal_widened_at_run_time_stays_an_int_ascribed_as_float(tmp_path: Path) -> None:
    # `{x: 2}` for a Float field widens the Int at run time (Int + ToSFloat); a plain `2` in the
    # same place would be folded into a Float constant.
    source = """
@:structInit
class Point {
    public var x:Float;
}
class Main {
    static function run() {
        var p:Point = {x: 2};
        Sys.println(p.x);
    }
    static function main() {
        run();
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "(2 : Float)" in files["src/Main.hx"]
    assert actual == expected
    assert _ops(original, "Main.run") == _ops(recompiled, "Main.run")
