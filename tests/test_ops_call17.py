"""Calls whose argument expression must keep the shape the original compiled from."""

import shutil
import subprocess
from pathlib import Path
from typing import Tuple

import pytest

from crashlink import Bytecode, project
from crashlink.equivalence import signature
from crashtest.behavior import resolve_hl_runtime


@pytest.fixture(autouse=True)
def _tools() -> None:
    if not shutil.which("haxe") or resolve_hl_runtime() is None:
        pytest.skip("project round trips require Haxe and HashLink")


def _roundtrip(tmp_path: Path, source: str) -> Tuple[str, Bytecode, Bytecode]:
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
    return files["src/Main.hx"], Bytecode.from_path(str(target)), Bytecode.from_path(str(folder / "out.hl"))


def _same(original: Bytecode, recompiled: Bytecode, name: str) -> bool:
    left = next(f for f in original.functions if original.full_func_name(f) == name)
    right = next(f for f in recompiled.functions if recompiled.full_func_name(f) == name)
    return signature(original, left).matches(signature(recompiled, right))


def test_unsigned_comparison_passed_as_a_value_is_not_negated(tmp_path: Path) -> None:
    source = """
class Main {
    static var v:UInt = 0x97000000;
    static function t(b:Bool) { Sys.println(b); }
    static function main() {
        var a:UInt = v;
        var b:UInt = 5;
        t(a > b);
        t(a >= b);
        t(v > 0);
    }
}
"""
    text, original, recompiled = _roundtrip(tmp_path, source)
    assert "!(" not in text
    assert _same(original, recompiled, "$Main.main")


def test_interface_cast_of_a_variable_that_lives_on_is_written_as_a_cast(tmp_path: Path) -> None:
    source = """
interface I1 { }
interface I2 { }
class A implements I1 { public function new() {} }
class Main {
    static function eq(a:Dynamic, b:Dynamic) { Sys.println(a == b); }
    static function exc(f:Void->Void) { try { f(); Sys.println("no"); } catch (e:Dynamic) { Sys.println("exc"); } }
    static function test() {
        var v = new A();
        eq(cast(v, I1), v);
        exc(function() cast(v, I2));
        var w:I1 = cast(v, I1);
        eq(w, v);
    }
    static function main() { test(); }
}
"""
    text, original, recompiled = _roundtrip(tmp_path, source)
    assert "Cast error" not in text
    assert _same(original, recompiled, "$Main.test")


def test_downcast_is_written_as_std_downcast(tmp_path: Path) -> None:
    source = """
class G { public function new() {} }
class Main {
    static function show(a:Dynamic, b:Dynamic) { Sys.println(a == b); }
    static function test(v:Dynamic, arr:Array<Int>) {
        var g:G = Std.downcast(v, G);
        show(g, v);
        var x:Array<Int> = Std.downcast(arr, Array);
        show(x, arr);
        x = Std.downcast(arr, Array);
        show(x, null);
    }
    static function main() { test(new G(), [1, 2]); test("s", [3]); }
}
"""
    text, original, recompiled = _roundtrip(tmp_path, source)
    assert "isOfType" not in text
    assert _same(original, recompiled, "$Main.test")


def test_map_of_maps_keeps_the_inner_value_type(tmp_path: Path) -> None:
    source = """
class Main {
    static function show(a:Dynamic, b:Dynamic) { Sys.println(a == b); }
    static function test() {
        var results = ["home" => [1 => 1, 2 => 3]];
        show(results["home"][1], 1);
    }
    static function main() { test(); }
}
"""
    text, original, recompiled = _roundtrip(tmp_path, source)
    assert "IntMap<Dynamic>" not in text
    assert _same(original, recompiled, "$Main.test")


def test_int_widened_to_float_and_boxed_keeps_the_float_ascription(tmp_path: Path) -> None:
    source = """
class Main {
    static var d = 1.665;
    static function run(t:Dynamic) { Sys.println(t); }
    static function test() {
        run((Std.int(d) : Float));
    }
    static function main() { test(); }
}
"""
    text, original, recompiled = _roundtrip(tmp_path, source)
    assert ": Float)" in text
    assert _same(original, recompiled, "$Main.test")

