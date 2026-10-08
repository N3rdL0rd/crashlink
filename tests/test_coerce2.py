"""Erased-array element reads, dynamic adds and private enum constructors must round-trip through the decompiler."""

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


def roundtrip(tmp_path: Path, modules: Dict[str, str]) -> Tuple[Dict[str, str], str, str]:
    """Compile `modules`, decompile the image, recompile that; return (decompiled sources, original output, new output)."""
    for name, source in modules.items():
        (tmp_path / "src" / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "src" / name).write_text(source)
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
    sources = {
        str(path.relative_to(folder / "src")): path.read_text() for path in (folder / "src").rglob("*.hx")
    }
    return sources, _run(target), _run(folder / "out.hl")


def test_float_pushed_into_int_array_through_any(tmp_path: Path) -> None:
    modules = {
        "Main.hx": """
class Main {
    static inline function addFloat(arr:Array<Any>, ...values:Float) {
        for (v in values) arr.push(v);
    }
    static function main() {
        var arr = [1, 3, 4];
        addFloat(arr, 5, 6, 7);
        Sys.println(arr);
    }
}
"""
    }
    _, expected, actual = roundtrip(tmp_path, modules)
    assert actual == expected


def test_dynamic_add_of_enum_parameter_into_int_array(tmp_path: Path) -> None:
    modules = {
        "Main.hx": """
class Main {
    static function main() {
        var a = 0;
        var b = 0;
        var fs = [];
        for (i in 0...3) fs.push(function() { a += b + 1; b++; return a; });
        var total = 0;
        for (f in fs) total += f();
        Sys.println(total + ":" + a + ":" + b);
    }
}
"""
    }
    _, expected, actual = roundtrip(tmp_path, modules)
    assert actual == expected


def test_dynamic_string_add_with_bool(tmp_path: Path) -> None:
    modules = {
        "Main.hx": """
class Main {
    static function t(v:Bool) try { Sys.println(v); } catch (e:Dynamic) { Sys.println("err"); }
    static function main() {
        var x:Array<Dynamic> = ["4", 1];
        try t((x[0] + x[0] is String)) catch (e:Dynamic) Sys.println("err");
        try t((x[0] + x[1] is String)) catch (e:Dynamic) Sys.println("err");
    }
}
"""
    }
    _, expected, actual = roundtrip(tmp_path, modules)
    assert actual == expected


def test_private_enum_constructor_named_like_enum(tmp_path: Path) -> None:
    modules = {
        "Main.hx": """
class Main {
    static function main() {
        Sys.println(A == A);
        Sys.println(Type.enumConstructor(A));
    }
}
private enum A { A; }
"""
    }
    _, expected, actual = roundtrip(tmp_path, modules)
    assert actual == expected
