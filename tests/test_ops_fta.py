"""Erased array parameters take the element type their callers pass, even when the caller is in another class."""

import shutil
import subprocess
from pathlib import Path

import pytest

from crashlink import Bytecode, project
from crashlink.equivalence import signature
from crashtest.behavior import resolve_hl_runtime

SOURCE = """
class Helper {
    public static function count(a:Array<String>):Int { return a.length; }
    public static function same(a:Array<String>, b:Array<String>):Int { return a.length + b.length; }
}
class Other {
    public static function pick(a:Array<Box>):Int { return a.length; }
}
class Box { public var v:Int; public function new(v:Int) { this.v = v; } }
class Main {
    static function main() {
        var arr = ["a", "b"];
        var n = Helper.count(arr);
        var m = Helper.same(arr, ["c"]);
        var boxes = [new Box(1)];
        var k = Other.pick(boxes);
        var k2 = Other.pick([new Box(2), new Box(3)]);
        Sys.println(n + m + k + k2);
    }
}
"""


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


def _function(code: Bytecode, name: str):  # type: ignore[no-untyped-def]
    return next(f for f in code.functions if code.full_func_name(f).endswith(name))


def test_erased_parameter_takes_element_type_from_caller_in_another_class(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Main.hx").write_text(SOURCE)
    target = tmp_path / "original.hl"
    result = subprocess.run(
        ["haxe", "-cp", str(tmp_path / "src"), "-main", "Main", "-hl", str(target)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    original = Bytecode.from_path(str(target))
    files = project.export(original)
    main = files["src/Main.hx"]
    assert "public static function count(a: Array<String>): Int" in main
    assert "public static function same(a: Array<String>, b: Array<String>): Int" in main
    assert "public static function pick(a: Array<Box>): Int" in main

    folder = tmp_path / "project"
    project.write(str(folder), files)
    build = subprocess.run(["haxe", "build.hxml"], cwd=folder, capture_output=True, text=True)
    assert build.returncode == 0, build.stderr
    assert _run(target) == _run(folder / "out.hl")

    recompiled = Bytecode.from_path(str(folder / "out.hl"))
    for name in ("Helper.count", "Other.pick"):
        a = signature(original, _function(original, name))
        b = signature(recompiled, _function(recompiled, name))
        assert a and b, (a.reason, b.reason)
        assert a.matches(b)
