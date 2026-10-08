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
