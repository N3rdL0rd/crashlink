"""A Dynamic value cast to a class keeps its SafeCast when a type parameter is fixed by another argument."""

import shutil
import subprocess
from pathlib import Path
from typing import Dict, Tuple

import pytest

from crashlink import Bytecode, project
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


def _func(code: Bytecode, name: str):
    return next(f for f in code.functions if code.full_func_name(f).endswith(name))


def test_dynamic_cast_to_string_argument_keeps_safecast(tmp_path: Path) -> None:
    # `eq(null, cast dyn)` fixes T to Dynamic, so an implicit Dynamic->String conversion would vanish.
    source = """
class Main {
    static function getNull():Dynamic return null;
    static function eq<T>(a:T, b:T) { if (a != b) throw "neq"; }
    static function main() {
        eq(null, cast(getNull(), String));
    }
}
"""
    files, original_out, recompiled_out, original, recompiled = roundtrip(tmp_path, source)
    assert recompiled_out == original_out
    assert "(cast Main.getNull() : String)" in files["src/Main.hx"]
    assert signature(original, _func(original, "Main.main")) == signature(
        recompiled, _func(recompiled, "Main.main")
    )


def test_dynamic_result_of_closure_passes_uncast(tmp_path: Path) -> None:
    # A Dynamic result of a closure, passed where `eq<T>` fixes T to String, has no cast in the original.
    source = """
class Main {
    static function eq<T>(a:T, b:T) { if (a != b) throw "neq"; }
    static function main() {
        var f:Dynamic->Dynamic = function(x) return x;
        eq("a", f("a"));
    }
}
"""
    files, original_out, recompiled_out, original, recompiled = roundtrip(tmp_path, source)
    assert recompiled_out == original_out
    assert '(cast f("a") : String)' not in files["src/Main.hx"]
    assert signature(original, _func(original, "Main.main")) == signature(
        recompiled, _func(recompiled, "Main.main")
    )
