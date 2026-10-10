"""Captured variables boxed in a one-element array: the decompiled source must compile back to the same behaviour."""

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


def test_closure_block_writing_captured_int_is_not_boxed(tmp_path: Path) -> None:
    # The compiler boxes `a` in a one-element Int array because a closure writes it. The closure has
    # several statements, so it is not inlined as an expression; the box must still render as `a`.
    source = """
class Main {
    static function add(x: Int, y: Int) return x + y;
    static function main() {
        var a = 999;
        var b = function() { a = 123; return a; };
        var r = add(a, b());
        Sys.println(r);
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "[0]" not in files["src/Main.hx"]
    assert actual == expected
    assert _same_signature(original, recompiled, "Main.main")
