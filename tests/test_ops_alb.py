"""A captured local that a closure assigns is one cell: the decompiler writes it as the variable,
not as the one-element array the compiler boxes it in, even when the closure takes several statements."""

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


def roundtrip(tmp_path: Path, source: str) -> Tuple[Dict[str, str], Bytecode, Bytecode]:
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
    assert _run(target) == _run(folder / "out.hl")
    return files, Bytecode.from_path(str(target)), Bytecode.from_path(str(folder / "out.hl"))


def test_multi_statement_closure_assigning_a_captured_string(tmp_path: Path) -> None:
    source = """
class Main {
    static function main() {
        var a = "foo";
        function sideEffect() {
            a = "bar";
            return 0;
        }
        { a: 1, b: sideEffect() };
        Sys.println(a);
    }
}
"""
    files, original, recompiled = roundtrip(tmp_path, source)
    text = files["src/Main.hx"]
    assert 'var a: String = "foo";' in text
    assert '["foo"]' not in text
    name = "$Main.main"
    fa = next(f for f in original.functions if original.full_func_name(f) == name)
    fb = next(f for f in recompiled.functions if recompiled.full_func_name(f) == name)
    assert signature(original, fa).matches(signature(recompiled, fb))
