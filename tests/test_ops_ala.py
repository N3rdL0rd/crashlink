"""An array of arrays must be ascribed its inner element type so Haxe allocates the same array classes."""

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


def _digest(code: Bytecode, name: str) -> str:
    func = next(f for f in code.functions if code.full_func_name(f).endswith(name))
    result = signature(code, func)
    assert result, result.reason
    assert result.digest is not None
    return result.digest


def test_nested_array_literal_is_ascribed_its_inner_element_type(tmp_path: Path) -> None:
    source = """
class Main {
    static function main() {
        var a = [["a"], ["b"]];
        var x = a.shift();
        a[0].push(x[0]);
        Sys.println(a[0].join("") + Sys.args().length);
    }
}
"""
    files, expected, actual, _, _ = roundtrip(tmp_path, source)
    assert '([["a"], ["b"]] : Array<Array<String>>)' in files["src/Main.hx"]
    assert actual == expected
