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
