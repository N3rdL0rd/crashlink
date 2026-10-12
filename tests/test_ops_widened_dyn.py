"""A value stored in a Dynamic variable and cast back out keeps its checked cast."""

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


def test_string_held_as_any_and_cast_back_keeps_its_variable(tmp_path: Path) -> None:
    source = """
class Main {
    static function eq(expected:Dynamic, actual:Dynamic) { Sys.println(expected == actual); }
    static function main() {
        var a:Array<Any> = [1, false, "hey", {}];
        eq("hey", (a[2] : String));
    }
}
"""
    _text, original, recompiled = _roundtrip(tmp_path, source)
    name = "$Main.main"
    left = next(f for f in original.functions if original.full_func_name(f) == name)
    right = next(f for f in recompiled.functions if recompiled.full_func_name(f) == name)
    assert signature(original, left).matches(signature(recompiled, right))


def test_cast_to_an_interface_is_written_as_a_cast(tmp_path: Path) -> None:
    source = """
interface Shape { }
class Main {
    static function id(v:Dynamic):Dynamic return v;
    static function eq(a:Dynamic, b:Dynamic) { Sys.println(a == b); }
    static function main() {
        eq(null, cast(id(null), Shape));
    }
}
"""
    text, original, recompiled = _roundtrip(tmp_path, source)
    assert "Cast error" not in text
    name = "$Main.main"
    left = next(f for f in original.functions if original.full_func_name(f) == name)
    right = next(f for f in recompiled.functions if recompiled.full_func_name(f) == name)
    assert signature(original, left).matches(signature(recompiled, right))
