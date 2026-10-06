"""Expressions the decompiler prints must have the type the bytecode gave them, so the project compiles back."""

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
        ["haxe", "-cp", str(tmp_path / "src"), "-main", "Main", "-hl", str(target)], capture_output=True, text=True
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


def test_static_uint_literal_is_a_valid_int(tmp_path: Path) -> None:
    # A literal above 2^31 is a Float in Haxe source; the static initialiser must write the same 32 bits as an Int.
    modules = {
        "Main.hx": """
class Main {
    static var MASK:UInt = 0x9747b28c;
    static var ALL:UInt = 0xffffffff;
    static function main() {
        Sys.println(MASK == 0x9747b28c);
        Sys.println(ALL > 0);
        Sys.println(ALL);
    }
}
"""
    }
    _, expected, actual = roundtrip(tmp_path, modules)
    assert actual == expected
