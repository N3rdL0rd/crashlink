"""A catch binding is declared by its own clause, so it must not be hoisted over a same-named local of another type."""

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


def test_untyped_catch_does_not_share_a_name_with_a_typed_catch(tmp_path: Path) -> None:
    # The nested typed `catch (e:Stop)` and the outer untyped catch's `e` must not be one variable.
    source = """
enum Stop { A; }

class Main {
    static function foo(o:String) return o.length;

    static function test() {
        try {
            try { foo(null); } catch (e:Stop) {}
            Sys.println("x");
        } catch (e) {
            Sys.println(e.stack.length > 0);
        }
    }

    static function main() {
        test();
    }
}
"""
    _, expected, actual, _, _ = roundtrip(tmp_path, source)
    assert actual == expected
