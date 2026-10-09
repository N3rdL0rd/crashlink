"""The compiler fills in a `?pos:haxe.PosInfos` argument; the decompiler leaves it out, keeping the position as a comment."""

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


def _ops(code: Bytecode, name: str) -> list:
    func = next(f for f in code.functions if code.full_func_name(f).endswith(name))
    return [str(op.op) for op in func.ops]


def test_unread_position_is_left_out_and_kept_as_a_comment(tmp_path: Path) -> None:
    source = """
class Main {
    static function note(v:Int, ?pos:haxe.PosInfos) {
        Sys.println(v);
    }
    static function relay(v:Int, ?pos:haxe.PosInfos) {
        note(v, pos);
    }
    static function main() {
        note(1);
        relay(2);
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    text = files["src/Main.hx"]
    assert "?pos: haxe.PosInfos" in text
    assert "fileName" not in text and "/* pos: Main.hx:" in text
    assert actual == expected
    # Without the literal the compiler builds the position the way it did originally.
    assert _ops(original, "Main.main") == _ops(recompiled, "Main.main")


def test_a_position_that_is_read_stays_a_literal(tmp_path: Path) -> None:
    # The recompiled source has its own layout: eliding a position the program prints would change its output.
    source = """
class Main {
    static function where(?pos:haxe.PosInfos) {
        Sys.println(pos.lineNumber + ":" + pos.methodName);
    }
    static function main() {
        where();
        where();
    }
}
"""
    files, expected, actual, _, _ = roundtrip(tmp_path, source)
    assert "fileName" in files["src/Main.hx"]
    assert actual == expected


def test_position_of_a_function_type_is_optional(tmp_path: Path) -> None:
    source = """
class Main {
    static function main() {
        final show = (v:Int, ?pos:haxe.PosInfos) -> Sys.println(v);
        show(1);
        show(2);
    }
}
"""
    files, expected, actual, _, _ = roundtrip(tmp_path, source)
    assert actual == expected
