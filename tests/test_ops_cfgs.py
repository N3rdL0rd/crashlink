"""Control-flow shape: a nested `if` whose else arm is itself a ternary is one ternary, not a nested `if`."""

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


def _function(code: Bytecode, name: str):
    return next(f for f in code.functions if code.full_func_name(f).endswith(name))


def test_null_switch_with_shared_arm_is_a_single_ternary(tmp_path: Path) -> None:
    source = """
class Main {
    static var calls = 0;
    static function getField():Null<Int> {
        calls++;
        return 42;
    }
    static function test():String {
        var s = switch getField() {
            case 42: "yes";
            case _: "no";
        };
        return s;
    }
    static function main() {
        Sys.println(test());
        Sys.println(calls);
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert actual == expected
    body = files["src/Main.hx"].split("function test(", 1)[1].split("function main", 1)[0]
    assert "?" in body and " : " in body
    assert "if (" not in body

    a = signature(original, _function(original, "Main.test"), strict=True)
    b = signature(recompiled, _function(recompiled, "Main.test"), strict=True)
    assert a.matches(b)
