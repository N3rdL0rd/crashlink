"""Constants, temporaries and arithmetic: the decompiled source must compile back to the same opcodes."""

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


def test_call_in_loop_condition_stays_in_the_condition(tmp_path: Path) -> None:
    # A temp assigned from a call and tested at the loop head folds back into `while (cond)`;
    # `while (true) { tmp = call(); if (!cond(tmp)) break; ... }` compiles to a different opcode sequence.
    source = """
class Main {
    static function main() {
        var n = 0;
        while (Math.random() > 2.0) {
            n++;
        }
        Sys.println(n);
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "while (true)" not in files["src/Main.hx"]
    assert actual == expected
    assert _ops(original, "Main.main") == _ops(recompiled, "Main.main")


def test_element_increment_stays_an_increment(tmp_path: Path) -> None:
    # `a[i]++` is read, Incr, write; `a[i] = a[i] + 1` compiles to a different opcode sequence.
    source = """
class Main {
    static function main() {
        var a = [1, 2, 3];
        var i = 1;
        a[i]++;
        a[2]--;
        Sys.println(a.join(","));
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "a[1] = a[1] + 1" not in files["src/Main.hx"]
    assert actual == expected
    assert _ops(original, "Main.main") == _ops(recompiled, "Main.main")


def test_captured_assigned_variable_is_not_written_as_its_box(tmp_path: Path) -> None:
    # The compiler boxes a captured variable that is assigned; source wrote a plain variable.
    source = """
class Main {
    static function main() {
        var n = 1;
        n++;
        var f = () -> Sys.println(n);
        n += 2;
        f();
        var s = "a";
        var g = () -> Sys.println(s);
        s = "b";
        g();
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "[0]" not in files["src/Main.hx"]
    assert actual == expected
    assert _ops(original, "Main.main") == _ops(recompiled, "Main.main")
