"""Enum parameter reads behind casts decompile to the switch patterns the compiler saw."""

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


def test_cast_enum_parameter_read_is_bound_by_a_pattern(tmp_path: Path) -> None:
    source = """
class Main {
    static function check(o:Outcome<Int,String>):Int {
        switch (o) {
            case Success(v):
                var n:Int = v;
                return n;
            default:
                return 0;
        }
    }
    static function main() {
        Sys.println(check(Success(5)));
        Sys.println(check(Failure("x")));
    }
}
private enum Outcome<D,F> {
    Success(data:D);
    Failure(error:F);
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "Type.enumParameters" not in files["src/Main.hx"]
    assert actual == expected
    assert _ops(original, "Main.check") == _ops(recompiled, "Main.check")


def test_multi_parameter_enum_reads_share_one_pattern(tmp_path: Path) -> None:
    source = """
class Main {
    static function sum(p:Pair<Int,String>):Int {
        switch (p) {
            case Two(a, b):
                var x:Int = a;
                var y:String = b;
                return x + y.length;
            case One(a):
                var x:Int = a;
                return x;
            default:
                return 0;
        }
    }
    static function main() {
        Sys.println(sum(Two(3, "four")));
        Sys.println(sum(One(9)));
    }
}
private enum Pair<A,B> {
    Two(a:A, b:B);
    One(a:A);
}
"""
    files, expected, actual, _, _ = roundtrip(tmp_path, source)
    text = files["src/Main.hx"]
    assert "Type.enumParameters" not in text
    assert "switch (" in text
    assert actual == expected
