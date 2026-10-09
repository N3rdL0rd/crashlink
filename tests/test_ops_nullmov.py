"""`a ?? b` lowered to an if/else writing one local decompiles to `??` and recompiles to the same ops."""

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


def test_null_coalesce_chain_on_nullable_fields_keeps_ops(tmp_path: Path) -> None:
    source = """
class Main {
var s1: Null<Int> = null;
var s2: Null<Int> = null;
public function new() {}
function test() {
var r: Int = s1 ?? s2 ?? 1;
Sys.println(r);
}
static function main() { new Main().test(); }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert actual == expected
    assert _ops(original, "Main.test") == _ops(recompiled, "Main.test")


def test_null_match_with_cast_on_tested_value_is_not_coalesce(tmp_path: Path) -> None:
    source = """
class Main {
static function f(v: Null<Float>): Null<Int> {
var r: Null<Int> = v == null ? null : Std.int(v);
return r;
}
static function main() {
Sys.println(f(2.5));
Sys.println(f(null));
}
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert actual == expected
    assert _ops(original, "Main.f") == _ops(recompiled, "Main.f")
