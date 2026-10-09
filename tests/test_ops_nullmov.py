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


def test_declared_local_assigned_in_both_arms_of_conditional_is_ternary(tmp_path: Path) -> None:
    source = """
class Main {
static function equals(a: Int, b: Int): Bool { return a == b; }
static function test() {
var s: String;
if (equals(1, 1) == true) { s = "1"; } else { s = "2"; }
Sys.println(s);
}
static function main() { test(); }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert actual == expected
    assert _ops(original, "Main.test") == _ops(recompiled, "Main.test")


def test_switch_expression_with_extension_call_is_ternary(tmp_path: Path) -> None:
    source = """
using Main;
class Base {
public function new() {}
function eq<T>(v: T, v2: T, ?pos: haxe.PosInfos) { Sys.println(v == v2); }
function t(v: Bool, ?pos: haxe.PosInfos) { Sys.println(v); }
}
class Main extends Base {
function test() {
t(true);
var s = switch(1) {
case _.equals(1) => true: "1";
case _: "2";
}
eq("1", s);
}
static function equals(i1: Int, i2: Int) { return i1 == i2; }
static function main() { new Main().test(); }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert actual == expected
    assert _ops(original, "Main.test") == _ops(recompiled, "Main.test")
