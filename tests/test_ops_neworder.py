"""Reads through Dynamic keep their Dynamic receiver so the compiler emits the same DynGet and casts."""

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


def test_a_dynamic_field_of_an_anonymous_structure_reads_through_dynamic(tmp_path: Path) -> None:
    # `var url:Dynamic = {query: s}` reads `query` with a DynGet; a typed anonymous read would be folded.
    source = """
class Main {
    static function main() {
        var s:String = null;
        var url:Dynamic = { query: s };
        t(url.query == null);
    }
    static function t(b:Bool) Sys.println(b);
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "(url : Dynamic).query" in files["src/Main.hx"]
    assert actual == expected
    assert _ops(original, "Main.main") == _ops(recompiled, "Main.main")


def test_an_unchecked_read_of_a_dynamic_string_field_keeps_its_cast(tmp_path: Path) -> None:
    # A Dynamic<String> read typed String is an UnsafeCast of the DynGet; a plain Dynamic read is not.
    source = """
class Main {
    static function eq<T>(a:T, b:T) Sys.println(a == b);
    static function main() {
        var s:String = null;
        var url:{ query:String } = { query: s };
        var c:Dynamic<String> = url;
        Sys.println(c.query == null);
        eq("foo", c.query);
        var d:Dynamic = url;
        eq("foo", d.query);
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "(url : Dynamic<String>).query" in files["src/Main.hx"]
    assert actual == expected
    assert _ops(original, "Main.main") == _ops(recompiled, "Main.main")
