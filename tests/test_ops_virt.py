"""The decompiled source makes the compiler emit the same array reads, casts and virtual wrappers."""

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


def test_an_array_popped_into_a_typed_enum_is_declared_with_that_element_type(tmp_path: Path) -> None:
    # `arr.pop()` is Dynamic; only the cast to Foo says the array holds Foos, so the parameter must be
    # declared `Array<Foo>` for the recompiled `arr.pop()` to read through the typed storage.
    source = """
enum Foo {
    FooRec(foo:Foo);
}
class Main {
    static function blowUp(arr:Array<Foo>) {
        var qp = FooRec(arr.pop());
        while (arr.length > 0) {
            qp = FooRec(qp);
        }
    }
    static function main() {
        blowUp([]);
        Sys.println("done");
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert actual == expected
    assert _ops(original, "Main.blowUp") == _ops(recompiled, "Main.blowUp")
    assert _ops(original, "Main.main") == _ops(recompiled, "Main.main")
