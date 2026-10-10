"""A field read through a structure view of a Dynamic value must keep that view on the same receiver."""

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


def test_structure_view_field_read_on_a_dynamic_argument_keeps_the_view(tmp_path: Path) -> None:
    source = """
class Main {
    static function merge(a:Dynamic, b:Dynamic):Dynamic {
        return { foo: (cast a : {foo:Dynamic}).foo, bar: (cast b : {bar:Dynamic}).bar };
    }

    static function main() {
        var a = merge({foo: 5}, {bar: "bar"});
        Sys.println(a.foo);
        Sys.println(a.bar);
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "(cast a : { var foo: Dynamic; }).foo" in files["src/Main.hx"]
    assert actual == expected
    assert _ops(original, "Main.merge") == _ops(recompiled, "Main.merge")
