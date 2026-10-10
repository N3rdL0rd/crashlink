"""A Dynamic value cast to a class or array keeps that type on the receiver of a field or element read."""

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


def _func(code: Bytecode, name: str):  # type: ignore[no-untyped-def]
    return next(f for f in code.functions if code.full_func_name(f).endswith(name))


def test_dynamic_array_cast_receiver_keeps_its_array_type(tmp_path: Path) -> None:
    source = """
class Final {
    public var a2:Dynamic;
    public function new() {}
}

class Main {
    static function main() {
        var data = new Final();
        data.a2 = cast hl.types.ArrayBase.allocI32(new hl.Bytes(0), 0);
        (data.a2 : Array<Int>).push(1);
        Sys.println((data.a2 : Array<Int>)[0]);
        Sys.println((data.a2 : Array<Int>).length);
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "(data.a2 : Array<Int>)[0]" in files["src/Main.hx"]
    assert actual == expected
    assert signature(original, _func(original, "Main.main")) == signature(
        recompiled, _func(recompiled, "Main.main")
    )
