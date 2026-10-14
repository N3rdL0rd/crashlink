"""Enum patterns and closure capture contexts: the decompiled source must compile back to the same code."""

import shutil
import subprocess
from pathlib import Path
from typing import Dict, Tuple

import pytest

from crashlink import Bytecode, project
from crashlink.core import Function
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


def _function(code: Bytecode, name: str) -> Function:
    return next(f for f in code.functions if code.full_func_name(f).endswith(name))


def _same_signature(original: Bytecode, recompiled: Bytecode, name: str) -> bool:
    a = signature(original, _function(original, name))
    b = signature(recompiled, _function(recompiled, name))
    assert a and b, (a.reason, b.reason)
    return a.digest == b.digest


def test_enum_parameter_built_from_a_structure_field_keeps_the_array_element_type(tmp_path: Path) -> None:
    # `Album(d.tracks)`: no `alloc_array` builds the array, it comes out of the structure's field,
    # whose element type the other functions' literals give. `Array<Dynamic>` would be an ArrayDyn.
    source = """
private typedef Data = {year:Int, ?tracks:Array<String>, ?side:String}

private enum Kind {
    Album(tracks:Array<String>);
    Single(side:String);
}

class Main {
    static function kind(d:Data):Kind {
        return d.tracks != null ? Album(d.tracks) : Single(d.side);
    }

    static function main() {
        var data:Data = {year: 1967, tracks: ["a", "b"]};
        Sys.println(Std.string(kind(data)));
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert expected == actual
    assert _same_signature(original, recompiled, "Main.kind")
