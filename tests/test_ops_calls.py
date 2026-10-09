"""Enum parameter reads and closure capture contexts decompile to the source the compiler saw."""

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


def test_closure_capture_context_is_not_rebuilt(tmp_path: Path) -> None:
    source = """
class Main {
    var tag = "t";
    function new() {}
    function show(v:Int) {
        Sys.println(tag + v);
    }
    function run(n:Int, word:String) {
        var f = () -> show(n + word.length);
        f();
    }
    static function main() {
        new Main().run(2, "abc");
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "__ClosureCtx" not in files["src/Main.hx"].split("class Main", 1)[1]
    assert actual == expected
    assert _ops(original, "Main.run") == _ops(recompiled, "Main.run")


def test_single_constructor_enum_parameter_is_read_by_a_pattern(tmp_path: Path) -> None:
    source = """
enum Box {
    Wrap(label:String);
}

class Main {
    static function label(b:Box) {
        return switch (b) {
            case Wrap(l): l;
        }
    }
    static function main() {
        Sys.println(label(Wrap("x")));
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "Type.enumParameters" not in files["src/Main.hx"]
    assert actual == expected
    assert _ops(original, "Main.label") == _ops(recompiled, "Main.label")
