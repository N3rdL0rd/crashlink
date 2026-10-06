"""Decompiled output of assorted one-off shapes recompiles and behaves the same."""

import shutil
import subprocess
from pathlib import Path
from typing import Dict

import pytest

from crashlink import Bytecode, project
from crashtest.behavior import resolve_hl_runtime


def _run(program: Path) -> str:
    runtime = resolve_hl_runtime()
    assert runtime is not None
    result = subprocess.run([runtime, str(program)], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    return result.stdout


def _round_trip(tmp_path: Path, sources: Dict[str, str]) -> Dict[str, str]:
    """Compile `sources`, export the image, recompile it and compare behaviour; return the files."""
    if not shutil.which("haxe") or resolve_hl_runtime() is None:
        pytest.skip("project round trips require Haxe and HashLink")
    for name, source in sources.items():
        (tmp_path / "src" / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "src" / name).write_text(source)
    original = tmp_path / "original.hl"
    result = subprocess.run(
        ["haxe", "-cp", str(tmp_path / "src"), "-main", "Main", "-hl", str(original)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    files = project.export(Bytecode.from_path(str(original)))
    folder = tmp_path / "project"
    project.write(str(folder), files)
    result = subprocess.run(["haxe", "build.hxml"], cwd=folder, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert _run(folder / "out.hl") == _run(original)
    return files


def test_lambda_callee_is_parenthesised(tmp_path: Path) -> None:
    files = _round_trip(
        tmp_path,
        {
            "Main.hx": """
class Main {
    static function main() {
        var data:Dynamic<() -> String> = {test: () -> "test"};
        Sys.println(data.test());
    }
}
"""
        },
    )
    assert '(() -> "test")()' in files["src/Main.hx"]


def test_interface_conversion_cache_slot_is_not_exposed(tmp_path: Path) -> None:
    files = _round_trip(
        tmp_path,
        {
            "Main.hx": """
interface Foo<T> { function whatever<X>():Int; }
interface I2 {}
class T implements Foo<Dynamic> implements I2 {
    public function new() {}
    public function whatever<X>():Int return 42;
}
class Main {
    static function discard(v:T) { cast(v, I2); }
    static function main() {
        var r = new T();
        Sys.println(r.whatever());
        var r:Foo<Dynamic> = new T();
        Sys.println(r.whatever());
        discard(r == null ? null : new T());
    }
}
"""
        },
    )
    assert "__hidden" not in files["src/Main.hx"]


def test_trace_lambda_passed_as_adapted_callback(tmp_path: Path) -> None:
    files = _round_trip(
        tmp_path,
        {
            "Main.hx": """
class Base {}
class Sprite extends Base { public function new() {} }
class Main {
    static function each<T:Base>(l:Array<T>, f:T->Void) {}
    static function main() {
        each([new Sprite()], sprite -> trace(sprite));
        Sys.println("done");
    }
}
"""
        },
    )
    # A position comment inside a one-line lambda would swallow the rest of the line.
    assert "// {" not in "".join(line for line in files["src/Main.hx"].splitlines() if "->" in line)
