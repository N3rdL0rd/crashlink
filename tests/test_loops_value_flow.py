"""Closures the compiler adapts or captures must decompile into source that compiles and behaves the same."""

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


def roundtrip(tmp_path: Path, source: str) -> Tuple[Dict[str, str], str, str]:
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
    return files, _run(target), _run(folder / "out.hl")


MAIN = """
class Main {
    static inline function log2Unsigned(n:Int):Int {
        var res = 0;
        while ((n >>>= 1) != 0) {
            res++;
        }
        return res;
    }
    static function shifts():Int {
        return log2Unsigned(16);
    }
    static function bound():String {
        var s = "";
        var t = 5;
        for (i in 0...t) {
            s += "," + t--;
        }
        return s;
    }
    static function once():Bool {
        var changed = false;
        do {
            changed = true;
        } while (false);
        return changed;
    }
    static function same(x:Dynamic, y:Dynamic):String {
        return Std.string(Type.typeof(x)) + "/" + Std.string(Type.typeof(y)) + "/" + (x == y);
    }
    static function single():String {
        var a:Single = 1;
        var c = a--;
        return same((0 : Single), a) + " " + same((1 : Single), c);
    }
    static function main() {
        Sys.println(log2Unsigned(16));
        Sys.println(shifts());
        Sys.println(bound());
        Sys.println(once());
        Sys.println(single());
    }
}
"""


def test_loop_value_flow(tmp_path: Path) -> None:
    files, original, recompiled = roundtrip(tmp_path, MAIN)
    assert original == recompiled, files
