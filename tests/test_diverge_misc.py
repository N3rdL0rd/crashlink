"""Decompiled programs that compiled but behaved differently: each case compares the output of both."""

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


def test_method_called_on_a_concatenation_keeps_its_receiver(tmp_path: Path) -> None:
    # `("bla" + "x").indexOf("x")` must not become `"bla" + "x".indexOf("x")`.
    source = """
class Main {
    static function main() {
        var a = "bla";
        Sys.println((a + "x").indexOf("x"));
        Sys.println((a + a).toUpperCase());
        Sys.println((a == "bla" ? a : "z").length);
    }
}
"""
    files, expected, actual = roundtrip(tmp_path, source)
    assert actual == expected


def test_number_to_string_conversions_sharing_a_length_cell(tmp_path: Path) -> None:
    # HL converts a number with `itos`/`ftos`, which write the length into a cell the compiler shares
    # between conversions and reuses as the input; reading it back as a plain local yields a wrong length.
    source = """
class P {
    public var x:Float;
    public function new(x:Float) this.x = x;
    public function toString() return "(" + x + "," + x + ")";
}
class Main {
    static function main() {
        var t = 5;
        var s = "";
        for (i in 0...3) {
            s += "," + t--;
        }
        Sys.println(s);
        Sys.println(new P(1.5).toString());
    }
}
"""
    files, expected, actual = roundtrip(tmp_path, source)
    assert "__alloc__" not in files["src/Main.hx"]
    assert actual == expected


def test_value_thrown_from_a_try_keeps_its_definition(tmp_path: Path) -> None:
    # `a` is read by the `throw` and again after it; folding the constant into one use must not drop `a`.
    source = """
class Main {
    static function main() {
        var a = "hello";
        try {
            throw a;
        } catch (e:String) {
            Sys.println(e + a);
        }
    }
}
"""
    files, expected, actual = roundtrip(tmp_path, source)
    assert actual == expected == "hellohello\n"
