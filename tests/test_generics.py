"""Type values and generic std types in decompiled projects recompile and behave the same."""

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


def roundtrip(tmp_path: Path, sources: Dict[str, str]) -> Dict[str, str]:
    """Compile `sources`, export and recompile the project, check both print the same; return the project text."""
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
    folder = tmp_path / "project"
    project.write(str(folder), project.export(Bytecode.from_path(str(original)), stubs=False))
    result = subprocess.run(["haxe", "build.hxml"], cwd=folder, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert _run(folder / "out.hl") == _run(original)
    return {p.name: p.read_text() for p in (folder / "src").rglob("*.hx")}


def test_basic_types_as_values_and_enum_parameters(tmp_path: Path) -> None:
    # `Int` as a value is a runtime type object of HL's one base type class, as is an `Enum<T>`.
    text = roundtrip(
        tmp_path,
        {
            "Main.hx": """
enum Color { Red; Green; }
class Main {
    static function nameOf(e:Enum<Color>):String return Type.getEnumName(e);
    static function main() {
        var t:Dynamic = Int;
        Sys.println(Std.isOfType(3, t));
        Sys.println(Std.isOfType("a", Int));
        Sys.println(Std.isOfType(1.5, Float));
        Sys.println(Std.isOfType(true, Bool));
        Sys.println(nameOf(Color));
    }
}
"""
        },
    )
    assert "hl.BaseType" not in text["Main.hx"]


def test_std_enums_keep_their_type_parameters(tmp_path: Path) -> None:
    roundtrip(
        tmp_path,
        {
            "Main.hx": """
import haxe.ds.Option;
import haxe.ds.Either;
class Main {
    static var cell:Option<Int> = null;
    static function pick(o:Option<String>, e:Either<Int, String>):String {
        var x:Option<String> = o;
        var y:Either<Int, String> = e;
        return Std.string(x) + Std.string(y);
    }
    static function main() {
        Sys.println(pick(Some("a"), Left(1)));
        Sys.println(pick(None, Right("b")));
        Sys.println(cell == null);
    }
}
"""
        },
    )
