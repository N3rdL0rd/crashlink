"""Casts to a basic type must keep their run-time conversion (null to zero, failing casts)."""

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


def test_dynamic_cast_to_basic_type_makes_null_zero(tmp_path: Path) -> None:
    source = """
class Main {
    static function getNull<T>():T return null;
    static function main() {
        Sys.println(cast(getNull(), Int));
        Sys.println(cast(getNull(), Float));
        Sys.println(cast(getNull(), Bool));
    }
}
"""
    _, original, decompiled = roundtrip(tmp_path, source)
    assert original == "0\n0\nfalse\n"
    assert decompiled == original


def test_nullable_int_returned_as_int(tmp_path: Path) -> None:
    source = """
class Main {
    static function foo(?e:Int):Null<Float> {
        return (e:Int);
    }
    static function main() {
        Sys.println(foo());
        Sys.println(foo(3));
    }
}
"""
    _, original, decompiled = roundtrip(tmp_path, source)
    assert original == "0\n3\n"
    assert decompiled == original


def test_failing_string_cast_to_int_throws(tmp_path: Path) -> None:
    source = """
class Main {
    static function main() {
        try {
            cast("foo", Int);
            Sys.println("fail");
        } catch (e:Dynamic) {
            Sys.println("threw");
        }
    }
}
"""
    _, original, decompiled = roundtrip(tmp_path, source)
    assert original == "threw\n"
    assert decompiled == original
