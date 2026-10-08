"""Inlined Array.map/filter assign over their source variable; the loop must still walk the source."""

import shutil
import subprocess
from pathlib import Path

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


def test_map_and_filter_assigned_back_to_their_source(tmp_path: Path) -> None:
    source = """
class Main {
    static function add(i:Int, s:String) return i + 1;
    static function main() {
        var arr = [1, 2, 3, 4, 5];
        arr = arr.map(add.bind(_, "test"));
        Sys.println(arr.join(","));
        var v = ["a", null, "", "b"];
        v = v.filter(function(s) return s != null && s != "");
        Sys.println(v.join(","));
    }
}
"""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Main.hx").write_text(source)
    target = tmp_path / "original.hl"
    result = subprocess.run(
        ["haxe", "-cp", str(tmp_path / "src"), "-main", "Main", "-hl", str(target)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    folder = tmp_path / "project"
    project.write(str(folder), project.export(Bytecode.from_path(str(target))))
    result = subprocess.run(["haxe", "build.hxml"], cwd=folder, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    expected = _run(target)
    assert expected == "2,3,4,5,6\na,b\n"
    assert _run(folder / "out.hl") == expected
