"""`a[pos++]` keeps the receiver's null check ahead of the increment."""

import shutil
import subprocess
from pathlib import Path
from typing import Tuple

import pytest

from crashlink import Bytecode, project
from crashlink.equivalence import signature
from crashtest.behavior import resolve_hl_runtime


@pytest.fixture(autouse=True)
def _tools() -> None:
    if not shutil.which("haxe") or resolve_hl_runtime() is None:
        pytest.skip("project round trips require Haxe and HashLink")


def _roundtrip(tmp_path: Path, source: str) -> Tuple[str, Bytecode, Bytecode]:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Main.hx").write_text(source)
    target = tmp_path / "original.hl"
    result = subprocess.run(
        ["haxe", "-cp", str(tmp_path / "src"), "-main", "Main", "-hl", str(target)], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    files = project.export(Bytecode.from_path(str(target)))
    folder = tmp_path / "project"
    project.write(str(folder), files)
    result = subprocess.run(["haxe", "build.hxml"], cwd=folder, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return files["src/Main.hx"], Bytecode.from_path(str(target)), Bytecode.from_path(str(folder / "out.hl"))


def _function(code: Bytecode, name: str):  # type: ignore[no-untyped-def]
    return next(f for f in code.functions if code.full_func_name(f) == name)


def test_element_read_with_post_increment_index_keeps_its_order(tmp_path: Path) -> None:
    source = """
class Cursor {
    var items:Array<Int>;
    var pos:Int;
    public function new(items:Array<Int>) { this.items = items; pos = 0; }
    public function next():Int { return items[pos++]; }
}
class Main {
    static function main() {
        var c = new Cursor([4, 5, 6]);
        Sys.println(c.next() + c.next() * 10);
    }
}
"""
    text, original, recompiled = _roundtrip(tmp_path, source)
    assert "pos++" in text
    assert signature(original, _function(original, "Cursor.next")).matches(
        signature(recompiled, _function(recompiled, "Cursor.next"))
    )
