"""A field read reached through a local must not be duplicated into each use of that local."""

import shutil
import subprocess
from pathlib import Path

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


def _func(code: Bytecode, name: str):
    return next(f for f in code.functions if code.full_func_name(f).endswith(name))


def test_inlined_method_receiver_read_once_keeps_its_signature(tmp_path: Path) -> None:
    source = """
class Obj {
    public var w:Float;
    public var h:Float;
    public function new(w:Float = 0, h:Float = 0) { this.w = w; this.h = h; }
}

class Node {
    public var obj:Obj;
    public function new() {}
    public inline function canPlace(w:Float, h:Float):Bool {
        return obj.w == w && obj.h == h;
    }
}

class Root {
    public var left:Node;
    public var right:Node;
    public function new() {}
}

class Main {
    static function test(root:Root):Bool {
        return root.left != null && root.left.canPlace(0, 0) && root.right != null && root.right.canPlace(0, 0);
    }

    static function main() {
        var r = new Root();
        r.left = new Node();
        r.left.obj = new Obj();
        Sys.println(test(r));
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
    original = Bytecode.from_path(str(target))
    files = project.export(original)
    folder = tmp_path / "project"
    project.write(str(folder), files)
    result = subprocess.run(["haxe", "build.hxml"], cwd=folder, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    recompiled = Bytecode.from_path(str(folder / "out.hl"))

    assert _run(target) == _run(folder / "out.hl")
    assert signature(original, _func(original, "$Main.test"), strict=True).matches(
        signature(recompiled, _func(recompiled, "$Main.test"), strict=True)
    )
