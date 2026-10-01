"""A whole image exports as a Haxe project that compiles back and behaves the same."""

import shutil
import subprocess
from pathlib import Path
from typing import Dict

import pytest

from crashlink import Bytecode, project
from crashtest.behavior import resolve_hl_runtime

MODULES: Dict[str, str] = {
    "Main.hx": """
import pk.Mod;
class Main {
    static function main() {
        var s:pk.Mod.Shape = new Mod(2);
        Sys.println(s.area() + Mod.make().n + Mod.secret());
        Sys.println(pk.Mod.Color.Green(4));
        var m = new pk.Meter(1.5);
        Sys.println(m.twice());
        Sys.println(new pk.Array.Pool().size() + new pk.Array(4).get());
    }
}
""",
    "pk/Mod.hx": """
package pk;
interface Shape { function area():Float; }
class Mod implements Shape {
    var k:Int;
    public function new(k:Int) { this.k = k; }
    public function area() return 2.0 * k;
    public static function make():Helper return new Helper(3);
    public static function secret():Int return new Hidden().v;
}
class Helper { public var n:Int; public function new(n) this.n = n; }
private class Hidden { public var v = 7; public function new() {} }
enum Color { Red; Green(v:Int); }
""",
    "pk/Meter.hx": """
package pk;
abstract Meter(Float) {
    public function new(v:Float) this = v;
    public function twice():Float return this * 2;
}
""",
    "pk/Array.hx": """
package pk;
abstract Array(Int) {
    public function new(v:Int) this = v;
    public function get():Int return this;
}
class Pool {
    var items:std.Array<Int> = [1, 2, 3];
    public function new() {}
    public function size():Int return items.length;
}
""",
}


def _run(program: Path) -> str:
    runtime = resolve_hl_runtime()
    assert runtime is not None
    result = subprocess.run([runtime, str(program)], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    return result.stdout


def _build(tmp_path: Path) -> Path:
    for name, source in MODULES.items():
        (tmp_path / "src" / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "src" / name).write_text(source)
    target = tmp_path / "original.hl"
    result = subprocess.run(
        ["haxe", "-cp", str(tmp_path / "src"), "-main", "Main", "-hl", str(target)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return target


def _export(original: Path, folder: Path, stubs: bool) -> Path:
    files = project.export(Bytecode.from_path(str(original)), stubs=stubs)
    project.write(str(folder), files)
    result = subprocess.run(["haxe", "build.hxml"], cwd=folder, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return folder / "out.hl"


@pytest.fixture
def original(tmp_path: Path) -> Path:
    if not shutil.which("haxe") or resolve_hl_runtime() is None:
        pytest.skip("project round trips require Haxe and HashLink")
    return _build(tmp_path)


def test_project_recompiles_and_runs_the_same(original: Path, tmp_path: Path) -> None:
    recompiled = _export(original, tmp_path / "project", stubs=False)
    src = tmp_path / "project" / "src"
    module = (src / "pk" / "Mod.hx").read_text()
    # Types declared in another type's module stay there; references go through it.
    assert "class Mod implements pk.Shape {" in module
    assert "class Helper {" in module
    assert "private class Hidden {" in module
    assert "make(): pk.Mod.Helper" in module
    # An interface has no code to place it by: it gets a module of its own.
    assert "interface Shape {" in (src / "pk" / "Shape.hx").read_text()
    assert "abstract Meter(Float)" in (src / "pk" / "Meter.hx").read_text()
    # The package's own `Array` shadows the std one, which is named `std.Array` there.
    assert "std.Array<Int>" in (src / "pk" / "Array.hx").read_text()
    assert _run(recompiled) == _run(original)


def test_stubbed_project_compiles(original: Path, tmp_path: Path) -> None:
    _export(original, tmp_path / "stubbed", stubs=True)
