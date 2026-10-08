"""Static field initialisers (boxed numbers, closures, structs, mixed arrays, class references) must be recovered."""

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


def test_static_initialisers_are_recovered(tmp_path: Path) -> None:
    source = """
class Other {}
class Holder {
    public static var arr:Array<Dynamic> = [0, "Hello", " World", 0.4];
    public static var a:Null<Int> = 1;
    public static var b:Null<Int> = 2;
    public static var fl:Null<Float> = 100;
    public static var nul:Null<Float> = null;
    public static var fn:Dynamic = function(a:Int, b:Int, c:Int) return a + b + c;
    public static var consts = {friction: 0.5, name: "x"};
    public static var opt:{?opt:Bool} = {opt: true};
    public static var classes:Array<Dynamic> = [null, Other];
}
class Main {
    static function main() {
        Sys.println(Holder.arr[1] + Holder.arr[2]);
        Sys.println(Holder.arr[3]);
        Sys.println(Holder.a / Holder.b);
        Sys.println(Holder.fl);
        Sys.println(Holder.nul == null);
        Sys.println(Holder.fn(1, 2, 3));
        Sys.println(Holder.consts.friction + Holder.consts.name);
        Sys.println(Holder.opt.opt);
        Sys.println(Holder.classes[0] == null && Holder.classes[1] == Other);
    }
}
"""
    files, expected, actual = roundtrip(tmp_path, source)
    assert "initializer not recovered" not in files["src/Main.hx"]
    assert actual == expected
