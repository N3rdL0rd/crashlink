"""Anonymous structures: literals that omit fields, aliases, and fields stored one by one."""

import shutil
import subprocess
from pathlib import Path

import pytest

from crashlink import Bytecode, project
from crashtest.behavior import resolve_hl_runtime

MAIN = """
typedef Opts = { ?name:String, ?cb:() -> String, ?items:Array<Int> }
typedef Pair = { key:Int, value:Int }
typedef P = { a:Int }
private abstract A(Int) {}
private abstract B(Int) from Int {}
private abstract C(Int) to Int {}

class Main {
    static var idx = 0;
    static var arr = [10, 20, 30];

    static function pair():Pair return { value: arr[idx], key: idx++ };

    static function describe(o:Opts):String {
        var s = "";
        if (o.name != null) s += o.name;
        if (o.cb != null) s += o.cb();
        if (o.items != null) s += o.items.length;
        return s + "|";
    }

    static function aliased() {
        var x:{a:Int} = {a:9};
        var y:{a:A} = {a:untyped 9};
        var z:{a:B} = {a:untyped 9};
        var w:{a:C} = {a:untyped 9};
        Sys.println(1);
        z = x;
        x = w;
        Sys.println(2);
    }

    static function main() {
        aliased();
        var x:P = { a: 9 };
        var z:P = { a: 1 };
        z = x;
        x = { a: 2 };
        Sys.println(x.a + " " + z.a);
        var o:Opts = {};
        Sys.println(describe(o));
        Sys.println(describe({ name: "n", cb: () -> "c" }));
        var p = pair();
        Sys.println(p.key + " " + p.value + " " + idx);
    }
}
"""


def _run(program: Path) -> str:
    runtime = resolve_hl_runtime()
    assert runtime is not None
    result = subprocess.run([runtime, str(program)], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    return result.stdout


@pytest.fixture
def exported(tmp_path: Path):
    if not shutil.which("haxe") or resolve_hl_runtime() is None:
        pytest.skip("round trips require Haxe and HashLink")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Main.hx").write_text(MAIN)
    original = tmp_path / "original.hl"
    built = subprocess.run(
        ["haxe", "-cp", str(tmp_path / "src"), "-main", "Main", "-hl", str(original)],
        capture_output=True,
        text=True,
    )
    assert built.returncode == 0, built.stderr
    folder = tmp_path / "project"
    project.write(str(folder), project.export(Bytecode.from_path(str(original))))
    result = subprocess.run(["haxe", "build.hxml"], cwd=folder, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return original, folder


def test_structure_literals_recompile_and_behave_the_same(exported) -> None:
    original, folder = exported
    # A copy of the object that compiled to the same register does not keep its literal from folding.
    text = (folder / "src" / "Main.hx").read_text()
    start = text.index("function aliased")
    aliased = text[start : text.index("function ", start + 1)]
    assert "cast {}" not in aliased
    assert _run(folder / "out.hl") == _run(original)
