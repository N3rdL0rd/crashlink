"""Std abstracts, private std members and abstract statics in a decompiled project:
the project recompiles and behaves like the original."""

import shutil
import subprocess
from pathlib import Path
from typing import Dict

import pytest

from crashlink import Bytecode, project
from crashtest.behavior import resolve_hl_runtime

MODULES: Dict[str, str] = {
    "Main.hx": """
import haxe.Int64;
import pk.Base;
import pk.Point;
import pk.Assert;

@:generic
class Gen {
    @:generic
    static public function each<T, I:Iterator<T>>(itr:I, f:T -> T) {
        for (x in itr) Sys.println(f(x));
    }
}

class Main extends Base {
    static inline function isNull<T>(v:Null<T>):Bool return v == null;

    function run() {
        // `Int64.make` and `.low`/`ushr` are inlined: `Int64.MASK` is private to the abstract.
        var i:Int64 = Int64.make(0xF0E3FF1B, 0x00000000);
        Sys.println(Int64.ushr(i, 32).low);
        // `Rest.append` is a member of a std abstract over a typed array.
        Sys.println(rest(1, 2).join(","));
        // `JsonParser.parse` is inlined: its constructor and `doParse` are private.
        Sys.println(haxe.format.JsonParser.parse('{"a":[1,2]}').a[1]);
        // A local function reaches an inherited method; `super` can't be named there.
        function show(v:Int) greet(v);
        show(3);
        Sys.println(isNull(4));
        Gen.each(0...3, function(x) return x * 2);
        // An `@:op(A += B) set_add` is an operator, not the setter of a property `add`.
        var p = new Point(1, 2);
        p += new Point(3, 4);
        Sys.println(p.x + "," + p.y);
        Sys.println(Assert.CHECK(true));
    }

    static function rest(...r:Int):Array<Int> {
        var appended = r.append(9);
        return appended.toArray();
    }

    static function main() new Main().run();
}
""",
    "pk/Base.hx": """
package pk;
class Base {
    public function new() {}
    public function greet(v:Int) Sys.println("hi " + v);
}
""",
    "pk/Point.hx": """
package pk;
@:forward(x, y)
abstract Point({x:Int, y:Int}) {
    public inline function new(x:Int, y:Int) this = {x: x, y: y};
    @:op(A + B) inline function add(other:Point):Point return new Point(this.x + 2 * other.x, this.y + 2 * other.y);
    @:op(A += B) public inline function set_add(other:Point):Void {
        this.x += other.x;
        this.y += other.y;
    }
}
""",
    "pk/Assert.hx": """
package pk;
@:callable
abstract Assert(Bool->String) {
    public static var CHECK = new Assert();
    function new() this = function(b) return b ? "ok" : "fail";
}
""",
}


def _run(program: Path) -> str:
    runtime = resolve_hl_runtime()
    assert runtime is not None
    result = subprocess.run([runtime, str(program)], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    return result.stdout


@pytest.fixture
def original(tmp_path: Path) -> Path:
    if not shutil.which("haxe") or resolve_hl_runtime() is None:
        pytest.skip("project round trips require Haxe and HashLink")
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


def test_std_abstracts_and_private_std_members_recompile_and_run_the_same(
    original: Path, tmp_path: Path
) -> None:
    files = project.export(Bytecode.from_path(str(original)))
    folder = tmp_path / "project"
    project.write(str(folder), files)
    build = subprocess.run(["haxe", "build.hxml"], cwd=folder, capture_output=True, text=True)
    assert build.returncode == 0, build.stderr + build.stdout
    assert _run(folder / "out.hl") == _run(original)
