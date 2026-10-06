"""Typed catch clauses, primitive/enum catches and `super` in lambdas survive a project round trip."""

import shutil
import subprocess
from pathlib import Path

import pytest

from crashlink import Bytecode, project
from crashtest.behavior import resolve_hl_runtime

SOURCE = """
private class A { public function new() {} }
private class B extends A {}
enum Dummy { DummyCtor; Other(v:Int); }

class Base {
    public function new() {}
    public function hello(x:Int):String return "base" + x;
}

class Main extends Base {
    // Subclass order differs from the order the wrapped-value dispatch reloads the payload in.
    static function classes(a:A):String {
        try {
            throw a;
        } catch (b:B) {
            return "first";
        } catch (a:A) {
            return "second";
        }
    }

    static function prims(v:Dynamic):String {
        try {
            throw v;
        } catch (i:Int) {
            return "int" + i;
        } catch (b:Bool) {
            return "bool" + b;
        } catch (e:Dynamic) {
            return "dyn";
        }
    }

    static function enums(v:Dynamic):String {
        try {
            throw v;
        } catch (d:Dummy) {
            return "dummy";
        } catch (s:String) {
            return "string " + s;
        }
    }

    static function swallow(v:Dynamic):String {
        var r = "ran";
        try {
            throw v;
        } catch (b:B) {
        } catch (a:A) {
        } catch (e:Dynamic) {
        }
        return r;
    }

    function viaLambda():String {
        var f = function(x:Int) return hello(x);
        return f(3);
    }

    static function main() {
        Sys.println(classes(new B()));
        Sys.println(classes(new A()));
        Sys.println(prims(1));
        Sys.println(prims(true));
        Sys.println(prims("x"));
        Sys.println(enums(DummyCtor));
        Sys.println(enums("s"));
        Sys.println(swallow(new B()));
        Sys.println(swallow(5));
        Sys.println(new Main().viaLambda());
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
def original(tmp_path: Path) -> Path:
    if not shutil.which("haxe") or resolve_hl_runtime() is None:
        pytest.skip("round trips require Haxe and HashLink")
    src = tmp_path / "src"
    src.mkdir()
    (src / "Main.hx").write_text(SOURCE)
    target = tmp_path / "original.hl"
    result = subprocess.run(
        ["haxe", "-cp", str(src), "-main", "Main", "-hl", str(target)], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    return target


def test_typed_catches_recompile_and_behave_the_same(original: Path, tmp_path: Path) -> None:
    folder = tmp_path / "project"
    project.write(str(folder), project.export(Bytecode.from_path(str(original)), stubs=False))
    build = subprocess.run(["haxe", "build.hxml"], cwd=folder, capture_output=True, text=True)
    assert build.returncode == 0, build.stderr
    assert _run(folder / "out.hl") == _run(original)
    text = (folder / "src" / "Main.hx").read_text()
    # Recovered as real catch clauses, not the HL dispatch chain.
    assert "catch (" in text and ":Int)" in text and ":Bool)" in text and ":Dynamic)" in text
    assert "hl.BaseType" not in text
    assert "super.hello" not in text.split("viaLambda")[1]
