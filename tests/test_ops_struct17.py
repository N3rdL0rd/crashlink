"""A position the callee reads is written out once, at its use, so it stays a typed structure."""

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


def _roundtrip(tmp_path: Path, source: str, prepared: bool = False) -> Tuple[str, Bytecode, Bytecode]:
    (tmp_path / "src").mkdir(exist_ok=prepared)
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
    return files["src/Main.hx"], Bytecode.from_path(str(target)), Bytecode.from_path(str(folder / "out.hl"))


def _same(original: Bytecode, recompiled: Bytecode, name: str) -> bool:
    left = next(f for f in original.functions if original.full_func_name(f) == name)
    right = next(f for f in recompiled.functions if recompiled.full_func_name(f) == name)
    return signature(original, left).matches(signature(recompiled, right))


def test_position_in_a_try_that_catches_dynamic(tmp_path: Path) -> None:
    source = """
class Main {
    static var tmp:String;
    static var last:haxe.PosInfos;
    static function pass(?pos:haxe.PosInfos) { last = pos; }
    static function fail(m:String, ?pos:haxe.PosInfos) { Sys.println(m + pos.lineNumber); }
    static function main() {
        var o = {rec:(null:Dynamic)};
        o.rec = o;
        try {
            tmp = Std.string(o);
            pass();
        } catch (e:Dynamic) {
            fail("bad " + e);
        }
    }
}
"""
    text, original, recompiled = _roundtrip(tmp_path, source)
    assert "Dynamic = {" not in text  # the position is not parked in the catch variable
    assert _same(original, recompiled, "$Main.main")


def test_position_read_after_a_computed_argument(tmp_path: Path) -> None:
    source = """
class Main {
    static function chk(v:Bool, ?pos:haxe.PosInfos) { Sys.println(v && pos.lineNumber > 0); }
    @:pure(false) static function foo(o:String) return o.length;
    static function main() {
        try {
            foo(null);
        } catch (e:Dynamic) {
            chk(Std.random(3) > 0);
        }
    }
}
"""
    text, original, recompiled = _roundtrip(tmp_path, source)
    assert _same(original, recompiled, "$Main.main")


def test_recursive_structure_keeps_its_own_type(tmp_path: Path) -> None:
    source = """
private typedef A = {f: A}
class Main {
    static function main() {
        var n:A = {f: null};
        do n = n.f while (n != null && (n != null || n != null));
        Sys.println(n == null);
    }
}
"""
    _text, original, recompiled = _roundtrip(tmp_path, source)
    assert _same(original, recompiled, "$Main.main")


def test_integer_text_in_a_catch_handler_folds_back(tmp_path: Path) -> None:
    source = """
class Main {
    static function throwInt(i:Int) {
        return try {
            throw i;
        } catch (i:Int) {
            "ok:" + i;
        }
    }
    static function main() {
        Sys.println(throwInt(12));
    }
}
"""
    text, original, recompiled = _roundtrip(tmp_path, source)
    assert "__alloc__" not in text
    assert _same(original, recompiled, "$Main.throwInt")


def test_recursive_structure_naming_a_private_type_still_compiles(tmp_path: Path) -> None:
    (tmp_path / "src" / "p").mkdir(parents=True)
    (tmp_path / "src" / "p" / "Holder.hx").write_text(
        """package p;

private class C implements I {
    public var v(get, never):String;
    function get_v():String return "";
    public function new() {}
    public function f(i:I) {
        Sys.println(i.v);
    }
}

private interface I {
    var v(get, never):String;
    function f(i:I):Void;
}

class Holder {
    public static function run() {
        var c = new C();
        c.f(c);
    }
}
"""
    )
    _roundtrip(tmp_path, "class Main { static function main() { p.Holder.run(); } }", prepared=True)
