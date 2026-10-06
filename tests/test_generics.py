"""Type values and generic std types in decompiled projects recompile and behave the same."""

import shutil
import subprocess
from pathlib import Path
from typing import Dict

import pytest

from crashlink import Bytecode, project
from crashtest.behavior import resolve_hl_runtime


def _run(program: Path) -> str:
    runtime = resolve_hl_runtime()
    assert runtime is not None
    result = subprocess.run([runtime, str(program)], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    return result.stdout


def roundtrip(tmp_path: Path, sources: Dict[str, str]) -> Dict[str, str]:
    """Compile `sources`, export and recompile the project, check both print the same; return the project text."""
    if not shutil.which("haxe") or resolve_hl_runtime() is None:
        pytest.skip("project round trips require Haxe and HashLink")
    for name, source in sources.items():
        (tmp_path / "src" / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "src" / name).write_text(source)
    original = tmp_path / "original.hl"
    result = subprocess.run(
        ["haxe", "-cp", str(tmp_path / "src"), "-main", "Main", "-hl", str(original)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    folder = tmp_path / "project"
    project.write(str(folder), project.export(Bytecode.from_path(str(original)), stubs=False))
    result = subprocess.run(["haxe", "build.hxml"], cwd=folder, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert _run(folder / "out.hl") == _run(original)
    return {p.name: p.read_text() for p in (folder / "src").rglob("*.hx")}


def test_basic_types_as_values_and_enum_parameters(tmp_path: Path) -> None:
    # `Int` as a value is a runtime type object of HL's one base type class, as is an `Enum<T>`.
    text = roundtrip(
        tmp_path,
        {
            "Main.hx": """
enum Color { Red; Green; }
class Main {
    static function nameOf(e:Enum<Color>):String return Type.getEnumName(e);
    static function main() {
        var t:Dynamic = Int;
        Sys.println(Std.isOfType(3, t));
        Sys.println(Std.isOfType("a", Int));
        Sys.println(Std.isOfType(1.5, Float));
        Sys.println(Std.isOfType(true, Bool));
        Sys.println(nameOf(Color));
    }
}
"""
        },
    )
    assert "hl.BaseType" not in text["Main.hx"]


def test_std_enums_keep_their_type_parameters(tmp_path: Path) -> None:
    roundtrip(
        tmp_path,
        {
            "Main.hx": """
import haxe.ds.Option;
import haxe.ds.Either;
class Main {
    static var cell:Option<Int> = null;
    static function pick(o:Option<String>, e:Either<Int, String>):String {
        var x:Option<String> = o;
        var y:Either<Int, String> = e;
        return Std.string(x) + Std.string(y);
    }
    static function main() {
        Sys.println(pick(Some("a"), Left(1)));
        Sys.println(pick(None, Right("b")));
        Sys.println(cell == null);
    }
}
"""
        },
    )


def test_get_and_set_calls_on_non_arrays_stay_calls(tmp_path: Path) -> None:
    # `get`/`set` collapse to `[]` only on HL arrays; a map or a class with its own `set` keeps the call.
    text = roundtrip(
        tmp_path,
        {
            "Main.hx": """
class Pair {
    public var a:Int;
    public var b:Int;
    public function new() { a = 1; b = 2; }
    public inline function set(x:Int, y:Int) { a = x; b = y; }
}
class Store {
    var items:Map<String, Int> = new Map();
    public function new() { items.set("k", 5); }
    @:generic public function get<T:Int>(key:Class<T>):Int return cast items.get(Reflect.field(key, "NAME"));
    public function at(key:String):Int return items.get(key);
}
class Main {
    static function main() {
        var p = new Pair();
        p.set(7, 8);
        Sys.println(p.a + p.b);
        var s = new Store();
        Sys.println(s.at("k"));
        var arr = [1, 2, 3];
        arr[1] = arr[2] + 1;
        Sys.println(arr);
    }
}
"""
        },
    )
    assert "this[" not in text["Main.hx"]


def test_string_code_unit_read_is_not_element_access(tmp_path: Path) -> None:
    text = roundtrip(
        tmp_path,
        {
            "Main.hx": """
class Main {
    static function count(s:String):Int {
        var n = 0;
        for (c in new haxe.iterators.StringIteratorUnicode(s)) if (c >= 65536) n++;
        return n;
    }
    static function main() {
        Sys.println(count("a\\u{1F600}b"));
        var f = function() (for (c in inline new haxe.iterators.StringIteratorUnicode("")) {});
        f();
    }
}
"""
        },
    )
