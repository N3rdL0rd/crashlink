"""Erased generic arguments of std maps/lists and method type variables: the decompiled source must
compile back to the same casts (unchecked where the compiler made them so)."""

import shutil
import subprocess
from pathlib import Path
from typing import Dict, Tuple

import pytest

from crashlink import Bytecode, project
from crashlink.core import Function
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


def roundtrip(tmp_path: Path, source: str) -> Tuple[Dict[str, str], str, str, Bytecode, Bytecode]:
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
    return (
        files,
        _run(target),
        _run(folder / "out.hl"),
        Bytecode.from_path(str(target)),
        Bytecode.from_path(str(folder / "out.hl")),
    )


def _function(code: Bytecode, name: str) -> Function:
    return next(f for f in code.functions if code.full_func_name(f).endswith(name))


def _same_signature(original: Bytecode, recompiled: Bytecode, name: str) -> bool:
    a = signature(original, _function(original, name))
    b = signature(recompiled, _function(recompiled, name))
    assert a and b, (a.reason, b.reason)
    return a.digest == b.digest


def _check(tmp_path: Path, source: str, *names: str) -> None:
    _files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert actual == expected
    for name in names:
        assert _same_signature(original, recompiled, name)


def test_map_of_maps_keeps_the_inner_value_type(tmp_path: Path) -> None:
    # `packages.get("")` is an unchecked cast to the inner map, whose own `get` is unchecked too only
    # if the inner map is declared with its value type.
    source = """
class Main {
    static function main() {
        var packages:Map<String, Map<String, String>> = ["" => new Map()];
        packages.get("").set("foo", "bar");
        Sys.println(packages.get("").get("foo"));
    }
}
"""
    _check(tmp_path, source, "Main.main")


def test_array_of_maps_keeps_the_map_value_type(tmp_path: Path) -> None:
    source = """
class Item {
    public var n = 1;
    public function new() {}
}

class Main {
    static function main() {
        var x:Array<Null<Map<Int, Item>>> = [];
        x.push([0 => new Item()]);
        Sys.println(x[0].get(0).n);
    }
}
"""
    _check(tmp_path, source, "Main.main")


def test_map_seen_as_imap_keeps_the_value_type(tmp_path: Path) -> None:
    source = """
class P {
    public var n:Int;
    public function new(n:Int) this.n = n;
}

class Main {
    static function main() {
        var m = new Map<P, Int>();
        m[new P(1)] = 2;
        var im:haxe.Constraints.IMap<P, Int> = m;
        for (key in im.keys()) {
            Sys.println(key.n);
            Sys.println(im.get(key));
        }
    }
}
"""
    _check(tmp_path, source, "Main.main")


def test_field_map_converted_to_imap_keeps_the_value_type(tmp_path: Path) -> None:
    source = """
class Component {
    public static var TYPE:String = "type";
    public function new() {}
}

class Holder {
    var _components:Map<String, Component>;
    public function new() {
        _components = new Map<String, Component>();
        _components.set(Component.TYPE, new Component());
    }

    @:generic public function get<T:Component>(classType:Class<T>):T {
        return cast _components.get(Reflect.field(classType, "TYPE"));
    }
}

class Main {
    static function main() {
        Sys.println(new Holder().get(Component) != null);
    }
}
"""
    _check(tmp_path, source, "Main.main", "Holder.get_Component")


def test_list_items_keep_their_element_type(tmp_path: Path) -> None:
    # Reading a `List<Block>` node's item is an unchecked cast to `Block`.
    source = """
enum Block {
    Frame(index:Int);
    Ext(ext:Int);
}

class Main {
    static function loopCount(blocks:List<Block>):Int {
        for (block in blocks) {
            switch (block) {
                case Ext(n):
                    return n;
                default:
            }
        }
        return 1;
    }

    static function main() {
        var blocks = new List<Block>();
        blocks.add(Frame(0));
        blocks.add(Ext(3));
        Sys.println(loopCount(blocks));
    }
}
"""
    _check(tmp_path, source, "Main.loopCount", "Main.main")


def test_instance_method_returning_its_own_type_variable(tmp_path: Path) -> None:
    # The instance method's erased result is cast without a check where its type is fixed.
    source = """
class Child {
    public var value:Null<Array<Int>>;
    public function new() {}

    public function forCast<T>(a:Array<Int>):T {
        value = a.copy();
        return cast this;
    }
}

class Main {
    static function main() {
        var child = new Child();
        var result:Child = child.forCast([10, 20, 30]);
        Sys.println(result.value.length);
    }
}
"""
    _check(tmp_path, source, "Main.main")


def test_array_read_through_dynamic_keeps_its_element_type(tmp_path: Path) -> None:
    # `a[0]` on a Dynamic where a `String` is wanted reads an `ArrayObj`: declared `Array<Dynamic>`
    # (an ArrayDyn) the local would be cast to the wrong array class.
    source = """
class Main {
    static function eq<T>(a:T, b:T) Sys.println(a == b);

    static function main() {
        var x = {"k": ["CheckBase", "UnusedImportCheck"]};
        var a = Reflect.field(x, "k");
        eq("CheckBase", a[0]);
        eq("UnusedImportCheck", a[1]);
    }
}
"""
    _check(tmp_path, source, "Main.main")


def test_array_of_arrays_keeps_the_inner_element_type(tmp_path: Path) -> None:
    source = """
class Main {
    static function main() {
        var a = [["a"], ["b"]];
        var x = a.shift();
        a[0].push(x[0]);
        Sys.println(a[0].length);
        Sys.println(a[0][1]);
    }
}
"""
    _check(tmp_path, source, "Main.main")


def test_array_converted_to_an_object_array_is_a_cast(tmp_path: Path) -> None:
    # An abstract's `Array<K>` is erased to an ArrayDyn; the caller's `Array<String>` casts it.
    source = """
abstract A<K>(haxe.DynamicAccess<Int>) {
    public function f():Array<K> return [];
}

class Main {
    static function eq<T>(a:T, b:T) Sys.println(a == b);

    static function main() {
        var a:A<String> = null;
        var k = a.f();
        eq(k[0], null);
        Sys.println(k.length);
    }
}
"""
    _check(tmp_path, source, "Main.main")
