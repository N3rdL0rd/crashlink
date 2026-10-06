"""Decompiled Haxe from small programs recompiles and behaves the same: assorted renderings."""

import shutil
import subprocess
from pathlib import Path
from typing import Dict, Tuple

import pytest

from crashlink import Bytecode, project
from crashtest.behavior import resolve_hl_runtime


def _run(program: Path) -> str:
    runtime = resolve_hl_runtime()
    assert runtime is not None
    result = subprocess.run([runtime, str(program)], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    return result.stdout


def _round_trip(tmp_path: Path, modules: Dict[str, str]) -> Tuple[Dict[str, str], str, str]:
    """Compile `modules`, export the image, recompile it. The decompiled sources and both outputs."""
    if not shutil.which("haxe") or resolve_hl_runtime() is None:
        pytest.skip("round trips require Haxe and HashLink")
    for name, source in modules.items():
        (tmp_path / "src" / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "src" / name).write_text(source)
    original = tmp_path / "original.hl"
    built = subprocess.run(
        ["haxe", "-cp", str(tmp_path / "src"), "-main", "Main", "-hl", str(original)],
        capture_output=True,
        text=True,
    )
    assert built.returncode == 0, built.stderr
    files = project.export(Bytecode.from_path(str(original)), stubs=False)
    folder = tmp_path / "project"
    project.write(str(folder), files)
    rebuilt = subprocess.run(["haxe", "build.hxml"], cwd=folder, capture_output=True, text=True)
    assert rebuilt.returncode == 0, rebuilt.stderr
    sources = {
        str(path.relative_to(folder / "src")): path.read_text() for path in (folder / "src").rglob("*.hx")
    }
    return sources, _run(original), _run(folder / "out.hl")


def _main(tmp_path: Path, body: str, extra: str = "") -> Tuple[str, str, str]:
    sources, expected, actual = _round_trip(tmp_path, {"Main.hx": f"{extra}\nclass Main {{\n{body}\n}}\n"})
    return sources["Main.hx"], expected, actual


def test_structure_converts_back_to_a_class_through_a_cast(tmp_path: Path) -> None:
    _, expected, actual = _main(
        tmp_path,
        """
    static function main() {
        var a:{function pop():Int;} = [1, 2];
        a.pop();
        var b:Array<Int> = cast a;
        Sys.println(b.length + "," + b[0]);
    }""",
    )
    assert actual == expected == "1,1\n"


def test_array_result_typed_as_the_erased_base_class_is_inferred(tmp_path: Path) -> None:
    _, expected, actual = _main(
        tmp_path,
        """
    static inline function shrink(buf:Array<Int>, size:Int) {
        if (buf.length != size) buf = buf.slice(0, size);
        return buf;
    }
    static function main() {
        var array = [0, 1, 2, 3];
        Sys.println(shrink(array, 2).length);
    }""",
    )
    assert actual == expected == "2\n"


def test_copy_keeps_the_element_type_of_the_original(tmp_path: Path) -> None:
    _, expected, actual = _main(
        tmp_path,
        """
    static function main() {
        var a = ["a", "b"];
        var b = a.copy();
        Sys.println(b[0] + b[1]);
        Sys.println(a == b);
    }""",
    )
    assert actual == expected == "ab\nfalse\n"


def test_std_private_type_is_not_named_outside_its_module(tmp_path: Path) -> None:
    text, expected, actual = _main(
        tmp_path,
        """
    static function total(a:List<Int>) {
        var n = 0;
        for (x in a) n += x;
        return n;
    }
    static function main() {
        var l = new List<Int>();
        l.add(2);
        l.add(5);
        Sys.println(total(l));
    }""",
    )
    assert "ListNode" not in text
    assert actual == expected == "7\n"


def test_primitive_compared_with_null_goes_through_nullable(tmp_path: Path) -> None:
    _, expected, actual = _main(
        tmp_path,
        """
    static inline function isNull<T>(v:Null<T>):Bool return v == null;
    static function main() {
        var i:Int = 0;
        Sys.println(isNull(i));
    }""",
    )
    assert actual == expected == "false\n"


def test_literal_narrowed_to_a_smaller_structure(tmp_path: Path) -> None:
    _, expected, actual = _main(
        tmp_path,
        """
    static inline function make(name:String, count:Int):Fruit return {name: name, count: count};
    static function check(item:Grocery) Sys.println(item.name);
    static function main() {
        check(make("apple", 5));
    }""",
        "typedef Grocery = {name:String}\ntypedef Fruit = {name:String, count:Int};",
    )
    assert actual == expected == "apple\n"


def test_unary_minus_literal_and_empty_object_member(tmp_path: Path) -> None:
    _, expected, actual = _main(
        tmp_path,
        """
    static inline var MINUS = -1;
    static inline var BIG = -1;
    static function main() {
        Sys.println(-MINUS);
        Sys.println(1 - BIG);
        Sys.println(({}:Dynamic).timeout);
    }""",
    )
    assert actual == expected == "1\n2\nnull\n"


def test_conversion_to_an_interface_is_a_plain_assignment(tmp_path: Path) -> None:
    text, expected, actual = _main(
        tmp_path,
        """
    static function conv(c:C):I return c;
    static function drop(c:C) { cast(c, I); }
    static function main() {
        var c = new C();
        Sys.println(conv(c) == c);
        Sys.println(conv(null) == null);
        drop(c);
    }""",
        "interface I {}\nclass C implements I { public function new() {} }",
    )
    assert "__hidden" not in text
    assert actual == expected == "true\ntrue\n"


def test_closure_context_constructor_does_not_shadow_string(tmp_path: Path) -> None:
    text, expected, actual = _main(
        tmp_path,
        """
    static function main() {
        var a = 3;
        var b = 4;
        var f = (x:Int) -> x + a + b;
        a = 10;
        Sys.println(Std.string(f(1)) + "!");
    }""",
    )
    assert "    String(" not in text
    assert actual == expected == "15!\n"


def test_local_named_like_a_package_does_not_shadow_qualified_types(tmp_path: Path) -> None:
    modules = {
        "Main.hx": """
import misc.Util;
class Main {
    @:analyzer(no_local_dce)
    static function main() {
        var misc = Std.random(1);
        Util.test();
        Sys.println(misc);
    }
}
""",
        "misc/Util.hx": "package misc;\nclass Util { public static function test() Sys.println('util'); }\n",
    }
    _, expected, actual = _round_trip(tmp_path, modules)
    assert actual == expected == "util\n0\n"
