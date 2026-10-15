"""Small mixed round-trip fixes: skipped optional arguments, locals whose address is taken."""

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


def _roundtrip(tmp_path: Path, source: str) -> Tuple[str, Bytecode, Bytecode]:
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
    return files["src/Main.hx"], Bytecode.from_path(str(target)), Bytecode.from_path(str(folder / "out.hl"))


def _same(original: Bytecode, recompiled: Bytecode, name: str) -> bool:
    left = next(f for f in original.functions if original.full_func_name(f) == name)
    right = next(f for f in recompiled.functions if recompiled.full_func_name(f) == name)
    return signature(original, left).matches(signature(recompiled, right))


def test_skipped_optional_argument_before_a_given_one_stays_skipped(tmp_path: Path) -> None:
    source = """
class Main {
    public function new() {}
    function get(a = 2, b = 4.25) return "" + a + "/" + b;
    function t() { Sys.println(get(8.5)); Sys.println(get(5, 8.5)); Sys.println(get(3)); }
    static function main() { new Main().t(); }
}
"""
    text, original, recompiled = _roundtrip(tmp_path, source)
    assert "get(8.5)" in text
    assert _same(original, recompiled, "Main.t")


def test_local_passed_by_reference_is_not_replaced_by_its_initial_value(tmp_path: Path) -> None:
    source = """
@:keep
class Foo {
    public function new() {}
    public function bar(p:String) { Sys.println(p.length); }
}
class Main {
    static function main() {
        var foo:Dynamic = new Foo();
        foo.bar(StringTools.urlDecode(""));
    }
}
"""
    _text, original, recompiled = _roundtrip(tmp_path, source)
    assert _same(original, recompiled, "$Main.main")


def test_array_parameter_is_typed_by_a_call_in_a_condition(tmp_path: Path) -> None:
    source = """
class Foo { public var v:Int; public function new(v:Int) { this.v = v; } }
class Main {
    public function new() {}
    function sub(a:Array<Foo>, b:Array<Foo>) { return a.length <= b.length; }
    function run(xs:Array<Foo>, ys:Array<Foo>, n:Int) {
        if (n > 0 && sub(xs, ys)) Sys.println("sub");
        while (sub(ys, xs)) { ys.pop(); }
    }
    static function main() {
        var xs = [new Foo(1)];
        var ys = [new Foo(2), new Foo(3)];
        new Main().run(xs, ys, 1);
    }
}
"""
    _text, original, recompiled = _roundtrip(tmp_path, source)
    assert _same(original, recompiled, "Main.sub")


def test_new_array_is_not_written_as_an_array_literal(tmp_path: Path) -> None:
    source = """
class Foo { public function new() {} }
class Main {
    static function main() {
        var a = new Array<Foo>();
        a.push(new Foo());
        Sys.println(a.length);
    }
}
"""
    text, original, recompiled = _roundtrip(tmp_path, source)
    assert "new Array()" in text
    assert _same(original, recompiled, "$Main.main")


def test_dynamic_addition_of_two_strings_stays_dynamic(tmp_path: Path) -> None:
    source = """
class Main {
    static function main() {
        var v:Dynamic = "foo";
        v += v;
        Sys.println(v);
    }
}
"""
    _text, original, recompiled = _roundtrip(tmp_path, source)
    assert _same(original, recompiled, "$Main.main")


def test_enum_parameter_keeps_its_runtime_type(tmp_path: Path) -> None:
    source = """
class Main {
    static function name<T>(e:Enum<T>) return Type.getEnumName(e);
    static function main() {
        Sys.println(name(haxe.ds.Option));
    }
}
"""
    _text, original, recompiled = _roundtrip(tmp_path, source)
    assert _same(original, recompiled, "$Main.name")


def test_lambda_that_only_calls_a_captured_function_is_kept(tmp_path: Path) -> None:
    source = """
class Base<T> { public var dispatch:T; public function new() {} }
class Signal<T> extends Base<T->Void> {
    public function new(handler:T->Void) { super(); this.dispatch = value -> handler(value); }
}
class Main {
    static function main() {
        var foo = 0;
        new Signal<Int>(i -> foo = i).dispatch(1);
        Sys.println(foo);
    }
}
"""
    _text, original, recompiled = _roundtrip(tmp_path, source)
    assert _same(original, recompiled, "$Signal.__constructor__")
