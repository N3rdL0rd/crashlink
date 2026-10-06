"""Anonymous structures: literals that omit fields, aliases, and fields stored one by one."""

import shutil
import subprocess
from pathlib import Path

import pytest

from crashlink import Bytecode, disasm, project
from crashlink.core import Virtual
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


def _roundtrip(tmp_path: Path, source: str):
    if not shutil.which("haxe") or resolve_hl_runtime() is None:
        pytest.skip("round trips require Haxe and HashLink")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Main.hx").write_text(source)
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


def test_structure_literals_recompile_and_behave_the_same(tmp_path: Path) -> None:
    original, folder = _roundtrip(tmp_path, MAIN)
    # A copy of the object that compiled to the same register does not keep its literal from folding.
    text = (folder / "src" / "Main.hx").read_text()
    start = text.index("function aliased")
    aliased = text[start : text.index("function ", start + 1)]
    assert "cast {}" not in aliased
    assert _run(folder / "out.hl") == _run(original)


GENERICS = """
interface I<T> { function foo(v:T, w:Int):T; }
abstract class Base implements I<Int> {
    public function new() {}
}
class Real extends Base {
    public function foo(v:Int, w:Int):Int return v + w;
}

class Holder<T> {
    public var seen:Array<String> = [];
    public function new() {}
    public dynamic function onItem(item:T):Void seen.push("base");
    public function trigger(item:T) onItem(item);
}
class Upper extends Holder<String> {
    override function onItem(item:String):Void seen.push(item.toUpperCase());
}

class Plain {
    public var got:String;
    public function new() {}
    public dynamic function put(item:String):Void got = item;
    public function go(item:String) put(item);
}
class Loud extends Plain {
    override function put(item:String):Void got = item + "!";
}

class Main {
    static function main() {
        var r = new Real();
        var i:I<Int> = r;
        Sys.println(i.foo(3, 4));
        var u = new Upper();
        u.trigger("ho");
        Sys.println(u.seen);
        var l = new Loud();
        l.go("x");
        Sys.println(l.got);
    }
}
"""


def test_generic_interface_and_class_overrides_recompile_and_behave_the_same(tmp_path: Path) -> None:
    original, folder = _roundtrip(tmp_path, GENERICS)
    assert _run(folder / "out.hl") == _run(original)


REDECLARED = """
interface IVar { function value():String; }
interface IUserVar extends IVar { function owner():String; }
interface IEntity { var id:Int; function fetch(n:String):IVar; }
interface IUser extends IEntity {
    var id:Int;
    var label:String;
    function fetch(n:String):IUserVar;
}
class UV implements IUserVar {
    public function new() {}
    public function value() return "v";
    public function owner() return "o";
}
class User implements IUser {
    public var id:Int = 3;
    public var label:String = "l";
    public function new() {}
    public function fetch(n:String):IUserVar return new UV();
}
class Main {
    static function main() {
        var u = new User();
        var bare:IEntity = u;
        var user:IUser = u;
        Sys.println(user.label + user.id);
        Sys.println(bare.fetch("a").value() + bare.id + u.fetch("b").owner());
    }
}
"""


def test_interface_redeclaring_an_inherited_field_renders_one_declaration(tmp_path: Path) -> None:
    original, folder = _roundtrip(tmp_path, REDECLARED)
    assert _run(folder / "out.hl") == _run(original)


BORROWED = """
class Main {
    static function main() {
        var a = [0, 4];
        var k = Lambda.array({ iterator: a.iterator });
        Sys.println(k);
        var counts = { inc: () -> a.length, dec: () -> a[0] };
        Sys.println(counts.inc() + counts.dec());
    }
}
"""


def test_function_field_stored_into_a_structure_is_a_var(tmp_path: Path) -> None:
    original, folder = _roundtrip(tmp_path, BORROWED)
    assert _run(folder / "out.hl") == _run(original)


ABSTRACT_DEFAULTS = """
abstract class Base {
    public function new() {}
    public abstract function f(x:Int, flag:Bool = false, n:Int = 3):Int;
}
class Impl extends Base {
    public function f(x:Int, flag:Bool = true, n:Int = 7):Int return x + (flag ? 10 : 1) + n;
}
class Main {
    static function call(b:Base) return b.f(100) + b.f(100, false) + b.f(100, true, 5);
    static function main() {
        Sys.println(call(new Impl()));
    }
}
"""


def test_abstract_method_called_with_optional_basic_arguments(tmp_path: Path) -> None:
    original, folder = _roundtrip(tmp_path, ABSTRACT_DEFAULTS)
    assert _run(folder / "out.hl") == _run(original)


POSITIONS = """
class Main {
    static var tmp:String;
    static function at(?pos:haxe.PosInfos):String return pos.methodName;
    static function main() {
        var o = {rec:(null:Dynamic)};
        o.rec = o;
        try {
            tmp = Std.string(o);
            Sys.println(at());
        } catch (e:Dynamic) {
            Sys.println(at() + e);
        }
        var a:Array<Dynamic> = [];
        a.push(a);
        try {
            tmp = Std.string(a);
            Sys.println(at());
        } catch (e:Dynamic) {
            Sys.println(at() + e);
        }
    }
}
"""


def test_position_literal_without_custom_params_is_a_pos_infos(tmp_path: Path) -> None:
    original, folder = _roundtrip(tmp_path, POSITIONS)
    code = Bytecode.from_path(str(original))
    bare = [
        typ
        for typ in code.types
        if isinstance(typ.definition, Virtual)
        and {f.name.resolve(code) for f in typ.definition.fields}
        == {"className", "fileName", "lineNumber", "methodName"}
    ]
    assert bare and all(disasm._haxe_annotation(code, typ) == "haxe.PosInfos" for typ in bare)
    assert _run(folder / "out.hl") == _run(original)
