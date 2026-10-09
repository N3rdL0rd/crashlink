"""Constants, temporaries and arithmetic: the decompiled source must compile back to the same opcodes."""

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


def _ops(code: Bytecode, name: str) -> list:
    func = next(f for f in code.functions if code.full_func_name(f).endswith(name))
    return [str(op.op) for op in func.ops]


def test_call_in_loop_condition_stays_in_the_condition(tmp_path: Path) -> None:
    # A temp assigned from a call and tested at the loop head folds back into `while (cond)`;
    # `while (true) { tmp = call(); if (!cond(tmp)) break; ... }` compiles to a different opcode sequence.
    source = """
class Main {
    static function main() {
        var n = 0;
        while (Math.random() > 2.0) {
            n++;
        }
        Sys.println(n);
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "while (true)" not in files["src/Main.hx"]
    assert actual == expected
    assert _ops(original, "Main.main") == _ops(recompiled, "Main.main")


def test_element_increment_stays_an_increment(tmp_path: Path) -> None:
    # `a[i]++` is read, Incr, write; `a[i] = a[i] + 1` compiles to a different opcode sequence.
    source = """
class Main {
    static function main() {
        var a = [1, 2, 3];
        var i = 1;
        a[i]++;
        a[2]--;
        Sys.println(a.join(","));
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "a[1] = a[1] + 1" not in files["src/Main.hx"]
    assert actual == expected
    assert _ops(original, "Main.main") == _ops(recompiled, "Main.main")


def test_captured_assigned_variable_is_not_written_as_its_box(tmp_path: Path) -> None:
    # The compiler boxes a captured variable that is assigned; source wrote a plain variable.
    source = """
class Main {
    static function main() {
        var n = 1;
        n++;
        var f = () -> Sys.println(n);
        n += 2;
        f();
        var s = "a";
        var g = () -> Sys.println(s);
        s = "b";
        g();
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "[0]" not in files["src/Main.hx"]
    assert actual == expected
    assert _ops(original, "Main.main") == _ops(recompiled, "Main.main")


def test_string_self_concat_is_not_split_by_a_temporary(tmp_path: Path) -> None:
    # `s += x` on a String is `s = s + x`: the result is stored in `s` through one register copy.
    # The temporary the decompiler used to write instead is a different register allocation.
    source = """
class Main {
    static function main() {
        var s = "hello" + Std.random(2);
        s += ", world";
        var t = "x" + Std.random(2);
        t = t + "y";
        Sys.println(s + t);
        Sys.println(t + s);
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "s = s + " in files["src/Main.hx"]
    assert actual == expected
    assert _ops(original, "Main.main") == _ops(recompiled, "Main.main")


def test_concat_fold_keeps_statements_between_the_chain_and_its_use(tmp_path: Path) -> None:
    # A chain of concatenations on one variable, then an unrelated variable's chain, then one use of both.
    source = """
class Main {
    static function main() {
        var s = "hello" + Std.random(1);
        s += ", world";
        var t = "x" + Std.random(1);
        t = t + "y";
        Sys.println(s + t);
    }
}
"""
    files, expected, actual, _, _ = roundtrip(tmp_path, source)
    assert actual == expected


def test_named_object_variable_is_not_folded_into_its_use(tmp_path: Path) -> None:
    # Folding `var o = {name: ...}` into the one call that reads it builds the object after the
    # call's other arguments were loaded.
    source = """
class Main {
    static function show(expected:String, actual:Dynamic) {
        Sys.println(expected + ":" + actual);
    }
    static function main() {
        var t2 = { name: "jason" };
        show("jason", Reflect.field(t2, "name"));
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "var t2" in files["src/Main.hx"]
    assert actual == expected
    assert _ops(original, "Main.main") == _ops(recompiled, "Main.main")


def test_chained_assignment_stays_a_chain(tmp_path: Path) -> None:
    # `a = b = c = 42` loads 42 once and stores that register to each target.
    source = """
class Main {
    public var a:Int;
    public var b:Int;
    public var c:Int;
    static var j:Int = 0;
    static var i(default, set):Int = 0;
    static function set_i(v:Int) {
        return i = v;
    }
    public function new() {
        a = b = c = 42;
    }
    static function main() {
        var m = new Main();
        i = j = 1;
        Sys.println(m.a);
        Sys.println(m.b);
        Sys.println(m.c);
        Sys.println(i);
        Sys.println(j);
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "this.a = this.b = this.c = 42" in files["src/Main.hx"]
    assert actual == expected
    assert _ops(original, "Main.main") == _ops(recompiled, "Main.main")
    assert _ops(original, "Main.__constructor__") == _ops(recompiled, "Main.__constructor__")


def test_stored_value_handed_on_keeps_the_read_it_came_from(tmp_path: Path) -> None:
    # `f(++a)` stores `a + 1` and passes it on: the read of `a` feeding the sum must stay.
    source = """
class Main {
    static var a = 0;
    static var b = 0;
    static function show(v:Int) {
        Sys.println(v);
    }
    static function main() {
        show(++a);
        show(++b);
        show(++a);
    }
}
"""
    files, expected, actual, _, _ = roundtrip(tmp_path, source)
    assert actual == expected
