"""Copies of inline functions decompile back to calls that recompile to the same code."""

import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

import pytest

from crashlink import Bytecode
from crashlink.core import Function
from crashlink.decomp.function import IRClass

SOURCE = """
class M {
    public var base = 3;
    public var x = 0.0;
    public function new() {}
    public static inline function sq(v:Int):Int return v * v;
    public static inline function lerp(a:Float, b:Float, t:Float):Float return a + (b - a) * t;
    public inline function add(a:Int):Int return base + a;
    public inline function bump():Void { base++; x += 1; }
    public static inline function hyp(a:Float, b:Float):Float return Math.sqrt(a * a + b * b);
}

class Main {
    static function main() {
        var m = new M();
        var k = Std.random(10);
        var f = Math.random();
        Sys.println(M.sq(k));
        Sys.println(M.lerp(f, 2.0, 0.5));
        Sys.println(m.add(k));
        m.bump();
        Sys.println(M.hyp(f, k));
        Sys.println(M.sq(k + 1) + m.add(k * 2));
    }
}
"""


def _compile(directory: Path, source: str, *flags: str, files: Optional[Dict[str, str]] = None) -> Path:
    directory.mkdir(parents=True)
    (directory / "Main.hx").write_text(source)
    for name, text in (files or {}).items():
        (directory / name).write_text(text)
    target = directory / "program.hl"
    result = subprocess.run(
        ["haxe", "-cp", str(directory), "-main", "Main", "-hl", str(target), *flags],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return target


def _main_ops(program: Path) -> List[str]:
    """`Main.main`'s opcodes, without the function and global indices a rebuild renumbers."""
    code = Bytecode.from_path(str(program))
    main = next(
        f for f in code.functions if isinstance(f, Function) and code.full_func_name(f) == "$Main.main"
    )
    return [f"{op.op}:{sorted(k for k in op.df if k not in ('fun', 'global'))}" for op in main.ops]


def test_inline_copies_become_calls_that_recompile_identically(tmp_path: Path) -> None:
    if not shutil.which("haxe"):
        pytest.skip("inline call regressions require Haxe")
    original = _compile(tmp_path / "original", SOURCE)
    code = Bytecode.from_path(str(original))
    main = IRClass(code, code.get_test_obj("Main")).pseudo(max_classes=0)
    helpers = IRClass(code, code.get_test_obj("M")).pseudo(max_classes=0)

    for call in (
        "M.sq(k)",
        "M.lerp(f, 2.0, 0.5)",
        "m.add(k)",
        "m.bump();",
        "M.hyp(f, k)",
        "M.sq(k + 1) + m.add(k * 2)",
    ):
        assert call in main
    for declaration in ("static inline function sq(", "inline function add(", "inline function bump("):
        assert declaration in helpers
    # `base++` inside bump is an increment, not a copy of `add(1)`.
    assert "this.base++;" in helpers

    decompiled = "\n".join(
        line for text in (helpers, main) for line in text.splitlines() if not line.startswith("// ...")
    )
    recompiled = _compile(tmp_path / "recompiled", decompiled)
    assert _main_ops(recompiled) == _main_ops(original)


HELPERS = """
class Cd {
    public var fast:Map<Int, Bool> = new Map();
    public function new() {}
    public inline function has(k:Int):Bool return fast.exists(k * 7 + 1);
    public static inline function scale(v:Float, by:Float):Float return v * by * 0.5 + 1.0;
}
"""

CALLER = """
class Main {
    static function main() {
        var c = new Cd();
        var f = Math.random();
        var k = Std.random(3);
        Sys.println(Cd.scale(f, 3.0));
        if (c.has(k)) Sys.println("a");
        Sys.println(Cd.scale(f * 2, f));
        if (c.has(k + 5)) Sys.println("b");
    }
}
"""


def test_removed_inline_functions_are_rebuilt_from_their_copies(tmp_path: Path) -> None:
    """With full dead-code elimination the functions are gone; the copies' debug
    positions (kept with keep-inline-positions) still give their bodies."""
    if not shutil.which("haxe"):
        pytest.skip("inline call regressions require Haxe")
    flags = ("-dce", "full", "-D", "keep-inline-positions")
    original = _compile(tmp_path / "original", CALLER, *flags, files={"Cd.hx": HELPERS})
    code = Bytecode.from_path(str(original))
    main = IRClass(code, code.get_test_obj("Main")).pseudo(max_classes=0)
    helpers = IRClass(code, code.get_test_obj("Cd")).pseudo(max_classes=0)

    # The multiply in `v * by` carries the caller's position (its last operand
    # is an argument), so it stays with the caller.
    for call in (
        "Cd.inlineL5(c.fast, k)",
        "Cd.inlineL5(c.fast, k + 5)",
        "Cd.inlineL6(f * 3.0)",
        "Cd.inlineL6(f * 2.0 * f)",
    ):
        assert call in main
    assert "public static inline function inlineL5(v0: haxe.ds.IntMap<Dynamic>, v1: Int): Bool {" in helpers

    decompiled = "\n".join(
        line for text in (helpers, main) for line in text.splitlines() if not line.startswith("// ...")
    )
    recompiled = _compile(tmp_path / "recompiled", decompiled, *flags)
    assert _main_ops(recompiled) == _main_ops(original)
