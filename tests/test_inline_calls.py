"""Copies of inline functions decompile back to calls that recompile to the same code."""

import shutil
import subprocess
from pathlib import Path
from typing import List

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


def _compile(directory: Path, source: str) -> Path:
    directory.mkdir(parents=True)
    (directory / "Main.hx").write_text(source)
    target = directory / "program.hl"
    result = subprocess.run(
        ["haxe", "-cp", str(directory), "-main", "Main", "-hl", str(target)], capture_output=True, text=True
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
