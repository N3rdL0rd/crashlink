"""Abstracts decompile to `abstract` declarations and uses that recompile to the same code."""

import shutil
import subprocess
from pathlib import Path
from typing import Dict, List

import pytest

from crashlink import Bytecode
from crashlink.core import Function
from crashlink.decomp.function import IRClass

SOURCE = """
class Pt {
    public var x:Int;
    public var y:Int;
    public function new(x, y) { this.x = x; this.y = y; }
}

abstract Vec(Pt) {
    public static var created:Int = 0;
    public function new(x:Int, y:Int) {
        this = new Pt(x, y);
        if (x < 0) return;
        created++;
    }
    public var len(get, set):Int;
    function get_len() return this.x + this.y;
    function set_len(v:Int) { this.x = v - this.y; return v; }
    public function scaled(k:Int):Vec return new Vec(this.x * k, this.y * k);
    public function sum(o:Vec):Int return len + o.len + scaled(2).len;
    public static function origin():Vec return new Vec(0, 0);
}

class Main {
    static function main() {
        var v = new Vec(1, 2);
        v.len = 5;
        Sys.println(v.sum(Vec.origin()));
        Sys.println(Vec.created);
    }
}
"""


def _compile(directory: Path, source: str) -> Path:
    directory.mkdir(parents=True)
    (directory / "Main.hx").write_text(source)
    target = directory / "program.hl"
    result = subprocess.run(
        ["haxe", "-cp", str(directory), "-main", "Main", "-hl", str(target)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return target


def _ops(program: Path) -> Dict[str, List[str]]:
    """Opcodes of `Main` and the abstract's members, without the function and global
    indices a rebuild renumbers."""
    code = Bytecode.from_path(str(program))
    return {
        name: [f"{op.op}:{sorted(k for k in op.df if k not in ('fun', 'global'))}" for op in func.ops]
        for func in code.functions
        if isinstance(func, Function)
        and ("Vec_Impl_" in (name := code.full_func_name(func)) or name.startswith("$Main."))
    }


def test_abstract_recompiles_identically(tmp_path: Path) -> None:
    if not shutil.which("haxe"):
        pytest.skip("abstract round trips require Haxe")
    original = _compile(tmp_path / "original", SOURCE)
    code = Bytecode.from_path(str(original))
    decompiled = IRClass(code, code.get_test_obj("Main")).pseudo()

    for text in (
        "abstract Vec(Pt) from Pt to Pt {",
        "public var len(get, set): Int;",
        "public function new(x: Int, y: Int) {",
        "this = new Pt(x, y);",
        "return len + (o : Vec).len + (scaled(2) : Vec).len;",
        "(v : Vec).len = 5;",
        "(v : Vec).sum(Vec.origin())",
        "Vec.created",
    ):
        assert text in decompiled
    assert "_Impl_" not in decompiled

    recompiled = _compile(tmp_path / "recompiled", decompiled)
    assert _ops(recompiled) == _ops(original)
