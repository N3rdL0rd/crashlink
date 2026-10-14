"""Control-flow shapes the decompiler must keep so the recompile has the original CFG."""

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


def test_ternary_joined_through_an_inlined_temp_is_returned_from_the_join(tmp_path: Path) -> None:
    source = """
class Main {
    static inline function clamp(v:Float):Float { var x:Float; x = v < 0 ? 0. : (v > 1 ? 1. : v); return x; }
    static function h(v:Float):Float { return clamp(v); }
    static function main() { Sys.println(h(0.5) + h(3)); }
}
"""
    _text, original, recompiled = _roundtrip(tmp_path, source)
    assert _same(original, recompiled, "$Main.h")


def test_if_return_true_else_false_is_not_folded_into_return_cond(tmp_path: Path) -> None:
    source = """
class Main {
    static function f(a:Int, b:Int):Bool { if (a == b) { return true; } return false; }
    static function h(a:Int, b:Int):Bool { if (a == b) return false; return true; }
    static function g(a:Int, b:Int):Bool { return a == b; }
    static function main() { Sys.println([f(1, 2), g(1, 1), h(1, 2)].toString()); }
}
"""
    _text, original, recompiled = _roundtrip(tmp_path, source)
    for name in ("$Main.f", "$Main.g", "$Main.h"):
        assert _same(original, recompiled, name), name


def test_for_in_over_a_parameter_keeps_the_iterator_copy_as_the_loop_preheader(tmp_path: Path) -> None:
    source = """
class Main {
    static function each(itr:IntIterator, f:Int->Int) { for (x in itr) { f(x); } }
    static function main() { each(new IntIterator(0, 3), function(x) return x); }
}
"""
    _text, original, recompiled = _roundtrip(tmp_path, source)
    assert _same(original, recompiled, "$Main.each")


def test_call_argument_of_trace_inside_try_stays_nested_in_the_call(tmp_path: Path) -> None:
    source = """
class Main {
    static function risky(n:Int):Int { return n * 2; }
    static function f(n:Int) { try { trace(risky(n)); } catch (e:String) { trace(e); } }
    static function main() { f(1); }
}
"""
    _text, original, recompiled = _roundtrip(tmp_path, source)
    assert _same(original, recompiled, "$Main.f")
