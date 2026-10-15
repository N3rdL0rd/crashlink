"""Array-literal loops and shadowing captured variables round-trip to the same behaviour."""

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


def test_inlined_map_over_an_array_literal_keeps_its_loop(tmp_path: Path) -> None:
    source = """
class Main {
    static function main() {
        var arr = [];
        [1, 2, 3].map(arr.push);
        Sys.println(arr.length);
    }
}
"""
    _text, original, recompiled = _roundtrip(tmp_path, source)
    assert _same(original, recompiled, "$Main.main")


def test_shadowing_variable_captured_by_a_closure_is_a_new_variable(tmp_path: Path) -> None:
    source = """
class Main {
    static function call(f:Void->String) return f();
    static function main() {
        var r = ~/a+/;
        Sys.println(r.match("aa"));
        Sys.println(call(function() return r.matched(0)));
        var r = ~/b/;
        Sys.println(r.match("b"));
        Sys.println(call(function() return r.matched(0)));
    }
}
"""
    text, original, recompiled = _roundtrip(tmp_path, source)
    assert "var r1" in text
    assert _same(original, recompiled, "$Main.main")


def test_loop_unrolled_closures_over_a_captured_counter_are_distinct_variables(tmp_path: Path) -> None:
    source = """
class Main {
    static function main() {
        var callbacks = [];
        for (i in 0...3) {
            var captured = i;
            callbacks.push(function() return captured);
        }
        for (cb in callbacks) Sys.println(cb());
    }
}
"""
    text, original, recompiled = _roundtrip(tmp_path, source)
    assert "captured1" in text
    assert _same(original, recompiled, "$Main.main")


def test_new_array_of_closures_keeps_its_element_type_and_allocation(tmp_path: Path) -> None:
    source = """
class Main {
    static function main() {
        var a = new Array<Void->Int>();
        a.push(function() return 1);
        var c = new Array<String>();
        c.push("x");
        Sys.println(a.length + c.length);
    }
}
"""
    text, original, recompiled = _roundtrip(tmp_path, source)
    assert "Array<Dynamic>" not in text
    assert _same(original, recompiled, "$Main.main")
