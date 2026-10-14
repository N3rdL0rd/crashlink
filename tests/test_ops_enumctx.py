"""Closure capture contexts decompile back to the lambdas they came from."""

import shutil
from pathlib import Path

import pytest

from crashtest.behavior import resolve_hl_runtime
from tests.test_ops_enums import roundtrip


@pytest.fixture(autouse=True)
def _tools() -> None:
    if not shutil.which("haxe") or resolve_hl_runtime() is None:
        pytest.skip("project round trips require Haxe and HashLink")


def test_lambda_capturing_a_loop_variable_inlines_without_a_context_enum(tmp_path: Path) -> None:
    source = """
class Main {
    static function main() {
        var objs:Iterable<Int> = [10, 20];
        var fns = [for (obj in objs) function() return obj];
        Sys.println(fns[0]());
        Sys.println(fns[1]());
    }
}
"""
    files, expected, actual, _, _ = roundtrip(tmp_path, source)
    assert actual == expected
    text = files["src/Main.hx"]
    print(text)
    assert "__ClosureCtx" not in text


def test_capture_context_reads_are_patterns_not_enum_parameter_lookups(tmp_path: Path) -> None:
    source = """
class Main {
    static function main() {
        var a = Sys.args().length;
        var b = a + 1;
        var f = function() { Sys.println(a); Sys.println(b); };
        f();
    }
}
"""
    files, expected, actual, _, _ = roundtrip(tmp_path, source)
    assert actual == expected
    text = files["src/Main.hx"]
    assert "__ClosureCtx" not in text
    assert "Type.enumParameters" not in text


def test_block_lambda_capturing_several_variables_keeps_its_captures_inline(tmp_path: Path) -> None:
    source = """
class Main {
    static function run(arr:Array<Dynamic>, multiplier:Int):Int {
        var doSomething = function() {
            var mul:Int = multiplier;
            arr.push({});
            return arr.length + mul;
        };
        return doSomething();
    }
    static function main() {
        Sys.println(run([], 1));
    }
}
"""
    files, expected, actual, _, _ = roundtrip(tmp_path, source)
    assert actual == expected
    text = files["src/Main.hx"]
    assert "__ClosureCtx" not in text
    assert "-> {" in text
