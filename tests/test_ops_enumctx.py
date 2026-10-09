"""Closure capture contexts decompile back to the lambdas they came from."""

from pathlib import Path

from tests.test_ops_enums import roundtrip


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
    assert "__ClosureCtx" in text
    assert "Type.enumParameters" not in text
