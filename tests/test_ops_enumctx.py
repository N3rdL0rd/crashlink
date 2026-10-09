"""Closure capture contexts decompile back to the lambdas they came from."""

from pathlib import Path

from tests.test_ops_enums import roundtrip


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
