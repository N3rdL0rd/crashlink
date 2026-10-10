"""Constants stringified in a concatenation must keep their conversion, not become literal text."""

import shutil
from pathlib import Path

import pytest

from crashtest.behavior import resolve_hl_runtime

from .test_ops_consts2 import _ops, roundtrip


@pytest.fixture(autouse=True)
def _tools() -> None:
    if not shutil.which("haxe") or resolve_hl_runtime() is None:
        pytest.skip("project round trips require Haxe and HashLink")


def test_int_constant_after_a_literal_is_stringified_by_the_chain(tmp_path: Path) -> None:
    # `"..." + 1` lowers to an `itos` call; folding the 1 into `"1"` changes the opcodes.
    source = """
class Main {
    static function main() {
        Sys.println("Haxe is great! " + 1);
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert '"Haxe is great! " + 1' in files["src/Main.hx"]
    assert actual == expected
    assert _ops(original, "Main.main") == _ops(recompiled, "Main.main")


def test_leading_int_constant_stays_arithmetic(tmp_path: Path) -> None:
    # `1 + 2 + ""` is arithmetic first ("3"); `1 + (2 + "")` concatenates ("12").
    source = """
class Main {
    static function main() {
        Sys.println(1 + 2 + "");
        Sys.println(1 + (2 + ""));
    }
}
"""
    _, expected, actual, _, _ = roundtrip(tmp_path, source)
    assert expected.splitlines() == ["3", "12"]
    assert actual == expected


def test_int_variable_in_a_string_concat_is_not_wrapped_in_std_string(tmp_path: Path) -> None:
    # `prefix + suffix` lowers to `itos(suffix)` followed by a concat; `Std.string` is a separate call.
    source = """
class Main {
    static function doIt(prefix: String, suffix: Int): String {
        return prefix + suffix;
    }
    static function main() {
        Sys.println(doIt("Alpha", 10));
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "Std.string" not in files["src/Main.hx"]
    assert actual == expected
    assert _ops(original, "Main.doIt") == _ops(recompiled, "Main.doIt")
