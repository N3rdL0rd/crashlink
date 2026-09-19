"""Preserve numeric conversion snapshots and native length out-parameters."""

import os
import shutil

import pytest

from crashlink import Bytecode
from crashlink.decomp.function import IRClass
from crashtest.behavior import compare_programs, compile_haxe


SOURCE = """
@:hlNative("std")
private class FormatNative {
    public static function itos(value:Int, length:hl.Ref<Int>):hl.Bytes { return null; }
}

class NumericStringProbe {
    static function standalone(value:Int):String {
        return "" + value;
    }

    static function observedCount(value:Int):String {
        var count = value;
        var bytes = FormatNative.itos(count, new hl.Ref(count));
        var text = @:privateAccess String.__alloc__(bytes, count);
        return text + ":" + count;
    }

    static function reusedInput(value:Int):String {
        var count = 0;
        var bytes = FormatNative.itos(value, new hl.Ref(count));
        value = 7;
        var text = @:privateAccess String.__alloc__(bytes, count);
        return text + ":" + value;
    }

    static function referencedCount(value:Int):String {
        var count = 0;
        var reference = new hl.Ref(count);
        var bytes = FormatNative.itos(value, reference);
        var text = @:privateAccess String.__alloc__(bytes, count);
        return text + ":" + reference.get();
    }

    static function main() {
        Sys.println(standalone(1200));
        Sys.println(observedCount(1200));
        Sys.println(reusedInput(1200));
        Sys.println(referencedCount(1200));
    }
}
"""


def test_numeric_conversion_snapshot_and_length_survive_roundtrip(tmp_path):
    if not shutil.which("haxe") or not (os.environ.get("HL_RUNTIME") or shutil.which("hl")):
        pytest.skip("numeric conversion regressions require Haxe and HashLink")
    name = "NumericStringProbe"
    original, error = compile_haxe(SOURCE, name, tmp_path / "original")
    assert error is None, error
    code = Bytecode.from_path(str(original))
    source = IRClass(code, code.get_test_obj(name), capture_layers=True).pseudo()
    recovered, error = compile_haxe(source, name, tmp_path / "recovered")
    assert error is None, error
    result = compare_programs(original, recovered, name)
    assert result.passed, result.to_json()
    assert result.original.stdout.splitlines() == ["1200", "1200:4", "1200:7", "1200:4"]


def test_interpolated_concatenation_is_rebuilt():
    code = Bytecode.from_path("tests/haxe/StringInterp.hl")
    out = IRClass(code, code.get_test_obj("StringInterp")).pseudo()
    # HL appends one value at a time through a recycled temp; the source was a
    # single interpolated literal and the values must keep their own order.
    assert "'the number is $a, a + 1 = $b !'" in out
    assert "__add__" not in out
    assert "Std.string" not in out


def test_concatenation_folds_into_call_arguments(tmp_path):
    if not shutil.which("haxe"):
        pytest.skip("building the fixture requires Haxe")
    name = "ConcatIntoCall"
    source = """class ConcatIntoCall {
    static function main() {
        var a = 1;
        var b = "x";
        Sys.println("a=" + a + " b=" + b);
        Sys.println("only " + a);
    }
}"""
    artifact, error = compile_haxe(source, name, tmp_path)
    assert error is None, error
    code = Bytecode.from_path(str(artifact))
    out = IRClass(code, code.get_test_obj(name)).pseudo()
    # A consumer that is neither an assignment nor a trace still ends a chain.
    assert "Sys.println('a=$a b=$b');" in out
