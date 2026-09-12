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
