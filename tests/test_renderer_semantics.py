"""Rendering must preserve values and real native-call ABI behavior."""

import os
import shutil

import pytest

from crashtest.behavior import compile_haxe
from crashtest.run import run_case


@pytest.mark.parametrize(
    "name,source",
    [
        (
            "ClassAliases",
            """class ClassAliases {
    static var count = 0;
    static function log(v:Int):Void { trace(v); count += v; }
    static function main():Void { log(2); log(3); Sys.println(count); }
}""",
        ),
        (
            "NativeBoundary",
            """@:hlNative("std") extern class RawNative {
    static function itos(value:Int, count:hl.Ref<Int>):hl.Bytes;
    static function string_compare(a:hl.Bytes, b:hl.Bytes, count:Int):Int;
}
class NativeBoundary {
    static function main():Void {
        var count = 0;
        var bytes = RawNative.itos(123, new hl.Ref(count));
        var text = @:privateAccess String.__alloc__(bytes, count);
        Sys.println(text);
        Sys.println(count);
        Sys.println(RawNative.string_compare(bytes, @:privateAccess "123".bytes, count));
    }
}""",
        ),
    ],
)
def test_renderer_roundtrip_preserves_observations(tmp_path, name, source):
    if not shutil.which("haxe") or not (os.environ.get("HL_RUNTIME") or shutil.which("hl")):
        pytest.skip("Haxe and HashLink required for renderer execution")
    artifact, error = compile_haxe(source, name, tmp_path)
    assert error is None, error
    artifact.rename(tmp_path / f"{name}.hl")
    result = run_case(str(tmp_path / f"{name}.hx"), 0)
    assert not result.failed, result.error or result.behavioral_comparison
