import shutil
import subprocess

import pytest

from crashlink import Bytecode
from crashlink import inlines
from crashlink.inlines import InlineFinder

_UTIL = """class Util {
    public static inline function scale(v:Float, k:Int):Float {
        var r = v * 2;
        if (r > 100) r = 100;
        return r + k;
    }

    public static function own(x:Float):Float {
        return scale(x, 3) + 1;
    }
}
"""

_MAIN = """class Main {
    static function main() {
        var a = Util.scale(Math.random(), 7);
        var b = Util.scale(Math.random() * 2, 9);
        Sys.println(a + b + Util.own(1.5));
    }
}
"""


@pytest.fixture(scope="module")
def inlined(tmp_path_factory):
    haxe = shutil.which("haxe")
    if not haxe:
        pytest.skip("inline detection fixture requires Haxe")
    directory = tmp_path_factory.mktemp("inlines")
    (directory / "Util.hx").write_text(_UTIL)
    (directory / "Main.hx").write_text(_MAIN)
    # Dead Cells is built with -D keep-inline-positions; without it the compiler stamps the
    # call site's position on every inlined expression and leaves nothing to find.
    compiled = subprocess.run(
        [haxe, "-hl", "main.hl", "-main", "Main", "-D", "keep-inline-positions"],
        cwd=directory,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert compiled.returncode == 0, compiled.stderr
    code = Bytecode.from_path(str(directory / "main.hl"))
    finder = InlineFinder(code)
    matches = [f for f in finder.find() if f.path.endswith("Util.hx")]
    assert len(matches) == 1, [(f.path, f.first_line, f.last_line) for f in finder.find()]
    return code, finder, matches[0]


def test_copies_are_found_in_other_modules_and_in_their_own(inlined):
    code, _, scale = inlined
    callers = sorted(code.full_func_name(code.fn(site.findex)) for site in scale.sites)
    # Two calls from Main, and the one from Util.own that the file alone does not reveal.
    assert callers == ["$Main.main", "$Main.main", "$Util.own"]
    assert scale.real_name is not None and scale.real_name.endswith("Util.scale")


def test_call_sites_share_parameter_types_and_differ_in_constants(inlined):
    _, finder, scale = inlined
    shapes = finder.shapes(scale)
    types = {name for shape in shapes for counter in shape.input_types for name in counter}
    assert "F64" in types
    constants = {value for shape in shapes for _, _, values in shape.varying_constants for value in values}
    # `k` is folded into each copy as a constant of its own. (Util.own's copy has a shape of
    # its own: the `+ 1` and `return` wrapped around it inherit the inlined position.)
    assert {"7", "9"} <= {value.removesuffix(".0") for value in constants}


def test_lookup_by_source_line_and_by_caller(inlined):
    code, finder, scale = inlined
    assert inlines.find_at(finder, f"Util.hx:{scale.first_line}") == [scale]
    # Util.own's own line (the call) holds no inlined body.
    assert inlines.find_at(finder, "Util.hx:9") == []
    main = next(f for f in code.functions if code.full_func_name(f) == "$Main.main")
    assert inlines.describe_function(finder, main.findex.value).splitlines()[0].endswith(": 2 inlined copies")
