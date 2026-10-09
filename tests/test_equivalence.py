"""`crashlink.equivalence`: equal signatures must mean equal behaviour.

Each case compiles two Haxe functions and compares their signatures. The pairs that must match
differ only in ways that cannot change behaviour (names, temporaries, constant folding, operand
order of commutative operators, branch layout). The pairs that must not match differ in behaviour,
including the subtle ways: a different call order, a dropped null check, a changed constant.
"""

import itertools
import shutil
import subprocess
from pathlib import Path
from typing import Tuple

import pytest

from crashlink import Bytecode
from crashlink.equivalence import signature

pytestmark = pytest.mark.skipif(not shutil.which("haxe"), reason="Haxe is required to build the fixtures")

PRELUDE = """
class Box { public var v:Int; public function new(v:Int) { this.v = v; } }
class Main {
    static var log:Array<Int> = [];
    @:keep static function a(x:Int):Int { log.push(x); return x; }
    @:keep static function b(x:Int):Int { log.push(-x); return x; }
"""
MAIN = "    static function main() { Sys.println(f(Sys.args().length, 3, new Box(2))); }\n}\n"


_counter = itertools.count()


def build(tmp_path: Path, name: str, body: str) -> Bytecode:
    folder = tmp_path / f"{name}{next(_counter)}"
    (folder / "src").mkdir(parents=True)
    (folder / "src" / "Main.hx").write_text(PRELUDE + body + MAIN)
    target = folder / "out.hl"
    result = subprocess.run(
        ["haxe", "-cp", str(folder / "src"), "-main", "Main", "-dce", "no", "-hl", str(target)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return Bytecode.from_path(str(target))


def sig(code: Bytecode, strict: bool = True) -> str:
    func = next(f for f in code.functions if code.full_func_name(f) == "$Main.f")
    result = signature(code, func, strict=strict)
    assert result, result.reason
    assert result.digest is not None
    return result.digest


def pair(tmp_path: Path, a: str, b: str, strict: bool = True) -> Tuple[str, str]:
    return sig(build(tmp_path, "a", a), strict), sig(build(tmp_path, "b", b), strict)


def f(body: str) -> str:
    return f"    @:keep static function f(p:Int, q:Int, o:Box):Int {{\n{body}\n    }}\n"


SAME = [
    (
        "names and temporaries",
        "var t = p + q; var u = t * 2; return u - p;",
        "var first = p + q; var second = first * 2; var r = second; return r - p;",
    ),
    ("constant folding", "return p + (1 + 2) * 4;", "return p + 12;"),
    ("commutative operands", "return (p + q) * (q + p) ^ (p & q);", "return (q & p) ^ (p + q) * (p + q);"),
    (
        "independent pure order",
        "var x = p * 3; var y = q * 5; return y - x;",
        "var y = q * 5; var x = p * 3; return y - x;",
    ),
    (
        "branch polarity",
        "if (p < q) return a(1); else return a(2);",
        "if (p >= q) return a(2); else return a(1);",
    ),
    (
        "branch laid out the other way",
        "var r = 0; if (p == q) { r = a(1); } else { r = a(2); } return r;",
        "var r; if (p != q) { r = a(2); } else { r = a(1); } return r;",
    ),
    (
        "loop with renamed counters",
        "var s = 0; var i = 0; while (i < p) { s += i * q; i++; } return s;",
        "var acc = 0; var k = 0; while (k < p) { acc += k * q; k++; } return acc;",
    ),
    (
        "copies through locals",
        "var x = a(p); var y = x; var z = y; return z + q;",
        "return a(p) + q;",
    ),
    (
        "field read order against pure code",
        "var m = o.v; var k = p * 2; return m + k;",
        "var k = p * 2; var m = o.v; return m + k;",
    ),
    ("identity arithmetic", "return (p + 0) * 1 - 0;", "return p;"),
    ("linear arithmetic", "return p + q + 1 + 1 - 1 - (p + 1) + 2 * q;", "return 3 * q;"),
    ("scaling by a shift", "return (p << 3) + p;", "return p * 9;"),
    ("dead values", "var dead = p * 31 + q; var d2 = dead - 7; return p + q;", "return p + q;"),
    ("float constants", "return Std.int(3 / 2) + p;", "return 1 + p;"),
    (
        "a condition decided by a constant",
        "var z = Sys.args().length * 0; var one = 1; if (one == 1) return a(p); return b(q);",
        "var z = Sys.args().length * 0; return a(p);",
    ),
]

DIFFERENT = [
    ("constant", "return p + 12;", "return p + 13;"),
    ("linear arithmetic that is not equal", "return p + q + 1 - (p + 1) + 2 * q;", "return 2 * q;"),
    ("a product of unknowns is not linear", "return p * q + p;", "return p * q + q;"),
    ("float truncation", "return Std.int(7 / 2) + p;", "return 4 + p;"),
    ("operator", "return p + q;", "return p - q;"),
    ("subtraction operand order", "return p - q;", "return q - p;"),
    ("call order", "var x = a(p); var y = b(q); return x + y;", "var y = b(q); var x = a(p); return x + y;"),
    ("callee", "return a(p);", "return b(p);"),
    (
        "a constant condition that goes the other way",
        "var one = 1; if (one == 2) return a(p); return b(q);",
        "return a(p);",
    ),
    ("dropped call", "a(p); return q;", "return q;"),
    (
        "branch targets swapped",
        "if (p < q) return a(1); else return a(2);",
        "if (p < q) return a(2); else return a(1);",
    ),
    ("comparison", "if (p < q) return 1; return 2;", "if (p <= q) return 1; return 2;"),
    (
        "store dropped",
        "o.v = p; return q;",
        "return q;",
    ),
    (
        "store moved past a call",
        "o.v = p; var x = a(q); return x + o.v;",
        "var x = a(q); o.v = p; return x + o.v;",
    ),
    (
        "loop bound",
        "var s = 0; var i = 0; while (i < p) { s += i; i++; } return s;",
        "var s = 0; var i = 0; while (i <= p) { s += i; i++; } return s;",
    ),
    (
        "loop step",
        "var s = 0; var i = 0; while (i < p) { s += i; i++; } return s;",
        "var s = 0; var i = 0; while (i < p) { s += i; i += 2; } return s;",
    ),
]


@pytest.mark.parametrize("name,a,b", SAME, ids=[c[0] for c in SAME])
def test_signatures_match_when_behaviour_cannot_differ(tmp_path: Path, name: str, a: str, b: str) -> None:
    left, right = pair(tmp_path, f(a), f(b))
    assert left == right


@pytest.mark.parametrize("name,a,b", DIFFERENT, ids=[c[0] for c in DIFFERENT])
def test_signatures_differ_when_behaviour_differs(tmp_path: Path, name: str, a: str, b: str) -> None:
    left, right = pair(tmp_path, f(a), f(b))
    assert left != right


def test_a_dropped_null_check_is_only_ignored_when_relaxed(tmp_path: Path) -> None:
    # Reading a field of a possibly-null object faults if it is null; an explicit check first is the same fault.
    checked = f("var n:Box = p > 100 ? null : o; return n.v;")
    unchecked = f("var n:Box = p > 100 ? null : o; if (n == null) throw 'x'; return n.v;")
    strict_a, strict_b = pair(tmp_path, checked, unchecked)
    assert strict_a != strict_b
    relaxed_a, relaxed_b = pair(tmp_path, checked, checked, strict=False)
    assert relaxed_a == relaxed_b


def test_signature_ignores_the_numbering_of_the_image(tmp_path: Path) -> None:
    # The same function in an image with extra functions in front of it has shifted function/type/global
    # indices; the signature must not notice.
    plain = build(tmp_path, "a", f("return a(p) + q;"))
    padded_source = "    static function pad1(x:String):String { return x + 'pad'; }\n    static function pad2(x:Int):Int { return x * 7; }\n"
    padded = build(tmp_path, "b", padded_source + f("return a(p) + q;"))
    assert sig(plain) == sig(padded)


def test_a_function_without_a_signature_never_matches() -> None:
    from crashlink.equivalence import Signature

    none = Signature(None, "unsupported")
    assert not none
    assert not none.matches(none)
    assert not none.matches(Signature("00"))


def test_a_program_is_proven_only_when_every_function_is(tmp_path: Path) -> None:
    from crashtest.hxsmith.compare import prove

    base = build(tmp_path, "a", f("var t = p + q; return t * 2 - p;"))
    same = build(tmp_path, "b", f("var u = q + p; var w = u * 2; return w - p;"))
    other = build(tmp_path, "c", f("return (p + q) * 2 + p;"))
    assert prove(base, same, ["Main"])
    assert not prove(base, other, ["Main"])
