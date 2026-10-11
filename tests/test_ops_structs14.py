"""Conversions to structural types: the decompiled source must convert to the same interface."""

import shutil
import subprocess
from pathlib import Path
from typing import Dict, Tuple

import pytest

from crashlink import Bytecode, project
from crashlink.core import Function
from crashlink.equivalence import signature
from crashtest.behavior import resolve_hl_runtime


@pytest.fixture(autouse=True)
def _tools() -> None:
    if not shutil.which("haxe") or resolve_hl_runtime() is None:
        pytest.skip("project round trips require Haxe and HashLink")


def _run(program: Path) -> str:
    runtime = resolve_hl_runtime()
    assert runtime is not None
    result = subprocess.run([runtime, str(program)], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    return result.stdout


def roundtrip(tmp_path: Path, source: str) -> Tuple[Dict[str, str], str, str, Bytecode, Bytecode]:
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
    return (
        files,
        _run(target),
        _run(folder / "out.hl"),
        Bytecode.from_path(str(target)),
        Bytecode.from_path(str(folder / "out.hl")),
    )


def _function(code: Bytecode, name: str) -> Function:
    return next(f for f in code.functions if code.full_func_name(f).endswith(name))


def _same_signature(original: Bytecode, recompiled: Bytecode, name: str) -> bool:
    a = signature(original, _function(original, name))
    b = signature(recompiled, _function(recompiled, name))
    assert a and b, (a.reason, b.reason)
    return a.digest == b.digest


def test_values_converted_to_interfaces_sharing_one_shape_keep_their_interface(tmp_path: Path) -> None:
    # `A`, `B` and `{}` are one HL type. Converting a class to its interface caches the wrapper
    # in the instance (a null check, a load and a store), which a conversion to `{}` doesn't:
    # the local, the parameter and the field must name the interface the cache slot holds.
    source = """
interface A {}
interface B {}
interface C extends A {}
class ImplA implements A { public function new() {} }
class ImplB implements B { public function new() {} }
class ImplC implements C { public function new() {} }

class Main {
    static var held:B;

    static function take(a:A):Bool {
        return a != null;
    }

    static function main() {
        var a:A = new ImplA();
        held = new ImplB();
        Sys.println(take(a) && take(new ImplC()) && held != null);
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert actual == expected
    assert "static function take(a: A)" in files["src/Main.hx"], files["src/Main.hx"]
    assert _same_signature(original, recompiled, "$Main.main")


def test_class_converted_to_a_typed_structure_then_to_an_erased_one_keeps_both_conversions(
    tmp_path: Path,
) -> None:
    # `Lambda.count(m)` converts the map to `Iterable<Int>`, then that to the `Iterable<A>` the
    # generic parameter erases to `next(): Dynamic`. A declaration of the erased structure alone
    # would convert the map to it directly, once.
    source = """
class Main {
    static function main() {
        var m = new Map<String, Int>();
        m.set("foo", 12);
        Sys.println(Lambda.count(m));
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert actual == expected
    assert _same_signature(original, recompiled, "$Main.main")
