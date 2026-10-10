"""Erased generic interface parameters: an implementor's concrete parameter type is kept when every
implementor of a leaf interface agrees on it, so the decompiled method keeps the original signature."""

import shutil
import subprocess
from pathlib import Path
from typing import Dict, Tuple

import pytest

from crashlink import Bytecode, project
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


def roundtrip(tmp_path: Path, source: str) -> Tuple[str, str, Bytecode, Bytecode]:
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
        _run(target),
        _run(folder / "out.hl"),
        Bytecode.from_path(str(target)),
        Bytecode.from_path(str(folder / "out.hl")),
    )


def _function(code: Bytecode, name: str):
    return next(f for f in code.functions if code.full_func_name(f).endswith(name))


def _same_signature(original: Bytecode, decompiled: Bytecode, name: str) -> Tuple[bool, Dict[str, str]]:
    a, b = signature(original, _function(original, name)), signature(decompiled, _function(decompiled, name))
    assert a, a.reason
    assert b, b.reason
    return a.matches(b), {"original": str(a.digest), "decompiled": str(b.digest)}


def test_subclass_override_narrows_an_erased_parameter_of_a_generic_interface(tmp_path: Path) -> None:
    source = """
interface I<T> {
    function foo(v:T):Void;
}

abstract class Base implements I<Int> {
    public function new() {}
}

class Real extends Base {
    public function new() { super(); }
    public function foo(v:Int) {
        Sys.println("foo " + v);
    }
}

class Main {
    static function main() {
        var r = new Real();
        r.foo(33);
    }
}
"""
    expected, actual, original, decompiled = roundtrip(tmp_path, source)
    assert actual == expected
    matches, digests = _same_signature(original, decompiled, "Real.foo")
    assert matches, digests


def test_a_leaf_interface_narrows_the_erased_parameter_of_its_implementor(tmp_path: Path) -> None:
    source = """
interface I<T> {
    function f(v:T):Int;
}

class C implements I<E> {
    public function new() {}
    public function f(v:E) return 42;
}

enum E {
    A;
}

class Main {
    static function main() {
        var c:I<E> = new C();
        Sys.println("" + c.f(A));
    }
}
"""
    expected, actual, original, decompiled = roundtrip(tmp_path, source)
    assert actual == expected
    matches, digests = _same_signature(original, decompiled, "C.f")
    assert matches, digests
