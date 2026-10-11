"""Evaluation order around null checks: the recompiled code must check and evaluate in the original order."""

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


def test_loop_body_temp_feeding_a_closure_call_is_inlined_after_the_callee_check(tmp_path: Path) -> None:
    # `append(arr[i].foo)` checks `append` before reading `arr[i]`. Keeping the element and field
    # reads as temps ahead of the call in the loop body reads them before the check instead.
    source = """
class Main {
    static function main() {
        var arr = [{foo: 1, bar: 2}, {foo: 3, bar: 4}];
        var buf = new StringBuf();
        var append = function(s:Int) buf.add(s);
        if (Std.random(1) == 1) append = null;
        for (i in 0...arr.length) {
            append(arr[i].foo);
            append(arr[i].bar);
        }
        Sys.println(buf.toString());
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert expected == actual
    assert "append(arr[i].foo);" in files["src/Main.hx"]
    assert _same_signature(original, recompiled, "Main.main")
