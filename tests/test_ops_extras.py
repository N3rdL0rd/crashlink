"""A bound instance method and a void forwarding helper decompile to the source the compiler saw."""

import shutil
import subprocess
from pathlib import Path
from typing import Dict, Tuple

import pytest

from crashlink import Bytecode, project
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


def _ops(code: Bytecode, name: str) -> list:
    func = next(f for f in code.functions if code.full_func_name(f).endswith(name))
    return [str(op.op) for op in func.ops]


def test_bound_instance_method_keeps_its_receiver(tmp_path: Path) -> None:
    source = """
class Main {
    static function main() {
        var a = [0, 1, 2];
        var boundPush = a.push.bind();
        Sys.println(boundPush(3));
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "__anon_" not in files["src/Main.hx"]
    assert actual == expected
    assert _ops(original, "Main.main") == _ops(recompiled, "Main.main")


def test_void_forwarding_helper_is_not_lifted(tmp_path: Path) -> None:
    source = """
private abstract A(Array<Int>) {
    public function new() {
        this = [];
    }
    public inline function add(i:Int):Void {
        this.push(i);
    }
    public function get() return this.pop();
}
class Main {
    static function main() {
        var a = new A();
        var f = a.add;
        f(12);
        Sys.println(a.get());
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "__anon_" not in files["src/Main.hx"]
    assert actual == expected


def test_block_closure_with_function_parameter_is_inlined(tmp_path: Path) -> None:
    source = """
class Main {
    var tag = "t";
    function new() {}
    function run() {
        var f = (g:(Int) -> Void, n:Int) -> {
            g(n);
            Sys.println(tag);
        };
        f(function(x:Int) Sys.println(x), 4);
    }
    static function main() {
        new Main().run();
    }
}
"""
    files, expected, actual, original, recompiled = roundtrip(tmp_path, source)
    assert "__anon_" not in files["src/Main.hx"].split("class Main", 1)[1]
    assert actual == expected
    assert _ops(original, "Main.run") == _ops(recompiled, "Main.run")
