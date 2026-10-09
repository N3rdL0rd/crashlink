"""Private types keep their bytecode names through a project round trip: a type that names a
private type of another module is declared in that module, so the private type stays there."""

import shutil
import subprocess
from pathlib import Path
from typing import Dict, Set, Tuple

import pytest

from crashlink import Bytecode, project
from crashtest.behavior import resolve_hl_runtime

SOURCE = """
class Main {
    static function main() {
        Sys.println(pk.Mod.run());
    }
}
"""

MOD = """
package pk;

@:forward @:native("Short")
private abstract TestAbstract(TestClass) from TestClass to TestClass {
    public inline function new() { this = new TestClass(); }
    public function getValue2() return this.value * 2;
}

private class TestClass {
    public var value:Int = 1;
    public function new() {}
}

class Mod {
    public static function run():Int {
        var o = new TestAbstract();
        return o.getValue2();
    }
}
"""


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


def _type_names(code: Bytecode) -> Set[str]:
    return {
        t.definition.name.resolve(code)
        for t in code.types
        if hasattr(t.definition, "name") and t.definition.name.value and t.definition.name.resolve(code)
    }


def roundtrip(tmp_path: Path) -> Tuple[Dict[str, str], str, str, Bytecode, Bytecode]:
    (tmp_path / "src" / "pk").mkdir(parents=True)
    (tmp_path / "src" / "Main.hx").write_text(SOURCE)
    (tmp_path / "src" / "pk" / "Mod.hx").write_text(MOD)
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


def test_private_type_named_by_a_module_keeps_its_bytecode_name(tmp_path: Path) -> None:
    files, original_output, recompiled_output, original, recompiled = roundtrip(tmp_path)
    assert recompiled_output == original_output
    assert "pk._Mod.TestClass" in _type_names(original)
    assert "pk._Mod.TestClass" in _type_names(recompiled)
    assert "pk.TestClass" not in _type_names(recompiled)
