"""Properties reached through a structure or an interface must stay properties, so the project compiles back."""

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


def roundtrip(tmp_path: Path, modules: Dict[str, str]) -> Tuple[Dict[str, str], str, str]:
    """Compile `modules`, decompile the image, recompile that; return (decompiled sources, original output, new output)."""
    for name, source in modules.items():
        (tmp_path / "src" / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "src" / name).write_text(source)
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
    sources = {
        str(path.relative_to(folder / "src")): path.read_text() for path in (folder / "src").rglob("*.hx")
    }
    return sources, _run(target), _run(folder / "out.hl")


def test_interface_over_properties_is_not_a_structure(tmp_path: Path) -> None:
    # A structure can't have accessor members; a value of an interface with a property is typed as the interface.
    modules = {
        "Main.hx": """
interface I { var x(get, set):Int; }
class C implements I {
    public var x(get, set):Int;
    var _x = 5;
    public function new() {}
    function get_x() return _x;
    function set_x(v:Int) return _x = v;
}
class Main {
    static function main() {
        var i:I = new C();
        Sys.println(i.x);
        i.x = 7;
        Sys.println(i.x);
    }
}
"""
    }
    _, expected, actual = roundtrip(tmp_path, modules)
    assert actual == expected


def test_structure_over_a_property_keeps_its_access(tmp_path: Path) -> None:
    # `{ var v(get, set):Int }` holds only `v`; code reaches it through get_v/set_v, and the class's field is a property.
    modules = {
        "Main.hx": """
typedef T = { var v(get, set):Int; }
class C {
    @:isVar public var v(get, set):Int;
    public function new(value:Int) { v = value; }
    public function get_v():Int return v + 1;
    public function set_v(value:Int):Int return v = value * 2;
}
class Main {
    static function main() {
        var t:T = new C(3);
        Sys.println(t.v);
        Sys.println(t.v = 10);
        Sys.println(t.v++);
        Sys.println(t.v);
    }
}
"""
    }
    sources, expected, actual = roundtrip(tmp_path, modules)
    assert "t.get_v" not in sources["Main.hx"] and "t.set_v" not in sources["Main.hx"]
    assert actual == expected
