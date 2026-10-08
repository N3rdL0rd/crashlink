"""Corpus leftovers: private extern classes, private std abstracts, @:callable abstracts, optional Ref arguments."""

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


def test_private_extern_class_beside_its_module_main_class(tmp_path: Path) -> None:
    # Haxe names a private extern class's statics `Main_Impl_`; that isn't an abstract colliding with `Main`.
    modules = {
        "Main.hx": """
private extern class Ext {
    static inline var v = "foo";
    static inline function test2():String { return v; }
}

class Main {
    static function main() {
        var f = Ext.test2;
        Sys.println(f());
    }
}
"""
    }
    _, expected, actual = roundtrip(tmp_path, modules)
    assert actual == expected


def test_optional_ref_parameters_called_without_arguments(tmp_path: Path) -> None:
    modules = {
        "Main.hx": """
class Main {
    function errorTryCatch(pos = 0, length = 100) {
        try {
            while (true) {
                pos += 10;
                length -= 10;
                if (length <= 40) throw haxe.io.Error.Blocked;
            }
        } catch (e:haxe.io.Error) {
            log += pos + "," + length + ";";
        }
        log += (pos + length) + ";";
    }
    var log = "";
    function new() {}
    static function main() {
        var m = new Main();
        m.errorTryCatch();
        m.errorTryCatch(5);
        Sys.println(m.log);
    }
}
"""
    }
    _, expected, actual = roundtrip(tmp_path, modules)
    assert actual == expected


def test_call_of_a_constructed_callable_abstract(tmp_path: Path) -> None:
    modules = {
        "Main.hx": """
@:callable
abstract Example(() -> String) {
    public function new() {
        this = null;
        this = fun;
    }
    function fun() return "foo";
}

class Main {
    static function main() {
        Sys.println(new Example()());
    }
}
"""
    }
    _, expected, actual = roundtrip(tmp_path, modules)
    assert actual == expected


def test_private_std_abstract_is_reached_through_its_public_property(tmp_path: Path) -> None:
    # `access.has.attr` inlines to a call of the private `HasAttribAccess.resolve`, a type source can't name.
    modules = {
        "Main.hx": """
class Main {
    static function main() {
        var access = new haxe.xml.Access(Xml.parse('<node attr="1"/>').firstElement());
        Sys.println(access.has.attr);
        Sys.println(access.has.attra);
        Sys.println(access.att.attr);
    }
}
"""
    }
    _, expected, actual = roundtrip(tmp_path, modules)
    assert actual == expected
