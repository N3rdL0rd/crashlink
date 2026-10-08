"""Erased generic parameters must not leave a `Dynamic` where Haxe needs the real type."""

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


def roundtrip(tmp_path: Path, source: str) -> Tuple[Dict[str, str], str, str]:
    """Compile `source` as Main, decompile the image, recompile that; return (sources, original output, new output)."""
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
    sources = {
        str(path.relative_to(folder / "src")): path.read_text() for path in (folder / "src").rglob("*.hx")
    }
    return sources, _run(target), _run(folder / "out.hl")


def test_monomorphised_generic_array_field_keeps_its_element_type(tmp_path: Path) -> None:
    source = """
private class PairIter<T> {
    var data:Array<T>;
    var x = 0;
    var prev:T;
    var cur:T;
    public inline function new(data:Array<T>) { this.data = data; }
    public inline function hasNext() { return x < data.length; }
    public inline function next() { prev = cur; cur = data[x++]; return {prev: prev, cur: cur}; }
}
class Main {
    static function main() {
        var buf = new StringBuf();
        for (p in new PairIter(["1", "2", "3"])) buf.add('${p.prev} ${p.cur} ');
        Sys.println(buf.toString());
    }
}
"""
    _, expected, actual = roundtrip(tmp_path, source)
    assert actual == expected


def test_enum_array_parameter_binds_into_a_typed_local(tmp_path: Path) -> None:
    source = """
private enum DataType<T> {
    leaf(v:T);
    node(v:T, cs:Array<DataType<T>>);
}
class Main {
    static function fold<T, U>(f:T->DataType<U>->T, acc:T, v:DataType<U>):T return switch v {
        case node(v, cs):
            var r = acc;
            for (c in cs) r = acc = f(acc, c);
            r;
        case _: acc;
    }
    static function main() {
        var nodes = node(1, [node(2, [leaf(1), leaf(2)]), node(5, [leaf(3)])]);
        function f(acc:Int, v) return switch v {
            case node(x, cs): fold(f, acc + x, v);
            case leaf(x): acc + x;
        }
        Sys.println(f(0, nodes));
    }
}
"""
    _, expected, actual = roundtrip(tmp_path, source)
    assert actual == expected


def test_generic_enum_value_is_built_with_the_erased_parameter(tmp_path: Path) -> None:
    source = """
import haxe.ds.Option;
private enum GADT<A> {
    AnInt(p:Bool):GADT<Int>;
    AString(p:Bool):GADT<String>;
}
class Main {
    static function broken<A>(gadt:GADT<A>):Option<A> {
        return switch gadt {
            case AnInt(p): if (p) Some(1) else None;
            case AString(p): if (p) Some("a") else None;
        };
    }
    static function main() {
        Sys.println(Type.enumEq(Some(1), broken(AnInt(true))));
        Sys.println(None == broken(AnInt(false)));
        Sys.println(Type.enumEq(Some("a"), broken(AString(true))));
    }
}
"""
    _, expected, actual = roundtrip(tmp_path, source)
    assert actual == expected
