"""Classes rewritten by hxbit's Serializable macro decompile to their source form."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from crashlink import Bytecode
from crashlink.decomp.function import IRClass

SOURCE = """
class Item implements hxbit.Serializable {
    @:s public var id:Int;
    @:s public var count:Int = 1;
    @:s public var tags:Array<String>;
    @:s public var owner:Item;
    public var cache:Int = 7;
    public function new(id:Int) { this.id = id; tags = []; }
    public function customSerialize(ctx:hxbit.Serializer) { ctx.addInt(cache); }
    public function customUnserialize(ctx:hxbit.Serializer) { cache = ctx.getInt() + 1; }
}

class Weapon extends Item {
    @:s public var dmg:Float = 3.5;
    public function new(id:Int) { super(id); }
    override function serialize(ctx:hxbit.Serializer) { super.serialize(ctx); ctx.addInt(99); }
    override function unserialize(ctx:hxbit.Serializer) { super.unserialize(ctx); cache += ctx.getInt(); }
}
"""

MAIN = """
class Main {
    static function main() {
        var w = new Weapon(4);
        w.count = 3;
        w.tags.push("a");
        w.owner = new Item(9);
        var bytes = new hxbit.Serializer().serialize(w);
        var copy = new hxbit.Serializer().unserialize(bytes, Weapon);
        Sys.println([copy.id, copy.count, copy.tags.length, copy.dmg, copy.cache, copy.owner.id].join(","));
    }
}
"""


def _toolchain() -> tuple[str, Path]:
    runtime = os.environ.get("HL_RUNTIME") or shutil.which("hl")
    if not shutil.which("haxe") or not runtime:
        pytest.skip("hxbit regressions require Haxe and HashLink")
    if subprocess.run(["haxelib", "path", "hxbit"], capture_output=True).returncode != 0:
        pytest.skip("hxbit is not installed")
    # hxbit links fmt.digest; hl loads libraries from its working directory.
    root = Path(runtime).resolve().parent
    libs = next((d for d in (root, root / "build" / "bin") if (d / "fmt.hdll").exists()), None)
    if libs is None:
        pytest.skip("fmt.hdll not found next to the HashLink runtime")
    return runtime, libs


def _build(directory: Path, sources: str) -> Path:
    directory.mkdir(parents=True)
    (directory / "Main.hx").write_text(sources + MAIN)
    target = directory / "program.hl"
    result = subprocess.run(
        ["haxe", "-lib", "hxbit", "-cp", str(directory), "-main", "Main", "-hl", str(target)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return target


def _run(runtime: str, libs: Path, program: Path) -> str:
    result = subprocess.run([runtime, str(program)], cwd=libs, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return result.stdout


def test_serializable_classes_recompile_through_the_macro(tmp_path: Path) -> None:
    runtime, libs = _toolchain()
    original = _build(tmp_path / "original", SOURCE)
    code = Bytecode.from_path(str(original))
    item = IRClass(code, code.get_test_obj("Item")).pseudo(max_classes=0)
    weapon = IRClass(code, code.get_test_obj("Weapon")).pseudo(max_classes=0)
    decompiled = "\n".join(
        line for line in (item + "\n" + weapon).splitlines() if not line.startswith("// ...")
    )

    # The generated members would clash with the ones recompiling regenerates.
    assert "class Item implements hxbit.Serializable" in decompiled
    assert "class Weapon extends Item {" in decompiled
    for generated in ("__uid", "__clid", "getCLID", "doSerialize", "getSerializeSchema", "unserializeInit"):
        assert generated not in decompiled
    assert "@:s public var count: Int;" in decompiled
    assert "@:s public var dmg: Float;" in decompiled
    assert "public var cache: Int;" in decompiled and "@:s public var cache" not in decompiled
    # A source override keeps its own body and parameter name.
    assert "super.serialize(ctx);\n        ctx.addInt(99);" in decompiled

    recompiled = _build(tmp_path / "recompiled", decompiled)
    assert _run(runtime, libs, recompiled) == _run(runtime, libs, original) == "4,3,1,3.5,107,9\n"
