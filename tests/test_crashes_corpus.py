"""Catching a module-private enum must not crash the decompiler (its `$Enum` holder has no dynamic Obj)."""

import shutil
import subprocess
from pathlib import Path

import pytest

from crashlink import Bytecode, project
from crashtest.behavior import resolve_hl_runtime

THING = """
package p;
class Thing {
    static function boom(o:String) return o.length;
    public function new() {}
    public function test() {
        try {
            try {
                boom(null);
            } catch (e:Stop) {
            }
            Sys.println("unreachable");
        } catch (e) {
            Sys.println(e.stack.length > 0);
        }
    }
}
private enum Stop { A; }
"""


@pytest.mark.skipif(shutil.which("haxe") is None or resolve_hl_runtime() is None, reason="needs haxe and HL")
def test_catch_private_enum_decompiles(tmp_path: Path) -> None:
    (tmp_path / "p").mkdir()
    (tmp_path / "p" / "Thing.hx").write_text(THING)
    (tmp_path / "Main.hx").write_text("class Main { static function main() { new p.Thing().test(); } }")
    out = tmp_path / "out.hl"
    done = subprocess.run(
        ["haxe", "-main", "Main", "-hl", str(out)], cwd=tmp_path, capture_output=True, text=True
    )
    assert done.returncode == 0, done.stderr
    text = project.export(Bytecode.from_path(str(out)))["src/p/Thing.hx"]
    assert "decompilation failed" not in text
    assert "catch (e:Stop)" in text
