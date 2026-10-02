from pathlib import Path

from crashlink.__main__ import _assemble_to_path
from crashlink.core import Bytecode

HELLO = Path(__file__).parent.parent / "examples" / "hlasm" / "hello.hlasm"
BAD_SOURCE = "this is not hlasm\n"


def test_failed_assembly_keeps_existing_output(tmp_path, capsys):
    src = tmp_path / "bad.hlasm"
    src.write_text(BAD_SOURCE)
    out = tmp_path / "out.hl"
    out.write_bytes(b"OLD")

    assert _assemble_to_path(str(src), str(out)) == 1
    assert out.read_bytes() == b"OLD"
    assert "error" in capsys.readouterr().err


def test_input_is_never_the_default_output(tmp_path, capsys):
    image = tmp_path / "game.hl"
    image.write_bytes(HELLO.read_bytes())  # not bytecode; must survive untouched

    assert _assemble_to_path(str(image), None) == 1
    assert image.read_bytes() == HELLO.read_bytes()
    assert "refusing to overwrite" in capsys.readouterr().err


def test_output_creates_directories_and_reports_real_path(tmp_path, capsys):
    out = tmp_path / "nested" / "dir" / "x.hl"

    assert _assemble_to_path(str(HELLO), str(out)) == 0
    assert Bytecode.from_path(str(out)).fn(0) is not None
    assert f"{HELLO} -> {out}" in capsys.readouterr().out
    assert [p.name for p in out.parent.iterdir()] == ["x.hl"]


def test_default_output_swaps_suffix_beside_source(tmp_path):
    src = tmp_path / "hello.v2.hlasm"
    src.write_bytes(HELLO.read_bytes())

    assert _assemble_to_path(str(src), None) == 0
    assert (tmp_path / "hello.v2.hl").is_file()
