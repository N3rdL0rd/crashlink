from pathlib import Path

import pytest

from crashlink.__main__ import Commands
from crashlink.core import Bytecode

IMAGE = Path(__file__).parent / "haxe" / "Arithmetic.hl"


@pytest.fixture
def commands() -> Commands:
    if not IMAGE.exists():
        pytest.skip("fixture image not built")
    cmds = Commands.__new__(Commands)
    cmds.code = Bytecode.from_path(str(IMAGE))
    return cmds


def _main_index(commands: Commands) -> int:
    return next(
        f.findex.value
        for f in commands.code.functions
        if commands.code.full_func_name(f) == "$Arithmetic.main"
    )


def test_sig_prints_the_name_and_a_stable_digest(
    commands: Commands, capsys: pytest.CaptureFixture[str]
) -> None:
    index = _main_index(commands)
    commands.sig([str(index)])
    first = capsys.readouterr().out
    commands.sig([str(index)])
    assert capsys.readouterr().out == first
    assert "$Arithmetic.main" in first and len(first.split()[-1]) == 32


def test_relaxed_and_explain_flags(commands: Commands, capsys: pytest.CaptureFixture[str]) -> None:
    index = _main_index(commands)
    commands.sig([str(index), "--explain"])
    assert "b0:" in capsys.readouterr().out


def test_natives_and_unknown_indexes_are_reported(
    commands: Commands, capsys: pytest.CaptureFixture[str]
) -> None:
    commands.sig([str(commands.code.natives[0].findex.value)])
    assert "no body" in capsys.readouterr().out
    commands.sig(["999999"])
    assert "not found" in capsys.readouterr().out
