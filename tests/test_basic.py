from glob import glob

import pytest

from crashlink import *

test_files = glob("tests/haxe/*.hl")


@pytest.mark.parametrize("path", test_files)
def test_deser_basic(path: str):
    with open(path, "rb") as f:
        code = Bytecode().deserialise(f)
        assert code.is_ok()


@pytest.mark.parametrize("path", test_files)
def test_reser_basic(path: str):
    with open(path, "rb") as f:
        code = Bytecode().deserialise(f)
        assert code.is_ok(), "Failed during deser"
        f.seek(0)
        assert f.read() == code.serialise(), "Failed during reser"
