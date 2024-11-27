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
        if not f.read() == code.serialise():
            # find 1st non-matching byte
            ser = code.serialise()
            f.seek(0)
            c = 0
            msg = ""
            while True:
                a = f.read(1)
                b = ser[c : c + 1]
                if a != b:
                    print(
                        f"First mismatch at {f.tell() - 1}: {a} != {b} (in section '{code.section_at(f.tell() - 1)}')"
                    )
                    msg = f"First mismatch at {f.tell() - 1}: {a} != {b} (in section '{code.section_at(f.tell() - 1)}')"
                    break
                c += 1
            assert False, "Failed during reser: " + msg
