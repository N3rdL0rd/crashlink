from glob import glob

import pytest

from crashlink import *

test_files = glob("tests/haxe/*.hl")


@pytest.mark.parametrize("path", test_files)
def test_diasm_equivalency(path: str):
    code = Bytecode.from_path(path)
    assert code.is_ok()
    for function in code.functions:
        if len(function.ops) > 1:  # skip small functions since they don't tell us much
            try:
                assert disasm.to_asm(function.ops) == disasm.to_asm(disasm.from_asm(disasm.to_asm(function.ops))), (
                    f"Function f@{function.findex} in {path} failed"
                )
            except:
                print(f"Function f@{function.findex} in {path} failed")
                raise
