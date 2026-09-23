from crashlink.asm import AsmFile
from crashlink.hlc import code_to_c


def _program(version: int, bytes_operand: str, strings: str = "") -> str:
    return f""".version {version}
{strings}
.types
    Bytes
    Fun () -> t@1
.f@0
    .type t@2
    .regs t@1
    .ops
        Bytes reg0, {bytes_operand}
        Ret reg0
.entrypoint f@0
"""


def test_bytes_opcode_loads_the_bytes_pool_like_hl2c():
    # Haxe's hl2c output for a resource holding "text res\n": the array is named after the
    # MD5 of its contents' MD5 hex digest, and OBytes loads that array.
    code = AsmFile(_program(5, 'x"74657874207265730a00"')).assemble()
    c = code_to_c(code)
    assert "vbyte bytes$2ff34d4[] = {116,101,120,116,32,114,101,115,10,0};" in c
    assert "r0 = bytes$2ff34d4;" in c


def test_bytes_opcode_before_version_5_loads_the_string_as_utf8():
    code = AsmFile(_program(4, "b@0", '.strings\n    "h\\u{e9}"')).assemble()
    assert 'r0 = (vbyte*)"h\\303\\251";' in code_to_c(code)
