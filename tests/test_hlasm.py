import math
import os
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from crashlink.asm import AsmError, AsmFile, to_hlasm
from crashlink.core import Bytecode, Function, Packed, Struct

HAXE_DIR = Path(__file__).parent / "haxe"


def _fn(code: Bytecode, findex: int) -> Function:
    func = code.fn(findex)
    assert isinstance(func, Function)
    return func


def _roundtrip(code: Bytecode) -> bytes:
    return AsmFile(to_hlasm(code)).assemble().serialise()


@pytest.mark.parametrize("name", ["Clazz", "Closure", "Anonymous", "CatchOrder", "BigControlFlow"])
def test_compiled_images_roundtrip_byte_for_byte(name):
    # Real images exercise objects, enums, virtuals, constants, debug info and assigns.
    code = Bytecode.from_path(str(HAXE_DIR / f"{name}.hl"))
    assert _roundtrip(code) == code.serialise()


PROGRAM = r""".version 5

.debugfiles
    "Main.hx"

.types
    Bytes                          # t@1
    I32                            # t@2
    Fun (t@1) -> t@0               # t@3: sys_print
    Fun (t@2, t@2, t@2) -> t@2     # t@4: sum3
    Fun () -> t@0                  # t@5: main
    Ref t@2                        # t@6
    Fun (t@2, t@6) -> t@1          # t@7: itos
    .obj "Point"                   # t@8
        .global g@0
        .fields
            "x" t@2
            "y" t@2

.globals
    t@8

.natives
    f@1 (t@3) "std" "sys_print"
    f@3 (t@7) std.itos

.f@2
    .type t@4
    .regs t@2 t@2 t@2 t@2
    .ops
        Add reg3, reg0, reg1   @"Main.hx":3
        Add reg3, reg3, reg2
        Ret reg3

.f@0
    .type t@5
    .regs t@0 t@1 t@2 t@2 t@2 t@2 t@8 t@2 t@6 t@2
    .assigns
        "i" 2
    .ops
        Int reg2, 0                              @0:10
        Int reg3, 3
        Int reg5, 1
        .label loop
        Label
        Switch reg2, [zero, one], print          @0:11
        CallN reg4, f@2, [reg2, reg3, reg5]
        Ref reg8, reg9
        Call2 reg1, f@3, reg4, reg8
        Call1 reg0, f@1, reg1
        Bytes reg1, x"0a000000"                  # "\n" as UTF-16, NUL-terminated
        JAlways print
        .label zero
        String reg1, "zero\t\"q\" #kept\n"
        JAlways print
        .label one
        String reg1, "one \u{e9}\n"
        .label print
        Call1 reg0, f@1, reg1                    @0:12
        Add reg2, reg2, reg5
        JSLt reg2, reg3, loop
        GetGlobal reg6, g@0
        Field reg7, reg6, 1
        Ref reg8, reg9
        Call2 reg1, f@3, reg7, reg8
        Call1 reg0, f@1, reg1
        Ret reg0

.constants
    g@0 i@0 i@1

.ints
    7
    -42

.entrypoint f@0
"""


def test_handwritten_program_assembles_with_labels_positions_and_pools():
    code = AsmFile(PROGRAM).assemble()
    main = _fn(code, 0)
    ops = main.ops
    switch = next(op for op in ops if op.op == "Switch")
    idx = ops.index(switch)
    # Labels resolve to offsets relative to the next opcode.
    targets = [idx + 1 + off.value for off in switch.df["offsets"].value]
    assert [ops[t].op for t in targets] == ["String", "String"]
    assert ops[idx + 1 + switch.df["end"].value].op == "Call1"
    back = next(op for op in ops if op.op == "JSLt")
    assert ops[ops.index(back) + 1 + back.df["offset"].value].op == "Label"
    # Escapes decode, and a '#' inside a string is not a comment.
    assert 'zero\t"q" #kept\n' in code.strings.value
    assert "one \u00e9\n" in code.strings.value
    assert code.bytes is not None and code.bytes.value == [b"\n\x00\x00\x00"]
    # Debug positions carry forward to later opcodes; a file can be named instead of indexed.
    assert main.debuginfo is not None
    lines = [ref.line for ref in main.debuginfo.value]
    assert lines[:4] == [10, 10, 10, 10] and lines[idx] == 11 and lines[-1] == 12
    sum3_debug = _fn(code, 2).debuginfo
    assert sum3_debug is not None and sum3_debug.value[0].value == 0
    assert code.initialized_globals[0] == {"x": 7, "y": 0xFFFFFFD6}
    assert _roundtrip(code) == code.serialise()


@pytest.mark.skipif(
    not (os.environ.get("HL_RUNTIME") or shutil.which("hl")), reason="needs a HashLink runtime"
)
def test_handwritten_program_runs(tmp_path):
    out = tmp_path / "program.hl"
    out.write_bytes(AsmFile(PROGRAM).assemble().serialise())
    runtime = os.environ.get("HL_RUNTIME") or shutil.which("hl") or "hl"
    result = subprocess.run([runtime, str(out)], capture_output=True, timeout=30, check=True)
    assert result.stdout.decode() == 'zero\t"q" #kept\none \u00e9\n6\n-42'


def test_every_type_kind_and_float_bits_roundtrip():
    source = """.version 4
.types novoid
    Void                        # t@0
    I32                         # t@1
    GUID                        # t@2
    DynObj                      # t@3
    Null t@1                    # t@4
    Abstract "hl_tls"           # t@5
    Method (t@1) -> t@0         # t@6
    .struct "Pair"              # t@7
        .fields
            "a" t@1
    Packed t@7                  # t@8
    Fun () -> t@0               # t@9
.floats
    nan
    -0.0
    -inf
    f64:0x7ff0000000000001
    1e300
.f@0
    .type t@9
    .regs t@0
    .ops
        Ret reg0
.entrypoint f@0
"""
    code = AsmFile(source).assemble()
    assert isinstance(code.types[7].definition, Struct)
    assert isinstance(code.types[8].definition, Packed)
    bits = [struct.pack("<d", f.value) for f in code.floats]
    assert bits[3] == struct.pack("<Q", 0x7FF0000000000001)
    assert math.copysign(1.0, code.floats[1].value) == -1.0
    assert _roundtrip(code) == code.serialise()


@pytest.mark.parametrize(
    ("ops", "message"),
    [
        ("JAlways nowhere", "Unknown label 'nowhere'"),
        ("Mov reg0", "Mov takes 2 operand(s)"),
        ('String reg0, "unterminated', "Unterminated string literal"),
        ("Ret reg0 @0:1", "Debug positions need a '.debugfiles' section"),
    ],
)
def test_errors_name_the_line(ops, message):
    source = f""".version 4
.types
    Fun () -> t@0
.f@0
    .type t@1
    .regs t@0
    .ops
        {ops}
.entrypoint f@0
"""
    with pytest.raises(AsmError) as err:
        AsmFile(source).assemble()
    assert message in str(err.value)
    assert err.value.line == 8


def test_asm_register_operand_is_biased_by_one():
    # Asm's reg operand is the VM register plus one (0 = none), so a naked function
    # with no registers is valid bytecode.
    source = """.version 4
.types
    I32
    Fun (t@1) -> t@1
    Fun () -> t@1
.f@0
    .type t@2
    .regs t@1
    .ops
        Asm 2, 0, reg1
        Ret reg0
.f@1
    .type t@3
    .regs
    .ops
        AsmNaked
        AsmByte 0xC3
.entrypoint f@1
"""
    code = AsmFile(source).assemble()
    assert _fn(Bytecode.from_bytes(code.serialise()), 1).ops[0].op == "Asm"
