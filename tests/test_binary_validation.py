from io import BytesIO

import pytest

from crashlink.asm import AsmFile
from crashlink.core import (
    Bytecode,
    BytesBlock,
    DebugInfo,
    Fun,
    Function,
    Opcode,
    Reg,
    SerialisableInt,
    StringsBlock,
    Type,
    VarInt,
    fIndex,
    intRef,
    tIndex,
)
from crashlink.errors import InvalidOpCode, MalformedBytecode


@pytest.mark.parametrize(
    "data,byteorder,signed,expected",
    [
        (b"\xff\0\0\0", "little", True, 255),
        (b"\0\0\xff\0", "big", False, 65280),
        (b"\xff\xff\xff\xff", "little", True, -1),
    ],
)
def test_fixed_integer_preserves_width(data, byteorder, signed, expected):
    value = SerialisableInt().deserialise(BytesIO(data), byteorder=byteorder, signed=signed)
    assert value.value == expected
    assert value.serialise() == data


def test_every_truncation_of_empty_image_is_rejected():
    data = Bytecode.create_empty().serialise()
    for end in range(len(data)):
        with pytest.raises(MalformedBytecode):
            Bytecode.from_bytes(data[:end], search_magic=False)


@pytest.mark.parametrize("data", [b"", b"\x80", b"\xc0\0\0"])
def test_truncated_varints_are_malformed(data):
    with pytest.raises(MalformedBytecode):
        VarInt().deserialise(BytesIO(data))


def test_negative_pool_integer_roundtrips_as_word():
    code = Bytecode.create_empty()
    index = code.add_i32(-1)
    restored = Bytecode.from_bytes(code.serialise())
    assert restored.ints[index.value].value == 0xFFFFFFFF


def test_negative_assembled_integer_roundtrips():
    source = """.version 5
.types
    I32
.f@0
    .returns t@1
    .regs
        t@1
    .ops
        Int reg0, -1
        Ret reg0
.entrypoint f@0
"""
    code = AsmFile(source).assemble()
    restored = Bytecode.from_bytes(code.serialise())
    assert restored.ints[0].value == 0xFFFFFFFF


def test_operand_dictionary_order_cannot_change_instruction():
    op = Opcode("Mov", {"src": Reg(1), "dst": Reg(2)})
    restored = Opcode().deserialise(BytesIO(op.serialise()))
    assert restored.df["src"].value == 1
    assert restored.df["dst"].value == 2


@pytest.mark.parametrize(
    "operands",
    [{"dst": Reg(0)}, {"dst": Reg(0), "src": Reg(1), "extra": Reg(2)}, {"dst": Reg(0), "src": 1}],
)
def test_invalid_opcode_schema_is_rejected(operands):
    with pytest.raises(InvalidOpCode):
        Opcode("Mov", operands).serialise()


def test_negative_opcode_number_is_not_python_indexing():
    with pytest.raises(InvalidOpCode):
        Opcode().deserialise(BytesIO(VarInt(-1).serialise() + b"\0"))


def test_declared_count_cannot_exceed_input():
    code = Bytecode.from_bytes(Bytecode.create_empty().serialise())
    blob = code.serialise()
    offset = code.section_offsets["ntypes"]
    for count in (-1, 1000000):
        malformed = blob[:offset] + VarInt(count).serialise() + blob[offset + 1 :]
        with pytest.raises(MalformedBytecode):
            Bytecode.from_bytes(malformed)


def test_invalid_pool_ranges_are_rejected():
    with pytest.raises(MalformedBytecode):
        StringsBlock().deserialise(BytesIO(b"\1\0\0\0\0" + VarInt(-1).serialise()), 1)
    with pytest.raises(MalformedBytecode):
        BytesBlock().deserialise(BytesIO(b"\2\0\0\0ab\0\3"), 2)


def test_debug_info_cannot_be_truncated_or_overrun():
    with pytest.raises(MalformedBytecode):
        DebugInfo().deserialise(BytesIO(b"\1"), 1)
    with pytest.raises(MalformedBytecode):
        DebugInfo().deserialise(BytesIO(bytes([2 | (2 << 2)])), 1)


def _code_with_op(op):
    code = Bytecode.create_empty()
    signature = Type()
    signature.kind.value = Type.Kind.FUN.value
    signature.definition = Fun()
    code.types.append(signature)
    function = Function()
    function.type = tIndex(len(code.types) - 1)
    function.findex = fIndex(0)
    function.regs = [tIndex(0)]
    function.ops = [op, Opcode("Ret", {"ret": Reg(0)})]
    function.has_debug = False
    code.functions.append(function)
    code.set_meta()
    return code


@pytest.mark.parametrize(
    "op",
    [
        Opcode("Mov", {"dst": Reg(0), "src": Reg(1)}),
        Opcode("Int", {"dst": Reg(0), "ptr": intRef(0)}),
        Opcode("Call0", {"dst": Reg(0), "fun": fIndex(99)}),
        Opcode("JAlways", {"offset": VarInt(99)}),
    ],
)
def test_invalid_references_fail_validation_and_serialization(op):
    code = _code_with_op(op)
    assert not code.is_ok()
    with pytest.raises(MalformedBytecode):
        code.serialise()


def test_invalid_register_in_binary_is_rejected_before_analysis():
    code = _code_with_op(Opcode("Mov", {"dst": Reg(0), "src": Reg(0)}))
    blob = code.serialise()
    with pytest.raises(MalformedBytecode):
        Bytecode.from_bytes(blob[:-1] + b"\x63")
