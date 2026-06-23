from glob import glob

import pytest

from crashlink import *

from crashlink.opcodes import opcodes

test_files = glob("tests/haxe/*.hl")


def _make_test_code():
    """Build a minimal valid Bytecode for pseudo_from_op smoke tests."""
    code = Bytecode.create_empty(no_extra_types=False, version=5)
    code.strings.value.append("test")
    code.ints.append(SerialisableInt())
    code.ints[-1].value = 0
    code.floats.append(SerialisableF64())
    code.floats[-1].value = 0.0
    code.bytes.value.append(b"")
    code.global_types.append(tIndex(0))
    code.nglobals.value = 1

    func = Function()
    func.findex.value = 0
    func.type = tIndex(0)
    func.regs = [tIndex(0)]
    func.version = code.version.value
    func.has_debug = False
    code.functions.append(func)
    code.invalidate_findex_cache()

    obj_def = Obj()
    obj_def.name = strRef(0)
    obj_def.super = tIndex()
    obj_def.super.value = -1
    obj_def._global = gIndex()
    obj_def._global.value = 0
    obj_def.nfields.value = 1
    obj_def.nprotos.value = 0
    obj_def.nbindings.value = 0
    field = Field()
    field.name = strRef(0)
    field.type = tIndex(1)
    obj_def.fields = [field]
    obj_def.protos = []
    obj_def.bindings = []

    obj_type = Type()
    obj_type.kind.value = Type.Kind.OBJ.value
    obj_type.definition = obj_def
    code.types.append(obj_type)
    code.invalidate_proto_field_cache()

    return code


def _make_operand(param_type):
    if param_type == "Regs":
        regs = Regs()
        regs.value.append(Reg(0))
        return regs
    if param_type == "InlineBool":
        b = InlineBool()
        b.value = True
        return b
    if param_type == "JumpOffsets":
        offsets = VarInts()
        offsets.value.append(VarInt(0))
        return offsets
    return {
        "Reg": Reg(0),
        "RefInt": intRef(0),
        "RefFloat": floatRef(0),
        "RefBytes": bytesRef(0),
        "RefString": strRef(0),
        "RefFun": fIndex(0),
        "RefField": fieldRef(0),
        "RefGlobal": gIndex(0),
        "JumpOffset": VarInt(0),
        "RefType": tIndex(0),
        "RefEnumConstant": VarInt(0),
        "RefEnumConstruct": VarInt(0),
        "InlineInt": VarInt(0),
    }[param_type]


def test_pseudo_from_op_all_opcodes():
    """Every opcode except Prefetch and Asm must have a non-default pseudo handler."""
    code = _make_test_code()
    obj_reg = tIndex(len(code.types) - 1)
    regs = [obj_reg]

    func = Function()
    func.regs = [obj_reg]

    skipped = {"Prefetch", "Asm"}
    for name, df in opcodes.items():
        if name in skipped:
            continue
        op = Opcode()
        op.op = name
        op.df = {param: _make_operand(param_type) for param, param_type in df.items()}
        out = disasm.pseudo_from_op(op, 0, regs, code, func=func)
        assert not out.startswith("unknown operation"), f"{name} fell through to default pseudo handler"


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
