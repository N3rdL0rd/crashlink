from io import BytesIO
from types import SimpleNamespace

import pytest

pytest.importorskip("capstone")
pytest.importorskip("lief")

from crashlink.core import Bytecode, Function, Opcode, fIndex
from crashlink.dehlc import emit
from crashlink.dehlc.binary import HLCBinary, _SymView
from crashlink.dehlc.emit import EmitContext, RecoveredOpcode, emit_function, emit_image, format_recovered_ops
from crashlink.dehlc.lift import LiftedOp
from crashlink.hlc import code_to_c, code_to_c_files
from crashlink.opcodes import conditionals, opcodes


class NativeImage(HLCBinary):
    def __init__(self, path=None, data=None):
        self.PTR = 8
        self.arch = "x86_64"
        table = _SymView("hl_functions_ptrs", 0x100, 8 * 8, "PROGBITS")
        function = _SymView("f$7", 0x200, 8, "PROGBITS")
        self.symbols_by_name = {table.name: table, function.name: function}
        self.symbols_by_addr = {table.value: [table], function.value: [function]}

    def read_ptr(self, address: int) -> int:
        return 0x200 if address == 0x100 + 7 * 8 else 0


def context():
    code = Bytecode.create_empty()
    code.functions = []
    code.natives = []
    ctx = EmitContext(code, NativeImage())
    ctx.global_index = {"g$0": 0}
    return code, ctx


def roundtrip(ops):
    wire = BytesIO(b"".join(op.serialise() for op in ops))
    restored = [Opcode().deserialise(wire) for _ in ops]
    assert wire.read() == b""
    assert [op.op for op in restored] == [op.op for op in ops]
    assert b"".join(op.serialise() for op in restored) == wire.getvalue()
    return restored


@pytest.mark.parametrize("arity", [4, 5, 8])
def test_calls_preserve_every_argument_in_canonical_schema(arity):
    _, ctx = context()
    ctx.arity_of = lambda _: arity
    ops = emit_function(ctx, [LiftedOp("Call", {"target_addr": 0x200}, 0x250), LiftedOp("Ret", {}, 0x260)])
    restored = roundtrip(ops)
    call = restored[0]
    assert set(call.df) == set(opcodes[call.op])
    if arity > 4:
        assert call.op == "CallN"
        assert len(call.df["args"].value) == arity
    else:
        assert call.op == "Call4"
        assert all(f"arg{i}" in call.df for i in range(arity))
    assert restored[1].op == "Ret"


@pytest.mark.parametrize("name", conditionals)
def test_conditional_schema_including_single_register_branches(monkeypatch, name):
    _, ctx = context()
    monkeypatch.setattr(emit, "cc_to_opcode", lambda cc, imm: name)
    ops = emit_function(
        ctx, [LiftedOp("JIfS", {"cc": "ne", "imm": True, "target": 0x20}, 0x10), LiftedOp("Ret", {}, 0x20)]
    )
    restored = roundtrip(ops)
    assert restored[0].op == name
    assert set(restored[0].df) == set(opcodes[name])
    assert restored[0].df["offset"].value == 0


def test_emitted_families_are_schema_valid_and_keep_unknowns():
    _, ctx = context()
    ctx.arity_of = lambda _: 0
    ctx.native_findex = {"foo": 7}
    names = [
        "Int",
        "Float",
        "New",
        "CallMethod",
        "Call",
        "CallVirtual",
        "Prim:throw",
        "Prim:foo",
        "GetGlobal",
        "SetGlobal",
        "StoreField",
        "LoadField",
        "GetThis",
        "SetThis",
        "JIfS",
        "JIfU",
        "JAlways",
        "Bool",
        "Ret",
        "Throw",
        "Null",
        "InstanceClosure",
        "SafeCast",
        "ToVirtual",
        "CallClosure",
        *emit._ARITH_OPS,
    ]
    events = [
        LiftedOp(name, {"value": 42, "target_addr": 0x200, "gidx": "g$0", "target": 0x1000}, 0x1000 + i * 4)
        for i, name in enumerate(names)
    ]
    ops = emit_function(ctx, events)
    assert len(ops) == len(events)
    roundtrip(ops)
    for op, event in zip(ops, events):
        assert isinstance(op, RecoveredOpcode)
        assert op.src_addr == event.src_addr
        assert op.source_op == event.op
        assert op.source_args == event.args
    text = format_recovered_ops(ops)
    assert "dst=?" in text
    assert "field=?" in text
    assert "offset=?" in text
    assert "[heuristic]" in text
    assert "0x1000" in text
    boolean = ops[names.index("Bool")]
    assert isinstance(boolean, RecoveredOpcode)
    assert boolean.unknown_operands["value"]


def test_emission_keeps_native_bodies_inspection_only(monkeypatch):
    code, _ = context()
    fn = Function()
    fn.findex = fIndex(7)
    code.functions = [fn]
    events = [LiftedOp("Ret", {}, 0x200)]
    monkeypatch.setattr(emit, "_resolve_plt_targets", lambda image: {})
    assert emit_image(code, NativeImage(), lifter=SimpleNamespace(lift=lambda addr: events)) == 1
    assert fn.ops == []
    assert 7 in code.recovery_opcodes
    assert code.recovery_lifts[7] == events
    with pytest.raises(ValueError, match="[Ii]nspection.only"):
        code.serialise()


@pytest.mark.parametrize("generate", [code_to_c, lambda code: code_to_c_files(code, 2)])
def test_native_c_generation_is_rejected_before_generation(generate):
    code, _ = context()
    with pytest.raises(ValueError, match="[Ii]nspection.only"):
        generate(code)


def test_cli_recovery_export_does_not_overwrite_existing_file(tmp_path, capsys):
    from crashlink.__main__ import Commands

    code, _ = context()
    dest = tmp_path / "existing"
    dest.write_bytes(b"original")
    commands = Commands(code)
    commands.save([str(dest)])
    commands.hlc([str(dest)])
    assert dest.read_bytes() == b"original"
    assert "Inspection-only" in capsys.readouterr().out


def test_cli_lift_does_not_attach_guessed_dataflow(monkeypatch, capsys):
    from crashlink.__main__ import Commands
    from crashlink.dehlc import binary
    from crashlink.dehlc.lift import FunctionLifter

    code, _ = context()
    fn = Function()
    fn.findex = fIndex(7)
    code.functions = [fn]
    code.hlc_binary = NativeImage()
    code.recovery_lifts = {}
    code.recovery_opcodes = {}
    original_regs = list(fn.regs)
    monkeypatch.setattr(binary, "_resolve_plt_targets", lambda image: {})
    monkeypatch.setattr(
        FunctionLifter,
        "for_binary",
        lambda *args: SimpleNamespace(
            lift=lambda addr: [LiftedOp("Int", {"value": 9}, addr), LiftedOp("Ret", {}, addr + 4)]
        ),
    )
    Commands(code).decomp(["7"])
    text = capsys.readouterr().out
    assert "dst=?" in text
    assert "ret=?" in text
    assert "0x200" in text
    assert fn.ops == []
    assert fn.regs == original_regs


def test_recovery_progress_cancellation_stops_before_next_pass(monkeypatch):
    from crashlink.dehlc import reconstruct

    monkeypatch.setattr(reconstruct, "HLCBinary", NativeImage)
    cancelled = RuntimeError("cancelled by caller")

    def cancel(status):
        raise cancelled

    def unexpected_analysis(image):
        pytest.fail("Recovery continued after caller cancelled the progress callback")

    monkeypatch.setattr(reconstruct, "analyse_init_types", unexpected_analysis)
    with pytest.raises(RuntimeError) as error:
        reconstruct.code_from_bin(data=b"native", progress_cb=cancel)
    assert error.value is cancelled


def test_native_recovery_cannot_bypass_cli_guard_through_ir_api():
    from crashlink.decomp import IRFunction

    code, _ = context()
    with pytest.raises(ValueError, match="Inspection-only"):
        IRFunction(code, Function())
