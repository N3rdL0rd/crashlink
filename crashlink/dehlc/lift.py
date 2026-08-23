"""
Shape-level opcode lifting for HL/C binaries (experimental).

Turns compiled function bodies back into abstract operation streams - a "lift"
in the same direction the decompiler's opcode->IR pipeline assumes, one tier
below it: instead of source text, we recover *opcode-family sequences*
(Int, Call2, New, SetField, JIf, Ret ...) from machine-code patterns.

Design contract (mirrors crashlink.decomp.ir's extensibility rules):

1. `LiftedOp` is the event model. It deliberately mirrors `core.Opcode`'s shape
   (`op` name + payload dict) so lifted streams can later be materialised into
   real opcodes without renaming anything.

2. Behaviour lives in `LiftRule` subclasses, never in the dispatcher. Adding
   support for a new pattern = define a rule and register it; existing rules are
   untouched. Rules are ordered: first match wins, so more specific rules
   register before general fallbacks.

3. `LiftContext` bundles everything a rule may need (instruction stream access,
   call-target resolution, memory-operand helpers, ABI-noise classification)
   so rules stay declarative and independently testable.

4. Architecture backends subclass `FunctionLifter` and supply their rule set;
   the dispatch loop itself is architecture-neutral.

Nothing here feeds `dehlc.code_from_bin` yet by default - use it through the
measurement harness (local/dehlc-tests/lift_ops.py) while fidelity is being
evaluated.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, Type

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from capstone.x86 import X86_OP_IMM as X86_OP_IMM
from capstone.x86 import X86_OP_MEM as X86_OP_MEM
from capstone.x86 import X86_OP_REG as X86_OP_REG

from .binary import HLCBinary


# ---------------------------------------------------------------------------
# Event model
# ---------------------------------------------------------------------------


@dataclass
class LiftedOp:
    """
    One abstract operation recovered from machine code.

    `op` uses HL opcode-family names when the mapping is direct ("Int", "New",
    "SetField", ...), or namespaced tags when the concept has no single HL
    opcode ("Prim:<name>" for libhl primitive calls, "ABI" placeholders are
    filtered out before emission).
    """

    op: str
    args: Dict[str, Any] = field(default_factory=dict)
    src_addr: int = 0  # provenance: address of the instruction that produced it

    def __repr__(self) -> str:
        payload = ",".join(f"{k}={v}" for k, v in self.args.items())
        return f"{self.op}({payload})" if payload else self.op


# ---------------------------------------------------------------------------
# Per-function context handed to rules
# ---------------------------------------------------------------------------


class LiftContext:
    """Decoding + resolution services for one function under lift."""

    def __init__(
        self,
        bin_view: HLCBinary,
        addr: int,
        insns: list,
        index: int,
        plt_map: Dict[int, str],
        out: List[LiftedOp],
    ):
        self.bin_view = bin_view
        self.addr = addr  # function entry
        self.insns = insns
        self.index = index  # current instruction index
        self.plt_map = plt_map
        self.out = out  # shared output stream

        from capstone.x86 import X86_REG_EBP, X86_REG_ESP, X86_REG_RBP, X86_REG_RSP

        self._spill_bases = {X86_REG_RSP, X86_REG_RBP, X86_REG_ESP, X86_REG_EBP}

    # -- instruction access -------------------------------------------------

    @property
    def insn(self):
        return self.insns[self.index]

    @property
    def mnemonic(self) -> str:
        return self.insns[self.index].mnemonic

    @property
    def ops(self):
        return self.insns[self.index].operands

    def peek(self, ahead: int = 1):
        """Instruction at +ahead positions, or None."""
        j = self.index + ahead
        return self.insns[j] if 0 <= j < len(self.insns) else None

    # -- operand helpers ----------------------------------------------------

    def resolve_mem(self, mem_op) -> Optional[int]:
        """Absolute address of a rip-relative / absolute memory operand."""
        from .binary import _resolve_mem_target

        return _resolve_mem_target(self.insn, mem_op)

    def is_spill_slot(self, mem_op) -> bool:
        """True when the operand addresses an ABI spill slot rather than a field."""
        try:
            return mem_op.mem.base in self._spill_bases
        except Exception:
            return False

    def call_target_name(self) -> Optional[str]:
        """Resolved symbol name of this instruction's direct call target."""
        target = None
        for op in self.ops:
            if op.type == X86_OP_IMM:
                target = op.imm
                break
        if target is None:
            return None
        return self.plt_map.get(target) or self.bin_view.symbol_at(target)

    def read_float_at(self, addr: int, size: int) -> Optional[float]:
        import struct as _struct

        raw = self.bin_view.read_bytes(addr, size)
        if len(raw) < size:
            return None
        try:
            return _struct.unpack("<d" if size == 8 else "<f", raw[:size])[0]
        except _struct.error:
            return None

    # -- emission ------------------------------------------------------------

    def emit(self, op: str, src_addr: int = 0, **args: Any) -> None:
        self.out.append(LiftedOp(op=op, args=args, src_addr=src_addr))


# ---------------------------------------------------------------------------
# Rule framework
# ---------------------------------------------------------------------------


class LiftRule(ABC):
    """
    One liftable machine pattern.

    Subclasses declare the mnemonics they handle (`MNEMONICS`) and implement
    `apply`. Return True from `apply` when the instruction was consumed;
    returning False falls through to later rules.
    """

    MNEMONICS: Tuple[str, ...] = ()

    def handles(self, mnemonic: str) -> bool:
        return mnemonic in self.MNEMONICS

    @abstractmethod
    def apply(self, ctx: LiftContext) -> bool: ...


def rule(*mnemonics: str) -> Callable[[Type["LiftRule"]], Type["LiftRule"]]:
    """Class decorator registering a rule's handled mnemonics."""

    def wrap(cls: Type["LiftRule"]) -> Type["LiftRule"]:
        cls.MNEMONICS = tuple(mnemonics)
        return cls

    return wrap


class NoiseRule(LiftRule):
    """Base for rules that consume compiler/ABI noise without emitting ops."""


# ---------------------------------------------------------------------------
# x86-64 rules (ordered: specific -> general)
# ---------------------------------------------------------------------------


@rule("call")
class CallRule(LiftRule):
    """Direct calls resolve to New/Ref for allocator prims, Prim:* for other
    libhl imports, and plain Call for module functions."""

    def apply(self, ctx: LiftContext) -> bool:
        name = ctx.call_target_name()
        if name is None:
            ctx.emit("Call?", src_addr=ctx.insn.address)
            return True
        if name.startswith("hl_"):
            prim = name[3:]
            mapped = {
                "alloc_obj": "New",
                "alloc_dynobj": "New",
                "alloc_array": "New",
                "alloc_closure_ptr": "Ref",
                "get_virtual_value": "CallVirtual",
            }.get(prim)
            if mapped:
                ctx.emit(mapped, src_addr=ctx.insn.address, prim=prim)
            else:
                ctx.emit(f"Prim:{prim}", src_addr=ctx.insn.address)
            return True
        ctx.emit("Call", src_addr=ctx.insn.address, target=name)
        return True


@rule("jmp")
class JmpRule(LiftRule):
    def apply(self, ctx: LiftContext) -> bool:
        ctx.emit("JAlways", src_addr=ctx.insn.address)
        return True


@rule(
    "je",
    "jne",
    "js",
    "jns",
    "jg",
    "jge",
    "jl",
    "jle",
    "ja",
    "jae",
    "jb",
    "jbe",
)
class CondBranchRule(LiftRule):
    """Conditional branches; comparison signedness survives in the condition code."""

    SIGNED = {"e", "ne", "s", "ns", "g", "ge", "l", "le"}

    def apply(self, ctx: LiftContext) -> bool:
        cc = ctx.mnemonic[1:]
        kind = "JIfS" if cc in self.SIGNED else "JIfU"
        ctx.emit(kind, src_addr=ctx.insn.address, cc=cc)
        return True


@rule("ret")
class RetRule(LiftRule):
    def apply(self, ctx: LiftContext) -> bool:
        ctx.emit("Ret", src_addr=ctx.insn.address)
        return True


@rule("movsd", "movss")
class FloatLoadRule(LiftRule):
    """SSE loads from rodata materialise float literals."""

    def apply(self, ctx: LiftContext) -> bool:
        if len(ctx.ops) != 2 or ctx.ops[1].type != X86_OP_MEM:
            return False
        tgt = ctx.resolve_mem(ctx.ops[1])
        if tgt is not None and not ctx.is_spill_slot(ctx.ops[1]):
            val = ctx.read_float_at(tgt, 8 if ctx.mnemonic == "movsd" else 4)
            if val is not None:
                ctx.emit("Float", src_addr=ctx.insn.address, value=val)
                return True
        return False


@rule("xorps", "xorpd", "pxor")
class FloatZeroRule(LiftRule):
    """Zeroing a vector register is how 0.0 gets materialised."""

    def apply(self, ctx: LiftContext) -> bool:
        if len(ctx.ops) == 2 and ctx.ops[0].type == X86_OP_REG and ctx.ops[0].reg == ctx.ops[1].reg:
            ctx.emit("Float", src_addr=ctx.insn.address, value=0.0)
            return True
        return False


@rule("cmp", "test")
class CompareImmRule(LiftRule):
    """Immediate comparisons carry Int constants feeding branches."""

    def apply(self, ctx: LiftContext) -> bool:
        for op in ctx.ops:
            if op.type == X86_OP_IMM:
                ctx.emit("Int", src_addr=ctx.insn.address, value=op.imm)
                return True
        return False


@rule("mov")
class MovRule(LiftRule):
    """Splits into immediate loads, field traffic, vreg shuffles and copies.

    Register allocation noise ([rsp+N] slots, reg-to-reg moves that only feed
    spills) is consumed silently so the lifted stream reflects semantics.
    """

    def apply(self, ctx: LiftContext) -> bool:
        if len(ctx.ops) != 2:
            return False
        dst, src = ctx.ops
        # immediate -> register: pool-style constant
        if src.type == X86_OP_IMM and dst.type == X86_OP_REG:
            ctx.emit("Int", src_addr=ctx.insn.address, value=src.imm)
            return True
        # field/array load: [base+disp] with a non-spill base
        if src.type == X86_OP_MEM and dst.type == X86_OP_REG and not ctx.is_spill_slot(src):
            disp = src.mem.disp
            ctx.emit("LoadField", src_addr=ctx.insn.address, off=disp)
            return True
        # store to field
        if dst.type == X86_OP_MEM and not ctx.is_spill_slot(dst):
            ctx.emit("StoreField", src_addr=ctx.insn.address, off=dst.mem.disp)
            return True
        # everything else is register management
        return True


@rule("lea")
class LeaRule(LiftRule):
    """Address materialisation: vreg slots are ABI, symbol addresses may be
    string/type literals. Kept minimal until literal typing lands."""

    def apply(self, ctx: LiftContext) -> bool:
        if len(ctx.ops) != 2 or ctx.ops[0].type != X86_OP_REG:
            return False
        mem = ctx.ops[1]
        if mem.type != X86_OP_MEM:
            return False
        if mem.mem.base in ctx._spill_bases:
            return True  # &r_i - consumed as noise
        tgt = ctx.resolve_mem(mem)
        sym = ctx.bin_view.symbol_at(tgt) if tgt is not None else None
        ctx.emit("LeaSym", src_addr=ctx.insn.address, sym=sym or "")
        return True


_ARITH_MAP = {
    "add": "Add",
    "sub": "Sub",
    "imul": "Mul",
    "mul": "Mul",
    "and": "And",
    "or": "Or",
    "shl": "Shl",
    "sar": "SShr",
    "shr": "UShr",
}


@rule("add", "sub", "imul", "mul", "and", "or", "shl", "sar", "shr")
class ArithRule(LiftRule):
    """Register arithmetic maps to HL arithmetic families; stack-pointer
    adjustment and reg-zeroing xors are consumed upstream/downstream."""

    def apply(self, ctx: LiftContext) -> bool:
        from capstone.x86 import X86_REG_RSP  # noqa: F401

        if len(ctx.ops) >= 1 and ctx.ops[0].type == X86_OP_REG:
            if ctx.ops[0].reg == X86_REG_RSP:
                return True  # frame adjustment
        if (
            ctx.mnemonic == "sub"
            and len(ctx.ops) == 2
            and all(o.type == X86_OP_REG for o in ctx.ops)
            and False
        ):
            pass
        fam = _ARITH_MAP.get(ctx.mnemonic)
        if fam is None:
            return False
        ctx.emit(fam, src_addr=ctx.insn.address)
        return True


@rule("xor")
class XorRule(LiftRule):
    """`xor r,r` zeroing is common idiom; treat as constant, not arithmetic."""

    def apply(self, ctx: LiftContext) -> bool:
        if len(ctx.ops) == 2 and ctx.ops[0].type == X86_OP_REG and ctx.ops[0].reg == ctx.ops[1].reg:
            ctx.emit("Int", src_addr=ctx.insn.address, value=0)
            return True
        return False


@rule("cvtsi2sd", "cvttsd2si", "cvtsi2ss", "cvtss2sd", "cvtsd2ss")
class ConvertRule(LiftRule):
    def apply(self, ctx: LiftContext) -> bool:
        ctx.emit("Convert", src_addr=ctx.insn.address, kind=ctx.mnemonic)
        return True


@rule("div", "idiv")
class DivRule(LiftRule):
    """x86 division uses RDX:RAX implicitly; HL models it as SDiv/UDiv + SMod/UMod."""

    def apply(self, ctx: LiftContext) -> bool:
        ctx.emit("Div", src_addr=ctx.insn.address, signed=ctx.mnemonic == "idiv")
        return True


_SETCC = {
    "sete",
    "setne",
    "sets",
    "setns",
    "setg",
    "setge",
    "setl",
    "setle",
    "seta",
    "setae",
    "setb",
    "setbe",
}


@rule(*_SETCC)
class SetBoolRule(LiftRule):
    """`setcc` materialises a comparison result - HL's `Bool` opcode."""

    def apply(self, ctx: LiftContext) -> bool:
        ctx.emit("Bool", src_addr=ctx.insn.address, cc=ctx.mnemonic[3:])
        return True


@rule("push", "pop", "endbr64", "nop", "cdq", "cqo", "leave", "ud2")
class PrologueNoiseRule(NoiseRule):
    """Frame management and padding consume silently."""

    def apply(self, ctx: LiftContext) -> bool:
        return True


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


class FunctionLifter:
    """
    Walks one function's instructions through the registered rule chain.

    Subclass per architecture and override `build_rules` / `_decode`. The loop
    below never changes: rules own the semantics.
    """

    md: Any  # capstone engine, set by architecture subclasses
    RULES: List[LiftRule] = [
        FloatZeroRule(),  # before Arith/Xor fallbacks
        FloatLoadRule(),
        CallRule(),
        CondBranchRule(),
        JmpRule(),
        RetRule(),
        CompareImmRule(),
        ConvertRule(),
        SetBoolRule(),
        DivRule(),
        XorRule(),
        MovRule(),
        LeaRule(),
        ArithRule(),
        PrologueNoiseRule(),
    ]

    def __init__(
        self,
        bin_view: HLCBinary,
        plt_map: Optional[Dict[int, str]] = None,
        rules: Optional[List[LiftRule]] = None,
        size_of: Optional[Callable[[int], int]] = None,
    ):
        self.bin_view = bin_view
        self.plt_map = plt_map if plt_map is not None else {}
        self.rules = rules if rules is not None else list(self.RULES)
        # Optional authoritative body-size source (e.g. derived from the module
        # function table), preferred over symbol-table sizes which can be
        # misleading when alias symbols sit adjacent to the entry point.
        self.size_of = size_of

    @staticmethod
    def for_binary(
        bin_view: HLCBinary,
        plt_map: Optional[Dict[int, str]] = None,
        size_of: Optional[Callable[[int], int]] = None,
    ) -> "FunctionLifter":
        """Architecture dispatch point - extend as new backends land."""
        if bin_view.arch in ("x86_64", "x86"):
            md_mode = CS_MODE_32 if bin_view.arch == "x86" else CS_MODE_64
            return X86FunctionLifter(bin_view, plt_map, md_mode, size_of=size_of)
        raise NotImplementedError(f"no lifting backend for arch {bin_view.arch!r}")

    def decode(self, addr: int, max_bytes: int = 65536) -> list:
        if self.size_of is not None:
            size = self.size_of(addr)
        else:
            sym_name = self.bin_view.symbol_at(addr)
            sym = self.bin_view.symbol(sym_name) if sym_name else None
            size = min(sym.size, max_bytes) if sym is not None and sym.size else 2048
        if size <= 0:
            size = 2048
        code = self.bin_view.read_bytes(addr, min(size, max_bytes))
        return list(self.md.disasm(code, addr))

    def lift(self, addr: int) -> List[LiftedOp]:
        insns = self.decode(addr)
        out: List[LiftedOp] = []
        ctx = LiftContext(self.bin_view, addr, insns, 0, self.plt_map, out)
        for i, _insn in enumerate(insns):
            ctx.index = i
            for rl in self.rules:
                if rl.handles(ctx.mnemonic):
                    if rl.apply(ctx):
                        break
            # no rule matched -> instruction ignored (conservative)
        return out


class X86FunctionLifter(FunctionLifter):
    def __init__(
        self,
        bin_view: HLCBinary,
        plt_map: Optional[Dict[int, str]],
        mode: int,
        size_of: Optional[Callable[[int], int]] = None,
    ):
        super().__init__(bin_view, plt_map, size_of=size_of)
        from capstone import Cs  # noqa: F401

        self.md = Cs(CS_ARCH_X86, mode)
        self.md.detail = True
