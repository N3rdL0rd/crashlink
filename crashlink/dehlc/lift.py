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
        # Per-backend state hooks: x86 keeps none; aarch64 tracks adrp/add
        # resolved addresses per register (see ARM64LiftContext.track).
        self.reg_addr: Dict[int, int] = {}

    def track(self) -> None:
        """Per-instruction backend bookkeeping; called before rule dispatch."""

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
        target = self.call_target_addr()
        if target is None:
            return None
        return self.plt_map.get(target) or self.bin_view.symbol_at(target)

    def call_target_addr(self) -> Optional[int]:
        """Absolute target address of this call - direct immediate or indirect
        through an import/GOT memory operand."""
        for op in self.ops:
            if op.type == X86_OP_IMM:
                return op.imm
            if op.type == X86_OP_MEM:
                from .binary import _resolve_mem_target

                return _resolve_mem_target(self.insn, op)
        return None

    def branch_target(self) -> Optional[int]:
        """Absolute target of this relative branch. Capstone already normalises
        x86 branch immediates to absolute addresses."""
        for op in self.ops:
            if op.type == X86_OP_IMM:
                return op.imm
        return None

    def resolve_mem_sym(self, mem_op) -> Optional[str]:
        """Symbol name of a memory operand's effective address (globals,
        string/type table slots, rodata literals)."""
        tgt = self.resolve_mem(mem_op)
        if tgt is None:
            return None
        return self.bin_view.symbol_at(tgt)

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

    def apply(self, ctx: LiftContext) -> bool:
        return True


# ---------------------------------------------------------------------------
# x86-64 rules (ordered: specific -> general)
# ---------------------------------------------------------------------------


def _classify_call(ctx: LiftContext, addr: Optional[int], name: Optional[str]) -> None:
    """Shared call semantics for all backends: allocator prims become New/Ref,
    other libhl imports become Prim:<name>, module functions plain Call."""
    if name is None:
        ctx.emit("Call?", src_addr=ctx.insn.address, target_addr=addr)
        return
    if name.startswith("hl_"):
        prim = name[3:]
        mapped = {
            "alloc_obj": "New",
            "alloc_dynobj": "New",
            "alloc_array": "New",
            "alloc_bytes": "Prim:alloc_bytes",
            "alloc_pointer_array": "New",
            "alloc_closure_ptr": "Ref",
            "get_virtual_value": "CallVirtual",
        }.get(prim)
        if mapped:
            ctx.emit(mapped, src_addr=ctx.insn.address)
        else:
            ctx.emit(f"Prim:{prim}", src_addr=ctx.insn.address)
        return
    ctx.emit("Call", src_addr=ctx.insn.address, target=name, target_addr=addr)


@rule("call")
class CallRule(LiftRule):
    """Direct calls resolve to New/Ref for allocator prims, Prim:* for other
    libhl imports, and plain Call (with target address) for module functions.
    Indirect calls through the GOT/PLT resolve to their import symbol."""

    def apply(self, ctx: LiftContext) -> bool:
        _classify_call(ctx, ctx.call_target_addr(), ctx.call_target_name())
        return True


@rule("jmp")
class JmpRule(LiftRule):
    def apply(self, ctx: LiftContext) -> bool:
        ctx.emit("JAlways", src_addr=ctx.insn.address, target=ctx.branch_target())
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
        ctx.emit(kind, src_addr=ctx.insn.address, cc=cc, target=ctx.branch_target())
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
    """Splits into immediate loads, global/string access, field traffic, vreg
    shuffles and copies.

    Register allocation noise ([rsp+N] slots, reg-to-reg moves that only feed
    spills) is consumed silently so the lifted stream reflects semantics.
    """

    def apply(self, ctx: LiftContext) -> bool:
        if len(ctx.ops) != 2:
            return False
        dst, src = ctx.ops
        # immediate -> register: pool constant, or a symbol address materialised
        # as an immediate (mov edi, <&t$_foo>) - never a real Int.
        if src.type == X86_OP_IMM and dst.type == X86_OP_REG:
            sym = ctx.bin_view.symbol_at(src.imm)
            if sym is None:
                ctx.emit("Int", src_addr=ctx.insn.address, value=src.imm)
            elif _is_type_table_sym(sym):
                ctx.emit("Type", src_addr=ctx.insn.address, sym=sym)
            else:
                ctx.emit("LeaSym", src_addr=ctx.insn.address, sym=sym)
            return True
        # load from memory
        if src.type == X86_OP_MEM and dst.type == X86_OP_REG:
            if ctx.is_spill_slot(src):
                return True
            return _emit_mem_read(ctx, src)
        # store to memory
        if dst.type == X86_OP_MEM:
            if ctx.is_spill_slot(dst):
                return True
            return _emit_mem_write(ctx, dst)
        # reg-to-reg moves stay silent: compilers emit many times more copies
        # than truth carries explicit Mov opcodes (measured - emitting them
        # desyncs streams).
        return True


def _emit_mem_read(ctx: LiftContext, mem) -> bool:
    """Classify one non-spill memory read: module global (value OR string -
    in HL bytecode even literals live in the global table), type-table slot,
    other rodata, or object field traffic."""
    from .binary import (
        HL_CONST_STRING_PREFIX,
        HL_STRING_GLOBAL_PREFIX,
        HL_VALUE_GLOBAL_PREFIX,
    )

    sym = ctx.resolve_mem_sym(mem)
    if sym is not None and _mem_base_is_rip(mem):
        if sym.startswith(HL_VALUE_GLOBAL_PREFIX) or (
            sym.startswith(HL_STRING_GLOBAL_PREFIX) and not sym.startswith(HL_CONST_STRING_PREFIX)
        ):
            ctx.emit("GetGlobal", src_addr=ctx.insn.address, gidx=sym)
            return True
        if _is_type_table_sym(sym):
            ctx.emit("Type", src_addr=ctx.insn.address, sym=sym)
            return True
        # other rodata: keep provenance, no HL mapping yet
        ctx.emit("LeaSym", src_addr=ctx.insn.address, sym=sym)
        return True
    ctx.emit("LoadField", src_addr=ctx.insn.address, off=mem.mem.disp)
    return True


_TYPE_TABLE_PREFIXES = ("t$", "objt$", "enumt$", "virtt$", "tfunt$")


def _is_type_table_sym(sym: str) -> bool:
    """True when a symbol names a recovered-type table slot (class/enum/vtable)."""
    return any(sym.startswith(p) for p in _TYPE_TABLE_PREFIXES)


def _emit_mem_write(ctx: LiftContext, mem) -> bool:
    from .binary import (
        HL_CONST_STRING_PREFIX,
        HL_STRING_GLOBAL_PREFIX,
        HL_VALUE_GLOBAL_PREFIX,
    )

    sym = ctx.resolve_mem_sym(mem)
    if sym is not None and _mem_base_is_rip(mem):
        if sym.startswith(HL_VALUE_GLOBAL_PREFIX) or (
            sym.startswith(HL_STRING_GLOBAL_PREFIX) and not sym.startswith(HL_CONST_STRING_PREFIX)
        ):
            ctx.emit("SetGlobal", src_addr=ctx.insn.address, gidx=sym)
            return True
    ctx.emit("StoreField", src_addr=ctx.insn.address, off=mem.mem.disp)
    return True


def _mem_base_is_rip(mem) -> bool:
    from capstone.x86 import X86_REG_RIP

    try:
        return mem.mem.base == X86_REG_RIP
    except Exception:
        return False


@rule("lea")
class LeaRule(LiftRule):
    """Address materialisation: vreg slots are ABI noise; string/type table
    addresses become literals; the rest keeps symbol provenance."""

    def apply(self, ctx: LiftContext) -> bool:
        if len(ctx.ops) != 2 or ctx.ops[0].type != X86_OP_REG:
            return False
        mem = ctx.ops[1]
        if mem.type != X86_OP_MEM:
            return False
        if mem.mem.base in ctx._spill_bases and not _mem_base_is_rip(mem):
            return True  # &r_i - consumed as noise
        sym = ctx.resolve_mem_sym(mem)
        if sym is not None and _is_type_table_sym(sym):
            ctx.emit("Type", src_addr=ctx.insn.address, sym=sym)
        else:
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
        from capstone.x86 import X86_REG_RSP

        if ctx.ops and ctx.ops[0].type == X86_OP_REG and ctx.ops[0].reg == X86_REG_RSP:
            return True  # frame adjustment
        fam = _ARITH_MAP.get(ctx.mnemonic)
        if fam is None:
            return False
        ctx.emit(fam, src_addr=ctx.insn.address)
        return True


_SSE_ARITH_MAP = {
    "addsd": "Add",
    "addss": "Add",
    "subsd": "Sub",
    "subss": "Sub",
    "mulsd": "Mul",
    "mulss": "Mul",
}


@rule(*_SSE_ARITH_MAP)
class SSEArithRule(LiftRule):
    """SSE float arithmetic maps onto the same HL arithmetic families - the
    register's type (float vs int) is what disambiguates downstream."""

    def apply(self, ctx: LiftContext) -> bool:
        fam = _SSE_ARITH_MAP.get(ctx.mnemonic)
        if fam is None:
            return False
        ctx.emit(fam, src_addr=ctx.insn.address)
        return True


@rule("divsd", "divss")
class SSEDivRule(LiftRule):
    """SSE float division; HL models float div with the same SDiv family."""

    def apply(self, ctx: LiftContext) -> bool:
        ctx.emit("SDiv", src_addr=ctx.insn.address, float=True)
        return True


@rule("xor")
class XorRule(LiftRule):
    """`xor r,r` zeroing materialises the constant 0 - HL emits an explicit Int
    for default values, so keep it."""

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
    """x86 division uses RDX:RAX implicitly; HL models it as SDiv/UDiv (+SMod/UMod
    via the paired remainder)."""

    def apply(self, ctx: LiftContext) -> bool:
        ctx.emit("SDiv" if ctx.mnemonic == "idiv" else "UDiv", src_addr=ctx.insn.address)
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
        SSEArithRule(),
        SSEDivRule(),
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
        # Mnemonic -> candidate rules; avoids scanning every rule per insn.
        self._buckets: Dict[str, List[LiftRule]] = {}
        for rl in self.rules:
            for mn in rl.MNEMONICS:
                self._buckets.setdefault(mn, []).append(rl)

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
        if bin_view.arch == "aarch64":
            return ARM64FunctionLifter(bin_view, plt_map, size_of=size_of)
        raise NotImplementedError(f"no lifting backend for arch {bin_view.arch!r}")

    def decode(self, addr: int, max_bytes: int = 65536) -> list:
        """Decode one function body.

        Size resolution order: exact ELF symbol size (GCC emits precise st_size,
        and trusting it prevents runaway decodes past the body into neighbouring
        functions/data - measured to matter a lot), then the module function
        table gap, then a conservative default.
        """
        sym_name = self.bin_view.symbol_at(addr)
        sym = self.bin_view.symbol(sym_name) if sym_name else None
        sym_size = sym.size if sym is not None and sym.size else 0
        if sym_size:
            size = sym_size
        elif self.size_of is not None:
            size = self.size_of(addr)
        else:
            size = 2048
        if size <= 0:
            size = 2048
        code = self.bin_view.read_bytes(addr, min(size, max_bytes))
        return list(self.md.disasm(code, addr))

    def lift(self, addr: int) -> List[LiftedOp]:
        insns = self.decode(addr)
        out: List[LiftedOp] = []
        ctx = self._make_context(addr, insns, out)
        for i, _insn in enumerate(insns):
            ctx.index = i
            for rl in self._buckets.get(ctx.mnemonic, ()):
                if rl.apply(ctx):
                    break
            # no rule matched -> instruction ignored (conservative)
        return out

    def _make_context(self, addr: int, insns: list, out: List[LiftedOp]) -> LiftContext:
        return LiftContext(self.bin_view, addr, insns, 0, self.plt_map, out)


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


# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# aarch64 rules
# ---------------------------------------------------------------------------

_ARM64_OP_IMM: int = 0  # capstone >= 5 ships the arm64 module under both names
_ARM64_OP_MEM: int = 0
_ARM64_OP_REG: int = 0
_ARM64_REG_SP: int = 0
_ARM64_REG_WZR: int = 0
_ARM64_REG_XZR: int = 0
try:
    from capstone.arm64 import (  # noqa: F401
        ARM64_OP_IMM as _ARM64_OP_IMM,
        ARM64_OP_MEM as _ARM64_OP_MEM,
        ARM64_OP_REG as _ARM64_OP_REG,
        ARM64_REG_SP as _ARM64_REG_SP,
        ARM64_REG_WZR as _ARM64_REG_WZR,
        ARM64_REG_XZR as _ARM64_REG_XZR,
    )
except ImportError:  # pragma: no cover - non-aarch64 toolchains
    pass

_ARM64_CC_RENAME = {"mi": "l", "pl": "ge"}  # sign-flag conditions -> HL cc names


class ARM64LiftContext(LiftContext):
    """aarch64 services: adrp/add address tracking (mirrors init_analysis's
    proven linear tracker) plus ARM-flavoured operand helpers."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._spill_bases = {_ARM64_REG_SP}

    def call_target_addr(self) -> Optional[int]:
        for op in self.ops:
            if op.type == _ARM64_OP_IMM:
                return op.imm  # bl encodes the absolute target
        return None

    def branch_target(self) -> Optional[int]:
        for op in self.ops:
            if op.type == _ARM64_OP_IMM:
                return op.imm
        return None

    def resolve_mem_sym(self, mem_op) -> Optional[str]:
        base = getattr(getattr(mem_op, "mem", None), "base", 0)
        if base in self.reg_addr:
            return self.bin_view.symbol_at(self.reg_addr[base] + mem_op.mem.disp)
        return None

    def track(self) -> None:
        """Update the adrp/add address tracker for the current instruction."""
        m, ops = self.mnemonic, self.ops
        if m == "adrp" and len(ops) == 2 and ops[0].type == _ARM64_OP_REG and ops[1].type == _ARM64_OP_IMM:
            self.reg_addr[ops[0].reg] = ops[1].imm
            return
        if (
            m in ("add", "sub")
            and len(ops) == 3
            and ops[0].type == _ARM64_OP_REG
            and ops[1].type == _ARM64_OP_REG
            and ops[2].type == _ARM64_OP_IMM
        ):
            delta = ops[2].imm if m == "add" else -ops[2].imm
            src = self.reg_addr.get(ops[1].reg)
            if src is not None:
                self.reg_addr[ops[0].reg] = src + delta
            else:
                self.reg_addr.pop(ops[0].reg, None)
            return
        # copies can propagate addresses (`mov x0, x19`)
        if (
            m in ("mov", "orr")
            and len(ops) == 2
            and ops[0].type == _ARM64_OP_REG
            and ops[1].type == _ARM64_OP_REG
        ):
            src = self.reg_addr.get(ops[1].reg)
            if src is not None:
                self.reg_addr[ops[0].reg] = src
                return
        # any other definition kills tracked state for the destination
        if ops and ops[0].type == _ARM64_OP_REG and not m.startswith(("cmp", "tst", "str")):
            self.reg_addr.pop(ops[0].reg, None)


def _classify_call_arm(ctx: LiftContext) -> None:
    _classify_call(ctx, ctx.call_target_addr(), ctx.call_target_name())


@rule("bl")
class ArmCallRule(LiftRule):
    """Direct calls; semantics shared with the x86 backend."""

    def apply(self, ctx: LiftContext) -> bool:
        _classify_call_arm(ctx)
        return True


@rule("b")
class ArmJmpRule(LiftRule):
    def apply(self, ctx: LiftContext) -> bool:
        ctx.emit("JAlways", src_addr=ctx.insn.address, target=ctx.branch_target())
        return True


@rule(*[f"b.{c}" for c in ("eq", "ne", "lt", "le", "gt", "ge", "hi", "hs", "lo", "ls", "mi", "pl")])
class ArmCondBranchRule(LiftRule):
    """`b.cond`; signedness from the condition family like x86 jcc."""

    SIGNED = {"eq", "ne", "lt", "le", "gt", "ge", "mi", "pl"}

    def apply(self, ctx: LiftContext) -> bool:
        cc = ctx.mnemonic[2:]
        kind = "JIfS" if cc in self.SIGNED else "JIfU"
        ctx.emit(kind, src_addr=ctx.insn.address, cc=_ARM64_CC_RENAME.get(cc, cc), target=ctx.branch_target())
        return True


@rule("cbz", "cbnz", "tbz", "tbnz")
class ArmZeroBranchRule(LiftRule):
    """Compare-against-zero / bit-test branches become equality branches."""

    def apply(self, ctx: LiftContext) -> bool:
        negated = ctx.mnemonic in ("cbnz", "tbnz")
        ctx.emit(
            "JIfS",
            src_addr=ctx.insn.address,
            cc="ne" if negated else "e",
            target=ctx.branch_target(),
        )
        return True


@rule("ret")
class ArmRetRule(LiftRule):
    def apply(self, ctx: LiftContext) -> bool:
        ctx.emit("Ret", src_addr=ctx.insn.address)
        return True


@rule("cmp", "cmn", "subs", "adds")
class ArmCompareRule(LiftRule):
    """Immediate comparisons carry constants feeding branches (like x86 cmp);
    register-register compares stay implicit. GCC spells many compares as
    `subs/adds xzr, ...` (the CMP/CMN alias) - recognised by their zero
    destination so they stop being swallowed as frame arithmetic."""

    ZERO_DEST = {_ARM64_REG_XZR, _ARM64_REG_WZR}

    def apply(self, ctx: LiftContext) -> bool:
        ops = ctx.ops
        is_cmp_alias = ctx.mnemonic in ("subs", "adds", "cmn") and (
            ctx.mnemonic == "cmn" or (ops and ops[0].type == _ARM64_OP_REG and ops[0].reg in self.ZERO_DEST)
        )
        if not is_cmp_alias and ctx.mnemonic != "cmp":
            return False
        for op in ops:
            if op.type == _ARM64_OP_IMM:
                ctx.emit("Int", src_addr=ctx.insn.address, value=op.imm)
                return True
        return True


@rule("cset", "csinc", "csinv")
class ArmSetBoolRule(LiftRule):
    """`cset dst, cond` materialises a comparison result - HL's Bool. The
    condition is parsed from the printed operands' tail."""

    def apply(self, ctx: LiftContext) -> bool:
        tail = ctx.insn.op_str.split(",")[-1].strip().lstrip("#")
        cc = tail if tail and not tail[0].isdigit() else "ne"
        ctx.emit("Bool", src_addr=ctx.insn.address, cc=_ARM64_CC_RENAME.get(cc, cc))
        return True


@rule("movz")
class ArmMovImmRule(LiftRule):
    """Immediate moves materialise Int constants. `movz` with lsl feeds movk
    continuation chains - the shifted chunk emits, movk chunks are consumed
    as noise so constants are not double-counted."""

    def apply(self, ctx: LiftContext) -> bool:
        ops = ctx.ops
        if len(ops) != 2 or ops[0].type != _ARM64_OP_REG or ops[1].type != _ARM64_OP_IMM:
            return False
        shift = 16 if "lsl" in ctx.insn.op_str else 0
        ctx.emit("Int", src_addr=ctx.insn.address, value=ops[1].imm << shift)
        return True


@rule("mov", "orr")
class ArmRegMoveRule(LiftRule):
    """`mov xN, xzr` (and its orr encoding) materialises 0; other reg-reg moves
    are allocation noise (measured on x86: emitting them desyncs streams)."""

    def apply(self, ctx: LiftContext) -> bool:
        ops = ctx.ops
        if len(ops) != 2 or ops[0].type != _ARM64_OP_REG or ops[1].type != _ARM64_OP_REG:
            return False
        if ops[1].reg in (_ARM64_REG_XZR, _ARM64_REG_WZR):
            ctx.emit("Int", src_addr=ctx.insn.address, value=0)
        return True


_ARM64_INT_ARITH = {
    "add": "Add",
    "sub": "Sub",
    "mul": "Mul",
    "mneg": "Mul",
    "and": "And",
    "eor": "Xor",
    "lsl": "Shl",
    "lsr": "UShr",
    "asr": "SShr",
    "sdiv": "SDiv",
    "udiv": "UDiv",
}


@rule(*_ARM64_INT_ARITH)
class ArmArithRule(LiftRule):
    """Three-register integer arithmetic; SP forms are frame noise and
    immediate forms are usually addressing (adrp/add chains), consumed by the
    tracker upstream - only plain register arithmetic emits."""

    def apply(self, ctx: LiftContext) -> bool:
        fam = _ARM64_INT_ARITH.get(ctx.mnemonic)
        ops = ctx.ops
        if fam is None or len(ops) < 2:
            return False
        if any(o.type == _ARM64_OP_REG and o.reg == _ARM64_REG_SP for o in ops[:2]):
            return True  # sp adjustment
        if len(ops) >= 3 and ops[2].type == _ARM64_OP_IMM:
            return True  # addressing / constant folding
        ctx.emit(fam, src_addr=ctx.insn.address)
        return True


_ARM64_FP_ARITH = {"fadd": "Add", "fsub": "Sub", "fmul": "Mul"}


@rule(*_ARM64_FP_ARITH)
class ArmFpArithRule(LiftRule):
    """SSE-equivalent float arithmetic maps onto the shared HL families."""

    def apply(self, ctx: LiftContext) -> bool:
        fam = _ARM64_FP_ARITH.get(ctx.mnemonic)
        if fam is None:
            return False
        ctx.emit(fam, src_addr=ctx.insn.address)
        return True


@rule("fdiv")
class ArmFpDivRule(LiftRule):
    def apply(self, ctx: LiftContext) -> bool:
        ctx.emit("SDiv", src_addr=ctx.insn.address, float=True)
        return True


@rule("scvtf", "ucvtf", "fcvtzs", "fcvtzu", "fcvtas", "fcvtau", "fcvtms", "fcvtmu", "fcvt")
class ArmConvertRule(LiftRule):
    def apply(self, ctx: LiftContext) -> bool:
        ctx.emit("Convert", src_addr=ctx.insn.address, kind=ctx.mnemonic)
        return True


def _arm64_global_or_field_read(ctx: LiftContext, mem_op) -> bool:
    from .binary import (
        HL_CONST_STRING_PREFIX,
        HL_STRING_GLOBAL_PREFIX,
        HL_VALUE_GLOBAL_PREFIX,
    )

    sym = ctx.resolve_mem_sym(mem_op)
    if sym is not None:
        if sym.startswith(HL_VALUE_GLOBAL_PREFIX) or (
            sym.startswith(HL_STRING_GLOBAL_PREFIX) and not sym.startswith(HL_CONST_STRING_PREFIX)
        ):
            ctx.emit("GetGlobal", src_addr=ctx.insn.address, gidx=sym)
            return True
        if _is_type_table_sym(sym):
            ctx.emit("Type", src_addr=ctx.insn.address, sym=sym)
            return True
        ctx.emit("LeaSym", src_addr=ctx.insn.address, sym=sym)
        return True
    ctx.emit("LoadField", src_addr=ctx.insn.address, off=mem_op.mem.disp)
    return True


def _arm64_global_or_field_write(ctx: LiftContext, mem_op) -> bool:
    from .binary import (
        HL_CONST_STRING_PREFIX,
        HL_STRING_GLOBAL_PREFIX,
        HL_VALUE_GLOBAL_PREFIX,
    )

    sym = ctx.resolve_mem_sym(mem_op)
    if sym is not None and (
        sym.startswith(HL_VALUE_GLOBAL_PREFIX)
        or (sym.startswith(HL_STRING_GLOBAL_PREFIX) and not sym.startswith(HL_CONST_STRING_PREFIX))
    ):
        ctx.emit("SetGlobal", src_addr=ctx.insn.address, gidx=sym)
        return True
    ctx.emit("StoreField", src_addr=ctx.insn.address, off=mem_op.mem.disp)
    return True


def _arm64_mem_base_addr(ctx: LiftContext, mem_op) -> Optional[int]:
    base = getattr(mem_op.mem, "base", 0)
    if base in ctx.reg_addr:
        return ctx.reg_addr[base] + mem_op.mem.disp
    return None


@rule("ldr", "ldur", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw", "ldurb", "ldurh", "ldursb", "ldursw")
class ArmLoadRule(LiftRule):
    """Loads: spill slots are noise, tracked bases resolve globals/literals,
    everything else is field traffic. FP literal loads read rodata floats."""

    def apply(self, ctx: LiftContext) -> bool:
        ops = ctx.ops
        if len(ops) != 2:
            return False
        # literal-pool form: `ldr d0, <imm>` (single immediate operand)
        if ops[1].type == _ARM64_OP_IMM:
            dest = ctx.insn.op_str.split(",")[0].strip()
            if dest[:1] in ("d", "s"):
                val = ctx.read_float_at(ops[1].imm, 8 if dest[0] == "d" else 4)
                if val is not None:
                    ctx.emit("Float", src_addr=ctx.insn.address, value=val)
                    return True
            return False
        if ops[1].type != _ARM64_OP_MEM or ctx.is_spill_slot(ops[1]):
            return True if ops[1].type == _ARM64_OP_MEM else False
        dest = ctx.insn.op_str.split(",")[0].strip()
        if dest[:1] in ("d", "s"):
            tgt = _arm64_mem_base_addr(ctx, ops[1])
            val = ctx.read_float_at(tgt, 8 if dest[0] == "d" else 4) if tgt is not None else None
            if val is not None:
                ctx.emit("Float", src_addr=ctx.insn.address, value=val)
                return True
        return _arm64_global_or_field_read(ctx, ops[1])


@rule("str", "stur", "strb", "strh", "sturb", "sturh")
class ArmStoreRule(LiftRule):
    def apply(self, ctx: LiftContext) -> bool:
        ops = ctx.ops
        if len(ops) != 2 or ops[1].type != _ARM64_OP_MEM:
            return False
        if ctx.is_spill_slot(ops[1]):
            return True
        return _arm64_global_or_field_write(ctx, ops[1])


@rule("ldp")
class ArmPairLoadRule(LiftRule):
    """Register-pair loads; spill traffic stays silent, non-spill pair loads
    emit their first field read in v1."""

    def apply(self, ctx: LiftContext) -> bool:
        mem_ops = [o for o in ctx.ops if o.type == _ARM64_OP_MEM]
        if mem_ops and not ctx.is_spill_slot(mem_ops[0]):
            _arm64_global_or_field_read(ctx, mem_ops[0])
        return True


@rule("stp")
class ArmPairStoreRule(NoiseRule):
    """Register-pair save/restore is frame management in practice."""

    def apply(self, ctx: LiftContext) -> bool:
        return True


@rule(
    "nop",
    "adrp",
    "adr",
    "movk",
    "sxtw",
    "sxth",
    "sxtb",
    "uxtw",
    "uxth",
    "uxtb",
    "mrs",
    "msr",
    "dmb",
    "dsb",
    "isb",
    "brk",
    "blr",
    "br",
    "tst",
    "madd",
    "msub",
)
class ArmNoiseRule(NoiseRule):
    """Padding, extensions, barriers, indirect transfers consumed silently.
    blr/br targets live in registers - v1 cannot resolve them; madd/msub fold
    multiply-accumulate which v1 does not split into Mul+Add."""


class ARM64FunctionLifter(FunctionLifter):
    RULES: List[LiftRule] = [
        ArmCallRule(),
        ArmCondBranchRule(),
        ArmZeroBranchRule(),
        ArmJmpRule(),
        ArmRetRule(),
        ArmCompareRule(),
        ArmSetBoolRule(),
        ArmConvertRule(),
        ArmFpArithRule(),
        ArmFpDivRule(),
        ArmMovImmRule(),
        ArmRegMoveRule(),
        ArmLoadRule(),
        ArmStoreRule(),
        ArmPairLoadRule(),
        ArmPairStoreRule(),
        ArmArithRule(),
        ArmNoiseRule(),
    ]

    def __init__(
        self,
        bin_view: HLCBinary,
        plt_map: Optional[Dict[int, str]] = None,
        size_of: Optional[Callable[[int], int]] = None,
    ):
        super().__init__(bin_view, plt_map, size_of=size_of)
        from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

        self.md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.md.detail = True

    def _make_context(self, addr: int, insns: list, out: List[LiftedOp]) -> LiftContext:
        return ARM64LiftContext(self.bin_view, addr, insns, 0, self.plt_map, out)

    def lift(self, addr: int) -> List[LiftedOp]:
        insns = self.decode(addr)
        out: List[LiftedOp] = []
        ctx = self._make_context(addr, insns, out)
        for i, _insn in enumerate(insns):
            ctx.index = i
            ctx.track()
            for rl in self._buckets.get(ctx.mnemonic, ()):
                if rl.apply(ctx):
                    break
        return out
