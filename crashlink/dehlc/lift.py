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

5. A rule may span several instructions. HL opcodes are frequently N:1 with
   machine code - a null guard is a test plus a branch, a virtual call is a
   proto load plus an indirect call - so `apply` can consume a window via
   `ctx.consume_through(n)` and the dispatcher resumes after it.

6. `LiftContext` carries an abstract value per register (`ctx.vals`: immediate,
   symbol address, or incoming argument). That is what separates argument
   set-up from a real constant, and a `this` field access (GetThis/SetThis)
   from an arbitrary pointer dereference. x86 maintains it in
   `X86LiftContext.track`; aarch64 still tracks only adrp/add addresses.

Lifting is available through the GUI's Asm/Ops toggle for de-HL/C images,
the REPL `lift <findex>` command, and two measurement harnesses:
`local/dehlc-tests/lift_ops.py` (per-function sequence similarity) and
`local/dehlc-tests/lift_confusion.py`, which scores every instruction against a
ground-truth oracle recovered from haxe's generated C plus DWARF and prints a
confusion matrix. Use the latter to decide what to work on - it names the
highest-volume mistakes instead of averaging them away.
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
        # Abstract value per register and per spill slot. Values are small tags:
        #   ("imm", n) ("sym", name) ("arg", i) - anything untracked is absent.
        # This is what lets a rule tell an argument set-up from a real constant,
        # and a `this` field access from an arbitrary pointer dereference.
        self.vals: Dict[int, Tuple[str, Any]] = {}
        self.slots: Dict[int, Tuple[str, Any]] = {}
        self.md: Any = None  # capstone engine, set by the lifter
        # Entry addresses listed in hl_functions_ptrs - the authority on what is
        # a module function rather than a runtime primitive.
        self.module_funcs: set = set()
        self._stable_this: set = set()

    def canon_reg(self, reg: int) -> int:
        """Register id collapsed across width aliases (eax and rax are one)."""
        return reg

    def val_of(self, reg: int) -> Optional[Tuple[str, Any]]:
        return self.vals.get(self.canon_reg(reg))

    def set_val(self, reg: int, val: Optional[Tuple[str, Any]]) -> None:
        r = self.canon_reg(reg)
        if val is None:
            self.vals.pop(r, None)
        else:
            self.vals[r] = val

    def seed_args(self) -> None:
        """Mark the argument registers at function entry, so `this` (arg 0) and
        call operands stay identifiable."""

    # Operand-type id for a register, per backend (capstone's X86_OP_REG etc).
    OP_REG: int = 0

    def is_this(self, reg: int) -> bool:
        """True when `reg` still holds argument 0 - hl2c's `this` pointer, which
        is what separates HL's GetThis/SetThis from plain Field/SetField."""
        return self.canon_reg(reg) in self._stable_this or self.val_of(reg) == ("arg", 0)

    def _compute_stable_this(self, arg0: int) -> None:
        """
        Find registers that hold `this` for the whole function.

        The per-instruction value map is linear, so it loses `this` at a branch
        join - but GCC's usual move is to park `this` in one callee-saved
        register at entry and never touch it again. A register written exactly
        once in the body, from argument 0, before argument 0 is itself
        clobbered, is `this` everywhere; that survives joins without needing a
        full dataflow pass.
        """
        # Callee-saved registers are spilled in the prologue and reloaded in the
        # epilogue. That reload writes the register but restores the value it
        # already had, so it must not count as a redefinition.
        saved: set = set()
        for ins in self.insns:
            mems = [o for o in ins.operands if o.type != self.OP_REG]
            regs = [o for o in ins.operands if o.type == self.OP_REG]
            if mems and regs and self.is_spill_slot(mems[0]) and ins.operands[0].type != self.OP_REG:
                for k, o in enumerate(regs):
                    saved.add((mems[0].mem.disp + k * 8, self.canon_reg(o.reg)))

        defs: Dict[int, int] = {}
        for ins in self.insns:
            ops = ins.operands
            if not ops or ops[0].type != self.OP_REG or self._defines_nothing(ins.mnemonic):
                continue
            mems = [o for o in ops if o.type != self.OP_REG]
            regs = [o for o in ops if o.type == self.OP_REG]
            if (
                mems
                and self.is_spill_slot(mems[0])
                and all(
                    (mems[0].mem.disp + k * 8, self.canon_reg(o.reg)) in saved for k, o in enumerate(regs)
                )
            ):
                continue  # epilogue restore, not a new value
            defs[self.canon_reg(ops[0].reg)] = defs.get(self.canon_reg(ops[0].reg), 0) + 1
        stable = set()
        for ins in self.insns:
            ops = ins.operands
            if len(ops) == 2 and ops[0].type == self.OP_REG and ops[1].type == self.OP_REG:
                dst, src = self.canon_reg(ops[0].reg), self.canon_reg(ops[1].reg)
                if src == arg0 and dst != arg0 and defs.get(dst) == 1:
                    stable.add(dst)
            if ops and ops[0].type == self.OP_REG and self.canon_reg(ops[0].reg) == arg0:
                break  # argument 0 is gone from here on
        self._stable_this = stable

    def _defines_nothing(self, mnemonic: str) -> bool:
        """Instructions whose first operand is a source, not a destination."""
        return False

    def mem_base_is_this(self, mem_op) -> bool:
        try:
            return not _mem_base_is_rip(mem_op) and self.is_this(mem_op.mem.base)
        except Exception:
            return False

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

    # Mnemonic classes the shared helpers need; overridden per backend.
    CALL_MNEMONICS: Tuple[str, ...] = ("call",)
    TERMINATORS: Tuple[str, ...] = ("ret",)
    BRANCH_PREFIXES: Tuple[str, ...] = ("j",)

    def index_at(self, addr: int) -> Optional[int]:
        """Position of the instruction starting at `addr`, if it was decoded."""
        if not hasattr(self, "_by_addr"):
            self._by_addr = {ins.address: k for k, ins in enumerate(self.insns)}
        return self._by_addr.get(addr)

    def leads_to_call(self, addr: int, names: Tuple[str, ...], limit: int = 6) -> bool:
        """
        True when the straight-line run starting at `addr` calls one of `names`.

        Used to recognise the cold half of a compiler-emitted guard (a null or
        bounds check) by where it lands, which is the only thing that separates
        such a branch from a real HL conditional jump.
        """
        k = self.index_at(addr)
        if k is None:
            return False
        saved, self.index = self.index, k
        try:
            for j in range(k, min(k + limit, len(self.insns))):
                self.index = j
                ins = self.insns[j]
                if ins.mnemonic in self.CALL_MNEMONICS:
                    nm = self.call_target_name()
                    return bool(nm and nm in names)
                if ins.mnemonic in self.TERMINATORS or ins.mnemonic.startswith(self.BRANCH_PREFIXES):
                    return False
            return False
        finally:
            self.index = saved

    COMPARE_MNEMONICS: Tuple[str, ...] = ("cmp", "test")

    def compare_used_immediate(self, back: int = 6) -> bool:
        """
        Whether the compare governing this branch tested against a constant.

        It is the one feature that meaningfully splits a condition code's
        possible HL opcodes: `a >= K` gets rewritten to `a > K-1` only when K is
        a literal, so an immediate compare and a register compare behind the
        same `jle` came from different opcodes.
        """
        for j in range(self.index - 1, max(self.index - back, -1), -1):
            ins = self.insns[j]
            if ins.mnemonic in self.COMPARE_MNEMONICS:
                return any(o.type == X86_OP_IMM for o in ins.operands)
        return False

    def consume_through(self, ahead: int) -> None:
        """Mark the next `ahead` instructions as consumed by this rule."""
        self.index = min(self.index + ahead, len(self.insns) - 1)

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


# libhl runtime helpers that hl2c emits *as* an HL opcode rather than as a
# native call. Without this they surface as `Prim:<name>`, resolve to no entry
# in the natives table, and get dropped - which is why SafeCast/ToVirtual used
# to vanish entirely. Measured against the corpus oracle: the dyn_set*/dyn_get*
# helpers back SetField/Field roughly 93% of the time and DynSet/DynGet the
# rest, and nothing in the machine code distinguishes the two, so they take the
# common reading.
_PRIM_TO_OPCODE = {
    "alloc_obj": "New",
    "alloc_dynobj": "New",
    "alloc_array": "New",
    "alloc_bytes": "Prim:alloc_bytes",
    "alloc_pointer_array": "New",
    "alloc_virtual": "New",
    "alloc_closure_ptr": "InstanceClosure",  # measured: never a Ref
    "get_virtual_value": "CallVirtual",
    "to_virtual": "ToVirtual",
    "dyn_castp": "SafeCast",
    "dyn_casti": "SafeCast",
    "dyn_castf": "SafeCast",
    "dyn_castd": "SafeCast",
    "dyn_setp": "SetField",
    "dyn_seti": "SetField",
    "dyn_setf": "SetField",
    "dyn_setd": "SetField",
    "dyn_getp": "LoadField",
    "dyn_geti": "LoadField",
    "dyn_getf": "LoadField",
    "dyn_getd": "LoadField",
    "dyn_call": "CallClosure",
    "rethrow": "Rethrow",
}

# `hl_get_thread` backs both halves of a try block - hl_trap() entering and
# hl_endtrap() leaving - so the name alone cannot say which. Only the entering
# form goes on to install a jump buffer.
_TRAP_PRIM = "get_thread"
_SETJMP = ("setjmp", "_setjmp", "__sigsetjmp", "setjmp@plt", "_setjmp@plt")


# Suffixes gcc appends when it splits or specialises a function at -O2/-O3.
_CLONE_SUFFIXES = (".part.", ".constprop.", ".isra.", ".lto_priv.", ".cold", ".localalias")


def _clone_origin(ctx: LiftContext, name: str) -> Optional[int]:
    """Entry address of the module function a gcc clone was derived from."""
    for suffix in _CLONE_SUFFIXES:
        idx = name.find(suffix)
        if idx <= 0:
            continue
        base = ctx.bin_view.symbol(name[:idx])
        if base is not None and base.value in ctx.module_funcs:
            return int(base.value)
    return None


def _dynamic_dispatch_kind(ctx: LiftContext) -> Optional[str]:
    """`CallMethod` for a call through an object slot, `CallClosure` for one
    through a register, None when the target is not dynamic at all."""
    for op in ctx.ops:
        if op.type == X86_OP_REG:
            return "CallClosure"
        if op.type == X86_OP_MEM:
            # Unoptimised builds route every indirect call through a stack slot,
            # so the slot's base cannot separate a closure from a dispatch
            # there; only the register form is a reliable closure signal.
            return None if _mem_base_is_rip(op) else "CallMethod"
    return None


def _classify_call(ctx: LiftContext, addr: Optional[int], name: Optional[str]) -> None:
    """Shared call semantics for all backends: allocator prims become New/Ref,
    other libhl imports become Prim:<name>, module functions plain Call."""
    if name is None:
        # An unresolvable target is dynamic dispatch, and how it is reached says
        # which kind: hl2c compiles a virtual call as a load from the proto
        # table followed by `call [slot]`, while a closure is already a value in
        # a register and becomes `call reg`. A rip-relative slot is an ordinary
        # import instead, and stays unknown.
        ctx.emit(
            _dynamic_dispatch_kind(ctx) or "Call?",
            src_addr=ctx.insn.address,
            target_addr=addr,
        )
        return
    # The `hl_` prefix does not imply a runtime primitive: Haxe classes in the
    # `hl.types` package compile to `hl_types_ArrayObj_new` and friends. Only
    # the module function table can tell them apart, so ask it first.
    if addr is not None and addr in ctx.module_funcs:
        ctx.emit("Call", src_addr=ctx.insn.address, target=name, target_addr=addr)
        return
    # -O2/-O3 clone functions (`foo.part.0`, `foo.constprop.0`, `foo.isra.0`).
    # The clone is not in the function table, but it *is* the module function it
    # was split from, so resolve through the base symbol to keep the call - and
    # its arity - instead of dropping it as an unknown primitive.
    base_addr = _clone_origin(ctx, name)
    if base_addr is not None:
        ctx.emit("Call", src_addr=ctx.insn.address, target=name, target_addr=base_addr)
        return
    if name.startswith("hl_"):
        prim = name[3:]
        if prim == _TRAP_PRIM:
            entering = ctx.leads_to_call(ctx.insn.address + ctx.insn.size, _SETJMP, limit=10)
            ctx.emit("Trap" if entering else "EndTrap", src_addr=ctx.insn.address)
            return
        mapped = _PRIM_TO_OPCODE.get(prim)
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


_EPILOGUE_NOISE = ("pop", "leave", "nop", "add", "mov", "endbr64")


@rule("jmp")
class TailJmpRule(LiftRule):
    """
    A `jmp` into a shared epilogue is a return, not an HL jump.

    GCC routes several `return;` statements through one epilogue, so the jump
    that gets there carries the Ret. Only a target that falls straight into
    `ret` through frame teardown qualifies.
    """

    def apply(self, ctx: LiftContext) -> bool:
        target = ctx.branch_target()
        if target is None:
            return False
        k = ctx.index_at(target)
        if k is None:
            return False
        for j in range(k, min(k + 14, len(ctx.insns))):
            m = ctx.insns[j].mnemonic
            if m == "ret":
                ctx.emit("Ret", src_addr=ctx.insn.address)
                return True
            if not m.startswith(_EPILOGUE_NOISE):
                return False
        return False


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
        ctx.emit(
            kind,
            src_addr=ctx.insn.address,
            cc=cc,
            imm=ctx.compare_used_immediate(),
            target=ctx.branch_target(),
        )
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
        # Not a literal: a float read out of an object or an array is the same
        # field/element traffic as the integer case.
        if ctx.is_spill_slot(ctx.ops[1]):
            return True
        return _emit_mem_read(ctx, ctx.ops[1])


@rule("movsd", "movss", "movaps", "movapd", "movups", "movupd", "movq")
class FloatStoreRule(LiftRule):
    """
    SSE stores. Float field and array writes go through these, and without a
    rule they lift to nothing at all - `movsd [rax + r9], xmm0` is an array
    element store exactly like its integer counterpart.
    """

    def apply(self, ctx: LiftContext) -> bool:
        ops = ctx.ops
        if len(ops) != 2 or ops[0].type != X86_OP_MEM:
            return False
        if ctx.is_spill_slot(ops[0]):
            return True
        return _emit_mem_write(ctx, ops[0])


@rule("xorps", "xorpd", "pxor")
class FloatZeroRule(LiftRule):
    """Zeroing a vector register is how 0.0 gets materialised."""

    def apply(self, ctx: LiftContext) -> bool:
        if len(ctx.ops) == 2 and ctx.ops[0].type == X86_OP_REG and ctx.ops[0].reg == ctx.ops[1].reg:
            ctx.emit("Float", src_addr=ctx.insn.address, value=0.0)
            return True
        return False


_NULL_ACCESS = ("hl_null_access", "hl_null_access@plt")


@rule("cmp", "test")
class NullCheckRule(LiftRule):
    """
    hl2c writes a null guard as `if( r == NULL ) hl_null_access();`, which
    compiles to a zero test plus a branch into a cold block that calls
    `hl_null_access`. That landing site is what distinguishes the pair from a
    real HL conditional jump, so both instructions collapse to one `NullCheck`.
    """

    def apply(self, ctx: LiftContext) -> bool:
        ops = ctx.ops
        if len(ops) != 2:
            return False
        # Unoptimised builds keep the value in its stack slot and compare the
        # memory directly (`cmp qword [rbp-0x28], 0`), so accept either form -
        # the branch's landing site is what actually identifies the guard.
        is_zero_test = (
            ctx.mnemonic == "test"
            and ops[0].type == X86_OP_REG
            and ops[1].type == X86_OP_REG
            and ops[0].reg == ops[1].reg
        ) or (ops[1].type == X86_OP_IMM and ops[1].imm == 0)
        if not is_zero_test:
            return False
        nxt = ctx.peek(1)
        if nxt is None or nxt.mnemonic not in ("je", "jne"):
            return False
        target = next((o.imm for o in nxt.operands if o.type == X86_OP_IMM), None)
        if target is None:
            return False
        # `je` takes the branch when the value *is* null, so that side is cold;
        # `jne` skips the guard, leaving the fallthrough cold.
        cold = target if nxt.mnemonic == "je" else nxt.address + nxt.size
        if not ctx.leads_to_call(cold, _NULL_ACCESS):
            return False
        ctx.emit("NullCheck", src_addr=ctx.insn.address)
        ctx.consume_through(1)  # the branch belongs to the guard, not the stream
        return True


@rule("cmp", "test")
class NullCompareRule(LiftRule):
    """
    A pointer-width comparison against zero is HL's JNull/JNotNull, not an
    integer JEq/JNotEq. The operand width is what separates them: hl2c compares
    references with `r == NULL` on a 64-bit value, integers with `r == 0` on a
    32-bit one. (A guard whose branch lands in `hl_null_access` was already
    claimed by NullCheckRule, which runs first.)
    """

    def apply(self, ctx: LiftContext) -> bool:
        ops = ctx.ops
        if len(ops) != 2 or ops[0].size != 8:
            return False
        is_zero = (
            ctx.mnemonic == "test"
            and ops[0].type == X86_OP_REG
            and ops[1].type == X86_OP_REG
            and ops[0].reg == ops[1].reg
        ) or (ops[1].type == X86_OP_IMM and ops[1].imm == 0)
        if not is_zero:
            return False
        nxt = ctx.peek(1)
        if nxt is None or nxt.mnemonic not in ("je", "jne"):
            return False
        target = next((o.imm for o in nxt.operands if o.type == X86_OP_IMM), None)
        # Same inversion as the ordered compares: gcc negates so the common path
        # falls through, and HL emits far more JNotNull than JNull, so `je` is
        # the usual spelling of "not null".
        ctx.emit(
            "JNotNull" if nxt.mnemonic == "je" else "JNull",
            src_addr=ctx.insn.address,
            target=target,
        )
        ctx.consume_through(1)
        return True


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
                # An immediate written straight into a vreg's stack slot *is* the
                # constant-materialising opcode. Unoptimised builds spell every
                # Int/Null/Bool this way, so consuming it as spill noise drops
                # them all.
                if src.type == X86_OP_IMM:
                    op, extra = _constant_op(src.imm, dst.size)
                    ctx.emit(op, src_addr=ctx.insn.address, **extra)
                elif src.type == X86_OP_REG:
                    # Slot -> slot through a scratch register is a register copy
                    # in the source: HL's `Mov`. A store of a freshly computed
                    # value is not, so require the value to have come from
                    # another slot.
                    val = ctx.val_of(src.reg)
                    if val is not None and val[0] == "slot" and val[1] != dst.mem.disp:
                        ctx.emit("Mov", src_addr=ctx.insn.address)
                return True
            return _emit_mem_write(ctx, dst)
        # reg-to-reg moves stay silent: compilers emit many times more copies
        # than truth carries explicit Mov opcodes (measured - emitting them
        # desyncs streams).
        return True


def _constant_op(value: int, width: int) -> Tuple[str, Dict[str, Any]]:
    """
    Which constant-materialising opcode an immediate of this width denotes.

    HL keeps Null, Bool and Int apart, and the store width is what distinguishes
    them: a pointer-sized zero is `null`, a byte-sized 0/1 is a bool, everything
    else is an integer literal.
    """
    if width == 8 and value == 0:
        return "Null", {}
    if width == 1 and value in (0, 1):
        return "Bool", {"value": bool(value)}
    return "Int", {"value": value}


# Indexed addressing (`[base + index*scale]`) -> the HL opcode it came from,
# keyed by (is a store, access width).
#
# An object field is always reached at a constant offset, so a *variable* index
# means the access is into an array or a byte buffer instead. Which of the two,
# and at what element type, is not visible in the machine code - only the access
# width is - so this is a prior like the branch table: fitted on 40 corpus
# samples, 81.4% correct on 20 disjoint ones, against ~0% for reading them all
# as field traffic.
_INDEXED_MEM_OP = {
    (False, 2): "GetI16",
    (False, 4): "GetMem",
    (False, 8): "GetMem",
    (True, 2): "SetI16",
    (True, 4): "SetMem",
    (True, 8): "SetArray",
}


def _indexed_mem_op(mem, store: bool) -> Optional[str]:
    """HL opcode for an indexed memory access, or None when not indexed."""
    try:
        if not mem.mem.index or _mem_base_is_rip(mem) or not mem.mem.base:
            return None
    except Exception:
        return None
    return _INDEXED_MEM_OP.get((store, mem.size))


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
    indexed = _indexed_mem_op(mem, store=False)
    if indexed is not None:
        ctx.emit(indexed, src_addr=ctx.insn.address)
        return True
    op = "GetThis" if ctx.mem_base_is_this(mem) else "LoadField"
    ctx.emit(op, src_addr=ctx.insn.address, off=mem.mem.disp)
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
    indexed = _indexed_mem_op(mem, store=True)
    if indexed is not None:
        ctx.emit(indexed, src_addr=ctx.insn.address)
        return True
    op = "SetThis" if ctx.mem_base_is_this(mem) else "StoreField"
    ctx.emit(op, src_addr=ctx.insn.address, off=mem.mem.disp)
    return True


def _mem_base_is_rip(mem) -> bool:
    from capstone.x86 import X86_REG_RIP

    try:
        return mem.mem.base == X86_REG_RIP
    except Exception:
        return False


def _lea_arithmetic(mem) -> Optional[Tuple[str, Dict[str, Any]]]:
    """
    Classify a `lea` operand that is really arithmetic, not an address.

    Returns (op name, extra payload), or None when the operand is a genuine
    address (rip-relative, or a plain base+displacement that names a symbol).
    """
    if _mem_base_is_rip(mem):
        return None
    m = mem.mem
    base, index, scale, disp = m.base, m.index, m.scale, m.disp
    if index:
        # base + index*scale
        if scale > 1 and not base:
            return ("Shl", {"amount": scale.bit_length() - 1})  # a * 2^k
        if base == index:
            # `lea [r + r*k]` computes r*(k+1) - a multiply, not an addition.
            # k==1 doubles, which HL more often spells as a shift.
            return ("Shl", {"amount": 1}) if scale == 1 else ("Mul", {"by": scale + 1})
        if base:
            return ("Add", {})
        return ("Shl", {"amount": 0}) if scale == 1 else ("Add", {})
    if base and disp:
        # `lea r, [b - N]` is a subtraction; capstone reports it as a negative
        # displacement, and reading it as an Add loses the Sub it came from.
        return ("Sub", {"imm": -disp}) if disp < 0 else ("Add", {"imm": disp})
    return None


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
        # `lea` is the compiler's cheap arithmetic unit long before it is an
        # address-of: GCC lowers `a * 2` to `lea [rax+rax]`, `a * 8` to
        # `lea [,rax*8]` and `a + b` to `lea [rax+rbx]`. Reading those as symbol
        # references loses the Shl/Add opcode they came from.
        fam = _lea_arithmetic(mem)
        if fam is not None:
            op, extra = fam
            ctx.emit(op, src_addr=ctx.insn.address, **extra)
            return True
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


@rule("add", "sub", "inc", "dec")
class IncrDecrRule(LiftRule):
    """
    A read-modify-write of +/-1 on a variable's own storage is HL's Incr/Decr,
    not a general Add/Sub - the destination is also the source operand.
    """

    def apply(self, ctx: LiftContext) -> bool:
        ops = ctx.ops
        if ctx.mnemonic in ("inc", "dec"):
            ctx.emit("Incr" if ctx.mnemonic == "inc" else "Decr", src_addr=ctx.insn.address)
            return True
        if len(ops) != 2 or ops[1].type != X86_OP_IMM or ops[1].imm != 1:
            return False
        # x86's two-operand form is destructive, so `add r, 1` is an in-place
        # increment; a non-destructive `+ 1` would have been lowered to `lea`.
        # The register form is a guess - measured net positive on every
        # optimised tier, and restricting to memory costs ~0.5pp.
        if ops[0].type == X86_OP_MEM and not ctx.is_spill_slot(ops[0]):
            return False
        ctx.emit("Incr" if ctx.mnemonic == "add" else "Decr", src_addr=ctx.insn.address)
        return True


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
    """
    `setcc` materialises a comparison result.

    That is HL's `Bool` only when the result is used as a *value*. When it is
    immediately re-tested and branched on, gcc has merely split one comparison
    across three instructions, and the opcode is the branch - emitting a Bool
    there is a phantom (measured: 64% of setcc sit inside a compare-and-jump).
    """

    def apply(self, ctx: LiftContext) -> bool:
        if self._feeds_branch(ctx):
            return True  # consumed; the branch rule emits the real opcode
        ctx.emit("Bool", src_addr=ctx.insn.address, cc=ctx.mnemonic[3:])
        return True

    @staticmethod
    def _feeds_branch(ctx: LiftContext, window: int = 3) -> bool:
        ops = ctx.ops
        if not ops or ops[0].type != X86_OP_REG:
            return False
        dst = ctx.canon_reg(ops[0].reg)
        for k in range(1, window + 1):
            nxt = ctx.peek(k)
            if nxt is None:
                return False
            if nxt.mnemonic in ("test", "cmp"):
                if any(o.type == X86_OP_REG and ctx.canon_reg(o.reg) == dst for o in nxt.operands):
                    after = ctx.peek(k + 1)
                    return after is not None and after.mnemonic.startswith("j") and after.mnemonic != "jmp"
            elif nxt.mnemonic.startswith("j"):
                return False
        return False


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
        NullCheckRule(),  # before CompareImm: the guard pair is not a real branch
        NullCompareRule(),  # pointer-width == 0 is JNull/JNotNull, not JEq
        FloatZeroRule(),  # before Arith/Xor fallbacks
        FloatLoadRule(),
        FloatStoreRule(),
        CallRule(),
        CondBranchRule(),
        TailJmpRule(),  # before JmpRule: a jump into the epilogue is a Ret
        JmpRule(),
        RetRule(),
        CompareImmRule(),
        ConvertRule(),
        SetBoolRule(),
        SSEArithRule(),
        SSEDivRule(),
        DivRule(),
        XorRule(),
        IncrDecrRule(),  # before Arith: a +/-1 read-modify-write is Incr/Decr
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
        self._module_funcs: Optional[set] = None
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

    @property
    def module_funcs(self) -> set:
        """Entry addresses of every module function, from hl_functions_ptrs."""
        if self._module_funcs is None:
            out: set = set()
            ps = self.bin_view.symbol("hl_functions_ptrs")
            if ps is not None and ps.size:
                for k in range(ps.size // self.bin_view.PTR):
                    p = self.bin_view.read_ptr(ps.value + self.bin_view.PTR * k)
                    if p:
                        out.add(p)
            self._module_funcs = out
        return self._module_funcs

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
        ctx.seed_args()
        i = 0
        while i < len(insns):
            ctx.index = i
            for rl in self._buckets.get(ctx.mnemonic, ()):
                if rl.apply(ctx):
                    break
            # A rule may consume a window by advancing ctx.index; remember it
            # before resetting for bookkeeping.
            consumed = ctx.index
            # Bookkeeping runs *after* the rule: operands describe the state
            # before the instruction executes, and the destination often aliases
            # a source (`mov rdi, [rdi+8]` loads a field of `this` into `this`).
            # Tracking first would kill the value the rule needs to read.
            ctx.index = i
            ctx.track()
            i = max(i + 1, consumed + 1)
        return out

    def _make_context(self, addr: int, insns: list, out: List[LiftedOp]) -> LiftContext:
        ctx = LiftContext(self.bin_view, addr, insns, 0, self.plt_map, out)
        ctx.md = self.md
        ctx.module_funcs = self.module_funcs
        return ctx


def _x86_parent_names() -> Dict[str, str]:
    """Sub-register name -> its 64-bit parent name."""
    out: Dict[str, str] = {}
    for b in ("ax", "bx", "cx", "dx"):
        q = "r" + b
        out.update({q: q, "e" + b: q, b: q, b[0] + "l": q, b[0] + "h": q})
    for b in ("si", "di", "bp", "sp"):
        q = "r" + b
        out.update({q: q, "e" + b: q, b: q, b + "l": q})
    for n in range(8, 16):
        q = f"r{n}"
        out.update({q: q, q + "d": q, q + "w": q, q + "b": q})
    return out


_X86_PARENT_NAMES = _x86_parent_names()
# SysV argument registers, in order.
_X86_ARG_NAMES = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
# Survive a call under SysV, so a value parked here stays known across one.
_X86_CALLEE_SAVED = ("rbx", "rbp", "r12", "r13", "r14", "r15")


class X86LiftContext(LiftContext):
    OP_REG = X86_OP_REG

    """x86-64 value tracking: immediates, symbol addresses, argument registers
    and spill slots, so rules can ask what a register holds instead of guessing
    from the mnemonic alone."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._canon: Dict[int, int] = {}
        self._arg_regs: List[int] = []
        self._callee_saved: set = set()

    def canon_reg(self, reg: int) -> int:
        """Collapse width aliases: eax, ax and al all canonicalise to rax."""
        hit = self._canon.get(reg)
        if hit is not None:
            return hit
        name = self.md.reg_name(reg) if self.md is not None else None
        parent = _X86_PARENT_NAMES.get(name or "", name or "")
        # Resolve the parent name back to an id via the first reg that maps to
        # it; ids are stable per engine, so cache aggressively.
        self._canon[reg] = reg if parent == name else self._name_to_id(parent, reg)
        return self._canon[reg]

    def _name_to_id(self, parent: str, fallback: int) -> int:
        from capstone import x86 as _x86

        return getattr(_x86, f"X86_REG_{parent.upper()}", fallback)

    def seed_args(self) -> None:
        for i, nm in enumerate(_X86_ARG_NAMES):
            rid = self._name_to_id(nm, 0)
            if rid:
                self._arg_regs.append(rid)
                self.vals[rid] = ("arg", i)
        if not self._has_frame_pointer():
            # Without a frame-pointer prologue, rbp is just another callee-saved
            # register and routinely holds an object pointer. Treating it as a
            # spill base swallows real field traffic, so only trust rsp.
            from capstone.x86 import X86_REG_EBP, X86_REG_RBP

            self._spill_bases = self._spill_bases - {X86_REG_RBP, X86_REG_EBP}
        self._callee_saved = {r for r in (self._name_to_id(n, 0) for n in _X86_CALLEE_SAVED) if r}
        self._compute_stable_this(self._name_to_id("rdi", 0))

    def _defines_nothing(self, mnemonic: str) -> bool:
        return mnemonic in ("cmp", "test", "push", "jmp", "ret", "call") or mnemonic.startswith("j")

    def _has_frame_pointer(self) -> bool:
        """True for the classic `push rbp; mov rbp, rsp` prologue."""
        from capstone.x86 import X86_REG_RBP, X86_REG_RSP

        for ins in self.insns[:4]:
            if ins.mnemonic != "mov" or len(ins.operands) != 2:
                continue
            dst, src = ins.operands
            if (
                dst.type == X86_OP_REG
                and src.type == X86_OP_REG
                and dst.reg == X86_REG_RBP
                and src.reg == X86_REG_RSP
            ):
                return True
        return False

    def track(self) -> None:
        m, ops = self.mnemonic, self.ops
        if m == "call":
            # Only the caller-saved set is clobbered. Keeping the callee-saved
            # registers matters: GCC parks `this` in one across a call, and
            # forgetting it there costs every GetThis after the first call.
            for r in list(self.vals):
                if r not in self._callee_saved:
                    del self.vals[r]
            return
        if m == "xor" and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[0].reg == ops[1].reg:
            self.set_val(ops[0].reg, ("imm", 0))
            return
        if m in ("mov", "movsxd", "movzx", "movsx", "lea") and len(ops) == 2:
            dst, src = ops
            if dst.type == X86_OP_REG:
                self.set_val(dst.reg, self._src_val(src, lea=(m == "lea")))
                return
            if dst.type == X86_OP_MEM and self.is_spill_slot(dst) and src.type == X86_OP_REG:
                self.slots[dst.mem.disp] = self.val_of(src.reg)  # type: ignore[assignment]
                return
        # any other write kills the destination
        if ops and ops[0].type == X86_OP_REG and m not in ("cmp", "test", "push"):
            self.set_val(ops[0].reg, None)

    def _src_val(self, src, lea: bool) -> Optional[Tuple[str, Any]]:
        if src.type == X86_OP_IMM:
            return ("imm", src.imm)
        if src.type == X86_OP_REG:
            return self.val_of(src.reg)
        if src.type == X86_OP_MEM:
            if self.is_spill_slot(src) and not _mem_base_is_rip(src):
                # Remember which slot a value came out of even when its content
                # is unknown: a slot-to-slot copy is HL's `Mov`.
                return self.slots.get(src.mem.disp) or ("slot", src.mem.disp)
            sym = self.resolve_mem_sym(src)
            if sym and _mem_base_is_rip(src):
                return ("sym", sym)
        return None


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

    def _make_context(self, addr: int, insns: list, out: List[LiftedOp]) -> LiftContext:
        ctx = X86LiftContext(self.bin_view, addr, insns, 0, self.plt_map, out)
        ctx.md = self.md
        ctx.module_funcs = self.module_funcs
        return ctx


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

    CALL_MNEMONICS = ("bl", "blr")
    TERMINATORS = ("ret",)
    BRANCH_PREFIXES = ("b.", "cb", "tb")
    OP_REG = _ARM64_OP_REG

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._spill_bases = {_ARM64_REG_SP}
        self._arg_regs: List[int] = []
        self._callee_saved: set = set()

    def _reg(self, name: str) -> int:
        from capstone import arm64 as _a

        return getattr(_a, f"ARM64_REG_{name.upper()}", 0)

    def canon_reg(self, reg: int) -> int:
        """Collapse the w/x views of one register (w0 and x0 are the same)."""
        name = self.md.reg_name(reg) if self.md is not None else None
        if name and name[:1] == "w" and name[1:].isdigit():
            return self._reg("x" + name[1:]) or reg
        return reg

    def seed_args(self) -> None:
        for i in range(8):  # AAPCS passes the first eight arguments in x0-x7
            rid = self._reg(f"x{i}")
            if rid:
                self._arg_regs.append(rid)
                self.vals[rid] = ("arg", i)
        self._callee_saved = {r for r in (self._reg(f"x{n}") for n in range(19, 29)) if r}
        self._compute_stable_this(self._reg("x0"))

    def _defines_nothing(self, mnemonic: str) -> bool:
        return mnemonic.startswith(("cmp", "cmn", "tst", "st", "b", "cb", "tb", "ret"))

    def _track_vals(self, m: str, ops) -> None:
        """Maintain the abstract value map alongside the address tracker."""
        if m in self.CALL_MNEMONICS:
            for r in list(self.vals):
                if r not in self._callee_saved:
                    del self.vals[r]
            return
        if m in ("mov", "orr") and len(ops) == 2 and all(o.type == _ARM64_OP_REG for o in ops):
            self.set_val(ops[0].reg, self.val_of(ops[1].reg))
            return
        if m in ("mov", "movz") and len(ops) == 2 and ops[1].type == _ARM64_OP_IMM:
            self.set_val(ops[0].reg, ("imm", ops[1].imm))
            return
        # Stores name the value first, so they define nothing; compares define
        # only flags. Everything else kills its destination.
        if ops and ops[0].type == _ARM64_OP_REG and not m.startswith(("cmp", "cmn", "tst", "st")):
            self.set_val(ops[0].reg, None)

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
        self._track_vals(m, ops)
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


@rule("cbz", "cbnz")
class ArmNullCheckRule(LiftRule):
    """
    aarch64 spelling of the null guard: `cbz x, <cold>` where the cold block
    calls `hl_null_access`. Same reasoning as the x86 `NullCheckRule` - the
    landing site is what separates the guard from a real conditional jump.
    """

    def apply(self, ctx: LiftContext) -> bool:
        target = ctx.branch_target()
        if target is None:
            return False
        # `cbz` branches when the value *is* null, so that side is the cold one;
        # `cbnz` skips the guard, leaving the fallthrough cold.
        cold = target if ctx.mnemonic == "cbz" else ctx.insn.address + ctx.insn.size
        if not ctx.leads_to_call(cold, _NULL_ACCESS):
            return False
        ctx.emit("NullCheck", src_addr=ctx.insn.address)
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
    op = "GetThis" if ctx.mem_base_is_this(mem_op) else "LoadField"
    ctx.emit(op, src_addr=ctx.insn.address, off=mem_op.mem.disp)
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
    op = "SetThis" if ctx.mem_base_is_this(mem_op) else "StoreField"
    ctx.emit(op, src_addr=ctx.insn.address, off=mem_op.mem.disp)
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
        ArmNullCheckRule(),  # before ArmZeroBranch: a guard is not a real jump
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
        ctx = ARM64LiftContext(self.bin_view, addr, insns, 0, self.plt_map, out)
        ctx.md = self.md
        ctx.module_funcs = self.module_funcs
        return ctx
