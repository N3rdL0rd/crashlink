"""
hl_init_types store/call analysis, per architecture.
"""

from __future__ import annotations

from typing import Dict, List, Optional

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: F401
    from capstone.x86 import X86_OP_MEM, X86_REG_RIP, X86_OP_IMM, X86_OP_REG, X86_REG_RDI, X86_REG_EDI  # noqa: F401
    from capstone.arm64 import (  # noqa: F401
        ARM64_OP_IMM,
        ARM64_OP_REG,
        ARM64_OP_MEM,
        ARM64_REG_X0,
        ARM64_REG_X17,
    )
    import lief  # noqa: F401
except ImportError:
    raise NotImplementedError(
        "Cannot run dehl without lief and capstone installed. Try `pip install crashlink[extras]` or `pip install lief capstone`."
    )
from .binary import (
    HL_TYPE_ENUM_GLOBAL_VALUE_OFFSET,
    HL_TYPE_GLOBAL_PREFIX,
    HL_TYPE_OBJ_GLOBAL_VALUE_OFFSET,
    HL_TYPE_UNION_OFFSET,
    HLCBinary,
    _find_source_symbol,
    _resolve_mem_target,
    disasm_function,
)


class InitTypesAnalysis:
    """Results of analysing the hl_init_types function."""

    def __init__(self):
        # Ordered t$ type names as their union field is assigned (module order).
        self.type_order: List[str] = []
        # substruct symbol (objt$X / enumt$X) -> global symbol (g$Y): class value linkage
        self.global_links: Dict[str, str] = {}
        # t$X -> referenced substruct/t$ symbol for REF/NULL/PACKED/VIRTUAL/ENUM kinds
        self.param_links: Dict[str, str] = {}
        # t$X -> raw UTF-16 abs_name content captured from immediate stores
        self.abs_names: Dict[str, str] = {}
        # internal: set of types already appended to type_order
        self._seen_types: set = set()


def _record_type_store(
    result: InitTypesAnalysis, bin_view: HLCBinary, dest_addr: int, src_addr: int, src_imm: Optional[int]
) -> None:
    """
    Classifies a single `*dest = <value>` store observed in hl_init_types, where the
    destination is a symbol-relative address and the source is either a resolved
    address or an immediate. Shared between the x86 and aarch64 analysers.
    """
    containing = bin_view.containing_symbol(dest_addr)
    if containing is None:
        return
    dest_name, offset = containing
    # Immediates may themselves be symbol addresses (x86 stores absolute addresses).
    src_name = None
    if src_addr:
        src_name = bin_view.symbol_at(src_addr)
    elif src_imm is not None:
        src_name = bin_view.symbol_at(src_imm)
        if src_name is not None:
            src_imm = None

    if dest_name.startswith(HL_TYPE_GLOBAL_PREFIX) and offset == HL_TYPE_UNION_OFFSET:
        if dest_name not in result._seen_types:
            result._seen_types.add(dest_name)
            result.type_order.append(dest_name)
        if src_name is not None:
            result.param_links[dest_name] = src_name
        elif src_imm is not None:
            # Abstract names are stored as direct UTF-16 pointers (no symbol).
            try:
                result.abs_names[dest_name] = bin_view.read_cstr_utf16(src_imm, max_chars=512)
            except Exception:
                pass
    elif dest_name.startswith("objt$") and offset == HL_TYPE_OBJ_GLOBAL_VALUE_OFFSET:
        if src_name is not None:
            result.global_links[dest_name] = src_name
    elif dest_name.startswith("enumt$") and offset == HL_TYPE_ENUM_GLOBAL_VALUE_OFFSET:
        if src_name is not None:
            result.global_links[dest_name] = src_name


def analyse_init_types(bin_view: HLCBinary) -> InitTypesAnalysis:
    """
    Disassembles hl_init_types and extracts everything it encodes:

      - ``t$X.<union> = &substruct``  -> module type order + param links
      - ``objt$X.global_value = &g$Y`` -> class value linkage
      - ``enumt$X.global_value = &g$Y`` -> enum value linkage
      - ``t$X.abs_name = <utf16>``     -> abstract type names
    """
    if bin_view.arch == "aarch64":
        return _analyse_init_types_arm64(bin_view)
    return _analyse_init_types_x86(bin_view)


def _analyse_init_types_x86(bin_view: HLCBinary) -> InitTypesAnalysis:
    result = InitTypesAnalysis()
    instructions = disasm_function(bin_view, "hl_init_types")
    if not instructions:
        print("Warning: could not disassemble 'hl_init_types'. Some info may be missing.")
        return result

    # Linear register tracker. GCC keeps `lea` adjacent to its store, but MSVC/MinGW
    # hoist address materialisation and reuse registers across many stores, so the
    # source of a stored pointer must be tracked rather than assumed adjacent.
    regs: Dict[int, int] = {}  # capstone reg id -> resolved address

    def kill(rid: int) -> None:
        regs.pop(rid, None)

    CALLER_SAVED_X86 = {
        "rax",
        "rcx",
        "rdx",
        "rsi",
        "rdi",
        "r8",
        "r9",
        "r10",
        "r11",
        "eax",
        "ecx",
        "edx",
        "esi",
        "edi",
        "r8d",
        "r9d",
        "r10d",
        "r11d",
    }

    for i, insn in enumerate(instructions):
        m = insn.mnemonic
        ops = insn.operands

        if m in ("call", "syscall"):
            for rid in list(regs):
                if bin_view._capstone().reg_name(rid) in CALLER_SAVED_X86:
                    kill(rid)
            continue

        # Address materialisation: lea reg, [rip+disp] / [abs]
        if m == "lea" and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM:
            target = _resolve_mem_target(insn, ops[1])
            if target:
                regs[ops[0].reg] = target
            else:
                kill(ops[0].reg)
            continue

        # Register copies keep tracked addresses alive.
        if m == "mov" and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
            if ops[1].reg in regs:
                regs[ops[0].reg] = regs[ops[1].reg]
            else:
                kill(ops[0].reg)
            continue

        # Stores: mov/qword-style [mem], <src>
        if m.startswith("mov") and len(ops) == 2 and ops[0].type == X86_OP_MEM:
            dest_addr = _resolve_mem_target(insn, ops[0])
            if dest_addr:
                src_addr = 0
                src_imm = None
                src_op = ops[1]
                if src_op.type == X86_OP_IMM:
                    src_imm = src_op.imm
                elif src_op.type == X86_OP_REG:
                    src_addr = regs.get(src_op.reg, 0)
                    if not src_addr and i > 0:
                        # Fallback for untracked patterns: immediately preceding lea.
                        source_name = _find_source_symbol(bin_view, instructions, i, src_op)
                        if source_name is not None:
                            sym = bin_view.symbol(source_name)
                            if sym is not None:
                                src_addr = sym.value
                _record_type_store(result, bin_view, dest_addr, src_addr, src_imm)
            # Any instruction writing a tracked register through memory kills it.
            continue

        # Everything else that writes its first register operand invalidates it.
        if ops and ops[0].type == X86_OP_REG:
            kill(ops[0].reg)

    return result


def _track_arm64_address_events(instructions, on_store, on_call=None) -> None:
    """
    Linear aarch64 address tracker. GCC materialises addresses with `adrp` (page)
    + `add` (offset) pairs into registers, then writes them with `str`/`stur`.
    Immediate constants are built with `movz`/`movk`. Events:
      on_store(dest_addr, src_addr_or_0, src_imm_or_None)
      on_call(target_addr, regs, partial_imm)
    Calls clobber caller-saved registers (x0-x17); callee-saved x19-x28 survive.
    """
    regs: Dict[int, int] = {}  # capstone reg id -> resolved address
    partial_imm: Dict[int, int] = {}  # movz/movk accumulation

    def kill(rid: int) -> None:
        regs.pop(rid, None)
        partial_imm.pop(rid, None)

    def copy_value(dst: int, src: int) -> None:
        if src in regs:
            regs[dst] = regs[src]
            partial_imm.pop(dst, None)
        elif src in partial_imm:
            partial_imm[dst] = partial_imm[src]
            regs.pop(dst, None)
        else:
            kill(dst)

    for insn in instructions:
        m = insn.mnemonic
        ops = insn.operands
        if m == "adrp" and len(ops) == 2 and ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_IMM:
            rid = ops[0].reg
            regs[rid] = ops[1].imm
            partial_imm.pop(rid, None)
        elif (
            m in ("add", "sub")
            and len(ops) == 3
            and ops[0].type == ARM64_OP_REG
            and ops[2].type == ARM64_OP_IMM
        ):
            dst, src = ops[0].reg, (ops[1].reg if ops[1].type == ARM64_OP_REG else 0)
            delta = ops[2].imm if m == "add" else -ops[2].imm
            if src and src in regs:
                regs[dst] = regs[src] + delta
                partial_imm.pop(dst, None)
            else:
                kill(dst)
        elif (
            m in ("movz", "mov")
            and len(ops) == 2
            and ops[0].type == ARM64_OP_REG
            and ops[1].type == ARM64_OP_IMM
        ):
            rid = ops[0].reg
            shift = 16 if "lsl" in insn.op_str else 0
            partial_imm[rid] = ops[1].imm << shift
            regs.pop(rid, None)
        elif m == "movk" and len(ops) == 2 and ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_IMM:
            rid = ops[0].reg
            shift = 16 if "lsl" in insn.op_str else 0
            partial_imm[rid] = partial_imm.get(rid, 0) | (ops[1].imm << shift)
        elif m == "orr" and len(ops) == 3 and all(o.type == ARM64_OP_REG for o in ops):
            # `mov xN, xM` is encoded as `orr xN, wzr/xzr, xM`
            copy_value(ops[0].reg, ops[2].reg)
        elif m == "mov" and len(ops) == 2 and ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_REG:
            copy_value(ops[0].reg, ops[1].reg)
        elif m in ("str", "stur") and len(ops) >= 2 and ops[1].type == ARM64_OP_MEM:
            val_op, mem_op = ops[0], ops[1]
            base = mem_op.mem.base
            if base in regs:
                dest_addr = regs[base] + mem_op.mem.disp
                src_addr = 0
                src_imm = None
                if val_op.type == ARM64_OP_REG:
                    rid = val_op.reg
                    if rid in regs:
                        src_addr = regs[rid]
                    elif rid in partial_imm:
                        src_imm = partial_imm[rid]
                elif val_op.type == ARM64_OP_IMM:
                    src_imm = val_op.imm
                on_store(dest_addr, src_addr, src_imm)
                if "!" in insn.op_str:  # pre-index writeback
                    regs[base] = dest_addr
            elif "!" in insn.op_str and base:
                kill(base)
        elif m == "bl":
            if on_call is not None and len(ops) == 1 and ops[0].type == ARM64_OP_IMM:
                on_call(ops[0].imm, dict(regs), dict(partial_imm))
            for rid in list(regs):
                if ARM64_REG_X0 <= rid <= ARM64_REG_X17:
                    del regs[rid]
            for rid in list(partial_imm):
                if ARM64_REG_X0 <= rid <= ARM64_REG_X17:
                    del partial_imm[rid]
        elif m in ("b", "br", "ret"):
            # Unconditional control flow: conservatively drop tracked state.
            regs.clear()
            partial_imm.clear()


def _analyse_init_types_arm64(bin_view: HLCBinary) -> InitTypesAnalysis:
    """
    aarch64 variant of the hl_init_types analysis; see `_track_arm64_address_events`.
    """
    result = InitTypesAnalysis()
    instructions = disasm_function(bin_view, "hl_init_types")
    if not instructions:
        print("Warning: could not disassemble 'hl_init_types'. Some info may be missing.")
        return result

    _track_arm64_address_events(
        instructions,
        on_store=lambda dest, src, imm: _record_type_store(result, bin_view, dest, src, imm),
    )
    return result
