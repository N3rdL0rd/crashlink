"""
Constant-pool synthesis from function-body immediates.
"""

from __future__ import annotations

import struct
from typing import Dict, List, Tuple

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
from .binary import HLCBinary, _resolve_mem_target
from .context import DehlcContext


def _recover_constant_pools(ctx: "DehlcContext", bin_view: "HLCBinary") -> Tuple[List[int], List[float]]:
    """
    Harvests pool candidates from function bodies: immediates, rip-relative
    SSE rodata loads and vector zeroing (x86); movz/movk accumulation and
    NEON page loads (aarch64).
    """
    import struct as _struct

    fptrs_sym = bin_view.symbol("hl_functions_ptrs")
    if fptrs_sym is None or not fptrs_sym.size:
        return [], []
    nentries = fptrs_sym.size // bin_view.PTR
    ptrs = []
    for k in range(nentries):
        p = bin_view.read_ptr(fptrs_sym.value + bin_view.PTR * k)
        if p and bin_view.symbol_at(p):
            ptrs.append(p)

    ints: List[int] = []
    floats: List[float] = []
    seen_int: set = set()
    seen_float: set = set()

    def add_int(v: int) -> None:
        if v not in seen_int and -(1 << 63) <= v < (1 << 64):
            seen_int.add(v)
            ints.append(v)

    def add_float(v: float) -> None:
        if v not in seen_float:
            seen_float.add(v)
            floats.append(v)

    md = bin_view._capstone()
    from capstone import x86 as cs_x86
    from capstone import arm64 as cs_a64

    for addr in ptrs:
        try:
            size = 4096
            sym = bin_view.symbol_at(addr)
            s = bin_view.symbol(sym) if sym else None
            if s is not None and s.size:
                size = min(s.size, 65536)
            code_bytes = bin_view.read_bytes(addr, size)
            insns = list(md.disasm(code_bytes, addr))
        except Exception:
            continue
        if bin_view.arch == "aarch64":
            partial: Dict[int, int] = {}
            adrp_pages: Dict[int, int] = {}
            for insn in insns:
                m, ops = insn.mnemonic, insn.operands
                if m == "adrp" and len(ops) == 2 and ops[0].type == cs_a64.ARM64_OP_REG:
                    adrp_pages[ops[0].reg] = ops[1].imm
                elif m in ("movz", "mov") and len(ops) == 2 and ops[1].type == cs_a64.ARM64_OP_IMM:
                    if m == "movz":
                        partial[ops[0].reg] = ops[1].imm & 0xFFFFFFFF
                        shift = getattr(ops[1], "shift", 0)
                        if shift:
                            partial[ops[0].reg] <<= shift.value if hasattr(shift, "value") else shift
                    else:
                        add_int(ops[1].imm)
                elif m == "movk" and len(ops) == 2 and ops[0].reg in partial:
                    shift = getattr(ops[1], "shift", 0)
                    sh = shift.value if hasattr(shift, "value") else shift
                    partial[ops[0].reg] |= (ops[1].imm & 0xFFFF) << sh
                    if sh >= 48:
                        add_int(partial.pop(ops[0].reg))
                elif m.startswith("ldr") and len(ops) == 2 and ops[1].type == cs_a64.ARM64_OP_MEM:
                    base, disp = ops[1].mem.base, ops[1].mem.disp
                    page = adrp_pages.get(base)
                    if page is not None:
                        target = page + disp
                        raw = bin_view.read_bytes(target, 8)
                        try:
                            if m in ("ldr d", "ldr") and ops[0].type == cs_a64.ARM64_OP_REG:
                                add_float(_struct.unpack("<d", raw)[0])
                            elif m == "ldr s":
                                add_float(_struct.unpack("<f", raw[:4])[0])
                        except struct.error:
                            pass
                elif m in ("blr", "ret"):
                    partial.clear()
        else:
            for insn in insns:
                m, ops = insn.mnemonic, insn.operands
                # zeroed vector register == float literal 0.0
                if (
                    m in ("xorps", "xorpd", "pxor")
                    and len(ops) == 2
                    and (ops[0].type == cs_x86.X86_OP_REG and ops[0].reg == ops[1].reg)
                ):
                    add_float(0.0)
                    continue
                # float literals: SSE loads from rip-relative rodata
                if m in ("movsd", "movss") and len(ops) == 2 and ops[1].type == cs_x86.X86_OP_MEM:
                    tgt = _resolve_mem_target(insn, ops[1])
                    if tgt:
                        raw = bin_view.read_bytes(tgt, 8)
                        try:
                            if m == "movsd":
                                add_float(_struct.unpack("<d", raw)[0])
                            else:
                                add_float(_struct.unpack("<f", raw[:4])[0])
                        except struct.error:
                            pass
                    continue
                for op in ops:
                    if op.type != cs_x86.X86_OP_IMM:
                        continue
                    imm = op.imm
                    # skip branch targets and call targets
                    if m.startswith(("j", "call", "loop")):
                        continue
                    if (
                        insn.operands
                        and insn.operands[0].type == cs_x86.X86_OP_REG
                        and m
                        in (
                            "mov",
                            "cmp",
                            "add",
                            "sub",
                            "and",
                            "or",
                            "xor",
                            "shl",
                            "shr",
                            "sar",
                            "test",
                        )
                    ):
                        if imm != 0 or True:
                            add_int(imm)
                    elif m in ("push",):
                        add_int(imm)

    return ints, floats
