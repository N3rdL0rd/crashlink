"""Constant-pool synthesis from function-body immediates."""

from __future__ import annotations

import struct
from typing import Dict, List, Optional, Tuple

from ..core import (
    tIndex,
)
from .binary import (
    HL_CONST_STRING_PREFIX,
    PTR,
    HLCBinary,
    _resolve_call_target_name,
    _resolve_mem_target,
    disasm_function,
)
from .init_analysis import _track_arm64_address_events

# ============================================================================
# pools
# ============================================================================

try:
    import lief  # noqa: F401
    from capstone import CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_64, CS_MODE_LITTLE_ENDIAN, Cs  # noqa: F401
    from capstone.arm64 import (  # noqa: F401
        ARM64_OP_IMM,
        ARM64_OP_MEM,
        ARM64_OP_REG,
        ARM64_REG_X0,
        ARM64_REG_X17,
    )
    from capstone.x86 import (  # noqa: F401
        X86_OP_IMM,
        X86_OP_MEM,
        X86_OP_REG,
        X86_REG_EDI,
        X86_REG_RDI,
        X86_REG_RIP,
    )
except ImportError:
    raise NotImplementedError(
        "Cannot run dehl without lief and capstone installed. Try `pip install crashlink[extras]` or `pip install lief capstone`."
    )


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
    from capstone import arm64 as cs_a64
    from capstone import x86 as cs_x86

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


# ============================================================================
# context
#
# Shared reconstruction context passed between recovery passes.
# ============================================================================


class DehlcContext:
    """Shared state for a single de-HL/C extraction run."""

    def __init__(self, bin_view: HLCBinary, verbose: bool = False):
        self.bin = bin_view
        self.verbose = verbose
        self.strs: List[str] = []
        self.name_to_tindex: Dict[str, tIndex] = {}
        # t$ symbol virtual address -> reconstructed type index (robust against
        # alias symbols like GCC's `$d` sharing an address with the real symbol).
        self.ptr_to_tindex: Dict[int, tIndex] = {}
        # findex -> "dll!symbol" import name (PE images only).
        self.pe_import_by_findex: Dict[int, str] = {}

    def log(self, msg: str) -> None:
        if self.verbose:
            print(msg)

    def add_str(self, val: str) -> int:
        if val not in self.strs:
            self.strs.append(val)
            return len(self.strs) - 1
        return self.strs.index(val)

    def tindex_for_ptr(self, ptr: int) -> Optional[tIndex]:
        if not ptr:
            return None
        # Prefer the exact address map; fall back to symbol-name resolution.
        ti = self.ptr_to_tindex.get(ptr)
        if ti is not None:
            return ti
        return self.name_to_tindex.get(self.bin.symbol_at(ptr))


# ============================================================================
# strings
#
# String table and hash-name recovery.
# ============================================================================

try:
    import lief  # noqa: F401
    from capstone import CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_64, CS_MODE_LITTLE_ENDIAN, Cs  # noqa: F401
    from capstone.arm64 import (  # noqa: F401
        ARM64_OP_IMM,
        ARM64_OP_MEM,
        ARM64_OP_REG,
        ARM64_REG_X0,
        ARM64_REG_X17,
    )
    from capstone.x86 import (  # noqa: F401
        X86_OP_IMM,
        X86_OP_MEM,
        X86_OP_REG,
        X86_REG_EDI,
        X86_REG_RDI,
        X86_REG_RIP,
    )
except ImportError:
    raise NotImplementedError(
        "Cannot run dehl without lief and capstone installed. Try `pip install crashlink[extras]` or `pip install lief capstone`."
    )


def _recover_strings(ctx: DehlcContext) -> None:
    """Reads string contents out of fully-initialised const_s$X objects."""
    bin_view = ctx.bin
    const_str_syms = [s for s in bin_view.symbols if str(s.name).startswith(HL_CONST_STRING_PREFIX)]
    # Reverse address order == declaration order == first-use order
    const_str_syms.sort(key=lambda s: s.value, reverse=True)
    for sym in const_str_syms:
        bytes_ptr = bin_view.read_ptr(sym.value + PTR)
        length = bin_view.read_int(sym.value + PTR * 2, 4)
        if bytes_ptr and 0 <= length < (1 << 24):
            ctx.add_str(bin_view.read_utf16(bytes_ptr, length))


def _recover_hash_names(ctx: DehlcContext, plt_map: Dict[int, str]) -> None:
    """
    Recovers field/method names from hl_init_hashes, which passes every hashed name to
    hl_hash as a literal UTF-16 string argument.
    """
    if ctx.bin.arch == "aarch64":
        _recover_hash_names_arm64(ctx, plt_map)
        return
    bin_view = ctx.bin
    instructions = disasm_function(bin_view, "hl_init_hashes")

    def is_hash_call(insn) -> bool:
        if insn.mnemonic != "call" or len(insn.operands) != 1 or insn.operands[0].type != X86_OP_IMM:
            return False
        return _resolve_call_target_name(bin_view, plt_map, insn.operands[0].imm) == "hl_hash"

    pending_addr = 0
    for insn in instructions:
        if insn.mnemonic in ("mov", "lea") and len(insn.operands) == 2:
            dest, src = insn.operands
            # mov edi/rdi, <imm> or lea rdi, [rip+X] - string address into first arg
            if dest.type == X86_OP_REG and dest.reg in (X86_REG_RDI, X86_REG_EDI):
                if src.type == X86_OP_IMM:
                    pending_addr = src.imm
                    continue
                if src.type == X86_OP_MEM:
                    addr = _resolve_mem_target(insn, src)
                    if addr:
                        pending_addr = addr
                        continue
        if pending_addr and is_hash_call(insn):
            try:
                ctx.add_str(bin_view.read_cstr_utf16(pending_addr, max_chars=512))
            except Exception:
                pass
        if insn.mnemonic in ("call", "jmp"):
            pending_addr = 0


def _recover_hash_names_arm64(ctx: DehlcContext, plt_map: Dict[int, str]) -> None:
    """
    aarch64 variant of hashed-name recovery: the string address is materialised into
    x0 via adrp/add (or movz/movk) and then `bl hl_hash` is called.
    """
    bin_view = ctx.bin
    instructions = disasm_function(bin_view, "hl_init_hashes")

    def on_call(target_addr: int, regs: Dict[int, int], partial_imm: Dict[int, int]) -> None:
        name = _resolve_call_target_name(bin_view, plt_map, target_addr)
        pending = regs.get(ARM64_REG_X0) or partial_imm.get(ARM64_REG_X0) or 0
        if name == "hl_hash" and pending:
            try:
                ctx.add_str(bin_view.read_cstr_utf16(pending, max_chars=512))
            except Exception:
                pass

    _track_arm64_address_events(
        instructions,
        on_store=lambda dest, src, imm: None,
        on_call=on_call,
    )


def _dwarf_local_names(bin_view: HLCBinary) -> List[str]:
    """
    Collects local variable/parameter names from DWARF subprograms, when available
    (requires pyelftools and a -g build). In the original bytecode these names live in
    the debug string table; HL/C compilation drops them everywhere except DWARF.
    """
    out: List[str] = []
    try:
        from elftools.elf.elffile import ELFFile  # noqa: F401
    except ImportError:
        return out

    if bin_view.data is None:
        return out
    try:
        elf = bin_view._elffile()
        if elf is None:
            return []
        dwarf = elf.get_dwarf_info()
        for cu in dwarf.iter_CUs():
            top = cu.get_top_DIE()
            if top.tag != "DW_TAG_compile_unit":
                continue
            for die in top.iter_children():
                if die.tag != "DW_TAG_subprogram":
                    continue
                for child in die.iter_children():
                    if child.tag in ("DW_TAG_variable", "DW_TAG_formal_parameter"):
                        name_attr = child.attributes.get("DW_AT_name")
                        if name_attr:
                            out.append(name_attr.value.decode(errors="replace"))
    except Exception:
        pass
    return out
