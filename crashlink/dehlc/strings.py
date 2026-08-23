"""
String table and hash-name recovery.
"""

from __future__ import annotations

from typing import Dict, List

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
    HL_CONST_STRING_PREFIX,
    HLCBinary,
    PTR,
    _resolve_call_target_name,
    _resolve_mem_target,
    disasm_function,
)
from .context import DehlcContext
from .init_analysis import _track_arm64_address_events


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
