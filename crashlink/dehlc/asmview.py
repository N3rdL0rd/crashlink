"""
Native assembly viewing for de-HL/C images.

The HL/C compiler keeps every recovered function's original machine code in the
binary; this module renders it per-findex (via `hl_functions_ptrs[]`) with
symbol annotations, so the assembly that actually runs stays inspectable even
where opcode lifting has not (or cannot) recover a body. Shared by the CLI
(`nasm`) and available to GUI views.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

try:
    from capstone import CS_GRP_CALL, CS_GRP_JUMP
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM
    from capstone.arm64 import ARM64_OP_IMM
except ImportError:
    raise NotImplementedError(
        "Cannot run dehl without lief and capstone installed. Try `pip install crashlink[extras]` or `pip install lief capstone`."
    )

from .binary import (
    HLCBinary,
    PTR,
    _resolve_call_target_name,
    _resolve_mem_target,
    _resolve_plt_targets,
)


def findex_code_addrs(bin_view: HLCBinary) -> Dict[int, int]:
    """
    Maps findex -> code address for every non-null `hl_functions_ptrs[]` entry.
    Null slots are native primitives resolved by the HL VM at runtime.
    Memoised per binary (the table read is O(functions)).
    """
    cached = getattr(bin_view, "_findex_code_addrs_cache", None)
    if cached is not None:
        return cached
    out: Dict[int, int] = {}
    sym = bin_view.symbol("hl_functions_ptrs")
    if sym is None or sym.size == 0:
        return out
    # Pair with the fun-type table like the recovery pass does, so trailing
    # linker padding entries are excluded.
    tsym = bin_view.symbol("hl_functions_types")
    n = min(sym.size, tsym.size if tsym is not None else sym.size) // PTR
    for k in range(n):
        p = bin_view.read_ptr(sym.value + k * PTR)
        if p:
            out[k] = p
    bin_view._findex_code_addrs_cache = out  # ty: ignore[unresolved-attribute]
    return out


def _function_extent(bin_view: HLCBinary, addr: int, addrs: List[int]) -> int:
    """
    Best-effort instruction budget for a function body: the symbol's own size
    when known, otherwise the gap to the next function-table address, capped so
    a bogus symbol never floods the output.
    """
    sym = bin_view.symbol(bin_view.symbol_at(addr) or "")
    if sym is not None and sym.size:
        return sym.size
    nxt = [a for a in addrs if a > addr]
    cap = (min(nxt) - addr) if nxt else 4096
    return max(16, min(cap, 65536))


def _target_name(bin_view: HLCBinary, plt_map: Dict[int, str], target: int) -> Optional[str]:
    """Resolves an address to a symbol, PLT import, or containing data symbol."""
    name = _resolve_call_target_name(bin_view, plt_map, target)
    if name:
        return name
    cont = bin_view.containing_symbol(target)
    if cont is not None:
        return f"{cont[0]}+{cont[1]:#x}" if cont[1] else cont[0]
    return None


def function_asm_block(
    bin_view: HLCBinary,
    findex: int,
    max_insns: Optional[int] = None,
    plt_map: Optional[Dict[int, str]] = None,
) -> Optional[Tuple[str, List[str]]]:
    """
    Renders the original compiled assembly of `findex` as (header, rows).

    Returns None when the slot has no code address (native primitive / out of
    range). Call and jump targets are annotated with resolved symbol names;
    RIP-relative memory references are annotated with the symbol containing the
    accessed data (`t$`/`g$`/`s$` tables included). Rows carry no header/ruler
    so callers can interleave several functions in one view.
    """
    addrs_map = findex_code_addrs(bin_view)
    addr = addrs_map.get(findex)
    if not addr:
        return None

    all_addrs = sorted(set(addrs_map.values()))
    size = _function_extent(bin_view, addr, all_addrs)
    if plt_map is None:
        plt_map = _resolve_plt_targets(bin_view)

    sym_name = bin_view.symbol_at(addr)
    code_bytes = bin_view.read_bytes(addr, size)
    insns = list(bin_view._capstone().disasm(code_bytes, addr))
    truncated = False
    if max_insns is not None and len(insns) > max_insns:
        insns = insns[:max_insns]
        truncated = True

    def note(target: int) -> Optional[str]:
        return _target_name(bin_view, plt_map, target)

    # (address, byte-hex column, instruction text, comment)
    rendered: List[Tuple[int, str, str, str]] = []
    byte_col = 0
    for insn in insns:
        raw = insn.bytes
        bstr = raw[:5].hex()
        if len(raw) > 5:
            bstr += ".."
        comments: List[str] = []

        # Direct call/jump targets.
        is_flow = any(_safe_group(insn, g) for g in (CS_GRP_CALL, CS_GRP_JUMP))
        if is_flow:
            for op in insn.operands:
                if op.type in (X86_OP_IMM, ARM64_OP_IMM):
                    nm = note(op.imm)
                    if nm:
                        comments.append(nm)
                    break

        # Data references through rip-relative memory operands (x86-64).
        if bin_view.arch != "aarch64":
            for op in insn.operands:
                if op.type != X86_OP_MEM:
                    continue
                tgt = _resolve_mem_target(insn, op)
                if not tgt:
                    continue
                nm = bin_view.symbol_at(tgt)
                if not nm:
                    cont = bin_view.containing_symbol(tgt)
                    nm = f"{cont[0]}+{cont[1]:#x}" if cont else None
                if nm:
                    comments.append(nm)

        rendered.append((insn.address, bstr, f"{insn.mnemonic} {insn.op_str}".rstrip(), "; ".join(comments)))
        byte_col = max(byte_col, len(bstr))

    addr_w = max((len(f"{a:x}") for a, _, _, _ in rendered), default=1)
    rows = [
        f"  0x{a:0{addr_w}x}  {b:<{byte_col}}  {t}" + (f"  ; {c}" if c else "") for a, b, t, c in rendered
    ]

    head_extra = "" if sym_name else " <anonymous>"
    trunc_note = f"  (first {len(rendered)} instructions)" if truncated else ""
    head = f"f@{findex}{head_extra}  {sym_name or ''} ({addr:#x}, ~{size:#x} bytes){trunc_note}"
    return head, rows


def format_function_asm(
    bin_view: HLCBinary,
    findex: int,
    max_insns: Optional[int] = None,
    plt_map: Optional[Dict[int, str]] = None,
) -> Optional[str]:
    """Renders one function's assembly as a standalone text block (`nasm` CLI)."""
    block = function_asm_block(bin_view, findex, max_insns=max_insns, plt_map=plt_map)
    if block is None:
        return None
    head, rows = block
    return "\n".join([head, "-" * max(len(head), 40)] + rows)


def _safe_group(insn, group: int) -> bool:
    """Capstone group membership check that tolerates arch quirks."""
    try:
        return bool(insn.group(group))
    except Exception:
        return False
