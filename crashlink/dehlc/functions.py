"""
Function/native table reconstruction.
"""

from __future__ import annotations

import struct
from typing import Dict, List, Optional, Tuple

from ..core import (
    Type,
    VarInt,
    fIndex,
    strRef,
    tIndex,
    Native,
    Function,
)
from .binary import (
    PTR,
    _elf_imports,
    _pe_import_map,
    _relocated_table_slots,
)
from .context import DehlcContext
from .types import _sign_from_recon_type


def _split_prim_symbol(sym: str, db_by_name: Dict[str, str]) -> Tuple[str, str]:
    """
    Splits a linked C primitive symbol into (lib, name). libhl "std" prims are
    `hl_<name>`; other known libs use `<lib>_<name>`. Unknown symbols fall back
    to stripping the hl_ prefix into lib "std".
    """
    if sym.startswith("hl_"):
        candidate = sym[3:]
        if candidate in db_by_name:
            return db_by_name[candidate], candidate
        return "std", candidate
    for lib in ("fmt", "ssl", "ui", "uv", "sdl", "openal", "mysql", "sqlite", "haxe"):
        if sym.startswith(lib + "_"):
            rest = sym[len(lib) + 1 :]
            if rest in db_by_name:
                return db_by_name[rest], rest
            return lib, rest
    if sym in db_by_name:
        return db_by_name[sym], sym
    return "std", sym


def _recover_native_names(ctx: "DehlcContext", natives: List[Native], types: List[Type]) -> None:
    """
    Recovers native lib/name pairs. PE resolves slots through the import
    directory; ELF uses JUMP_SLOT relocations, with a signature-shape
    fallback against the DEFINE_PRIM database.
    """
    try:
        from .hlnative_db import HL_NATIVE_SIGNATURES
    except ImportError:
        HL_NATIVE_SIGNATURES = {}
    db_by_name: Dict[str, str] = {name: lib for name, (lib, _) in HL_NATIVE_SIGNATURES.items()}
    db_by_sign: Dict[str, List[str]] = {}
    for name, (_lib, sign) in HL_NATIVE_SIGNATURES.items():
        db_by_sign.setdefault(sign, []).append(name)

    by_slot = _relocated_table_slots(ctx.bin, "hl_functions_ptrs")
    imports = _elf_imports(ctx.bin)

    def prim_name_from_tag(tag: str) -> Optional[str]:
        """dll!symbol -> bare primitive symbol (hl_obj_get_field / fmt_alloc_array...)."""
        return tag.split("!", 1)[1] if "!" in tag else None

    used = set()
    unmatched = 0
    for nat in natives:
        fi = nat.findex.value if nat.findex else -1
        lib = name = None
        if fi in by_slot:
            lib, name = _split_prim_symbol(by_slot[fi], db_by_name)
        elif fi in getattr(ctx, "pe_import_by_findex", {}):
            sym = ctx.pe_import_by_findex[fi].split("!", 1)[1]
            dll = ctx.pe_import_by_findex[fi].split("!", 1)[0]
            lib, name = _split_prim_symbol(sym, db_by_name)
            # Non-libhdll imports keep their module identity (fmt.hdll -> fmt).
            base_dll = dll.lower()
            for suf in (".hdll", ".dll"):
                if base_dll.endswith(suf):
                    base_dll = base_dll[: -len(suf)]
                    break
            base_dll = base_dll.removeprefix("lib")
            if base_dll not in ("hl", "libhl"):
                lib = base_dll
        else:
            # Signature-based fallback.
            ti = nat.type.value if nat.type else -1
            sign = _sign_from_recon_type(types, ti, ctx) if 0 <= ti < len(types) else None
            candidates = db_by_sign.get(sign, []) if sign else []
            pick = None
            for c in sorted(candidates):
                if c in imports and c not in used:
                    pick = c
                    break
            if pick is None:
                for c in sorted(candidates):
                    if c not in used:
                        pick = c
                        break
            if pick is not None:
                used.add(pick)
                lib, name = _split_prim_symbol(
                    "hl_" + pick if not pick.startswith("hl_") else pick, db_by_name
                )
        if lib is None:
            unmatched += 1
            lib, name = "std", ""
        nat.lib = strRef(ctx.add_str(lib))
        nat.name = strRef(ctx.add_str(name or ""))
    if unmatched:
        ctx.log(f"  {unmatched} natives unmatched")


def _recover_functions(ctx: DehlcContext) -> Tuple[List[Function], List[Native], Optional[fIndex]]:
    """
    Rebuilds the function/native tables from hl_functions_ptrs[]/hl_functions_types[].
    NULL entries in the pointer array are natives (resolved at runtime by the HL VM);
    every other entry is a real function body in this binary.
    """
    bin_view = ctx.bin
    functions: List[Function] = []
    natives: List[Native] = []
    entrypoint: Optional[fIndex] = None

    fptrs_sym = bin_view.symbol("hl_functions_ptrs")
    ftypes_sym = bin_view.symbol("hl_functions_types")
    if fptrs_sym is None or ftypes_sym is None:
        print("Warning: hl_functions_ptrs/hl_functions_types missing - no function recovery.")
        return functions, natives, entrypoint

    nentries = min(fptrs_sym.size, ftypes_sym.size) // PTR
    raw_ptrs = bin_view.read_bytes(fptrs_sym.value, nentries * PTR)
    raw_types = bin_view.read_bytes(ftypes_sym.value, nentries * PTR)
    ibase = getattr(bin_view, "image_base", 0)
    ptrs = tuple(v - ibase if v else 0 for v in struct.unpack(f"<{nentries}Q", raw_ptrs))
    ftypes = tuple(v - ibase if v else 0 for v in struct.unpack(f"<{nentries}Q", raw_types))

    # ELF marks native slots as NULL; on PE the slots hold import thunks / IAT
    # addresses instead, so resolve them through the import tables.
    pe_imports = _pe_import_map(bin_view) if bin_view.format == "pe" else {}
    import_names = {tag.split("!", 1)[1] for tag in pe_imports.values()}

    def _resolve_native_slot(fptr: int) -> Optional[str]:
        """Returns the dll!symbol tag when this slot references an imported primitive."""
        if not fptr:
            return None
        tag = pe_imports.get(fptr)
        if tag:
            return tag
        # MinGW emits a jump thunk named after the import itself.
        nm = bin_view.symbol_at(fptr)
        if nm and nm in import_names:
            for a, t in pe_imports.items():
                if t.endswith("!" + nm):
                    return t
            return "libhl.dll!" + nm
        return None

    for findex, (fptr, ftype_ptr) in enumerate(zip(ptrs, ftypes)):
        ftype_ti = ctx.tindex_for_ptr(ftype_ptr)
        imp_tag = _resolve_native_slot(fptr)
        if fptr == 0 or imp_tag:
            if imp_tag:
                ctx.pe_import_by_findex[findex] = imp_tag
            nat = Native()
            nat.findex = fIndex(findex)
            nat.type = ftype_ti if ftype_ti is not None else tIndex(-1)
            natives.append(nat)
        else:
            fn = Function()
            fn.type = ftype_ti if ftype_ti is not None else tIndex(-1)
            fn.findex = fIndex(findex)
            fn.nregs = VarInt(0)
            fn.nops = VarInt(0)
            fn.has_debug = False
            fn.version = None
            fn.debuginfo = None
            functions.append(fn)

    if ptrs:
        # The module initialiser is emitted last by the HL/C generator. Newer Haxe
        # names it `fun$init`; older builds leave an `f$<n>` name - the final entry
        # is still the entrypoint in both cases.
        entrypoint = fIndex(nentries - 1)
        for i, p in enumerate(ptrs):
            if bin_view.symbol_at(p) == "fun$init":
                entrypoint = fIndex(i)
                break
        # Some linkers append zero-padding entries to the pointer array; those
        # trailing slots are not module members. Padding is fully zeroed (no
        # pointer AND no fun-type), unlike genuine native slots which carry a type.
        cutoff = nentries - 1
        while cutoff >= 0 and ptrs[cutoff] == 0 and ftypes[cutoff] == 0:
            cutoff -= 1
        if cutoff < nentries - 1:
            functions = [fn for fn in functions if fn.findex.value <= cutoff]
            natives = [nat for nat in natives if nat.findex.value <= cutoff]
    return functions, natives, entrypoint
