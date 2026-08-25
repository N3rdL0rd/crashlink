"""
Module global table recovery (values, types, string constants).
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from ..core import (
    Bytecode,
    Obj,
    tIndex,
    Enum,
)

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
    HL_STRING_GLOBAL_PREFIX,
    HL_TYPE_GLOBAL_PREFIX,
    HL_VALUE_GLOBAL_PREFIX,
)
from .context import DehlcContext
from .init_analysis import InitTypesAnalysis
from .types import _dwarf_def_die_order, _dwarf_global_types, _hl_type_from_c_desc


def _recover_globals(
    ctx: DehlcContext,
    code: Bytecode,
    init_analysis: InitTypesAnalysis,
    string_type_ti: Optional[tIndex],
) -> List[tIndex]:
    """
    Recovers the module global table: BSS `g$`/`s$` symbols ordered via DWARF
    DIE order with address-sort validation against class-value links.
    """
    bin_view = ctx.bin
    global_syms = []
    seen = set()
    for s in bin_view.symbols:
        n = str(s.name)
        if (
            n.startswith(HL_STRING_GLOBAL_PREFIX) or n.startswith(HL_VALUE_GLOBAL_PREFIX)
        ) and not n.startswith(HL_CONST_STRING_PREFIX):
            if s.value != 0 and (n, s.value) not in seen:
                seen.add((n, s.value))
                global_syms.append(s)

    # Ordering: prefer DWARF definition-DIE emission order (= C declaration order =
    # module global order); it is immune to .bss address scrambling. Fall back to
    # address sort whose direction is validated against hl_init_types class-value
    # links (reverse on x86-64 GCC; forward on aarch64 -O0/-fno-toplevel-reorder).
    dwarf_order = _dwarf_def_die_order(bin_view, (HL_VALUE_GLOBAL_PREFIX, HL_STRING_GLOBAL_PREFIX))
    used_dwarf_globals = False
    if dwarf_order:
        rank = {n: i for i, n in enumerate(dwarf_order)}
        known = [s for s in global_syms if str(s.name) in rank]
        unknown = [s for s in global_syms if str(s.name) not in rank]
        if len(known) >= len(global_syms) * 0.9:
            known.sort(key=lambda s: rank[str(s.name)])
            global_syms = known + sorted(unknown, key=lambda s: s.value)
            used_dwarf_globals = True

    if not used_dwarf_globals:
        global_links_targets = set(init_analysis.global_links.values())
        forward = sorted(global_syms, key=lambda s: s.value)
        reverse = sorted(global_syms, key=lambda s: s.value, reverse=True)

        def link_hits(order) -> int:
            names = [str(s.name) for s in order]
            return sum(1 for n in names if n in global_links_targets)

        # Prefer whichever direction places linked class-value globals consistently;
        # fall back to architecture default when no links exist.
        if global_links_targets and link_hits(forward) > link_hits(reverse):
            global_syms = forward
        elif global_links_targets and link_hits(reverse) > link_hits(forward):
            global_syms = reverse
        else:
            global_syms = reverse if bin_view.arch != "aarch64" else forward

    # Collect all candidate type names per global value.
    # Note (from Haxe's hl2c.ml): both objt$X.global_value (o.pclassglobal) and
    # enumt$X.global_value (e.eglobal) targets hold the *class value* of the type,
    # which the original module types as the `$`-prefixed implementation variant.
    global_candidates: Dict[str, List[str]] = {}
    for substruct_name, global_name in init_analysis.global_links.items():
        if substruct_name.startswith("objt$"):
            tname = HL_TYPE_GLOBAL_PREFIX + substruct_name[len("objt$") :]
        elif substruct_name.startswith("enumt$"):
            tname = HL_TYPE_GLOBAL_PREFIX + substruct_name[len("enumt$") :]
        else:
            continue
        global_candidates.setdefault(global_name, []).append(tname)

    def mangle(name: str) -> str:
        # Mirrors Haxe's valid_ident: runs of invalid chars collapse to a single "_".
        return re.sub(r"[^A-Za-z0-9_]+", "_", name)

    # Map of object names -> tIndex for sibling lookups.
    obj_name_to_ti: Dict[str, tIndex] = {}
    enum_ti_by_mangled: Dict[str, tIndex] = {}
    enum_constructs: Dict[int, List[str]] = {}
    for i, t in enumerate(code.types):
        d = t.definition
        if isinstance(d, Obj):
            obj_name_to_ti[d.name.resolve(code)] = tIndex(i)
        elif isinstance(d, Enum):
            mangled = mangle(d.name.resolve(code))
            enum_ti_by_mangled[mangled] = tIndex(i)
            enum_constructs[i] = [c.name.resolve(code) for c in d.constructs]

    # Core type value globals ($Int/$Float/$Dynamic -> hl.CoreType, $Bool -> hl.CoreEnum,
    # $Class/$Enum -> hl.Class/hl.Enum) - their names do not encode the class.
    core_type_map: Dict[str, str] = {}
    for core_name, target in (
        ("Int", "hl.CoreType"),
        ("Float", "hl.CoreType"),
        ("Bool", "hl.CoreEnum"),
        ("Dynamic", "hl.CoreType"),
        ("Class", "hl.Class"),
        ("Enum", "hl.Enum"),
    ):
        ti = obj_name_to_ti.get(target)
        if ti is not None:
            core_type_map[core_name] = target

    def dollar_sibling(name: str) -> Optional[str]:
        """hl.types.ArrayBase -> hl.types.$ArrayBase ; String -> $String"""
        if "." in name:
            head, _, last = name.rpartition(".")
            return f"{head}.$" + last
        return "$" + name

    def class_value_ti(class_name: str) -> Optional[tIndex]:
        """Resolves the class-value global type for a class path (its $-variant)."""
        base = obj_name_to_ti.get(class_name)
        if base is None:
            return None
        sib = obj_name_to_ti.get(dollar_sibling(class_name))
        return sib if sib is not None else base

    global_types: List[tIndex] = []
    unresolved = 0
    dwarf_types = _dwarf_global_types(bin_view)
    for sym in global_syms:
        gname = str(sym.name)
        ti: Optional[tIndex] = None

        if gname.startswith(HL_STRING_GLOBAL_PREFIX):
            if string_type_ti is not None:
                ti = string_type_ti
        else:
            bare = gname[len(HL_VALUE_GLOBAL_PREFIX) :]
            # 1. Direct links from hl_init_types (obj/enum class values).
            cands = global_candidates.get(gname, [])
            best: Optional[str] = None
            desired = bare.lstrip("_")
            for tn in cands:
                if mangle(tn[len(HL_TYPE_GLOBAL_PREFIX) :]) == desired:
                    best = tn
                    break
            if best is None and cands:
                best = cands[0]
            if best is not None:
                base_ti = ctx.name_to_tindex.get(best)
                if base_ti is not None:
                    d = code.types[base_ti.value].definition
                    if isinstance(d, Obj):
                        ti = class_value_ti(d.name.resolve(code)) or base_ti
                    elif isinstance(d, Enum):
                        # e.eglobal holds the enum's *class* value: use $-sibling OBJ.
                        sib = obj_name_to_ti.get(dollar_sibling(d.name.resolve(code)))
                        ti = sib if sib is not None else base_ti
                    else:
                        ti = base_ti
            # 2. Class value globals by name: g$_<mangled class path>. The generator
            #    always prefixes class-value global names with "$" (mangled to "_"),
            #    so match both the bare name and the stripped one; a match against a
            #    "$"-prefixed class is already the implementation variant.
            if ti is None and bare.startswith("_"):
                stripped = bare[1:]
                if stripped in core_type_map:
                    ti = obj_name_to_ti.get(core_type_map[stripped])
                else:
                    for cls_name, cls_ti in obj_name_to_ti.items():
                        m = mangle(cls_name)
                        if m == stripped:
                            ti = class_value_ti(cls_name)
                            break
                        if m == bare:
                            ti = cls_ti
                            break
            # 3. Nullary enum instance globals: g$<mangled enum>_<construct>.
            if ti is None:
                for mangled, eti in enum_ti_by_mangled.items():
                    if bare.startswith(mangled + "_"):
                        construct = bare[len(mangled) + 1 :]
                        if construct in enum_constructs.get(eti.value, []):
                            ti = eti
                            break
            # 4. DWARF C-type fallback (bytes maps, statics, dyn values...).
            if ti is None and dwarf_types:
                desc = dwarf_types.get(gname)
                if desc:
                    ti = _hl_type_from_c_desc(ctx, code, desc)

        if ti is None:
            unresolved += 1
            global_types.append(tIndex(-1))
        else:
            global_types.append(ti)
    if unresolved:
        print(f"Note: {unresolved} globals could not be linked to a type statically.")
    return global_types
