"""
Type-table reconstruction: ordering, parsing and typing.
"""

from __future__ import annotations

import re
import struct
from typing import Any, Dict, List, Optional, Tuple

from ..core import (
    Binding,
    Bytecode,
    Field,
    Fun,
    Null,
    Obj,
    Packed,
    Proto,
    Ref,
    Type,
    VarInt,
    Virtual,
    fIndex,
    fieldRef,
    strRef,
    tIndex,
    Abstract,
    Enum,
    EnumConstruct,
    Native,
    Function,
)
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    from capstone.x86 import X86_OP_MEM, X86_REG_RIP, X86_OP_IMM, X86_OP_REG, X86_REG_RDI, X86_REG_EDI
    from capstone.arm64 import (
        ARM64_OP_IMM,
        ARM64_OP_REG,
        ARM64_OP_MEM,
        ARM64_REG_X0,
        ARM64_REG_X17,
    )
    import lief
except ImportError:
    raise NotImplementedError(
        "Cannot run dehl without lief and capstone installed. Try `pip install crashlink[extras]` or `pip install lief capstone`."
    )
from .binary import (
    HL_BINDING_SIZE,
    HL_CONST_STRING_PREFIX,
    HL_ENUM_CONSTRUCT_SIZE,
    HL_OBJ_FIELD_SIZE,
    HL_OBJ_PROTO_SIZE,
    HL_STRING_GLOBAL_PREFIX,
    HL_TYPE_ENUM_CONSTRUCTS_OFFSET,
    HL_TYPE_ENUM_GLOBAL_VALUE_OFFSET,
    HL_TYPE_ENUM_NAME_OFFSET,
    HL_TYPE_ENUM_NCONSTRUCTS_OFFSET,
    HL_TYPE_FUN_NARGS_OFFSET,
    HL_TYPE_GLOBAL_PREFIX,
    HL_TYPE_OBJ_BINDINGS_OFFSET,
    HL_TYPE_OBJ_FIELDS_OFFSET,
    HL_TYPE_OBJ_GLOBAL_VALUE_OFFSET,
    HL_TYPE_OBJ_NAME_OFFSET,
    HL_TYPE_OBJ_NFIELDS_OFFSET,
    HL_TYPE_OBJ_PROTOS_OFFSET,
    HL_TYPE_OBJ_SUPER_OFFSET,
    HL_TYPE_UNION_OFFSET,
    HL_TYPE_VIRT_FIELDS_OFFSET,
    HL_TYPE_VIRT_NFIELDS_OFFSET,
    HL_VALUE_GLOBAL_PREFIX,
    HLCBinary,
    PTR,
    SIMPLE_KINDS,
    _find_source_symbol,
    _resolve_mem_target,
    disasm_function,
)
from .init_analysis import InitTypesAnalysis, analyse_init_types

def recover_type_order(bin_view: HLCBinary, init_analysis: InitTypesAnalysis) -> Tuple[List[str], bool]:
    """
    Derives type-table declaration order. Candidates from .data layout
    (reverse on x86-64 GCC) are cross-checked against hl_init_types store
    order; scrambled builds fall back to DWARF DIE order anchored by static
    reference tables.
    """
    t_syms = [s for s in bin_view.symbols if str(s.name).startswith(HL_TYPE_GLOBAL_PREFIX)]

    def sec_type(sym) -> str:
        try:
            return str(sym.section.type) if sym.section else ""
        except Exception:
            return ""

    data_syms = sorted((s for s in t_syms if "NOBITS" not in sec_type(s)), key=lambda s: s.value)
    bss_syms = sorted((s for s in t_syms if "NOBITS" in sec_type(s)), key=lambda s: s.value)
    all_syms = sorted(t_syms, key=lambda s: s.value)

    init_order = init_analysis.type_order

    candidates = [
        [str(s.name) for s in reversed(all_syms)],  # x86-64 GCC: reverse everything
        [str(s.name) for s in bss_syms] + [str(s.name) for s in data_syms],  # forward + bss-first
        [str(s.name) for s in all_syms],  # plain forward
        [str(s.name) for s in reversed(bss_syms)] + [str(s.name) for s in reversed(data_syms)],
    ]

    def check(names: List[str]) -> bool:
        init_set = set(init_order)
        sub = [n for n in names if n in init_set]
        if len(sub) != len(init_order):
            return False
        if sub == init_order:
            return True
        # Some compilers reorder independent global stores inside hl_init_types
        # while keeping the .data emission faithful to declaration order. Judge by
        # adjacent-pair agreement instead of positional equality so a handful of
        # local swaps cannot veto an otherwise perfect layout, while genuinely
        # scrambled layouts (~50% pair agreement) stay firmly rejected.
        rank = {name: idx for idx, name in enumerate(init_order)}
        ok = sum(1 for a, b in zip(sub, sub[1:]) if rank.get(a, 0) < rank.get(b, 0))
        return ok / max(len(sub) - 1, 1) >= 0.95

    all_names = {str(s.name) for s in t_syms}

    # Self-validating path first: exact .data layout candidates cross-checked
    # against the hl_init_types store chain.
    if init_order:
        for cand in candidates:
            if check(cand):
                return cand, True

        # ------------------------------------------------------------------
        # Scrambled-layout reconstruction.
        #
        # The first 16 type-table entries are compiler-generated boilerplate with a
        # fixed symbol sequence (verified invariant across corpora): 10 VM core
        # types, then hl.BaseType, ARRAY, hl.Class, String, BYTES, hl.$BaseType.
        # Every other non-simple type is complex and therefore already exactly
        # ordered by the hl_init_types store chain. Only DYNOBJ (t$_dynobj) lacks
        # any static anchor - its position encodes when the first anonymous-object
        # literal was compiled - so it is placed just before the fun-type of the
        # function following the first `hl_alloc_dynobj` call site (types are
        # created on demand while a body is compiled, i.e. after that function's
        # own fun-type and before the next one).
        # ------------------------------------------------------------------
        canon = [
            "t$_void",
            "t$_ui8",
            "t$_ui16",
            "t$_i32",
            "t$_i64",
            "t$_f32",
            "t$_f64",
            "t$_bool",
            "t$_type",
            "t$_dyn",
            "t$hl_BaseType",
            "t$_array",
            "t$hl_Class",
            "t$String",
            "t$_bytes",
            "t$hl_$BaseType",
        ]
        canon_syms = [s for s in canon if s in all_names]
        canon_set = set(canon_syms)
        dwarf_type_order = _dwarf_def_die_order(bin_view, (HL_TYPE_GLOBAL_PREFIX,))
        if dwarf_type_order:
            # Preferred signal on optimised builds: DWARF definition-DIE emission
            # order follows C declaration order even when .data/instructions are
            # reordered by the compiler.
            rest = [n for n in dwarf_type_order if n not in canon_set]
            skeleton_note = "DWARF declaration order"
        else:
            rest = [n for n in init_order if n not in canon_set]
            skeleton_note = "hl_init_types skeleton"
        order = canon_syms + rest

        # Types absent from the primary signal still have static anchors:
        #  - deduped-away fun types follow functions_types[] first-use order;
        #  - core-type-like ABSTRACTs / NULL / REF singletons are referenced by
        #    fun-signature argument arrays (fargst$X);
        #  - DYNOBJ sits right before the fun-type of the function following the
        #    first `hl_alloc_dynobj` call site.
        leftovers = [s for s in all_names if s not in set(order)]
        anchors: Dict[str, Optional[str]] = {}
        if leftovers:
            anchors = _find_leftover_anchors(bin_view, order, leftovers)

        def splice(anchor: Optional[str], sym: str) -> None:
            idx = order.index(anchor) if anchor and anchor in order else len(order)
            order.insert(idx, sym)

        def resolve_chain(sym: str, memo: Dict[str, Optional[str]]) -> Optional[str]:
            """Follows leftover->anchor chains until an element of `order` is reached."""
            seen = set()
            cur = sym
            while cur not in order and cur not in seen:
                seen.add(cur)
                nxt = memo.get(cur)
                if nxt is None or nxt == cur:
                    return None
                cur = nxt
            return cur if cur in order else None

        for sym in leftovers:
            splice(resolve_chain(sym, anchors) or anchors.get(sym), sym)

        dynobj = "t$_dynobj"
        if dynobj in all_names and dynobj not in order:
            da = _find_dynobj_anchor(bin_view, init_order)
            target = da if da and da in order else (resolve_chain(da, anchors) if da else None)
            splice(target, dynobj)

        print(
            "Note: .data layout is scrambled by compiler toplevel reordering; "
            f"reconstructed via canonical prefix + {skeleton_note} "
            f"({len(order)} types)."
        )
        return order, False

    print("Warning: hl_init_types yielded no ordering information; using raw address order.")
    base = candidates[1] if bin_view.arch == "aarch64" else candidates[0]
    return base, False


def _dwarf_def_die_order(bin_view: HLCBinary, prefixes: Tuple[str, ...]) -> List[str]:
    """
    Returns global variable names in DWARF top-level DIE emission order, restricted
    to definition DIEs (those carrying DW_AT_specification + DW_AT_location) whose
    name starts with any of `prefixes`. GCC emits definition DIEs in source
    declaration order even when toplevel reordering scrambles .data layout and
    instruction order - making this the most reliable ordering signal available on
    optimised builds. Requires pyelftools and a -g build; returns [] otherwise.
    """
    out: List[str] = []
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return out
    import io

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
                if die.tag != "DW_TAG_variable":
                    continue
                spec_attr = die.attributes.get("DW_AT_specification")
                if not spec_attr or not die.attributes.get("DW_AT_location"):
                    continue
                try:
                    spec = cu.get_DIE_from_refaddr(spec_attr.value)
                except Exception:
                    continue
                nm = spec.attributes.get("DW_AT_name")
                if not nm:
                    continue
                name = nm.value.decode(errors="replace")
                if any(name.startswith(p) for p in prefixes):
                    if not name.startswith(HL_CONST_STRING_PREFIX):
                        out.append(name)
    except Exception:
        pass
    return out


def _find_dynobj_anchor(bin_view: HLCBinary, init_order: List[str]) -> Optional[str]:
    """
    Returns the skeleton symbol before which DYNOBJ belongs: the fun-type of the
    function *following* the first function whose body calls `hl_alloc_dynobj`
    (its type is created on demand while that body compiles). None if unknown.
    """
    try:
        ptrs_sym = bin_view.symbol("hl_functions_ptrs")
        types_sym = bin_view.symbol("hl_functions_types")
        if ptrs_sym is None or types_sym is None or ptrs_sym.size == 0 or types_sym.size == 0:
            return None
        n_entries = min(ptrs_sym.size, types_sym.size) // PTR
        plt_map = _resolve_plt_targets(bin_view)
        target_name = "hl_alloc_dynobj"

        def is_dynobj_call(target_addr: int) -> bool:
            direct = bin_view.symbol_at(target_addr)
            if direct == target_name:
                return True
            return plt_map.get(target_addr) == target_name

        for k in range(n_entries):
            fn_addr = bin_view.read_ptr(ptrs_sym.value + PTR * k)
            if not fn_addr:
                continue  # native entry
            fsym_name = bin_view.symbol_at(fn_addr)
            if not fsym_name:
                continue
            fsym = bin_view.symbol(fsym_name)
            if fsym is None or fsym.size == 0:
                continue
            instructions = disasm_function(bin_view, fsym_name)
            found = False

            def on_call(target_addr: int, regs=None, partial=None):
                nonlocal found
                if is_dynobj_call(target_addr):
                    found = True

            if bin_view.arch == "aarch64":
                _track_arm64_address_events(instructions, on_store=lambda d, s, i_: None, on_call=on_call)
            else:
                for insn in instructions:
                    if insn.mnemonic == "call" and len(insn.operands) == 1 and insn.operands[0].type == X86_OP_IMM:
                        if is_dynobj_call(insn.operands[0].imm):
                            found = True
                            break
                    if found:
                        break
            if not found:
                continue
            # First user at findex k -> dynobj sits before the NEXT function's fun-type.
            if k + 1 < n_entries:
                ft_next = bin_view.read_ptr(types_sym.value + PTR * (k + 1))
                if ft_next:
                    return bin_view.symbol_at(ft_next)
            ft_k = bin_view.read_ptr(types_sym.value + PTR * k)
            if ft_k:
                return bin_view.symbol_at(ft_k)
            return None
    except Exception:
        pass
    return None


def _find_leftover_anchors(bin_view: HLCBinary, base_order: List[str], leftovers: List[str]) -> Dict[str, str]:
    """
    For each leftover type symbol, finds the base-order element it should be
    inserted before. Two anchor sources:
      1. functions_types[] first-use order pins deduped fun types (genhl creates a
         function's fun-type when registering it, i.e. in findex order);
      2. static reference arrays (fargst$X argument tables) pin everything a fun
         signature mentions - abstract singletons, NULL/REF wrappers, etc.
    Returns {leftover_symbol -> anchor_symbol}; unanchored symbols are absent.
    """
    anchors: Dict[str, str] = {}
    leftover_set = set(leftovers)
    rank = {name: i for i, name in enumerate(base_order)}

    try:
        # --- source 1: functions_types[] first-use order -----------------------
        types_sym = bin_view.symbol("hl_functions_types")
        ptrs_sym = bin_view.symbol("hl_functions_ptrs")
        if types_sym is not None and types_sym.size > 0:
            n_ftypes = types_sym.size // PTR
            n_fptrs = (ptrs_sym.size // PTR) if (ptrs_sym is not None and ptrs_sym.size) else n_ftypes
            seen_first: Dict[str, int] = {}
            for k in range(min(n_ftypes, n_fptrs)):
                ft = bin_view.read_ptr(types_sym.value + PTR * k)
                if not ft:
                    continue
                fname = bin_view.symbol_at(ft)
                if not fname or fname in seen_first:
                    continue
                seen_first[fname] = k
            ordered_fun_syms = sorted(seen_first, key=lambda n: seen_first[n])
            for sym in leftover_set:
                if not sym.startswith("t$fun_") or sym in rank:
                    continue
                if sym not in seen_first:
                    continue
                k_self = seen_first[sym]
                # next registered fun-type that already sits in base order
                best = None
                for other in ordered_fun_syms:
                    if seen_first[other] <= k_self or other not in rank:
                        continue
                    if best is None or rank[other] < rank[best]:
                        best = other
                if best is not None:
                    anchors[sym] = best

        # --- source 2: static substructure reference tables ---------------------
        # Aux arrays embed their owner's identity in the symbol name:
        #   fargst$fun_H / tfunt$fun_H -> t$fun_H ; fieldst$N / protot$N -> t$N.
        # Every pointer word inside them may reference a leftover type
        # (arguments, return types, object fields).
        def owner_of(aux_name: str) -> Optional[str]:
            for pfx, mk in (
                ("fargst$", lambda h: "t$fun_" + h),
                ("tfunt$", lambda h: "t$fun_" + h),
                ("fieldst$", lambda h: "t$" + h),
                ("protot$", lambda h: "t$" + h),
            ):
                if aux_name.startswith(pfx):
                    return mk(aux_name[len(pfx):])
            return None

        for s in bin_view.symbols:
            aux = str(s.name)
            if s.size == 0 or s.size > 65536:
                continue
            if not bin_view.is_static_data(s):
                continue
            owner = owner_of(aux)
            if owner is None:
                continue
            owner_rank = rank.get(owner)
            if owner_rank is None:
                continue
            for off in range(0, s.size, PTR):
                try:
                    ptr = bin_view.read_ptr(s.value + off)
                except Exception:
                    break
                if not ptr:
                    continue
                tgt = bin_view.symbol_at(ptr)
                if tgt in leftover_set:
                    cur = anchors.get(tgt)
                    if cur is None or owner_rank < rank.get(cur, 1 << 60):
                        anchors[tgt] = owner

        # --- source 3: general reverse-pointer graph ----------------------------
        # Follow chains of static pointers backwards from each leftover until a
        # base-order element is reached, e.g.:
        #   leftover <- fieldst$X <- objt$X <- t$X      (object field types)
        #   leftover <- tfunt$H  <- t$fun_H            (fun signature / ret)
        # No naming conventions required - pure pointer topology.
        sym_by_addr = {}
        for s in bin_view.symbols:
            try:
                if s.size and s.size > 0:
                    nm = str(s.name)
                    if nm:
                        sym_by_addr.setdefault(s.value, nm)
            except Exception:
                continue

        rev: Dict[str, List[str]] = {}

        def note_edge(src_sym: str, tgt: Optional[str]) -> None:
            if tgt:
                rev.setdefault(tgt, []).append(src_sym)

        for s in bin_view.symbols:
            try:
                if not s.size or s.size <= 0 or s.size > 65536 or s.size % PTR:
                    continue
                if not bin_view.is_static_data(s):
                    continue
                sec = str(getattr(s, "section", ""))
                name = str(s.name)
                if not name or name.startswith(("fun$", "__", "_")):
                    continue
                src_sym = name
                for off in range(0, s.size, PTR):
                    try:
                        ptr = bin_view.read_ptr(s.value + off)
                    except Exception:
                        break
                    if ptr:
                        note_edge(src_sym, sym_by_addr.get(ptr))
            except Exception:
                continue

        for left in leftover_set:
            if left in anchors:
                continue
            seen_syms = {left}
            frontier = [left]
            best = None
            best_rank = None
            for _depth in range(4):
                nxt: List[str] = []
                for node in frontier:
                    for ref in rev.get(node, ()):
                        if ref in seen_syms:
                            continue
                        seen_syms.add(ref)
                        r = rank.get(ref)
                        if r is not None and (best_rank is None or r < best_rank):
                            best, best_rank = ref, r
                        nxt.append(ref)
                if best is not None:
                    break
                frontier = nxt
            if best is not None:
                anchors[left] = best
    except Exception:
        pass
    return anchors


def _read_fields(ctx: DehlcContext, ptr_fields: int, nfields: int) -> List[Field]:
    fields = []
    for i in range(nfields):
        base = ptr_fields + (HL_OBJ_FIELD_SIZE * i)
        name_ptr = ctx.bin.read_ptr(base)
        ftype = ctx.tindex_for_ptr(ctx.bin.read_ptr(base + PTR))
        if name_ptr and ftype is not None:
            fields.append(Field(name=strRef(ctx.add_str(ctx.bin.read_cstr_utf16(name_ptr))), type=ftype))
    return fields


def _parse_type(ctx: DehlcContext, name: str, init_analysis: InitTypesAnalysis) -> Type:
    bin_view = ctx.bin
    sym = bin_view.symbol(name)
    typ = Type()
    typ.kind.value = bin_view.read_int(sym.value, 1)
    kind = Type.Kind(typ.kind.value)

    if kind in SIMPLE_KINDS:
        typ.definition = Type.TYPEDEFS[typ.kind.value]()
        return typ

    if kind in (Type.Kind.FUN, Type.Kind.METHOD):
        tfunt = bin_view.symbol("tfun" + name)
        args_ptr = bin_view.read_ptr(tfuntptr := tfunt.value)
        ret_ptr = bin_view.read_ptr(tfuntptr + PTR)
        nargs = bin_view.read_int(tfuntptr + HL_TYPE_FUN_NARGS_OFFSET, 4)
        args = []
        for j in range(nargs):
            ti = ctx.tindex_for_ptr(bin_view.read_ptr(args_ptr + (PTR * j)))
            args.append(ti if ti is not None else tIndex(-1))
        fun_def = Fun()
        fun_def.nargs.value = nargs
        ret = ctx.tindex_for_ptr(ret_ptr)
        fun_def.ret = ret if ret is not None else tIndex(-1)
        fun_def.args = args
        typ.definition = fun_def
        return typ

    if kind in (Type.Kind.OBJ, Type.Kind.STRUCT):
        objt = bin_view.symbol("obj" + name)
        base = objt.value
        nfields = bin_view.read_int(base + HL_TYPE_OBJ_NFIELDS_OFFSET, 4)
        nprotos = bin_view.read_int(base + 4, 4)
        nbindings = bin_view.read_int(base + 8, 4)
        ptr_name = bin_view.read_ptr(base + HL_TYPE_OBJ_NAME_OFFSET)
        ptr_super = bin_view.read_ptr(base + HL_TYPE_OBJ_SUPER_OFFSET)
        ptr_fields = bin_view.read_ptr(base + HL_TYPE_OBJ_FIELDS_OFFSET)
        ptr_protos = bin_view.read_ptr(base + HL_TYPE_OBJ_PROTOS_OFFSET)
        ptr_bindings = bin_view.read_ptr(base + HL_TYPE_OBJ_BINDINGS_OFFSET)

        obj_def = Obj()
        obj_def.name = strRef(ctx.add_str(bin_view.read_cstr_utf16(ptr_name) if ptr_name else name[1:]))
        super_ti = ctx.tindex_for_ptr(ptr_super)
        obj_def.super = super_ti if super_ti is not None else tIndex(-1)
        obj_def.nfields.value = nfields
        obj_def.nprotos.value = nprotos
        obj_def.nbindings.value = nbindings
        obj_def.fields = _read_fields(ctx, ptr_fields, nfields) if ptr_fields else []

        protos: List[Proto] = []
        for j in range(nprotos):
            pbase = ptr_protos + (HL_OBJ_PROTO_SIZE * j)
            p_name_ptr = bin_view.read_ptr(pbase)
            prot = Proto()
            prot.findex = fIndex(bin_view.read_int(pbase + 8, 4))
            # pindex is stored signed (-1 = none)
            pindex = bin_view.read_int(pbase + 12, 4)
            if pindex >= 0x80000000:
                pindex -= 0x100000000
            prot.pindex = VarInt(pindex)
            prot.name = strRef(ctx.add_str(bin_view.read_cstr_utf16(p_name_ptr) if p_name_ptr else "null"))
            protos.append(prot)
        obj_def.protos = protos

        bindings: List[Binding] = []
        for j in range(nbindings):
            bbase = ptr_bindings + (HL_BINDING_SIZE * j)
            bind = Binding()
            bind.field = fieldRef(bin_view.read_int(bbase, 4))
            bind.findex = fIndex(bin_view.read_int(bbase + 4, 4))
            bindings.append(bind)
        obj_def.bindings = bindings
        typ.definition = obj_def
        return typ

    if kind in (Type.Kind.REF, Type.Kind.NULL, Type.Kind.PACKED):
        target = init_analysis.param_links.get(name)
        ti = ctx.name_to_tindex.get(target) if target else None
        if kind == Type.Kind.PACKED:
            definition = Packed()
            definition.inner = ti if ti is not None else tIndex(-1)
        else:
            definition = Ref() if kind == Type.Kind.REF else Null()
            definition.type = ti if ti is not None else tIndex(-1)
        if ti is None:
            print(f"Warning: no tparam link found for ref-like type '{name}'")
        typ.definition = definition
        return typ

    if kind == Type.Kind.VIRTUAL:
        target = init_analysis.param_links.get(name)
        virt_sym = bin_view.symbol(target) if target else None
        virt_def = Virtual()
        if virt_sym is not None:
            ptr_fields = bin_view.read_ptr(virt_sym.value + HL_TYPE_VIRT_FIELDS_OFFSET)
            nfields = bin_view.read_int(virt_sym.value + HL_TYPE_VIRT_NFIELDS_OFFSET, 4)
            virt_def.nfields.value = nfields
            virt_def.fields = _read_fields(ctx, ptr_fields, nfields) if ptr_fields else []
        else:
            print(f"Warning: no virt link found for virtual type '{name}'")
        typ.definition = virt_def
        return typ

    if kind == Type.Kind.ABSTRACT:
        abstract_def = Abstract()
        recovered = init_analysis.abs_names.get(name)
        abstract_def.name = strRef(ctx.add_str(recovered if recovered else name[2:]))
        typ.definition = abstract_def
        return typ

    if kind == Type.Kind.ENUM:
        target = init_analysis.param_links.get(name)
        enum_sym = bin_view.symbol(target) if target else None
        enum_def = Enum()
        if enum_sym is not None:
            base = enum_sym.value
            ptr_name = bin_view.read_ptr(base + HL_TYPE_ENUM_NAME_OFFSET)
            nconstructs = bin_view.read_int(base + HL_TYPE_ENUM_NCONSTRUCTS_OFFSET, 4)
            ptr_constructs = bin_view.read_ptr(base + HL_TYPE_ENUM_CONSTRUCTS_OFFSET)
            enum_def.name = strRef(ctx.add_str(bin_view.read_cstr_utf16(ptr_name) if ptr_name else name[2:]))
            enum_def.nconstructs.value = nconstructs
            constructs: List[EnumConstruct] = []
            for j in range(nconstructs):
                cbase = ptr_constructs + (HL_ENUM_CONSTRUCT_SIZE * j)
                c_name_ptr = bin_view.read_ptr(cbase)
                c_nparams = bin_view.read_int(cbase + PTR, 4)
                c_params_ptr = bin_view.read_ptr(cbase + PTR * 2)
                construct = EnumConstruct()
                construct.name = strRef(
                    ctx.add_str(bin_view.read_cstr_utf16(c_name_ptr) if c_name_ptr else f"unknown_construct_{j}")
                )
                construct.nparams.value = c_nparams
                params: List[tIndex] = []
                for k in range(c_nparams):
                    ti = ctx.tindex_for_ptr(bin_view.read_ptr(c_params_ptr + (PTR * k)))
                    if ti is not None:
                        params.append(ti)
                construct.params = params
                constructs.append(construct)
            enum_def.constructs = constructs
        else:
            print(f"Warning: no tenum link found for enum type '{name}'")
        typ.definition = enum_def
        return typ

    print(f"Unsupported (for now...) type kind: {kind}")
    return typ


def _dwarf_global_types(bin_view: HLCBinary) -> Dict[str, str]:
    """
    Extracts {global symbol name -> C type description} from DWARF info, when available
    (requires pyelftools and a -g build). The description is one of:
      "String", "$<Class>", "*<Base>" (pointer to struct/typedef <Base>), "<base>" (int/double/...),
      "vdynamic", "venum", "varray", "vbyte", "vclosure"
    """
    out: Dict[str, str] = {}
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return out
    import io

    data = bin_view.data if bin_view.data is not None else None
    stream = io.BytesIO(data) if data is not None else None
    if stream is None:
        return out
    try:
        elf = bin_view._elffile()
        dwarf = elf.get_dwarf_info()
    except Exception:
        return out

    def describe(die, cu, depth: int = 0) -> Optional[str]:
        if depth > 6 or die is None:
            return None
        tag = die.tag
        name_attr = die.attributes.get("DW_AT_name")
        name = name_attr.value.decode(errors="replace") if name_attr else None
        ty_attr = die.attributes.get("DW_AT_type")
        inner = None
        if ty_attr:
            try:
                ref = ty_attr.value
                if ty_attr.form in ("DW_FORM_ref4", "DW_FORM_ref1", "DW_FORM_ref2", "DW_FORM_ref8"):
                    tdie = cu.get_DIE_from_refaddr(ref + cu.cu_offset)
                elif ty_attr.form == "DW_FORM_ref_addr":
                    tdie = cu.get_DIE_from_refaddr(ref)
                elif ty_attr.form == "DW_FORM_ref_cu":
                    tdie = cu.get_DIE_from_refaddr(ref)
                else:
                    tdie = None
                inner = describe(tdie, cu, depth + 1) if tdie is not None else None
            except Exception:
                inner = None
        if tag == "DW_TAG_typedef" or tag == "DW_TAG_structure_type":
            return name
        if tag == "DW_TAG_pointer_type":
            return "*" + (inner or "void")
        if tag == "DW_TAG_base_type":
            return name or "int"
        if tag == "DW_TAG_const_type" or tag == "DW_TAG_volatile_type":
            return inner
        return inner

    try:
        for cu in dwarf.iter_CUs():
            top = cu.get_top_DIE()
            if top.tag != "DW_TAG_compile_unit":
                continue
            for die in top.iter_children():
                if die.tag != "DW_TAG_variable":
                    continue
                name_attr = die.attributes.get("DW_AT_name")
                if not name_attr:
                    continue
                name = name_attr.value.decode(errors="replace")
                if not (name.startswith(HL_VALUE_GLOBAL_PREFIX) or name.startswith(HL_STRING_GLOBAL_PREFIX)):
                    continue
                desc = describe(die, cu)
                if desc and name not in out:
                    out[name] = desc
    except Exception:
        pass
    return out


def _hl_type_from_c_desc(ctx: DehlcContext, code: Bytecode, desc: str) -> Optional[tIndex]:
    """Maps a DWARF-derived C type description to an HL type index."""
    if desc in ("String", "$String"):
        for i, t in enumerate(code.types):
            d = t.definition
            if isinstance(d, Obj) and d.name.resolve(code) == "String":
                return tIndex(i)
        return None
    if desc == "vdynamic" or desc == "*vdynamic" or desc == "vclosure":
        for i, t in enumerate(code.types):
            if Type.Kind(t.kind.value) == Type.Kind.DYN:
                return tIndex(i)
        return None
    base_map = {"int": Type.Kind.I32, "long int": Type.Kind.I64, "double": Type.Kind.F64, "float": Type.Kind.F32, "char": Type.Kind.I32, "short int": Type.Kind.U16, "long long int": Type.Kind.I64, "unsigned int": Type.Kind.I32}
    if not desc.startswith("*"):
        kind = base_map.get(desc)
        if kind:
            for i, t in enumerate(code.types):
                if Type.Kind(t.kind.value) == kind:
                    return tIndex(i)
        return None
    # Pointer to struct/typedef: match by mangled name against abstracts and classes.
    base = desc[1:]
    mangled = base.replace(".", "_")
    for i, t in enumerate(code.types):
        d = t.definition
        k = Type.Kind(t.kind.value)
        if k == Type.Kind.ABSTRACT and d is not None:
            try:
                if d.name.resolve(code).replace(".", "_") == mangled:
                    return tIndex(i)
            except Exception:
                pass
    return None


def _dwarf_local_names(bin_view: HLCBinary) -> List[str]:
    """
    Collects local variable/parameter names from DWARF subprograms, when available
    (requires pyelftools and a -g build). In the original bytecode these names live in
    the debug string table; HL/C compilation drops them everywhere except DWARF.
    """
    out: List[str] = []
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return out
    import io

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


HL_TYPE_STR = "vcsilfdbBDPOATR??X?N?S?g"


def _encode_type_sign(bin_view: "HLCBinary", type_ptr: int, depth: int = 0) -> str:
    """
    Encodes an in-binary hl_type into hashlink's runtime signature string
    (mirrors append_type() in hashlink's module.c): TYPE_STR[kind] char, with
    FUN = P<args>_<ret>, REF/NULL = prefix + inner, OBJ = field types
    (super first) + '_', ABSTRACT = abs_name + '_'.
    """
    if type_ptr == 0 or depth > 8:
        return "?"
    kind = bin_view.read_int(type_ptr, 1)
    if kind < 0 or kind >= len(HL_TYPE_STR):
        return "?"
    ch = HL_TYPE_STR[kind]
    if kind == Type.Kind.FUN.value:
        nargs = bin_view.read_int(type_ptr + HL_TYPE_FUN_NARGS_OFFSET, 4)
        args_ptr = bin_view.read_ptr(type_ptr)
        ret_ptr = bin_view.read_ptr(type_ptr + 8)
        parts = []
        if args_ptr and 0 < nargs <= 64:
            for i in range(nargs):
                parts.append(_encode_type_sign(bin_view, bin_view.read_ptr(args_ptr + PTR * i), depth + 1))
        return ch + "".join(parts) + "_" + _encode_type_sign(bin_view, ret_ptr, depth + 1)
    if kind in (Type.Kind.REF.value, Type.Kind.NULL.value):
        inner = bin_view.read_ptr(type_ptr + 8)  # tparam
        return ch + _encode_type_sign(bin_view, inner, depth + 1)
    if kind == Type.Kind.OBJ.value:
        nfields = bin_view.read_int(type_ptr + HL_TYPE_OBJ_NFIELDS_OFFSET, 4)
        fields_ptr = bin_view.read_ptr(type_ptr + HL_TYPE_OBJ_FIELDS_OFFSET)
        super_ptr = bin_view.read_ptr(type_ptr + HL_TYPE_OBJ_SUPER_OFFSET)
        parts = []
        if super_ptr:
            parts.append(_encode_type_sign(bin_view, super_ptr, depth + 1))
        if fields_ptr and 0 <= nfields <= 256:
            fsize = HL_TYPE_OBJ_FIELD_SIZE
            for i in range(nfields):
                parts.append(_encode_type_sign(bin_view, bin_view.read_ptr(fields_ptr + fsize * i + PTR), depth + 1))
        return ch + "".join(parts) + "_"
    if kind == Type.Kind.ABSTRACT.value:
        name_ptr = bin_view.read_ptr(type_ptr + 8)
        name = bin_view.read_cstr_utf16(name_ptr) if name_ptr else ""
        return ch + (name or "?") + "_"
    return ch


def _sign_from_recon_type(types: List[Type], ti: int, ctx: "DehlcContext" = None, depth: int = 0) -> str:
    """
    Encodes a reconstructed Type (by table index) into hashlink's runtime
    signature string. References are tIndices resolved through the table.
    Abstract names resolve through the context string table (recovered text).
    """
    def enc(idx, depth=0):
        if idx is None or idx < 0 or idx >= len(types) or depth > 8:
            return "?"
        t = types[idx]
        ch = HL_TYPE_STR[t.kind.value] if t.kind.value < len(HL_TYPE_STR) else "?"
        k = Type.Kind(t.kind.value)
        d = t.definition

        def inner(attr):
            v = getattr(d, attr, None)
            return v.value if isinstance(v, tIndex) else None

        if k in (Type.Kind.FUN,) and isinstance(d, Fun):
            args = "".join(enc(a.value, depth + 1) for a in (d.args or []))
            ret = enc(d.ret.value if d.ret is not None else -1, depth + 1)
            return ch + args + "_" + ret
        if k in (Type.Kind.REF, Type.Kind.NULL):
            return ch + enc(inner("type"), depth + 1)
        if k == Type.Kind.OBJ and isinstance(d, Obj):
            return ch + "".join(enc(f.type.value if f.type else -1, depth + 1) for f in (d.fields or [])) + "_"
        if k == Type.Kind.ABSTRACT and isinstance(d, Abstract):
            # abs_name is recovered textually; the DB stores the C abstract name.
            nm = ""
            if d.name is not None and ctx is not None and 0 <= d.name.value < len(ctx.strs):
                nm = ctx.strs[d.name.value]
            return "X" + (nm or "?") + "_"
        return ch
    return enc(ti)

