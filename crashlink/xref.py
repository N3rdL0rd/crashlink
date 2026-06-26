"""
Cross-reference index for HashLink bytecode.

Builds a complete, bidirectional map of every reference between functions,
types, fields, enum constructs, globals, and strings in a single O(n) pass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Dict, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from .core import Bytecode


class SourceKind(Enum):
    FUNCTION = "function"
    TYPE = "type"
    GLOBAL = "global"


class TargetKind(Enum):
    FUNCTION = "function"
    TYPE = "type"
    FIELD = "field"  # aux = field_slot in declaring type's own fields
    ENUM_CONSTRUCT = "enum_construct"  # aux = construct_idx
    GLOBAL = "global"
    STRING = "string"


class RefKind(Enum):
    # Calls
    CALL = "call"
    CALL_VIRTUAL = "call_virtual"
    CLOSURE = "closure"
    # Field access
    FIELD_READ = "field_read"
    FIELD_WRITE = "field_write"
    DYN_FIELD_READ = "dyn_field_read"
    DYN_FIELD_WRITE = "dyn_field_write"
    # Type use
    ALLOC = "alloc"
    CAST = "cast"
    TYPE_REF = "type_ref"
    TYPE_CHECK = "type_check"
    # Globals
    GLOBAL_READ = "global_read"
    GLOBAL_WRITE = "global_write"
    # Constants
    STRING_USE = "string_use"
    # Enums
    ENUM_CONSTRUCT = "enum_construct"
    ENUM_FIELD_READ = "enum_field_read"
    ENUM_INDEX = "enum_index"
    # Structural (source = TYPE or GLOBAL)
    INHERITS = "inherits"
    FIELD_DECL = "field_decl"
    PROTO_DECL = "proto_decl"
    BINDING_DECL = "binding_decl"
    GLOBAL_TYPE = "global_type"
    ENUM_PARAM_TYPE = "enum_param_type"
    SIGNATURE_TYPE = "signature_type"


@dataclass
class XRef:
    source_kind: SourceKind
    source_index: int
    target_kind: TargetKind
    target_index: int
    target_aux: Optional[int]  # field_slot or construct_idx
    ref_kind: RefKind
    opcode_index: Optional[int]  # position in function op list; None for structural refs


# Storage key types
_TargetKey = Tuple[TargetKind, int, Optional[int]]
_SourceKey = Tuple[SourceKind, int]


def _target_key(ref: XRef) -> _TargetKey:
    return (ref.target_kind, ref.target_index, ref.target_aux)


def _source_key(ref: XRef) -> _SourceKey:
    return (ref.source_kind, ref.source_index)


class XrefIndex:
    """
    Bidirectional cross-reference index. Build once with `XrefIndex.build(code)`,
    then query with the typed convenience methods.
    """

    def __init__(self) -> None:
        self._to: Dict[_TargetKey, List[XRef]] = {}
        self._from: Dict[_SourceKey, List[XRef]] = {}

    def _add(self, ref: XRef) -> None:
        tk = _target_key(ref)
        sk = _source_key(ref)
        self._to.setdefault(tk, []).append(ref)
        self._from.setdefault(sk, []).append(ref)

    # ── Generic queries ──────────────────────────────────────────────────────

    def refs_to(self, target_kind: TargetKind, index: int, aux: Optional[int] = None) -> List[XRef]:
        return self._to.get((target_kind, index, aux), [])

    def refs_from(self, source_kind: SourceKind, index: int) -> List[XRef]:
        return self._from.get((source_kind, index), [])

    # ── Typed convenience queries ─────────────────────────────────────────────

    def callers_of(self, findex: int) -> List[XRef]:
        """All CALL, CALL_VIRTUAL, and CLOSURE refs pointing at this function."""
        return [
            r for r in self.refs_to(TargetKind.FUNCTION, findex)
            if r.ref_kind in (RefKind.CALL, RefKind.CALL_VIRTUAL, RefKind.CLOSURE)
        ]

    def callees_of(self, findex: int) -> List[XRef]:
        """All outbound call/closure refs from this function."""
        return [
            r for r in self.refs_from(SourceKind.FUNCTION, findex)
            if r.ref_kind in (RefKind.CALL, RefKind.CALL_VIRTUAL, RefKind.CLOSURE)
        ]

    def field_reads(self, tindex: int, field_slot: int) -> List[XRef]:
        return [r for r in self.refs_to(TargetKind.FIELD, tindex, field_slot) if r.ref_kind == RefKind.FIELD_READ]

    def field_writes(self, tindex: int, field_slot: int) -> List[XRef]:
        return [r for r in self.refs_to(TargetKind.FIELD, tindex, field_slot) if r.ref_kind == RefKind.FIELD_WRITE]

    def all_field_accesses(self, tindex: int, field_slot: int) -> List[XRef]:
        return [r for r in self.refs_to(TargetKind.FIELD, tindex, field_slot)
                if r.ref_kind in (RefKind.FIELD_READ, RefKind.FIELD_WRITE)]

    def allocators_of(self, tindex: int) -> List[XRef]:
        return [r for r in self.refs_to(TargetKind.TYPE, tindex) if r.ref_kind == RefKind.ALLOC]

    def subtypes_of(self, tindex: int) -> List[XRef]:
        return [r for r in self.refs_to(TargetKind.TYPE, tindex) if r.ref_kind == RefKind.INHERITS]

    def construct_uses(self, tindex: int, construct_idx: int) -> List[XRef]:
        return self.refs_to(TargetKind.ENUM_CONSTRUCT, tindex, construct_idx)

    def global_reads(self, gindex: int) -> List[XRef]:
        return [r for r in self.refs_to(TargetKind.GLOBAL, gindex) if r.ref_kind == RefKind.GLOBAL_READ]

    def global_writes(self, gindex: int) -> List[XRef]:
        return [r for r in self.refs_to(TargetKind.GLOBAL, gindex) if r.ref_kind == RefKind.GLOBAL_WRITE]

    def string_uses(self, string_idx: int) -> List[XRef]:
        return self.refs_to(TargetKind.STRING, string_idx)

    def type_refs(self, tindex: int) -> List[XRef]:
        """Every reference to a type — allocations, casts, field decls, inherits, etc."""
        return self.refs_to(TargetKind.TYPE, tindex)

    # ── Builder ───────────────────────────────────────────────────────────────

    @classmethod
    def build(cls, code: "Bytecode") -> "XrefIndex":
        from .core import Obj, Enum as HLEnum, Fun, Virtual, Function, Native

        idx = cls()

        # ── 1. Per-function opcode scan ──────────────────────────────────────

        # Pre-build definition-object → tindex map to avoid O(n) scans in _field_owner
        _defn_to_ti: Dict[int, int] = {id(t.definition): ti for ti, t in enumerate(code.types)}
        # Cache (tindex, flat_slot) → (owner_tindex, own_slot) across all functions
        _field_owner_cache: Dict[Tuple[int, int], Tuple[int, int]] = {}

        for func in code.functions:
            findex = func.findex.value
            regs = func.regs  # list[tIndex]

            def _reg_tindex(reg_val: int) -> Optional[int]:
                try:
                    return regs[reg_val].value
                except IndexError:
                    return None

            def _field_owner(flat_slot: int, tindex: int, obj: Obj) -> Tuple[int, int]:
                """Return (declaring_tindex, own_slot) for a flat resolved field slot."""
                cache_key = (tindex, flat_slot)
                cached = _field_owner_cache.get(cache_key)
                if cached is not None:
                    return cached
                chain: List[Obj] = []
                visited: Set[int] = set()
                cur: Optional[Obj] = obj
                while cur is not None and id(cur) not in visited:
                    visited.add(id(cur))
                    chain.append(cur)
                    if cur.super.value < 0:
                        break
                    s = cur.super.resolve(code).definition
                    cur = s if isinstance(s, Obj) else None
                chain.reverse()
                offset = 0
                result = (0, flat_slot)
                for ancestor in chain:
                    if flat_slot < offset + len(ancestor.fields):
                        own_slot = flat_slot - offset
                        owner_ti = _defn_to_ti.get(id(ancestor), 0)
                        result = (owner_ti, own_slot)
                        break
                    offset += len(ancestor.fields)
                _field_owner_cache[cache_key] = result
                return result

            for op_idx, op in enumerate(func.ops):
                op_name = op.op
                df = op.df

                def _emit(
                    tk: TargetKind,
                    ti: int,
                    rk: RefKind,
                    aux: Optional[int] = None,
                ) -> None:
                    idx._add(XRef(SourceKind.FUNCTION, findex, tk, ti, aux, rk, op_idx))

                if op_name in ("Call0", "Call1", "Call2", "Call3", "Call4", "CallN"):
                    _emit(TargetKind.FUNCTION, df["fun"].value, RefKind.CALL)

                elif op_name in ("CallMethod", "CallThis"):
                    pindex = df["field"].value
                    # Receiver is first arg for CallMethod, reg 0 for CallThis
                    if op_name == "CallThis":
                        recv_t = _reg_tindex(0)
                    else:
                        args = df["args"].value  # Regs.value is List[Reg]
                        recv_t = _reg_tindex(args[0].value) if args else None
                    if recv_t is not None:
                        t = code.types[recv_t]
                        if isinstance(t.definition, Obj):
                            proto = code.proto_by_pindex(t.definition, pindex)
                            if proto is not None:
                                _emit(TargetKind.FUNCTION, proto.findex.value, RefKind.CALL_VIRTUAL)

                elif op_name in ("StaticClosure", "InstanceClosure"):
                    _emit(TargetKind.FUNCTION, df["fun"].value, RefKind.CLOSURE)

                elif op_name == "VirtualClosure":
                    # field is a pindex into the receiver's vtable
                    pindex = df["field"].value
                    recv_t = _reg_tindex(df["obj"].value)
                    if recv_t is not None:
                        t = code.types[recv_t]
                        if isinstance(t.definition, Obj):
                            proto = code.proto_by_pindex(t.definition, pindex)
                            if proto is not None:
                                _emit(TargetKind.FUNCTION, proto.findex.value, RefKind.CLOSURE)

                elif op_name in ("Field",):
                    obj_t = _reg_tindex(df["obj"].value)
                    if obj_t is not None:
                        t = code.types[obj_t]
                        if isinstance(t.definition, Obj):
                            try:
                                flat = df["field"].value
                                owner_t, own_slot = _field_owner(flat, obj_t, t.definition)
                                _emit(TargetKind.FIELD, owner_t, RefKind.FIELD_READ, own_slot)
                            except (IndexError, KeyError):
                                pass

                elif op_name == "GetThis":
                    this_t = _reg_tindex(0)
                    if this_t is not None:
                        t = code.types[this_t]
                        if isinstance(t.definition, Obj):
                            try:
                                flat = df["field"].value
                                owner_t, own_slot = _field_owner(flat, this_t, t.definition)
                                _emit(TargetKind.FIELD, owner_t, RefKind.FIELD_READ, own_slot)
                            except (IndexError, KeyError):
                                pass

                elif op_name == "SetField":
                    obj_t = _reg_tindex(df["obj"].value)
                    if obj_t is not None:
                        t = code.types[obj_t]
                        if isinstance(t.definition, Obj):
                            try:
                                flat = df["field"].value
                                owner_t, own_slot = _field_owner(flat, obj_t, t.definition)
                                _emit(TargetKind.FIELD, owner_t, RefKind.FIELD_WRITE, own_slot)
                            except (IndexError, KeyError):
                                pass

                elif op_name == "SetThis":
                    this_t = _reg_tindex(0)
                    if this_t is not None:
                        t = code.types[this_t]
                        if isinstance(t.definition, Obj):
                            try:
                                flat = df["field"].value
                                owner_t, own_slot = _field_owner(flat, this_t, t.definition)
                                _emit(TargetKind.FIELD, owner_t, RefKind.FIELD_WRITE, own_slot)
                            except (IndexError, KeyError):
                                pass

                elif op_name == "DynGet":
                    _emit(TargetKind.STRING, df["field"].value, RefKind.DYN_FIELD_READ)

                elif op_name == "DynSet":
                    _emit(TargetKind.STRING, df["field"].value, RefKind.DYN_FIELD_WRITE)

                elif op_name == "New":
                    dst_t = _reg_tindex(df["dst"].value)
                    if dst_t is not None:
                        _emit(TargetKind.TYPE, dst_t, RefKind.ALLOC)

                elif op_name in ("SafeCast", "UnsafeCast", "ToVirtual"):
                    dst_t = _reg_tindex(df["dst"].value)
                    if dst_t is not None:
                        _emit(TargetKind.TYPE, dst_t, RefKind.CAST)

                elif op_name == "GetGlobal":
                    _emit(TargetKind.GLOBAL, df["global"].value, RefKind.GLOBAL_READ)

                elif op_name == "SetGlobal":
                    _emit(TargetKind.GLOBAL, df["global"].value, RefKind.GLOBAL_WRITE)

                elif op_name == "String":
                    _emit(TargetKind.STRING, df["ptr"].value, RefKind.STRING_USE)

                elif op_name == "Type":
                    _emit(TargetKind.TYPE, df["ty"].value, RefKind.TYPE_REF)

                elif op_name in ("GetType", "GetTID"):
                    src_t = _reg_tindex(df["src"].value)
                    if src_t is not None:
                        _emit(TargetKind.TYPE, src_t, RefKind.TYPE_CHECK)

                elif op_name == "MakeEnum":
                    dst_t = _reg_tindex(df["dst"].value)
                    if dst_t is not None:
                        construct_idx = df["construct"].value
                        _emit(TargetKind.ENUM_CONSTRUCT, dst_t, RefKind.ENUM_CONSTRUCT, construct_idx)

                elif op_name == "EnumField":
                    val_t = _reg_tindex(df["value"].value)
                    if val_t is not None:
                        construct_idx = df["construct"].value
                        _emit(TargetKind.ENUM_CONSTRUCT, val_t, RefKind.ENUM_FIELD_READ, construct_idx)

                elif op_name == "EnumIndex":
                    val_t = _reg_tindex(df["value"].value)
                    if val_t is not None:
                        _emit(TargetKind.TYPE, val_t, RefKind.ENUM_INDEX)

        # ── 2. Type structural scan ──────────────────────────────────────────

        for tindex, t in enumerate(code.types):
            defn = t.definition

            def _struct(tk: TargetKind, ti: int, rk: RefKind, aux: Optional[int] = None) -> None:
                idx._add(XRef(SourceKind.TYPE, tindex, tk, ti, aux, rk, None))

            if isinstance(defn, Obj):
                if defn.super.value >= 0:
                    _struct(TargetKind.TYPE, defn.super.value, RefKind.INHERITS)
                for f in defn.fields:
                    _struct(TargetKind.TYPE, f.type.value, RefKind.FIELD_DECL)
                for proto in defn.protos:
                    _struct(TargetKind.FUNCTION, proto.findex.value, RefKind.PROTO_DECL)
                for binding in defn.bindings:
                    _struct(TargetKind.FUNCTION, binding.findex.value, RefKind.BINDING_DECL)

            elif isinstance(defn, HLEnum):
                for construct in defn.constructs:
                    for param_t in construct.params:
                        _struct(TargetKind.TYPE, param_t.value, RefKind.ENUM_PARAM_TYPE)

            elif isinstance(defn, Fun):
                for arg_t in defn.args:
                    _struct(TargetKind.TYPE, arg_t.value, RefKind.SIGNATURE_TYPE)
                _struct(TargetKind.TYPE, defn.ret.value, RefKind.SIGNATURE_TYPE)

            elif isinstance(defn, Virtual):
                for f in defn.fields:
                    _struct(TargetKind.TYPE, f.type.value, RefKind.FIELD_DECL)

        # ── 3. Global structural scan ────────────────────────────────────────

        for gindex, gt in enumerate(code.global_types):
            idx._add(XRef(SourceKind.GLOBAL, gindex, TargetKind.TYPE, gt.value, None, RefKind.GLOBAL_TYPE, None))

        return idx


__all__ = [
    "XrefIndex",
    "XRef",
    "SourceKind",
    "TargetKind",
    "RefKind",
]
