"""Identity of the program entities a rendered source token names."""

from __future__ import annotations

import enum
import weakref
from dataclasses import dataclass
from typing import Dict, Tuple

from .. import disasm
from ..core import (
    Abstract,
    Bytecode,
    Enum,
    Fun,
    Null,
    Obj,
    Packed,
    Ref,
    Type,
    Virtual,
    destaticify,
    is_static_name,
)

# ============================================================================
# symbols
# ============================================================================


class SymbolKind(enum.Enum):
    FUNCTION = "function"  # index = findex
    GLOBAL = "global"  # index = gindex
    TYPE = "type"  # index = tindex (class / enum / abstract)
    FIELD = "field"  # index = tindex of the owning class, slot = field slot
    ENUM_CONSTRUCT = "enum_construct"  # index = tindex of the enum, slot = construct index
    LOCAL = "local"  # scope = findex of the owning function, name = the local's name
    STRING = "string"  # index = string table index


@dataclass(frozen=True)
class SymbolRef:
    kind: SymbolKind
    index: int = -1
    slot: int = -1
    scope: int = -1
    name: str = ""

    @staticmethod
    def function(findex: int) -> "SymbolRef":
        return SymbolRef(SymbolKind.FUNCTION, index=findex)

    @staticmethod
    def global_(gindex: int) -> "SymbolRef":
        return SymbolRef(SymbolKind.GLOBAL, index=gindex)

    @staticmethod
    def type_(tindex: int) -> "SymbolRef":
        return SymbolRef(SymbolKind.TYPE, index=tindex)

    @staticmethod
    def field(tindex: int, slot: int) -> "SymbolRef":
        return SymbolRef(SymbolKind.FIELD, index=tindex, slot=slot)

    @staticmethod
    def enum_construct(tindex: int, construct: int) -> "SymbolRef":
        return SymbolRef(SymbolKind.ENUM_CONSTRUCT, index=tindex, slot=construct)

    @staticmethod
    def local(findex: int, name: str) -> "SymbolRef":
        return SymbolRef(SymbolKind.LOCAL, scope=findex, name=name)

    @staticmethod
    def string(sindex: int) -> "SymbolRef":
        return SymbolRef(SymbolKind.STRING, index=sindex)


@dataclass(frozen=True)
class SymbolSpan:
    """One symbol occurrence in rendered text: `[start, end)` columns on `line` (0-based,
    str indices). `is_def` marks the declaring occurrence (a method header, a `var`)."""

    line: int
    start: int
    end: int
    ref: SymbolRef
    is_def: bool = False


@dataclass(frozen=True)
class ExprType:
    """Tag for an expression's type: `source` is how Haxe spells it, `kind` the
    HashLink kind (`I32`, `Obj`, `Fun`, ...)."""

    source: str
    kind: str = ""


@dataclass(frozen=True)
class TypeSpan:
    """The expression at `[start, end)` on `line` produces a value of `type`."""

    line: int
    start: int
    end: int
    type: ExprType


# ============================================================================
# typetext
#
# Readable text for a bytecode type, for hover tooltips.
#
# Unlike `disasm._haxe_annotation` this has no side effects (that one records the
# recursive structures it names, which changes what a later export declares) and is
# cheap enough to run for every expression of a function.
# ============================================================================

_MAX_DEPTH = 3

_cache: Dict[int, Tuple["weakref.ReferenceType[Bytecode]", Dict[int, Tuple[Type, str, str]]]] = {}


def _per_code(code: Bytecode) -> Dict[int, Tuple[Type, str, str]]:
    entry = _cache.get(id(code))
    if entry is not None and entry[0]() is code:
        return entry[1]
    table: Dict[int, Tuple[Type, str, str]] = {}
    _cache[id(code)] = (weakref.ref(code), table)
    return table


def type_text(code: Bytecode, typ: Type, depth: int = 0) -> str:
    """The type as source spells it: `Int`, `Array<Dynamic>`, `(Int, String) -> Void`,
    `Null<Float>`, `{x:Int, y:Int}` for a structure."""
    defn = typ.definition
    try:
        if isinstance(defn, Obj):
            name = defn.name.resolve(code)
            if is_static_name(name):
                return f"Class<{destaticify(name)}>"
            return disasm.type_to_haxe(name)
        if isinstance(defn, Enum):
            return disasm.type_to_haxe(disasm.type_name(code, typ))
        if isinstance(defn, Abstract):
            return disasm.type_to_haxe(defn.name.resolve(code))
        if depth >= _MAX_DEPTH:
            return (
                "…"
                if isinstance(defn, (Fun, Null, Ref, Packed, Virtual))
                else disasm.type_to_haxe(disasm.type_name(code, typ))
            )
        if isinstance(defn, Fun):
            args = ", ".join(type_text(code, a.resolve(code), depth + 1) for a in defn.args)
            return f"({args}) -> {type_text(code, defn.ret.resolve(code), depth + 1)}"
        if isinstance(defn, Null):
            return f"Null<{type_text(code, defn.type.resolve(code), depth + 1)}>"
        if isinstance(defn, Ref):
            return f"hl.Ref<{type_text(code, defn.type.resolve(code), depth + 1)}>"
        if isinstance(defn, Packed):
            return f"packed {type_text(code, defn.inner.resolve(code), depth + 1)}"
        if isinstance(defn, Virtual):
            fields = ", ".join(
                f"{f.name.resolve(code)}:{type_text(code, f.type.resolve(code), depth + 1)}"
                for f in defn.fields
            )
            return "{" + fields + "}"
        return disasm.type_to_haxe(disasm.type_name(code, typ))
    except IndexError:
        # Corrupt bytecode: a name/type table index is out of range — fall back
        # to the HashLink kind name; hover text must never crash the renderer.
        # Anything else is our own bug and must propagate.
        return type(defn).__name__


def type_kind(typ: Type) -> str:
    """The HashLink kind of the type (`I32`, `Obj`, `Fun`, ...)."""
    return type(typ.definition).__name__


def describe(code: Bytecode, typ: Type) -> Tuple[str, str]:
    """(source spelling, HashLink kind) of the type, memoised per document."""
    table = _per_code(code)
    entry = table.get(id(typ))
    if entry is not None and entry[0] is typ:
        return entry[1], entry[2]
    text, kind = type_text(code, typ), type_kind(typ)
    table[id(typ)] = (typ, text, kind)
    return text, kind
