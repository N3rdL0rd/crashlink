"""Identity of the program entities a rendered source token names.

A `SymbolRef` is a value, not a string: two tokens spelled `x` (a local and a field)
are different refs, so consumers (the GUI's xrefs and jump-to-definition) never have
to guess what a word means.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class SymbolKind(Enum):
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
