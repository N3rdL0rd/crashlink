"""
Function search index for HashLink bytecode.

Indexes functions by full name, partial name, source file, and containing type
for fast lookup without repeated linear scans.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

if TYPE_CHECKING:
    from .core import Bytecode, Function, Native, Obj


class SearchIndex:
    """
    Fast lookup index for functions and natives. Build once with
    `SearchIndex.build(code)`, then query with the typed methods.
    Cached on `Bytecode.search_index()`.
    """

    def __init__(self) -> None:
        self._full: Dict[str, List["Function | Native"]] = {}
        self._partial: Dict[str, List["Function | Native"]] = {}
        self._by_file: Dict[str, List["Function"]] = {}
        self._by_type: Dict[int, List["Function | Native"]] = {}
        self._all: List["Function | Native"] = []
        self._findex_to_full: Dict[int, str] = {}  # findex → full qualified name

    # ── Build ──────────────────────────────────────────────────────────────────

    @classmethod
    def build(cls, code: "Bytecode") -> "SearchIndex":
        from .core import Function, Obj

        idx = cls()

        # pre-build definition → tindex map (same pattern as xref)
        defn_to_ti: Dict[int, int] = {id(t.definition): ti for ti, t in enumerate(code.types)}

        # ensure proto/field maps are built so full_func_name works
        _ = code.get_proto_map()

        all_funcs: List["Function | Native"] = [*code.functions, *code.natives]
        for func in all_funcs:
            full = code.full_func_name(func)
            partial = code.partial_func_name(func)
            findex = func.findex.value

            idx._all.append(func)
            idx._full.setdefault(full, []).append(func)
            idx._partial.setdefault(partial, []).append(func)
            idx._findex_to_full[findex] = full

            # owner type
            owner_obj: Optional[Obj] = None
            if code._proto_owner_map:
                owner_obj = code._proto_owner_map.get(findex)
            if owner_obj is None and code._field_owner_map:
                owner_obj = code._field_owner_map.get(findex)
            if owner_obj is not None:
                ti = defn_to_ti.get(id(owner_obj))
                if ti is not None:
                    idx._by_type.setdefault(ti, []).append(func)

            # source file (Functions only)
            if isinstance(func, Function) and func.has_debug and func.debuginfo and func.debuginfo.value:
                ref = func.debuginfo.value[0]
                if code.debugfiles and ref.value < len(code.debugfiles.value):
                    fname = code.debugfiles.value[ref.value]
                    idx._by_file.setdefault(fname, []).append(func)

        return idx

    # ── Queries ────────────────────────────────────────────────────────────────

    def find(self, query: str) -> List["Function | Native"]:
        """Exact full-name match (e.g. 'ClassName.methodName')."""
        return self._full.get(query, [])

    def find_partial(self, query: str) -> List["Function | Native"]:
        """Exact partial-name match (method name only, no class prefix)."""
        return self._partial.get(query, [])

    def search(self, query: str) -> List["Function | Native"]:
        """Case-insensitive substring match against the full qualified name."""
        q = query.lower()
        return [f for f in self._all if q in self._findex_to_full.get(f.findex.value, "").lower()]

    def in_file(self, filename: str) -> List["Function"]:
        """
        All functions originating from `filename`. Accepts exact match or
        trailing suffix (e.g. 'Clazz.hx' matches '/path/to/Clazz.hx').
        """
        exact = self._by_file.get(filename)
        if exact is not None:
            return exact
        result: List["Function"] = []
        for k, v in self._by_file.items():
            if k.endswith(filename) or k.endswith("/" + filename) or k.endswith("\\" + filename):
                result.extend(v)
        return result

    def files(self) -> List[str]:
        """All source filenames that have at least one function."""
        return list(self._by_file.keys())

    def in_type(self, tindex: int) -> List["Function | Native"]:
        """All functions/natives belonging to the type at `tindex`."""
        return self._by_type.get(tindex, [])


__all__ = ["SearchIndex"]
