"""
Source location map for HashLink bytecode.

Bidirectional mapping between (function, opcode index) and (source file, line number).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

if TYPE_CHECKING:
    from .core import Bytecode, Function, fileRef

# (file_idx, line) → list of (Function, op_idx)
_LocKey = Tuple[int, int]
# (findex, op_idx) → fileRef
_OpKey = Tuple[int, int]


class SourceMap:
    """
    Bidirectional source-location index. Build once with `SourceMap.build(code)`.
    Cached on `Bytecode.source_map()`.
    """

    def __init__(self) -> None:
        self._by_op: Dict[_OpKey, "fileRef"] = {}
        self._by_loc: Dict[_LocKey, List[Tuple["Function", int]]] = {}
        self._file_names: Dict[int, str] = {}  # file_idx → filename

    @classmethod
    def build(cls, code: "Bytecode") -> "SourceMap":
        from .core import Function

        sm = cls()

        if code.debugfiles:
            sm._file_names = {i: name for i, name in enumerate(code.debugfiles.value)}

        for func in code.functions:
            if not isinstance(func, Function):
                continue
            if not func.has_debug or not func.debuginfo or not func.debuginfo.value:
                continue
            findex = func.findex.value
            for op_idx, ref in enumerate(func.debuginfo.value):
                sm._by_op[(findex, op_idx)] = ref
                sm._by_loc.setdefault((ref.value, ref.line), []).append((func, op_idx))

        return sm

    # ── Forward (op → location) ───────────────────────────────────────────────

    def loc_of(self, findex: int, op_idx: int) -> "Optional[fileRef]":
        """Source location for a specific opcode."""
        return self._by_op.get((findex, op_idx))

    def loc_str(self, findex: int, op_idx: int) -> str:
        """'filename:line' string, or empty string if unavailable."""
        ref = self._by_op.get((findex, op_idx))
        if ref is None:
            return ""
        fname = self._file_names.get(ref.value, f"file#{ref.value}")
        return f"{fname}:{ref.line}"

    # ── Reverse (location → ops) ──────────────────────────────────────────────

    def ops_at(self, file_idx: int, line: int) -> List[Tuple["Function", int]]:
        """All (function, op_idx) pairs that map to a given source location."""
        return self._by_loc.get((file_idx, line), [])

    def funcs_at_line(self, file_idx: int, line: int) -> List["Function"]:
        """Unique functions that have at least one opcode at this source line."""
        seen: Dict[int, "Function"] = {}
        for func, _ in self._by_loc.get((file_idx, line), []):
            seen[func.findex.value] = func
        return list(seen.values())

    # ── File helpers ──────────────────────────────────────────────────────────

    def file_index(self, filename: str) -> Optional[int]:
        """
        Find the file_idx for a filename. Accepts exact or trailing-suffix match
        (e.g. 'Clazz.hx' matches '/src/Clazz.hx').
        """
        for idx, name in self._file_names.items():
            if name == filename:
                return idx
        for idx, name in self._file_names.items():
            if name.endswith(filename) or name.endswith("/" + filename) or name.endswith("\\" + filename):
                return idx
        return None

    def files(self) -> List[str]:
        """All source filenames present in the debug info."""
        return list(self._file_names.values())


__all__ = ["SourceMap"]
