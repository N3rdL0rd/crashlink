"""
Shared reconstruction context passed between recovery passes.
"""

from __future__ import annotations

from typing import Dict, List, Optional


from ..core import (
    tIndex,
)

from .binary import HLCBinary


class DehlcContext:
    """Shared state for a single de-HL/C extraction run."""

    def __init__(self, bin_view: HLCBinary, verbose: bool = False):
        self.bin = bin_view
        self.verbose = verbose
        self.strs: List[str] = []
        self.name_to_tindex: Dict[str, tIndex] = {}
        # t$ symbol virtual address -> reconstructed type index (robust against
        # alias symbols like GCC's `$d` sharing an address with the real symbol).
        self.ptr_to_tindex: Dict[int, tIndex] = {}
        # findex -> "dll!symbol" import name (PE images only).
        self.pe_import_by_findex: Dict[int, str] = {}

    def log(self, msg: str) -> None:
        if self.verbose:
            print(msg)

    def add_str(self, val: str) -> int:
        if val not in self.strs:
            self.strs.append(val)
            return len(self.strs) - 1
        return self.strs.index(val)

    def tindex_for_ptr(self, ptr: int) -> Optional[tIndex]:
        if not ptr:
            return None
        # Prefer the exact address map; fall back to symbol-name resolution.
        ti = self.ptr_to_tindex.get(ptr)
        if ti is not None:
            return ti
        return self.name_to_tindex.get(self.bin.symbol_at(ptr))
