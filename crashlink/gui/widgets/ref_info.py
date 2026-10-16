"""Cheap, cached lookups for `f@`/`g@`/`t@` references and opcode docs, shared by
the code views for inline names and hover tooltips."""

from __future__ import annotations

import html
from typing import Dict, Optional

from ... import disasm
from ...core import Bytecode, Function, Native, Obj, destaticify
from ...opcodes import opcode_docs, opcodes

# Longest constant-string preview shown inline in the disassembly.
_INLINE_STRING_MAX = 40


class RefInfo:
    """Per-document resolver. Every result is memoised: a class tab renders
    thousands of rows and hover fires on every mouse pause."""

    def __init__(self, code: Bytecode) -> None:
        self.code = code
        self._names: Dict[int, Optional[str]] = {}
        self._globals: Dict[int, Optional[str]] = {}

    # ── Inline annotations ───────────────────────────────────────────────────

    def function_name(self, findex: int) -> Optional[str]:
        """Readable name for `f@N` (`h2d.Scene.over`, `std.alloc_array`), or None."""
        if findex not in self._names:
            self._names[findex] = self._function_name(findex)
        return self._names[findex]

    def _function_name(self, findex: int) -> Optional[str]:
        fn = self.code.get_findex_map().get(findex)
        if isinstance(fn, Native):
            try:
                return f"{fn.lib.resolve(self.code)}.{fn.name.resolve(self.code)}"
            except IndexError:
                return None  # corrupt bytecode: the native's lib/name strRef is out of range
        if isinstance(fn, Function):
            try:
                name = self.code.full_func_name(fn)
            except IndexError:
                return None  # corrupt bytecode: a proto/field name's strRef is out of range
            if not name or "<none>" in name:
                return None
            # `$Foo.__constructor__` reads as `Foo.new`, as in the pseudocode.
            owner, _, method = name.rpartition(".")
            if method == "__constructor__":
                method = "new"
            return f"{destaticify(owner)}.{method}" if owner else method
        return None

    def global_string(self, gindex: int) -> Optional[str]:
        """The value of a constant-initialized String global, or None."""
        if gindex not in self._globals:
            try:
                self._globals[gindex] = self.code.const_str(gindex)
            except (ValueError, TypeError, KeyError, IndexError):
                # Expected: the global has no constant String initializer (ValueError/TypeError/
                # KeyError); corrupt bytecode: a table index is out of range (IndexError).
                self._globals[gindex] = None
        return self._globals[gindex]

    def global_inline(self, gindex: int) -> Optional[str]:
        value = self.global_string(gindex)
        if value is None:
            return None
        if len(value) > _INLINE_STRING_MAX:
            value = value[: _INLINE_STRING_MAX - 1] + "..."
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'

    # ── Hover text (rich text) ───────────────────────────────────────────────

    def opcode_tooltip(self, name: str) -> Optional[str]:
        doc = opcode_docs.get(name)
        schema = opcodes.get(name)
        if doc is None and schema is None:
            return None
        operands = ", ".join(f"{param}: {kind}" for param, kind in (schema or {}).items()) or "none"
        return (
            f"<b>{html.escape(name)}</b><br>{html.escape(doc or 'No description.')}"
            f"<br><span style='opacity:0.7'>operands: {html.escape(operands)}</span>"
        )

    def function_tooltip(self, findex: int) -> Optional[str]:
        fn = self.code.get_findex_map().get(findex)
        if fn is None:
            return None
        try:
            header = disasm.func_header(self.code, fn)
        except IndexError:
            header = f"f@{findex}"  # corrupt bytecode: a name/signature's table index is out of range
        kind = "native" if isinstance(fn, Native) else f"{len(fn.ops)} opcodes"
        return f"<b>{html.escape(header)}</b><br><span style='opacity:0.7'>{kind}</span>"

    def global_tooltip(self, gindex: int) -> Optional[str]:
        if not 0 <= gindex < len(self.code.global_types):
            return None
        try:
            type_label = disasm.type_name(self.code, self.code.global_types[gindex].resolve(self.code))
        except IndexError:
            type_label = "?"  # corrupt bytecode: the global's tIndex or a name's strRef is out of range
        text = f"<b>global g@{gindex}</b>: {html.escape(type_label)}"
        value = self.global_string(gindex)
        if value is not None:
            text += f"<br>= {html.escape(repr(value[:300]))}"
        elif gindex in self.code.initialized_globals:
            init = self.code.initialized_globals[gindex]
            text += f"<br>initialized: {html.escape(repr(init)[:300])}"
        return text

    def type_tooltip(self, tindex: int) -> Optional[str]:
        if not 0 <= tindex < len(self.code.types):
            return None
        typ = self.code.types[tindex]
        try:
            summary = disasm.type_name(self.code, typ)
        except IndexError:
            summary = f"t@{tindex}"  # corrupt bytecode: a type name's strRef is out of range
        kind = type(typ.definition).__name__
        text = f"<b>t@{tindex}</b> {html.escape(summary)}<br><span style='opacity:0.7'>{kind}</span>"
        if isinstance(typ.definition, Obj):
            try:
                fields = [f.name.resolve(self.code) for f in typ.definition.resolve_fields(self.code)]
            except (IndexError, ValueError):
                # Corrupt bytecode: a field name/superclass index is out of range, or the
                # hierarchy is cyclic/invalid (resolve_fields' own ValueError).
                fields = []
            if fields:
                shown = ", ".join(fields[:12]) + (" ..." if len(fields) > 12 else "")
                text += f"<br>fields: {html.escape(shown)}"
        return text
