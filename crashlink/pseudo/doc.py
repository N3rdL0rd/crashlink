"""Source documents: rendered text that remembers which symbol each token names.

The renderer builds Haxe text with ordinary string operations. To also get symbol
spans out of it without changing any of that text, symbol tokens are wrapped in
private-use marker characters while `marked()` is active:

    OPEN <id-char> text CLOSE

Every string operation the renderer performs (concatenation, joins, indentation,
line splitting) carries the markers along untouched. `Doc.parse` then turns the
marked string into a `Doc` tree, and `Doc.render` into plain text plus spans.
Outside `marked()`, `mark()` returns its text as is, so the str-returning API is
byte-identical to what it always produced.
"""

from __future__ import annotations

import re

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Sequence, Tuple, Union

from .symbols import SymbolRef, SymbolSpan

OPEN = "\ue000"
CLOSE = "\ue001"
# One supplementary private-use character per registered symbol: plane 15, then 16.
_ID_BASE = 0xF0000
_ID_LIMIT = 0x10FFFD - _ID_BASE


@dataclass(frozen=True)
class Text:
    text: str


@dataclass(frozen=True)
class Sym:
    ref: SymbolRef
    body: "Doc"
    is_def: bool = False


@dataclass(frozen=True)
class Concat:
    parts: Tuple["Doc", ...]


Doc = Union[Text, Sym, Concat]


@dataclass
class RenderedSource:
    """Plain source text with the symbol spans and opcode→line map that came with it."""

    text: str
    spans: List[SymbolSpan] = field(default_factory=list)
    oplines: Dict[int, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._by_line: Optional[Dict[int, List[SymbolSpan]]] = None
        self._by_ref: Optional[Dict[SymbolRef, List[SymbolSpan]]] = None

    def _index(self) -> Dict[int, List[SymbolSpan]]:
        if self._by_line is None:
            by_line: Dict[int, List[SymbolSpan]] = {}
            for span in self.spans:
                by_line.setdefault(span.line, []).append(span)
            self._by_line = by_line
        return self._by_line

    def spans_on_line(self, line: int) -> List[SymbolSpan]:
        return self._index().get(line, [])

    def span_at(self, line: int, col: int) -> Optional[SymbolSpan]:
        """The innermost span covering `col` on `line` (`start <= col < end`), if any."""
        best: Optional[SymbolSpan] = None
        for span in self.spans_on_line(line):
            if span.start <= col < span.end and (
                best is None or span.end - span.start <= best.end - best.start
            ):
                best = span
        return best

    def symbol_at(self, line: int, col: int) -> Optional[SymbolRef]:
        span = self.span_at(line, col)
        return span.ref if span is not None else None

    def spans_of(self, ref: SymbolRef) -> List[SymbolSpan]:
        """Every span naming `ref`, in text order."""
        if self._by_ref is None:
            by_ref: Dict[SymbolRef, List[SymbolSpan]] = {}
            for span in self.spans:
                by_ref.setdefault(span.ref, []).append(span)
            self._by_ref = by_ref
        return self._by_ref.get(ref, [])

    def definition_of(self, ref: SymbolRef) -> Optional[SymbolSpan]:
        """The declaring span of `ref` in this text, if it declares one."""
        return next((s for s in self.spans_of(ref) if s.is_def), None)


def plain(doc: Doc) -> str:
    if isinstance(doc, Text):
        return doc.text
    if isinstance(doc, Sym):
        return plain(doc.body)
    return "".join(plain(p) for p in doc.parts)


def render(doc: Doc) -> RenderedSource:
    """Flatten a doc to text and spans."""
    chunks: List[str] = []
    spans: List[SymbolSpan] = []
    state = [0, 0]  # line, col

    def advance(text: str) -> None:
        chunks.append(text)
        newlines = text.count("\n")
        if newlines:
            state[0] += newlines
            state[1] = len(text) - text.rindex("\n") - 1
        else:
            state[1] += len(text)

    def walk(node: Doc) -> None:
        if isinstance(node, Text):
            advance(node.text)
        elif isinstance(node, Concat):
            for part in node.parts:
                walk(part)
        else:
            start_line, start_col = state
            walk(node.body)
            if state[0] == start_line and state[1] > start_col:
                spans.append(SymbolSpan(start_line, start_col, state[1], node.ref, node.is_def))
            # A symbol never spans lines in practice; a multi-line body gets no span.

    walk(doc)
    return RenderedSource("".join(chunks), spans)


# ── Marker mode ───────────────────────────────────────────────────────────────

_table: ContextVar[Optional[List[Tuple[SymbolRef, bool]]]] = ContextVar("pseudo_symbol_table", default=None)
_ids: ContextVar[Dict[Tuple[SymbolRef, bool], int]] = ContextVar("pseudo_symbol_ids")


def marking() -> bool:
    return _table.get() is not None


@contextmanager
def marked() -> Iterator[List[Tuple[SymbolRef, bool]]]:
    """Make `mark()` wrap symbol tokens for the duration; yields the symbol table
    `parse` needs."""
    table: List[Tuple[SymbolRef, bool]] = []
    token = _table.set(table)
    ids_token = _ids.set({})
    try:
        yield table
    finally:
        _ids.reset(ids_token)
        _table.reset(token)


def mark(text: str, ref: Optional[SymbolRef], is_def: bool = False) -> str:
    """`text`, tagged as naming `ref` when marker mode is on; `text` untouched otherwise.

    The same symbol always gets the same id, so rendering one expression twice yields
    equal strings (the renderer compares renderings)."""
    table = _table.get()
    if table is None or ref is None or not text:
        return text
    ids = _ids.get()
    key = (ref, is_def)
    sym_id = ids.get(key)
    if sym_id is None:
        if len(table) >= _ID_LIMIT:
            return text
        sym_id = len(table)
        ids[key] = sym_id
        table.append(key)
    return f"{OPEN}{chr(_ID_BASE + sym_id)}{text}{CLOSE}"


_MARKER_RX = re.compile(f"{OPEN}(.)|{CLOSE}", re.DOTALL)


def strip(text: str) -> str:
    """Remove marker characters from a marked string."""
    if OPEN not in text and CLOSE not in text:
        return text
    return _MARKER_RX.sub("", text)


def parse(text: str, table: Sequence[Tuple[SymbolRef, bool]]) -> Doc:
    """Turn a marked string into a `Doc`. A closing marker with no opener is dropped, and
    an opener never closed (a renderer that sliced a marked string) folds back in as text."""
    stack: List[List[Doc]] = [[]]
    refs: List[Tuple[SymbolRef, bool]] = []
    at = 0
    for m in _MARKER_RX.finditer(text):
        if m.start() > at:
            stack[-1].append(Text(text[at : m.start()]))
        at = m.end()
        if m.group(1) is not None:
            refs.append(table[ord(m.group(1)) - _ID_BASE])
            stack.append([])
        elif len(stack) > 1:
            parts = stack.pop()
            ref, is_def = refs.pop()
            body: Doc = parts[0] if len(parts) == 1 else Concat(tuple(parts))
            stack[-1].append(Sym(ref, body, is_def))
    if at < len(text):
        stack[-1].append(Text(text[at:]))
    while len(stack) > 1:
        parts = stack.pop()
        stack[-1].extend(parts)
    parts = stack[0]
    return parts[0] if len(parts) == 1 else Concat(tuple(parts))


def render_marked(text: str, table: Sequence[Tuple[SymbolRef, bool]]) -> RenderedSource:
    return render(parse(text, table))


def utf16_col(line: str, col: int) -> int:
    """Convert a str column to a Qt (UTF-16) column on `line`."""
    return col + sum(1 for ch in line[:col] if ord(ch) > 0xFFFF)


__all__ = [
    "CLOSE",
    "OPEN",
    "Concat",
    "Doc",
    "RenderedSource",
    "Sym",
    "Text",
    "mark",
    "marked",
    "marking",
    "parse",
    "plain",
    "render",
    "render_marked",
    "strip",
    "utf16_col",
]
