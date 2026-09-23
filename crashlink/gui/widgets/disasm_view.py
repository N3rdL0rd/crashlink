"""Disassembly view: HashLink opcodes for all methods of a class, with op-line tracking."""

from __future__ import annotations

import html
import os
import re
from typing import Callable, Dict, List, Optional, Tuple

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QKeyEvent, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import QMenu, QWidget

from ... import disasm
from ...core import Bytecode, Function, Native
from ..themes import Theme
from .decomp_view import DecompHighlighter, DecompView
from .ref_info import RefInfo

# f@N / g@N / t@N / e@N reference tokens, exactly as disasm.py renders them,
# optionally followed by the name this view appends to `f@N` (`f@439 h2d.Scene.over`).
# Qt's default word-under-cursor selection splits these on the '@', so follow /
# xref lookups need this instead.
_REF_SPAN_RX = re.compile(r"\b([a-z])@(\d+)(?: ([A-Za-z_$][\w$.]*)(?![\w<]))?")
_REG_RX = re.compile(r"\breg(\d+)<([^<>]*)>")
# `  12. Mnemonic` after the (possibly blank) source-location gutter.
_OPCODE_RX = re.compile(r"^\s*(?:\S+:\d+\s+)?\d+\.\s+(\w+)")


class _Rule:
    def __init__(self, pattern: str, fmt_attr: str, group: int = 0) -> None:
        self.rx = re.compile(pattern)
        self.fmt_attr = fmt_attr
        self.group = group


# Applied in order; later rules win where ranges overlap, so put the most
# specific / important tokens last. All "comment"-tagged rules are last of all,
# so nothing inside them (e.g. digits in "file.hx:9" or "(int #0)") gets
# re-painted as a number/type by a later, more generic rule.
_DISASM_RULES: List[_Rule] = [
    _Rule(r'"(?:[^"\\]|\\.)*"', "string"),
    _Rule(r"(?<![\w@])-?\d+(?:\.\d+)?\b", "number"),
    _Rule(r"\b0x[0-9a-fA-F]+\b", "number"),  # native-asm addresses / immediates
    _Rule(r"^\s+0x[0-9a-f]+\s+[0-9a-f.]+\s+([a-z][a-z0-9.]*)", "opcode", group=1),  # mnemonic column
    _Rule(r"<[^<>]+>", "type_name"),  # reg<Type> / field<Type> annotation
    _Rule(r"\b(Int|Float|Bool|String|Dynamic|Void|Array|Bytes|Any|Dyn)\b", "type_name"),
    _Rule(r"\b(true|false)\b", "keyword"),
    _Rule(r"->", "keyword"),
    _Rule(r"\b(static|native)\b", "modifier"),
    _Rule(r"\$[\w.]+", "func_name"),
    _Rule(r"\bf@\d+\b", "ref_fun"),
    _Rule(r"\bf@\d+ ([A-Za-z_$][\w$.]*)(?![\w<])", "func_name", group=1),  # name appended to f@N
    _Rule(r"\bg@\d+\b", "ref_global"),
    _Rule(r"\bt@\d+\b", "ref_type"),
    _Rule(r"\be@\d+\b", "ref_type"),
    _Rule(r"\bbytes #\d+\b", "ref_type"),
    _Rule(r"\breg\d+\b", "reg"),
    _Rule(r"^\s*(?:\S+:\d+\s+)?\d+\.\s+(\w+)", "opcode", group=1),
    _Rule(r"^\s*(?:\S+:\d+\s+)?(\d+)\.", "index", group=1),
    _Rule(r"(?<![\w$/])(?:[a-zA-Z_][\w$.]*_)?(?:hl|fmt|sdl|ui|uv|openal)_[A-Za-z_]\w*", "func_name"),
    _Rule(r"\(from [^)]*\)", "comment"),
    _Rule(r"\[native\]", "comment"),
    _Rule(r"^[^\s:]+:\d+(?=\s)", "comment"),  # source-location gutter
    _Rule(r"\((?:int|float|str) #\d+\)", "comment"),  # constant-pool index annotation
    _Rule(r"\(len=\d+\)", "comment"),
    _Rule(r";.*$", "comment"),  # trailing user comment — dim over everything inside it
]


class DisasmHighlighter(DecompHighlighter):
    """Tokenizes HashLink disassembly: opcode names, register/global/type refs, operands."""

    def _formats(self, fmt: Callable[..., QTextCharFormat], theme: Theme) -> Dict[str, QTextCharFormat]:
        return {
            "index": fmt(theme.subtext),
            "opcode": fmt(theme.mauve, bold=True),
            "reg": fmt(theme.teal),
            "ref_fun": fmt(theme.peach),
            "ref_global": fmt(theme.peach),
            "ref_type": fmt(theme.peach),
            "func_name": fmt(theme.green),
            "type_name": fmt(theme.teal),
            "keyword": fmt(theme.red, bold=True),
            "modifier": fmt(theme.red),
            "number": fmt(theme.yellow),
            "string": fmt(theme.yellow),
            "comment": fmt(theme.overlay, italic=True),
        }

    def highlight_text(self, text: str) -> None:
        # Same protection as DecompHighlighter: a "string" match's span is
        # recorded, and any later rule's match starting inside it is
        # skipped - a raw string preview (`"..." (str #N)`) can contain any
        # byte a real comment/number/keyword rule would otherwise latch onto.
        string_spans: List[Tuple[int, int]] = []
        for rule in _DISASM_RULES:
            for m in rule.rx.finditer(text):
                fmt = self._fmts.get(rule.fmt_attr)
                if fmt is None:
                    continue
                start, end = m.span(rule.group)
                if start < 0:
                    continue
                if rule.fmt_attr != "string" and any(s <= start < e for s, e in string_spans):
                    continue
                self.setFormat(start, end - start, fmt)
                if rule.fmt_attr == "string":
                    string_spans.append((start, end))


_FILE_PREFIX_RX = re.compile(r"^\[([^:\]]+):(\d+)\] ")


def _split_file_prefix(row: str) -> Tuple[Optional[str], Optional[int], str]:
    """Split off the leading `[file:line] ` prefix of a disasm row.
    Returns (path, line, rest_of_row); path/line are None when there's no prefix."""
    m = _FILE_PREFIX_RX.match(row)
    if not m:
        return None, None, row
    return m.group(1), int(m.group(2)), row[m.end() :]


class DisasmView(DecompView):
    """Renders opcodes for every method of a class, mapping each op to its line.

    Rows are `gutter  idx. Op operands`: the gutter shows `File.hx:line` only when
    the source location changes (full path on hover), call targets get their
    name appended (`f@439 h2d.Scene.over`), and constant-string globals their value."""

    function_focused = Signal(int)  # findex when cursor moves to a new function
    xref_requested = Signal(int, str)  # findex, word/ref-token under cursor
    op_focused = Signal(int, int)  # findex, op_idx when the cursor moves onto another op

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._op_ranges: List[Tuple[int, int, int]] = []  # (op_start_line, findex, n_ops)
        self._focused_findex: Optional[int] = None
        self._focused_op: Optional[Tuple[int, int]] = None
        # True while showing original machine code (de-HL/C images): rows carry
        # no opcode semantics, so op_at_cursor must report None.
        self._native_mode = False
        self._refs: Optional[RefInfo] = None
        # block number -> "full/path.hx:line" for gutter hover
        self._line_sources: Dict[int, str] = {}
        self._gutter_width = 0
        self.cursorPositionChanged.connect(self._on_cursor_moved)

    def _make_highlighter(self, theme: Theme) -> DecompHighlighter:
        return DisasmHighlighter(self.document(), theme)

    def set_ref_info(self, refs: RefInfo) -> None:
        self._refs = refs

    @property
    def ref_info(self) -> Optional[RefInfo]:
        return self._refs

    def _annotate(self, rest: str) -> str:
        """Append names to `f@N` call targets and values to constant-string `g@N`."""
        refs = self._refs
        if refs is None:
            return rest

        def repl(m: "re.Match[str]") -> str:
            kind, index = m.group(1), int(m.group(2))
            if kind == "f":
                name = refs.function_name(index)
                return f"{m.group(0)} {name}" if name else m.group(0)
            value = refs.global_inline(index)
            return f"{m.group(0)} {value}" if value else m.group(0)

        return re.sub(r"\b([fg])@(\d+)\b", repl, rest)

    def load(self, code: Bytecode, methods: List[Tuple[int, "Function | Native"]]) -> None:
        """methods: list of (findex, Function|Native), rendered in order."""
        self._native_mode = False
        if self._refs is None or self._refs.code is not code:
            self._refs = RefInfo(code)
        saved_block = self.textCursor().blockNumber()
        saved_vscroll = self.verticalScrollBar().value()
        saved_hscroll = self.horizontalScrollBar().value()

        # Each entry is either a plain line (header/blank) or a (gutter, source, rest) op row.
        entries: List[str | Tuple[str, str, str]] = []
        self._op_ranges = []

        for findex, fn in methods:
            try:
                header = disasm.func_header(code, fn)
            except Exception:
                header = f"f@{findex}"
            entries.append(header + ":")
            op_start = len(entries)
            n_ops = 0
            if isinstance(fn, Function):
                debug = fn.debuginfo.value if fn.debuginfo else None
                previous: Optional[Tuple[str, int]] = None
                for i, op in enumerate(fn.ops):
                    try:
                        row = disasm.fmt_op_compact(code, fn.regs, op, i, debug=debug, func=fn)
                    except Exception as e:
                        row = f"{i:>3}. <fmt error: {e}>"
                    path, line, rest = _split_file_prefix(row.replace("\n", " "))
                    gutter = source = ""
                    if path is not None and line is not None:
                        source = f"{path}:{line}"
                        # Only print the location when it changes, so the gutter stays readable.
                        if (path, line) != previous:
                            gutter = f"{os.path.basename(path)}:{line}"
                        previous = (path, line)
                    entries.append((gutter, source, self._annotate(rest)))
                n_ops = len(fn.ops)
            self._op_ranges.append((op_start, findex, n_ops))
            entries.append("")

        # Pad the gutter to the widest location actually present.
        self._gutter_width = max((len(e[0]) for e in entries if isinstance(e, tuple)), default=0)
        self._line_sources = {}
        lines: List[str] = []
        for number, e in enumerate(entries):
            if isinstance(e, tuple):
                gutter, source, rest = e
                if source:
                    self._line_sources[number] = source
                lines.append(f"{gutter.ljust(self._gutter_width)} {rest}" if self._gutter_width else rest)
            else:
                lines.append(e)

        self.setPlainText("\n".join(lines))

        doc = self.document()
        block = doc.findBlockByNumber(min(saved_block, doc.blockCount() - 1))
        cursor = self.textCursor()
        cursor.setPosition(block.position())
        self.setTextCursor(cursor)
        self.verticalScrollBar().setValue(saved_vscroll)
        self.horizontalScrollBar().setValue(saved_hscroll)

    def load_native(self, blocks: List[Tuple[int, str, List[str]]]) -> None:
        """blocks: list of (findex, header, asm_rows) — original machine code for
        de-HL/C images. Keeps the same focus-tracking ranges as `load`, but rows
        carry no opcode mapping (op_at_cursor reports None)."""
        saved_block = self.textCursor().blockNumber()
        saved_vscroll = self.verticalScrollBar().value()
        saved_hscroll = self.horizontalScrollBar().value()

        lines: List[str] = []
        self._op_ranges = []
        self._native_mode = True
        self._line_sources = {}
        self._gutter_width = 0

        for findex, header, rows in blocks:
            lines.append(header)
            row_start = len(lines)
            lines.extend(rows)
            self._op_ranges.append((row_start, findex, len(rows)))
            lines.append("")

        self.setPlainText("\n".join(lines))

        doc = self.document()
        block = doc.findBlockByNumber(min(saved_block, doc.blockCount() - 1))
        cursor = self.textCursor()
        cursor.setPosition(block.position())
        self.setTextCursor(cursor)
        self.verticalScrollBar().setValue(saved_vscroll)
        self.horizontalScrollBar().setValue(saved_hscroll)

    def combined_line_for_op(self, findex: int, op_idx: int) -> Optional[int]:
        for op_start, fi, n_ops in self._op_ranges:
            if fi == findex:
                if n_ops == 0:
                    return op_start - 1  # header line
                return op_start + max(0, min(op_idx, n_ops - 1))
        return None

    def scroll_to_op(self, findex: int, op_idx: int) -> None:
        """Move the cursor to `op_idx` of `findex` and centre it."""
        line = self.combined_line_for_op(findex, op_idx)
        if line is None:
            return
        block = self.document().findBlockByNumber(line)
        cursor = self.textCursor()
        cursor.setPosition(block.position())
        self.setTextCursor(cursor)
        self.centerCursor()

    def op_at_cursor(self) -> Optional[Tuple[int, int]]:
        if self._native_mode:
            return None  # machine-code rows have no opcode mapping
        line = self.textCursor().blockNumber()
        for op_start, findex, n_ops in self._op_ranges:
            if op_start <= line < op_start + n_ops:
                return findex, line - op_start
        return None

    def findex_at_cursor(self) -> Optional[int]:
        line = self.textCursor().blockNumber()
        for op_start, findex, n_ops in self._op_ranges:
            # header line (op_start - 1) through last op
            if op_start - 1 <= line < op_start + n_ops:
                return findex
        return None

    def _on_cursor_moved(self) -> None:
        findex = self.findex_at_cursor()
        if findex is not None and findex != self._focused_findex:
            self._focused_findex = findex
            self.function_focused.emit(findex)
        op = self.op_at_cursor()
        if op is not None and op != self._focused_op:
            self._focused_op = op
            self.op_focused.emit(*op)

    def _word_at_cursor(self) -> str:
        c = self.textCursor()
        text = c.block().text()
        # A reference under the cursor wins over Qt's word selection, which splits
        # `f@123` at the '@' (a double-click selects just "123"); a name appended
        # to f@N counts as part of the reference.
        start = c.selectionStart() - c.block().position()
        end = c.selectionEnd() - c.block().position()
        for m in _REF_SPAN_RX.finditer(text):
            if m.start() <= start and end <= m.end():
                return f"{m.group(1)}@{m.group(2)}"
        if c.hasSelection():
            return c.selectedText().strip()
        c.select(QTextCursor.SelectionType.WordUnderCursor)
        return c.selectedText()

    def tooltip_at(self, cursor: QTextCursor) -> Optional[str]:
        refs = self._refs
        if refs is None or self._native_mode:
            return None
        text = cursor.block().text()
        col = cursor.positionInBlock()

        source = self._line_sources.get(cursor.blockNumber())
        if source is not None and col < self._gutter_width:
            return html.escape(source)

        opcode = _OPCODE_RX.match(text)
        if opcode is not None and opcode.start(1) <= col <= opcode.end(1):
            return refs.opcode_tooltip(opcode.group(1))

        for m in _REF_SPAN_RX.finditer(text):
            if m.start() <= col <= m.end():
                kind, index = m.group(1), int(m.group(2))
                if kind == "f":
                    return refs.function_tooltip(index)
                if kind == "g":
                    return refs.global_tooltip(index)
                if kind == "t":
                    return refs.type_tooltip(index)
                return None

        for m in _REG_RX.finditer(text):
            if m.start() <= col <= m.end():
                return f"<b>reg{m.group(1)}</b>: {html.escape(m.group(2))}"
        return None

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if not event.modifiers() and event.key() == Qt.Key.Key_X:
            findex = self.findex_at_cursor()
            if findex is not None:
                self.xref_requested.emit(findex, self._word_at_cursor())
                return
        super().keyPressEvent(event)

    def _context_actions(self, menu: QMenu) -> None:
        super()._context_actions(menu)
        findex = self.findex_at_cursor()
        if findex is None:
            return
        word = self._word_at_cursor()
        menu.addAction("Cross-references\tX", lambda: self.xref_requested.emit(findex, word))
        if self.op_at_cursor() is not None:
            menu.addAction("Comment\t/", self.comment_menu_requested.emit)
