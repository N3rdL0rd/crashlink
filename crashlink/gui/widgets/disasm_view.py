"""Disassembly view: HashLink opcodes for all methods of a class, with op-line tracking."""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from PySide6.QtCore import Signal
from PySide6.QtGui import QColor, QFont, QTextCharFormat, QTextDocument
from PySide6.QtWidgets import QWidget

from ... import disasm
from ...core import Bytecode, Function
from ..themes import Theme
from .decomp_view import DecompHighlighter, DecompView


class _Rule:
    def __init__(self, pattern: str, fmt_attr: str, group: int = 0) -> None:
        self.rx = re.compile(pattern)
        self.fmt_attr = fmt_attr
        self.group = group


# Applied in order; later rules win where ranges overlap, so put the most
# specific / important tokens last.
_DISASM_RULES: List[_Rule] = [
    _Rule(r'"(?:[^"\\]|\\.)*"', "string"),
    _Rule(r"\(from [^)]*\)", "comment"),
    _Rule(r"\[native\]", "comment"),
    _Rule(r"^\[[^\]]*\]", "comment"),  # [file:line] prefix
    _Rule(r"\((?:int|float|str) #\d+\)", "comment"),  # constant-pool index annotation
    _Rule(r"\(len=\d+\)", "comment"),
    _Rule(r"(?<![\w@])-?\d+(?:\.\d+)?\b", "number"),
    _Rule(r"<[^<>]+>", "type_name"),  # reg<Type> / field<Type> annotation
    _Rule(r"\b(Int|Float|Bool|String|Dynamic|Void|Array|Bytes|Any|Dyn)\b", "type_name"),
    _Rule(r"\b(true|false)\b", "keyword"),
    _Rule(r"->", "keyword"),
    _Rule(r"\b(static|native)\b", "modifier"),
    _Rule(r"\$[\w.]+", "func_name"),
    _Rule(r"\bf@\d+\b", "ref_fun"),
    _Rule(r"\bg@\d+\b", "ref_global"),
    _Rule(r"\bt@\d+\b", "ref_type"),
    _Rule(r"\be@\d+\b", "ref_type"),
    _Rule(r"\bbytes #\d+\b", "ref_type"),
    _Rule(r"\breg\d+\b", "reg"),
    _Rule(r"^\s*(?:\[[^\]]*\]\s*)?\d+\.\s+(\w+)", "opcode", group=1),
    _Rule(r"^\s*(?:\[[^\]]*\]\s*)?(\d+)\.", "index", group=1),
]


class DisasmHighlighter(DecompHighlighter):
    """Tokenizes HashLink disassembly: opcode names, register/global/type refs, operands."""

    def apply_theme(self, theme: Theme) -> None:
        def fmt(color: str, bold: bool = False, italic: bool = False) -> QTextCharFormat:
            f = QTextCharFormat()
            f.setForeground(QColor(color))
            if bold:
                f.setFontWeight(QFont.Weight.Bold)
            if italic:
                f.setFontItalic(True)
            return f

        self._fmts = {
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
        self.rehighlight()

    def highlightBlock(self, text: str) -> None:
        for rule in _DISASM_RULES:
            for m in rule.rx.finditer(text):
                fmt = self._fmts.get(rule.fmt_attr)
                if fmt is None:
                    continue
                start, end = m.span(rule.group)
                if start < 0:
                    continue
                self.setFormat(start, end - start, fmt)


_FILE_PREFIX_RX = re.compile(r"^\[([^:\]]+):(\d+)\] ")
_PATH_MAX_LEN = 32


def _truncate_path(path: str, max_len: int = _PATH_MAX_LEN) -> str:
    """Collapse a long path to its first directory and filename, e.g.
    /usr/share/haxe/std/hl/_std/Std.hx -> /usr/.../Std.hx"""
    if len(path) <= max_len:
        return path
    prefix = "/" if path.startswith("/") else ""
    parts = [p for p in path.split("/") if p]
    if len(parts) <= 2:
        return path
    return f"{prefix}{parts[0]}/.../{parts[-1]}"


def _shorten_file_prefix(row: str) -> Tuple[str, str, int]:
    """Split off and shorten the leading `[file:line] ` prefix. Returns
    (bracket, rest_of_row, bracket_len); bracket is "" when there's no prefix."""
    m = _FILE_PREFIX_RX.match(row)
    if not m:
        return "", row, 0
    path, line = m.group(1), m.group(2)
    bracket = f"[{_truncate_path(path)}:{line}]"
    return bracket, row[m.end() :], len(bracket)


class DisasmView(DecompView):
    """Renders opcodes for every method of a class, mapping each op to its line."""

    function_focused = Signal(int)  # findex when cursor moves to a new function

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._op_ranges: List[Tuple[int, int, int]] = []  # (op_start_line, findex, n_ops)
        self._focused_findex: Optional[int] = None
        self.cursorPositionChanged.connect(self._on_cursor_moved)

    def set_theme(self, theme: Theme) -> None:
        self._theme = theme
        if self._highlighter is None:
            self._highlighter = DisasmHighlighter(self.document(), theme)
        else:
            self._highlighter.apply_theme(theme)

    def load(self, code: Bytecode, methods: List[Tuple[int, object]]) -> None:
        """methods: list of (findex, Function|Native), rendered in order."""
        saved_block = self.textCursor().blockNumber()
        saved_vscroll = self.verticalScrollBar().value()
        saved_hscroll = self.horizontalScrollBar().value()

        # Each entry is either a plain line (header/blank) or an (bracket, rest) op row.
        entries: List[str | Tuple[str, str]] = []
        self._op_ranges = []

        for findex, fn in methods:
            try:
                header = disasm.func_header(code, fn)  # type: ignore[arg-type]
            except Exception:
                header = f"f@{findex}"
            entries.append(header + ":")
            op_start = len(entries)
            n_ops = 0
            if isinstance(fn, Function):
                debug = fn.debuginfo.value if fn.debuginfo else None
                for i, op in enumerate(fn.ops):
                    try:
                        row = disasm.fmt_op_compact(code, fn.regs, op, i, debug=debug, func=fn)
                    except Exception as e:
                        row = f"{i:>3}. <fmt error: {e}>"
                    bracket, rest, _ = _shorten_file_prefix(row.replace("\n", " "))
                    entries.append((bracket, rest) if bracket else rest)
                n_ops = len(fn.ops)
            self._op_ranges.append((op_start, findex, n_ops))
            entries.append("")

        # Pad every bracket to the widest one actually present, so the opcode column
        # lines up without ballooning the gap for classes with only short filenames.
        prefix_width = max((len(e[0]) for e in entries if isinstance(e, tuple)), default=0)

        lines: List[str] = [
            f"{e[0].ljust(prefix_width)} {e[1]}" if isinstance(e, tuple) else e for e in entries
        ]

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

    def op_at_cursor(self) -> Optional[Tuple[int, int]]:
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
