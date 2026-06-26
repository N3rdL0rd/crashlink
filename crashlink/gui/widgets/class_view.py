"""Class view: all methods of a class in one scrollable pane with cursor-tracking."""

from __future__ import annotations

from typing import List, Optional, Tuple

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QKeyEvent, QTextCursor
from PySide6.QtWidgets import QWidget

from .decomp_view import DecompView, _NAV_KEYS
from ..themes import Theme


class ClassView(DecompView):
    """Renders all methods of a class together, emitting which function the cursor is in."""

    function_focused   = Signal(int)        # findex when cursor moves to a new function
    rename_requested   = Signal(int, str)   # findex, word under cursor
    xref_requested     = Signal(int, str)   # findex, word under cursor

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._line_ranges: List[Tuple[int, int, int]] = []  # (start, end, findex)
        self._focused_findex: Optional[int] = None
        self.cursorPositionChanged.connect(self._on_cursor_moved)

    def load_methods(self, class_name: str, methods: List[Tuple[int, str]]) -> None:
        """
        Render combined class output.
        methods: list of (findex, pseudo_text) — pseudo_text may be a placeholder.
        Preserves cursor block position across refreshes.
        """
        saved_block = self.textCursor().blockNumber()
        saved_vscroll = self.verticalScrollBar().value()
        saved_hscroll = self.horizontalScrollBar().value()

        lines: List[str] = [f"class {class_name} {{"]
        self._line_ranges = []

        for findex, text in methods:
            func_lines = text.split("\n")
            # pseudo wraps each method in "class X {\n    body\n}" — strip the wrapper
            if len(func_lines) >= 3 and func_lines[0].startswith("class ") and func_lines[-1].strip() == "}":
                content = func_lines[1:-1]
            else:
                content = [f"    // f@{findex}"] if not func_lines else func_lines

            start = len(lines)
            lines.extend(content)
            end = len(lines) - 1
            self._line_ranges.append((start, end, findex))
            lines.append("")  # blank line between methods

        lines.append("}")
        self.setPlainText("\n".join(lines))

        # Restore approximate cursor position
        doc = self.document()
        block = doc.findBlockByNumber(min(saved_block, doc.blockCount() - 1))
        cursor = self.textCursor()
        cursor.setPosition(block.position())
        self.setTextCursor(cursor)

        self.verticalScrollBar().setValue(saved_vscroll)
        self.horizontalScrollBar().setValue(saved_hscroll)

    def scroll_to_findex(self, findex: int) -> None:
        """Scroll so the given function's first line is near the top of the view."""
        for start, _, fi in self._line_ranges:
            if fi == findex:
                block = self.document().findBlockByNumber(start)
                cursor = self.textCursor()
                cursor.setPosition(block.position())
                self.setTextCursor(cursor)
                self.centerCursor()
                return

    def findex_at_cursor(self) -> Optional[int]:
        line = self.textCursor().blockNumber()
        for start, end, findex in self._line_ranges:
            if start <= line <= end:
                return findex
        return None

    def _on_cursor_moved(self) -> None:
        findex = self.findex_at_cursor()
        if findex is not None and findex != self._focused_findex:
            self._focused_findex = findex
            self.function_focused.emit(findex)

    def keyPressEvent(self, event: object) -> None:  # type: ignore[override]
        if isinstance(event, QKeyEvent) and not event.modifiers():
            findex = self.findex_at_cursor()
            word = self._word_at_cursor()
            if event.key() == Qt.Key.Key_N and findex is not None:
                self.rename_requested.emit(findex, word)
                return
            if event.key() == Qt.Key.Key_X and findex is not None:
                self.xref_requested.emit(findex, word)
                return
        super().keyPressEvent(event)

    def _word_at_cursor(self) -> str:
        c = self.textCursor()
        if c.hasSelection():
            return c.selectedText().strip()
        c.select(QTextCursor.SelectionType.WordUnderCursor)
        return c.selectedText()
