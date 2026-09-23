"""Class view: all methods of a class in one scrollable pane with cursor-tracking."""

from __future__ import annotations

from typing import List, Optional, Tuple

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QKeyEvent, QTextCursor
from PySide6.QtWidgets import QMenu, QWidget

from .decomp_view import DecompView
from .ref_info import RefInfo


class ClassView(DecompView):
    """Renders all methods of a class together, emitting which function the cursor is in."""

    function_focused = Signal(int)  # findex when cursor moves to a new function
    rename_requested = Signal(int, str)  # findex, word under cursor
    xref_requested = Signal(int, str)  # findex, word under cursor

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._line_ranges: List[Tuple[int, int, int]] = []  # (start, end, findex)
        self._focused_findex: Optional[int] = None
        self._refs: Optional[RefInfo] = None
        self.cursorPositionChanged.connect(self._on_cursor_moved)

    def set_ref_info(self, refs: RefInfo) -> None:
        self._refs = refs

    def load_methods(
        self, class_name: str, methods: List[Tuple[int, str]], fields: Optional[List[str]] = None
    ) -> None:
        """
        Render combined class output.
        methods: list of (findex, pseudo_text) — pseudo_text may be a placeholder.
        fields: field declaration lines shown at the top of the class body.
        Preserves cursor block position across refreshes.
        """
        # Methods change length as their decompiles land, so a raw block number
        # would drift into another method: remember (findex, line within it).
        saved_block = self.textCursor().blockNumber()
        anchor = next(
            (
                (fi, saved_block - start)
                for start, end, fi in self._line_ranges
                if start <= saved_block <= end
            ),
            None,
        )
        top_block = self.firstVisibleBlock().blockNumber()
        top_anchor = next(
            ((fi, top_block - start) for start, end, fi in self._line_ranges if start <= top_block <= end),
            None,
        )
        saved_vscroll = self.verticalScrollBar().value()
        saved_hscroll = self.horizontalScrollBar().value()
        lines: List[str] = [f"class {class_name} {{"]
        if fields:
            lines.extend(f"    {field}" for field in fields)
            lines.append("")
        self._line_ranges = []

        for findex, text in methods:
            content = _method_lines(findex, text)

            start = len(lines)
            lines.extend(content)
            end = len(lines) - 1
            self._line_ranges.append((start, end, findex))
            lines.append("")  # blank line between methods

        lines.append("}")
        self.setPlainText("\n".join(lines))

        def resolve(anchor_: Optional[Tuple[int, int]], fallback: int) -> int:
            if anchor_ is not None:
                for start, end, fi in self._line_ranges:
                    if fi == anchor_[0]:
                        return min(start + anchor_[1], end)
            return fallback

        # Restore the cursor (and view) to the same place in the same method.
        doc = self.document()
        block = doc.findBlockByNumber(min(resolve(anchor, saved_block), doc.blockCount() - 1))
        self.blockSignals(True)
        cursor = self.textCursor()
        cursor.setPosition(block.position())
        self.setTextCursor(cursor)
        self.blockSignals(False)

        if top_anchor is not None:
            self.verticalScrollBar().setValue(resolve(top_anchor, top_block))
        else:
            self.verticalScrollBar().setValue(saved_vscroll)
        self.horizontalScrollBar().setValue(saved_hscroll)

    def replace_method(self, findex: int, text: str) -> None:
        """Swap one method's text in place. Only that range is re-laid-out and
        re-highlighted, so methods finishing one by one don't re-render the class."""
        index = next((i for i, (_, _, fi) in enumerate(self._line_ranges) if fi == findex), None)
        if index is None:
            return
        start, end, _ = self._line_ranges[index]
        content = _method_lines(findex, text)
        delta = len(content) - (end - start + 1)

        cursor_block = self.textCursor().blockNumber()
        top_block = self.firstVisibleBlock().blockNumber()
        hscroll = self.horizontalScrollBar().value()
        # Methods finishing off screen leave the visible lines (and their
        # highlighting) as they were; only an edit in view needs a catch-up pass.
        first, last_visible = self._visible_blocks()
        in_view = start <= last_visible and end >= first

        doc = self.document()
        edit = QTextCursor(doc.findBlockByNumber(start))
        last = doc.findBlockByNumber(end)
        edit.setPosition(last.position() + last.length() - 1, QTextCursor.MoveMode.KeepAnchor)
        with self.quiet_scroll():
            self.blockSignals(True)
            edit.insertText("\n".join(content))
            self._line_ranges[index] = (start, start + len(content) - 1, findex)
            for i in range(index + 1, len(self._line_ranges)):
                s, e, fi = self._line_ranges[i]
                self._line_ranges[i] = (s + delta, e + delta, fi)

            # Keep the cursor and the view where the user left them.
            if cursor_block > end:
                cursor_block += delta
            elif cursor_block >= start:
                cursor_block = min(cursor_block, start + len(content) - 1)
            cursor = self.textCursor()
            cursor.setPosition(doc.findBlockByNumber(cursor_block).position())
            self.setTextCursor(cursor)
            self.blockSignals(False)
            self.verticalScrollBar().setValue(top_block + delta if top_block > end else top_block)
            self.horizontalScrollBar().setValue(hscroll)
        self.refresh_highlighting(catch_up=in_view)

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

    def scroll_to_op_line(self, findex: int, body_line: int) -> None:
        """Scroll to a body-relative pseudocode line within the given function and center it."""
        for start, end, fi in self._line_ranges:
            if fi == findex:
                combined = max(start, min(start + body_line, end))
                block = self.document().findBlockByNumber(combined)
                cursor = self.textCursor()
                cursor.setPosition(block.position())
                self.setTextCursor(cursor)
                self.centerCursor()
                return

    def findex_at_cursor(self) -> Optional[int]:
        return self._findex_at_line(self.textCursor().blockNumber())

    def _findex_at_line(self, line: int) -> Optional[int]:
        for start, end, findex in self._line_ranges:
            if start <= line <= end:
                return findex
        return None

    def _on_cursor_moved(self) -> None:
        findex = self.findex_at_cursor()
        if findex is not None and findex != self._focused_findex:
            self._focused_findex = findex
            self.function_focused.emit(findex)

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if not event.modifiers():
            findex = self.findex_at_cursor()
            if event.key() == Qt.Key.Key_N and findex is not None:
                self.rename_requested.emit(findex, self._word_at_cursor())
                return
            if event.key() == Qt.Key.Key_X and findex is not None:
                self.xref_requested.emit(findex, self._word_at_cursor())
                return
        super().keyPressEvent(event)

    def tooltip_at(self, cursor: QTextCursor) -> Optional[str]:
        if self._refs is None:
            return None
        word_cursor = QTextCursor(cursor)
        word_cursor.select(QTextCursor.SelectionType.WordUnderCursor)
        word = word_cursor.selectedText()
        if not word.isidentifier():
            return None
        # Only names used as calls (`name(`); plain identifiers are locals or fields.
        block_text = cursor.block().text()
        after = block_text[word_cursor.selectionEnd() - cursor.block().position() :].lstrip()
        if not after.startswith("("):
            return None
        return self._refs.method_tooltip(word, self._findex_at_line(cursor.blockNumber()))

    def _context_actions(self, menu: QMenu) -> None:
        super()._context_actions(menu)
        findex = self.findex_at_cursor()
        if findex is None:
            return
        word = self._word_at_cursor()
        menu.addAction("Cross-references\tX", lambda: self.xref_requested.emit(findex, word))
        menu.addAction("Rename\tN", lambda: self.rename_requested.emit(findex, word))
        menu.addAction("Comment\t/", self.comment_menu_requested.emit)


def _method_lines(findex: int, text: str) -> List[str]:
    """A method's lines as shown in the class body. pseudo wraps each method in
    `class X {` ... `}`, which is stripped."""
    func_lines = text.split("\n")
    if len(func_lines) >= 3 and func_lines[0].startswith("class ") and func_lines[-1].strip() == "}":
        return func_lines[1:-1]
    return [f"    // f@{findex}"] if not func_lines else func_lines
