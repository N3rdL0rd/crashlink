"""Class view: all methods of a class in one scrollable pane with cursor-tracking."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtGui import QKeyEvent, QTextCursor
from PySide6.QtWidgets import QMenu, QWidget

from ...pseudo.doc import RenderedSource, utf16_col
from ...pseudo.symbols import SymbolKind, SymbolRef, SymbolSpan
from .decomp_view import DecompView, to_str_col
from .hover import hover_html
from .ref_info import RefInfo


class ClassView(DecompView):
    """Renders all methods of a class together, emitting which function the cursor is in."""

    function_focused = Signal(int)  # findex when cursor moves to a new function
    rename_requested = Signal(int, object)  # findex, the local's SymbolRef (None when not on a local)
    #: findex, and what to find references to: a `SymbolRef`, or the selected text.
    xref_requested = Signal(int, object)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._line_ranges: List[Tuple[int, int, int]] = []  # (start, end, findex)
        self._focused_findex: Optional[int] = None
        self._refs: Optional[RefInfo] = None
        # findex -> (rendered source, text line of the method's first shown line).
        self._spans: Dict[int, Tuple[RenderedSource, int]] = {}
        self.cursorPositionChanged.connect(self._on_cursor_moved)

    def set_ref_info(self, refs: RefInfo) -> None:
        self._refs = refs

    def _method_content(self, findex: int, text: str, rendered: Optional[RenderedSource]) -> List[str]:
        """The lines of the method as shown, remembering `rendered`'s symbols for them.
        Symbols only apply to exactly the text they were rendered with, and then the
        rendered source says which of its lines are the function body. Text without
        symbols (a placeholder or error the window wrote itself) is unwrapped by
        `_method_lines`."""
        if rendered is not None and rendered.text == text:
            self._spans[findex] = (rendered, rendered.body_start)
            return rendered.body_lines()
        self._spans.pop(findex, None)
        return _method_lines(findex, text)

    def load_methods(
        self,
        class_name: str,
        methods: List[Tuple[int, str]],
        fields: Optional[List[str]] = None,
        spans: Optional[Dict[int, RenderedSource]] = None,
    ) -> None:
        """
        Render combined class output.
        methods: list of (findex, pseudo_text) — pseudo_text may be a placeholder.
        fields: field declaration lines shown at the top of the class body.
        spans: the rendered source (with its symbols) of the methods that have one.
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
        self._spans = {}

        for findex, text in methods:
            content = self._method_content(findex, text, spans.get(findex) if spans else None)

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

    def replace_method(self, findex: int, text: str, rendered: Optional[RenderedSource] = None) -> None:
        """Swap one method's text in place. Only that range is re-laid-out and
        re-highlighted, so methods finishing one by one don't re-render the class."""
        index = next((i for i, (_, _, fi) in enumerate(self._line_ranges) if fi == findex), None)
        if index is None:
            return
        content = self._method_content(findex, text, rendered)
        start, end, _ = self._line_ranges[index]
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
        self._last_highlight_word = ""
        self.refresh_highlighting(catch_up=in_view)
        self._emit_symbol_focus()

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

    # ── Symbols ───────────────────────────────────────────────────────────────

    def rendered_for(self, findex: int) -> Optional[RenderedSource]:
        """The rendered source (symbols included) of the method as currently shown."""
        entry = self._spans.get(findex)
        return entry[0] if entry is not None else None

    def _qt_span(self, block_no: int, span: SymbolSpan) -> SymbolSpan:
        line = self.document().findBlockByNumber(block_no).text()
        return SymbolSpan(
            block_no, utf16_col(line, span.start), utf16_col(line, span.end), span.ref, span.is_def
        )

    def symbol_span_at(self, block_no: int, col: int) -> Optional[SymbolSpan]:
        for start, end, findex in self._line_ranges:
            if not start <= block_no <= end:
                continue
            entry = self._spans.get(findex)
            if entry is None:
                return None
            rendered, offset = entry
            line = self.document().findBlockByNumber(block_no).text()
            span = rendered.span_at(block_no - start + offset, to_str_col(line, col))
            return self._qt_span(block_no, span) if span is not None else None
        return None

    def symbol_ranges(self, ref: SymbolRef, first: int, last: int) -> List[Tuple[int, int, int]]:
        ranges: List[Tuple[int, int, int]] = []
        for start, end, findex in self._line_ranges:
            if end < first or start > last:
                continue
            entry = self._spans.get(findex)
            if entry is None:
                continue
            rendered, offset = entry
            for span in rendered.spans_of(ref):
                block_no = start + span.line - offset
                if first <= block_no <= last and start <= block_no <= end:
                    shown = self._qt_span(block_no, span)
                    ranges.append((block_no, shown.start, shown.end))
        return ranges

    def goto_definition(self, ref: SymbolRef) -> bool:
        """Move the caret to the token declaring `ref` (a local's `var`, a method's
        header) when this pane shows it. False when it does not."""
        for start, _, findex in self._line_ranges:
            if ref.kind == SymbolKind.LOCAL and findex != ref.scope:
                continue
            if ref.kind == SymbolKind.FUNCTION and findex != ref.index:
                continue
            entry = self._spans.get(findex)
            if entry is None:
                continue
            rendered, offset = entry
            span = rendered.definition_of(ref)
            if span is None:
                continue
            block_no = start + span.line - offset
            shown = self._qt_span(block_no, span)
            block = self.document().findBlockByNumber(block_no)
            cursor = self.textCursor()
            cursor.setPosition(block.position() + shown.start)
            self.setTextCursor(cursor)
            self.centerCursor()
            self.setFocus()
            return True
        return False

    def symbol_uses(self, ref: SymbolRef) -> List[Tuple[int, int, str]]:
        """(findex, line within the method's shown body, line text) of every line of the
        pane that has a token naming `ref`."""
        uses: List[Tuple[int, int, str]] = []
        for start, end, findex in self._line_ranges:
            entry = self._spans.get(findex)
            if entry is None:
                continue
            rendered, offset = entry
            seen = set()
            for span in rendered.spans_of(ref):
                body_line = span.line - offset
                if body_line in seen or not 0 <= start + body_line <= end:
                    continue
                seen.add(body_line)
                uses.append(
                    (findex, body_line, self.document().findBlockByNumber(start + body_line).text().strip())
                )
        return uses

    def _rename_target(self) -> Optional[SymbolRef]:
        """The local under the caret; renaming anything else is not offered."""
        span = self.symbol_at_cursor()
        return span.ref if span is not None and span.ref.kind == SymbolKind.LOCAL else None

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if not event.modifiers():
            findex = self.findex_at_cursor()
            if event.key() == Qt.Key.Key_N and findex is not None:
                self.rename_requested.emit(findex, self._rename_target())
                return
            if event.key() == Qt.Key.Key_X and findex is not None:
                self.xref_requested.emit(findex, self._xref_target())
                return
        super().keyPressEvent(event)

    def tooltip_at_point(self, cursor: QTextCursor, viewport_pos: QPoint) -> Optional[str]:
        """What the token or expression under the pointer is, from the symbols and
        expression types the renderer recorded. Text without them (a function still
        decompiling) has no tooltip."""
        if self._refs is None:
            return None
        hovered = self.hovered_char(viewport_pos)
        if hovered is None:
            return None
        block_no, qt_col = hovered
        for start, end, findex in self._line_ranges:
            if not start <= block_no <= end:
                continue
            entry = self._spans.get(findex)
            if entry is None:
                return None
            rendered, offset = entry
            line = self.document().findBlockByNumber(block_no).text()
            return hover_html(
                self._refs, rendered, block_no - start + offset, to_str_col(line, qt_col), self._theme
            )
        return None

    def _context_actions(self, menu: QMenu) -> None:
        super()._context_actions(menu)
        findex = self.findex_at_cursor()
        if findex is None:
            return
        target = self._xref_target()
        menu.addAction("Cross-references\tX", lambda: self.xref_requested.emit(findex, target))
        menu.addAction("Rename\tN", lambda: self.rename_requested.emit(findex, self._rename_target()))
        menu.addAction("Comment\t/", self.comment_menu_requested.emit)


def wrapper_lines(text: str) -> int:
    """How many leading lines of `text` the class view drops (pseudo wraps each method in
    `class X {` ... `}`)."""
    func_lines = text.split("\n")
    if len(func_lines) >= 3 and func_lines[0].startswith("class ") and func_lines[-1].strip() == "}":
        return 1
    return 0


def _method_lines(findex: int, text: str) -> List[str]:
    """A method's lines as shown in the class body. pseudo wraps each method in
    `class X {` ... `}`, which is stripped."""
    func_lines = text.split("\n")
    if wrapper_lines(text):
        return func_lines[1:-1]
    return [f"    // f@{findex}"] if not func_lines else func_lines
