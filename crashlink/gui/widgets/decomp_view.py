"""Decompiled pseudocode viewer with syntax highlighting."""

from __future__ import annotations

import re
from contextlib import contextmanager
from typing import Callable, Iterator, List, Optional, Tuple, cast

from PySide6.QtCore import QEvent, Qt, QTimer, Signal
from PySide6.QtGui import (
    QColor,
    QContextMenuEvent,
    QFont,
    QHelpEvent,
    QKeyEvent,
    QKeySequence,
    QMouseEvent,
    QSyntaxHighlighter,
    QTextCharFormat,
    QResizeEvent,
    QTextCursor,
    QTextDocument,
    QTextFormat,
)
from PySide6.QtWidgets import QMenu, QPlainTextEdit, QTextEdit, QToolTip, QWidget

from ..themes import Theme


class _Rule:
    def __init__(self, pattern: str, fmt_attr: str, flags: re.RegexFlag = re.RegexFlag(0)) -> None:
        self.rx = re.compile(pattern, flags)
        self.fmt_attr = fmt_attr


_RULES: List[_Rule] = [
    _Rule(r'"(?:[^"\\]|\\.)*"', "string"),
    _Rule(
        r"\b(function|var|if|else|while|for|return|new|this|true|false|null|"
        r"break|continue|switch|case|default|throw|try|catch|class|public|"
        r"static|override|inline|dynamic|extern)\b",
        "keyword",
    ),
    _Rule(
        r"\b(Int|Float|Bool|String|Dynamic|Void|Array|Bytes|haxe\.io\.Bytes|Any)\b",
        "type_name",
    ),
    _Rule(r"\b\d+(?:\.\d+)?\b", "number"),
    _Rule(r"\b([a-z_]\w*)\s*(?=\()", "func_call"),
    # Applied last so it wins over anything else matched inside the comment text
    # (e.g. digits/quotes that would otherwise get re-painted as number/string).
    _Rule(r"//[^\n]*", "comment"),
]

_NAV_KEYS = {
    Qt.Key.Key_Left,
    Qt.Key.Key_Right,
    Qt.Key.Key_Up,
    Qt.Key.Key_Down,
    Qt.Key.Key_Home,
    Qt.Key.Key_End,
    Qt.Key.Key_PageUp,
    Qt.Key.Key_PageDown,
}


# Block state for a line whose highlighting was deferred because it was off screen.
# (-1, Qt's default, means highlighted.)
_DEFERRED = 1


class DecompHighlighter(QSyntaxHighlighter):
    """Highlights only blocks near the viewport; the rest are marked and done when
    they scroll into view (`catch_up`). Highlighting runs Python per line, so
    doing a 20k-line class in one go froze the UI for seconds."""

    def __init__(self, document: QTextDocument, theme: Theme) -> None:
        super().__init__(document)
        self._fmts: dict[str, QTextCharFormat] = {}
        #: Block numbers to highlight right away; the owning view keeps it current.
        self.window: Tuple[int, int] = (0, 1 << 30)
        self.apply_theme(theme)

    def apply_theme(self, theme: Theme) -> None:
        def fmt(color: str, bold: bool = False, italic: bool = False) -> QTextCharFormat:
            f = QTextCharFormat()
            f.setForeground(QColor(color))
            if bold:
                f.setFontWeight(QFont.Weight.Bold)
            if italic:
                f.setFontItalic(True)
            return f

        self._fmts = self._formats(fmt, theme)
        self.rehighlight()

    def _formats(self, fmt: Callable[..., QTextCharFormat], theme: Theme) -> dict[str, QTextCharFormat]:
        return {
            "keyword": fmt(theme.mauve, bold=True),
            "type_name": fmt(theme.teal),
            "number": fmt(theme.peach),
            "string": fmt(theme.yellow),
            "func_call": fmt(theme.green),
            "comment": fmt(theme.overlay, italic=True),
        }

    def highlightBlock(self, text: str) -> None:
        first, last = self.window
        if not first <= self.currentBlock().blockNumber() <= last:
            self.setCurrentBlockState(_DEFERRED)
            return
        self.setCurrentBlockState(-1)
        self.highlight_text(text)

    def catch_up(self) -> None:
        """Highlight deferred blocks that are now inside `window`."""
        first, last = self.window
        doc = self.document()
        if doc is None:
            return
        block = doc.findBlockByNumber(first)
        # Counted loop: every Qt call made here may have to wait for the GIL.
        for _ in range(min(last, doc.blockCount() - 1) - first + 1):
            if block.userState() == _DEFERRED:
                self.rehighlightBlock(block)
            block = block.next()

    def highlight_text(self, text: str) -> None:
        # A "string" match's span is recorded and protected: any later rule's
        # match starting inside it is skipped, so a `//`-heavy string body
        # (raw base64 is a common real source) can't get repainted as a
        # comment, and a stray digit/keyword substring inside a string can't
        # get repainted as a number/keyword either.
        string_spans: List[Tuple[int, int]] = []
        for rule in _RULES:
            for m in rule.rx.finditer(text):
                if rule.rx.groups and m.lastindex:
                    start, end = m.start(1), m.end(1)
                else:
                    start, end = m.start(), m.end()
                if rule.fmt_attr != "string" and any(s <= start < e for s, e in string_spans):
                    continue
                fmt = self._fmts.get(rule.fmt_attr)
                if fmt:
                    self.setFormat(start, end - start, fmt)
                if rule.fmt_attr == "string":
                    string_spans.append((start, end))


class DecompView(QPlainTextEdit):
    """Read-only code pane: syntax highlighting, word/sync-line highlights, follow
    (double-click / Enter), hover tooltips, and a context menu of the pane actions."""

    #: (findex at cursor, word under cursor), on double-click or Enter.
    follow_requested = Signal(int, str)
    #: The '/' comment action picked from the context menu (SyncView resolves the op).
    comment_menu_requested = Signal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        # Do NOT setReadOnly — it hides the cursor. Block editing in keyPressEvent instead.
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setCursorWidth(2)
        # These views are display-only; without this, dragging a selection out of one
        # (or pasting one into the other) silently inserts editable text and corrupts
        # the rendered disassembly/pseudocode.
        self.setAcceptDrops(False)
        font = QFont("JetBrains Mono", 13)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.setFont(font)
        self._highlighter: Optional[DecompHighlighter] = None
        self._theme: Optional[Theme] = None
        self._last_highlight_word: str = ""
        self._word_sel: List[QTextEdit.ExtraSelection] = []
        self._sync_sel: List[QTextEdit.ExtraSelection] = []
        self._sync_block: Optional[int] = None
        # Views are rewritten in place as decompiles land; an undo history of those
        # edits would only cost memory.
        self.setUndoRedoEnabled(False)
        # Word highlighting searches only the visible lines, a moment after the cursor
        # or scroll position settles, instead of the whole document on every move.
        self._word_timer = QTimer(self)
        self._word_timer.setSingleShot(True)
        self._word_timer.setInterval(60)
        self._word_timer.timeout.connect(self._update_highlights)
        self.cursorPositionChanged.connect(self._word_timer.start)
        self._quiet_scroll = False
        self.verticalScrollBar().valueChanged.connect(self._on_scrolled)

    def _visible_blocks(self) -> Tuple[int, int]:
        """Block numbers of the visible lines plus a screenful either side."""
        first = self.firstVisibleBlock().blockNumber()
        page = max(1, self.viewport().height() // max(1, self.fontMetrics().height()))
        return max(0, first - page), first + 2 * page

    def refresh_highlighting(self, catch_up: bool = True) -> None:
        """Aim the lazy highlighting at the visible lines (after a scroll, resize or
        edit). With `catch_up`, lines now in view get highlighted, along with the
        occurrences of the word under the cursor."""
        if self._highlighter is not None:
            self._highlighter.window = self._visible_blocks()
            if catch_up:
                self._highlighter.catch_up()
        if catch_up:
            self._last_highlight_word = ""
            self._word_timer.start()

    @contextmanager
    def quiet_scroll(self) -> Iterator[None]:
        """Scroll without the highlighting catch-up, for callers that know the
        visible lines are unchanged (e.g. restoring the view after an edit)."""
        self._quiet_scroll = True
        try:
            yield
        finally:
            self._quiet_scroll = False

    def resizeEvent(self, e: QResizeEvent) -> None:
        super().resizeEvent(e)
        self.refresh_highlighting()

    def set_theme(self, theme: Theme) -> None:
        self._theme = theme
        if self._highlighter is None:
            self._highlighter = self._make_highlighter(theme)
            self.refresh_highlighting()
        else:
            self._highlighter.window = self._visible_blocks()
            self._highlighter.apply_theme(theme)
        # Existing highlight selections carry the old theme's colours: rebuild them.
        self.set_sync_line(self._sync_block)
        self._last_highlight_word = ""
        self._update_highlights()

    def _make_highlighter(self, theme: Theme) -> "DecompHighlighter":
        return DecompHighlighter(self.document(), theme)

    def setPlainText(self, text: str) -> None:
        super().setPlainText(text)
        self.refresh_highlighting()

    def set_code(self, text: str) -> None:
        self.setPlainText(text)

    def clear_view(self) -> None:
        self.setPlainText("")
        self._word_sel = []
        self._sync_sel = []
        self._sync_block = None
        self.setExtraSelections([])
        self._last_highlight_word = ""

    # ── Overridden by panes that know which function a line belongs to ────────

    def findex_at_cursor(self) -> Optional[int]:
        return None

    def _word_at_cursor(self) -> str:
        c = self.textCursor()
        if c.hasSelection():
            return c.selectedText().strip()
        c.select(QTextCursor.SelectionType.WordUnderCursor)
        return c.selectedText()

    def tooltip_at(self, cursor: QTextCursor) -> Optional[str]:
        """Rich-text hover for the text at `cursor`, or None."""
        return None

    # ── Highlights ───────────────────────────────────────────────────────────

    def _apply_selections(self) -> None:
        # Sync-line layer underneath the word-highlight layer.
        self.setExtraSelections(self._sync_sel + self._word_sel)

    def set_sync_line(self, block_no: Optional[int]) -> None:
        """Highlight a whole line (op↔pseudo sync), or clear it when block_no is None."""
        self._sync_block = block_no
        if block_no is None or block_no < 0:
            if self._sync_sel:
                self._sync_sel = []
                self._apply_selections()
            return
        fmt = QTextCharFormat()
        fmt.setBackground(QColor(self._theme.surface1 if self._theme else "#313244"))
        fmt.setProperty(QTextFormat.Property.FullWidthSelection, True)
        block = self.document().findBlockByNumber(block_no)
        if not block.isValid():
            return
        cursor = QTextCursor(block)
        sel = QTextEdit.ExtraSelection()
        sel.cursor = cursor
        sel.format = fmt
        self._sync_sel = [sel]
        self._apply_selections()

    def _on_scrolled(self) -> None:
        if not self._quiet_scroll:
            self.refresh_highlighting()

    def _update_highlights(self) -> None:
        cursor = self.textCursor()
        # Prefer an explicit selection; fall back to word under cursor.
        if cursor.hasSelection():
            word = cursor.selectedText().strip()
        else:
            c = self.textCursor()
            c.select(QTextCursor.SelectionType.WordUnderCursor)
            word = c.selectedText()

        if not word or not word.isidentifier():
            if self._last_highlight_word:
                self._word_sel = []
                self._apply_selections()
                self._last_highlight_word = ""
            return

        if word == self._last_highlight_word:
            return
        self._last_highlight_word = word

        bg = QColor(self._theme.accent if self._theme else "#b4befe")
        bg.setAlpha(60)
        fmt = QTextCharFormat()
        fmt.setBackground(bg)

        doc = self.document()
        first, last = self._visible_blocks()
        start = doc.findBlockByNumber(first).position()
        end_block = doc.findBlockByNumber(min(doc.blockCount() - 1, last))
        end = end_block.position() + end_block.length()

        # Search just this slice (QTextDocument.find would scan on to the end of a
        # large document looking for the next match).
        span = QTextCursor(doc)
        span.setPosition(start)
        span.setPosition(end - 1, QTextCursor.MoveMode.KeepAnchor)
        text = span.selectedText()  # same length as the range; newlines become U+2029
        selections: List[QTextEdit.ExtraSelection] = []
        for m in re.finditer(rf"(?<![\w$]){re.escape(word)}(?![\w$])", text):
            c = QTextCursor(doc)
            c.setPosition(start + m.start())
            c.setPosition(start + m.end(), QTextCursor.MoveMode.KeepAnchor)
            sel = QTextEdit.ExtraSelection()
            sel.cursor = c
            sel.format = fmt
            selections.append(sel)

        self._word_sel = selections
        self._apply_selections()

    # ── Input ────────────────────────────────────────────────────────────────

    def insertFromMimeData(self, source: object) -> None:
        # Belt-and-suspenders: also blocks X11 middle-click paste, which bypasses
        # both keyPressEvent and the drag/drop guards above.
        pass

    def _emit_follow(self) -> None:
        findex = self.findex_at_cursor()
        word = self._word_at_cursor()
        if findex is not None and word:
            self.follow_requested.emit(findex, word)

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:
        super().mouseDoubleClickEvent(event)  # moves the cursor / selects the word
        if event.button() == Qt.MouseButton.LeftButton:
            self._emit_follow()

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if not event.modifiers() and event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self._emit_follow()
            return
        if (
            event.matches(QKeySequence.StandardKey.Copy)
            or event.matches(QKeySequence.StandardKey.SelectAll)
            or event.key() in _NAV_KEYS
        ):
            super().keyPressEvent(event)
        # Drop all other keys (typing, paste, delete, etc.)

    def event(self, event: QEvent) -> bool:
        if event.type() == QEvent.Type.ToolTip:
            help_event = cast(QHelpEvent, event)
            viewport_pos = self.viewport().mapFrom(self, help_event.pos())
            text = self.tooltip_at(self.cursorForPosition(viewport_pos))
            if text:
                QToolTip.showText(help_event.globalPos(), text, self)
            else:
                QToolTip.hideText()
                event.ignore()
            return True
        return super().event(event)

    def _context_actions(self, menu: QMenu) -> None:
        """Pane-specific actions for the context menu (added above Copy)."""
        menu.addAction("Follow\tDouble-click", self._emit_follow)

    def contextMenuEvent(self, event: object) -> None:
        if not isinstance(event, QContextMenuEvent):
            return
        # Act on what was right-clicked, not wherever the cursor was before.
        if not self.textCursor().hasSelection():
            self.setTextCursor(self.cursorForPosition(event.pos()))
        menu = QMenu(self)
        self._context_actions(menu)
        menu.addSeparator()
        menu.addAction("Copy", self.copy)
        menu.addAction("Select All", self.selectAll)
        menu.exec_(
            event.globalPos()
        )  # exec()'s stub overloads are broken (PySide6 marks them overload-cannot-match)
