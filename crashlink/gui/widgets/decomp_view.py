"""Decompiled pseudocode viewer with syntax highlighting."""

from __future__ import annotations

import re
from typing import List, Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import (
    QColor,
    QContextMenuEvent,
    QFont,
    QKeyEvent,
    QKeySequence,
    QSyntaxHighlighter,
    QTextCharFormat,
    QTextCursor,
    QTextDocument,
)
from PySide6.QtWidgets import QMenu, QPlainTextEdit, QTextEdit, QWidget

from ..themes import Theme


class _Rule:
    def __init__(self, pattern: str, fmt_attr: str, flags: re.RegexFlag = re.NOFLAG) -> None:
        self.rx = re.compile(pattern, flags)
        self.fmt_attr = fmt_attr


_RULES: List[_Rule] = [
    _Rule(r"//[^\n]*", "comment"),
    _Rule(r'"(?:[^"\\]|\\.)*"', "string"),
    _Rule(
        r"\b(function|var|if|else|while|for|return|new|this|true|false|null|"
        r"break|continue|switch|case|default|throw|try|catch|class|public|"
        r"static|override|inline|dynamic|extern)\b",
        "keyword",
    ),
    _Rule(r"\b(Int|Float|Bool|String|Dynamic|Void|Array|Bytes|haxe\.io\.Bytes|Any)\b", "type_name"),
    _Rule(r"\b\d+(?:\.\d+)?\b", "number"),
    _Rule(r"\b([a-z_]\w*)\s*(?=\()", "func_call"),
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


class DecompHighlighter(QSyntaxHighlighter):
    def __init__(self, document: QTextDocument, theme: Theme) -> None:
        super().__init__(document)
        self._fmts: dict[str, QTextCharFormat] = {}
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

        self._fmts = {
            "keyword": fmt(theme.mauve, bold=True),
            "type_name": fmt(theme.teal),
            "number": fmt(theme.peach),
            "string": fmt(theme.yellow),
            "func_call": fmt(theme.green),
            "comment": fmt(theme.overlay, italic=True),
        }
        self.rehighlight()

    def highlightBlock(self, text: str) -> None:
        for rule in _RULES:
            for m in rule.rx.finditer(text):
                fmt = self._fmts.get(rule.fmt_attr)
                if fmt:
                    if rule.rx.groups and m.lastindex:
                        self.setFormat(m.start(1), m.end(1) - m.start(1), fmt)
                    else:
                        self.setFormat(m.start(), m.end() - m.start(), fmt)


class DecompView(QPlainTextEdit):
    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        # Do NOT setReadOnly — it hides the cursor. Block editing in keyPressEvent instead.
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setCursorWidth(2)
        font = QFont("JetBrains Mono", 13)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.setFont(font)
        self._highlighter: Optional[DecompHighlighter] = None
        self._theme: Optional[Theme] = None
        self._last_highlight_word: str = ""
        self.cursorPositionChanged.connect(self._update_highlights)

    def set_theme(self, theme: Theme) -> None:
        self._theme = theme
        if self._highlighter is None:
            self._highlighter = DecompHighlighter(self.document(), theme)
        else:
            self._highlighter.apply_theme(theme)

    def set_code(self, text: str) -> None:
        self.setPlainText(text)

    def clear_view(self) -> None:
        self.setPlainText("")
        self.setExtraSelections([])
        self._last_highlight_word = ""

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
                self.setExtraSelections([])
                self._last_highlight_word = ""
            return

        if word == self._last_highlight_word:
            return
        self._last_highlight_word = word

        accent = self._theme.accent if self._theme else "#b4befe"
        bg = QColor(accent)
        bg.setAlpha(70)
        fmt = QTextCharFormat()
        fmt.setBackground(bg)

        flags = QTextDocument.FindFlag.FindWholeWords | QTextDocument.FindFlag.FindCaseSensitively
        selections: List[QTextEdit.ExtraSelection] = []
        c = self.document().find(word, 0, flags)
        while not c.isNull():
            sel = QTextEdit.ExtraSelection()
            sel.cursor = c
            sel.format = fmt
            selections.append(sel)
            c = self.document().find(word, c, flags)

        self.setExtraSelections(selections)

    def keyPressEvent(self, event: object) -> None:  # type: ignore[override]
        if not isinstance(event, QKeyEvent):
            return
        if (
            event.matches(QKeySequence.StandardKey.Copy)
            or event.matches(QKeySequence.StandardKey.SelectAll)
            or event.key() in _NAV_KEYS
        ):
            super().keyPressEvent(event)
        # Drop all other keys (typing, paste, delete, etc.)

    def contextMenuEvent(self, event: object) -> None:  # type: ignore[override]
        if not isinstance(event, QContextMenuEvent):
            return
        menu = QMenu(self)
        menu.addAction("Copy", self.copy)
        menu.addSeparator()
        menu.addAction("Select All", self.selectAll)
        menu.exec(event.globalPos())
