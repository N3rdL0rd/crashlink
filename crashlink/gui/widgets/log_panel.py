"""Log panel — timestamped, coloured output for GUI events."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from PySide6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import QTextEdit, QVBoxLayout, QWidget

from ..themes import Theme


class LogPanel(QWidget):
    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._theme: Optional[Theme] = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._output = QTextEdit()
        self._output.setReadOnly(True)
        self._output.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self._output.document().setMaximumBlockCount(2000)
        font = QFont("JetBrains Mono", 11)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self._output.setFont(font)
        layout.addWidget(self._output)

    def set_theme(self, theme: Theme) -> None:
        self._theme = theme

    # ── Public log methods ────────────────────────────────────────────────────

    def info(self, msg: str) -> None:
        self._append("INFO", msg, self._col("subtext"))

    def success(self, msg: str) -> None:
        self._append("OK  ", msg, self._col("green"))

    def warn(self, msg: str) -> None:
        self._append("WARN", msg, self._col("yellow"))

    def error(self, msg: str) -> None:
        self._append("ERR ", msg, self._col("red"))

    def result(self, msg: str) -> None:
        """Used for xref / rename results — stands out without being an error."""
        self._append(">>  ", msg, self._col("accent"))

    def clear(self) -> None:
        self._output.clear()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _col(self, attr: str) -> str:
        if self._theme:
            return getattr(self._theme, attr, self._theme.text)
        _fallbacks = {
            "subtext": "#a6adc8", "green": "#a6e3a1", "yellow": "#f9e2af",
            "red": "#f38ba8", "accent": "#b4befe", "text": "#cdd6f4",
        }
        return _fallbacks.get(attr, "#cdd6f4")

    def _append(self, level: str, msg: str, color: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        cursor = self._output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        ts_fmt = QTextCharFormat()
        ts_fmt.setForeground(QColor(self._col("overlay") if self._theme else "#6c7086"))

        level_fmt = QTextCharFormat()
        level_fmt.setForeground(QColor(color))
        level_fmt.setFontWeight(QFont.Weight.Bold)

        msg_fmt = QTextCharFormat()
        msg_fmt.setForeground(QColor(self._col("text")))

        cursor.insertText(f"{ts} ", ts_fmt)
        cursor.insertText(f"[{level}]", level_fmt)
        cursor.insertText(f"  {msg}\n", msg_fmt)

        self._output.setTextCursor(cursor)
        self._output.ensureCursorVisible()
