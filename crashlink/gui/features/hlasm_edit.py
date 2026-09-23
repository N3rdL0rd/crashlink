"""Edit > Edit Function as .hlasm: rewrite the focused function's opcodes as text.

The edited text is assembled against the loaded image (crashlink.asm.edit_function),
validated, and swapped in through the undo stack, so it can be undone like any edit."""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable, Dict, List, Optional

from PySide6.QtCore import QObject, Qt
from PySide6.QtGui import QFont, QKeySequence, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QVBoxLayout,
)

from ...asm import AsmError, edit_function, function_to_hlasm
from ...core import Function
from ..themes import Theme
from ..widgets.disasm_view import DisasmHighlighter, _Rule

if TYPE_CHECKING:
    from ..main_window import MainWindow


_HLASM_RULES: List[_Rule] = [
    _Rule(r'x?"(?:[^"\\]|\\.)*"', "string"),
    _Rule(r"(?<![\w@.])-?\d+(?:\.\d+)?(?:e[+-]?\d+)?\b", "number"),
    _Rule(r"\b0x[0-9a-fA-F]+\b", "number"),
    _Rule(r"^\s*([A-Z]\w*)", "opcode", group=1),
    _Rule(r"\b(true|false)\b|->", "keyword"),
    _Rule(r"^\s*\.\w+", "keyword"),
    _Rule(r"\breg\d+\b", "reg"),
    _Rule(r"\bf@-?\d+\b", "ref_fun"),
    _Rule(r"\bg@-?\d+\b", "ref_global"),
    _Rule(r"\b[tsidb]@-?\d+\b", "ref_type"),
    _Rule(r"^\s*\.label\s+(\S+)", "func_name", group=1),
    _Rule(r"@(?:-?\d+|\"(?:[^\"\\]|\\.)*\"):-?\d+", "comment"),  # debug position
    _Rule(r'^(?:"(?:[^"\\]|\\.)*"|[^"#])*(#.*)$', "comment", group=1),
]


class HlasmHighlighter(DisasmHighlighter):
    RULES = _HLASM_RULES

    def _formats(self, fmt: Callable[..., QTextCharFormat], theme: Theme) -> Dict[str, QTextCharFormat]:
        formats = super()._formats(fmt, theme)
        formats["keyword"] = fmt(theme.red, bold=True)
        return formats


class HlasmEditDialog(QDialog):
    """Shows one function as .hlasm; Apply assembles it and pushes the change onto the
    undo stack. Errors are shown in place, with the offending line selected."""

    def __init__(self, mw: "MainWindow", func: Function) -> None:
        super().__init__(mw)
        code = mw.code
        assert code is not None
        self._mw = mw
        self._findex = func.findex.value
        try:
            name = code.full_func_name(func)
        except Exception:
            name = "<none>"
        suffix = f" ({name})" if name != "<none>" else ""
        self.setWindowTitle(f"Edit f@{self._findex}{suffix} as .hlasm")
        self.resize(960, 720)

        self.editor = QPlainTextEdit()
        font = QFont("JetBrains Mono", 12)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.editor.setFont(font)
        self.editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.editor.setTabStopDistance(4 * self.editor.fontMetrics().horizontalAdvance(" "))
        self.editor.setPlainText(function_to_hlasm(code, func))
        self._highlighter = HlasmHighlighter(self.editor.document(), mw.theme)

        self.error = QLabel()
        self.error.setWordWrap(True)
        self.error.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.error.setStyleSheet(f"color: {mw.theme.red};")
        self.error.hide()

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Apply | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Apply).clicked.connect(self.apply)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(self.editor, 1)
        layout.addWidget(self.error)
        layout.addWidget(buttons)
        mw.theme_changed.connect(self._on_theme)

    def _on_theme(self, theme: Theme) -> None:
        self._highlighter.apply_theme(theme)
        self.error.setStyleSheet(f"color: {theme.red};")

    def apply(self) -> bool:
        """Assemble and apply the text. Returns False (and shows why) if it is invalid."""
        code = self._mw.code
        if code is None:
            self.reject()
            return False
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            edit = edit_function(code, self.editor.toPlainText(), findex=self._findex)
        except AsmError as e:
            self._show_error(str(e), e.line)
            return False
        finally:
            QApplication.restoreOverrideCursor()
        self._mw.apply_function_edit(edit)
        self._mw.log.success(f"Edited f@{self._findex}")
        self.accept()
        return True

    def _show_error(self, message: str, line: int) -> None:
        self.error.setText(message)
        self.error.show()
        if line > 0:
            block = self.editor.document().findBlockByNumber(line - 1)
            if block.isValid():
                cursor = QTextCursor(block)
                cursor.movePosition(QTextCursor.MoveOperation.EndOfBlock, QTextCursor.MoveMode.KeepAnchor)
                self.editor.setTextCursor(cursor)
                self.editor.centerCursor()
        self.editor.setFocus()


class _FunctionEditor(QObject):
    """Tracks the focused function for the menu action (parented to the window, which
    keeps it alive)."""

    def __init__(self, mw: "MainWindow") -> None:
        super().__init__(mw)
        self.mw = mw
        self.findex: Optional[int] = None
        mw.function_focused.connect(self._on_focus)
        mw.code_loaded.connect(lambda _code: self._on_focus(None))

    def _on_focus(self, findex: Optional[int]) -> None:
        self.findex = findex

    def open(self) -> None:
        code = self.mw.code
        if code is None:
            self.mw.statusBar().showMessage("Open a file first", 3000)
            return
        if code.inspection_only:
            QMessageBox.information(
                self.mw, "Not available", "Inspection-only native images have no bytecode to edit."
            )
            return
        func = code.get_findex_map().get(self.findex) if self.findex is not None else None
        if not isinstance(func, Function):
            self.mw.statusBar().showMessage("Put the cursor in a function (not a native) first", 3000)
            return
        dialog = HlasmEditDialog(self.mw, func)
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        dialog.open()


def install(mw: "MainWindow") -> None:
    editor = _FunctionEditor(mw)
    menu = mw.menu("Edit")
    menu.addSeparator()
    action = menu.addAction("Edit Function as .hlasm…", editor.open)
    action.setShortcut(QKeySequence("Ctrl+E"))
