"""Strings window (IDA's Shift+F12): every string constant with its xref count;
X / double-click lists references, F2 edits (undoable)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, List, Optional, Tuple

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QGuiApplication, QKeySequence
from PySide6.QtWidgets import QInputDialog, QMenu, QVBoxLayout, QWidget

from ...core import Bytecode
from ..widgets.table_view import FilterTable
from ..widgets.xref_panel import XrefGroup, site_from_ref

if TYPE_CHECKING:
    from ..main_window import MainWindow

_TAB_KEY = "__strings__"
_MAX_DISPLAY = 400


def _display(value: str) -> str:
    """One-line, escaped rendering of a string constant."""
    text = value.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return text if len(text) <= _MAX_DISPLAY else text[: _MAX_DISPLAY - 1] + "…"


def _string_rows(code: Bytecode) -> List[Tuple[Any, ...]]:
    xi = code.xref_index()
    return [(i, len(s), len(xi.string_uses(i)), _display(s)) for i, s in enumerate(code.strings.value)]


class StringsView(QWidget):
    """Filterable table of string constants for one document."""

    def __init__(self, mw: "MainWindow", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._mw = mw
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.table = FilterTable(
            ["Index", "Length", "Xrefs", "Value"],
            "Filter strings…",
        )
        self.table.row_activated.connect(self._show_xrefs)
        self.table.xref_requested.connect(self._show_xrefs)
        self.table.edit_requested.connect(self._edit)
        self.table.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.table.customContextMenuRequested.connect(self._context_menu)
        layout.addWidget(self.table)
        self.reload()

    def reload(self) -> None:
        code = self._mw.code
        if code is None:
            self.table.set_rows([])
            return
        self.table.set_placeholder_message("loading…")
        self._mw.run_background(
            "Indexing strings…",
            lambda: _string_rows(code),
            lambda rows: self.table.set_rows(rows, column_widths=(80, 70, 60)),
        )

    def _show_xrefs(self, row: int) -> None:
        code = self._mw.code
        if code is None:
            return
        index, _, _, display = self.table.model.row_values(row)
        refs = code.xref_index().string_uses(index)
        group = XrefGroup(
            label=f'string #{index} "{display[:60]}"',
            kind="string",
            sites=[site_from_ref(code, r) for r in refs],
        )
        self._mw.show_xrefs(f"string #{index}", [group])

    def _edit(self, row: int) -> None:
        code = self._mw.code
        if code is None:
            return
        index = self.table.model.row_values(row)[0]
        current = code.strings.value[index]
        value, ok = QInputDialog.getMultiLineText(self, "Edit string", f"String #{index}:", current)
        if not ok or value == current:
            return
        self._mw.apply_setstring(index, value)
        self.table.model.update_row(
            row, (index, len(value), len(code.xref_index().string_uses(index)), _display(value))
        )
        self._mw.log.success(f"String #{index} updated (Edit > Undo reverts it)")

    def _context_menu(self, pos: Any) -> None:
        row = self.table.current_row()
        if row is None:
            return
        index, _, _, _ = self.table.model.row_values(row)
        code = self._mw.code
        value = code.strings.value[index] if code is not None else ""
        menu = QMenu(self)
        menu.addAction("Cross-references\tX", lambda: self._show_xrefs(row))
        menu.addAction("Edit string…\tF2", lambda: self._edit(row))
        menu.addSeparator()
        menu.addAction("Copy value", lambda: QGuiApplication.clipboard().setText(value))
        menu.addAction("Copy index", lambda: QGuiApplication.clipboard().setText(str(index)))
        menu.exec_(self.table.table.viewport().mapToGlobal(pos))


def open_strings(mw: "MainWindow") -> None:
    if mw.code is None:
        mw.statusBar().showMessage("Open a file first", 3000)
        return
    mw.open_tab(_TAB_KEY, "Strings", lambda: StringsView(mw))


def install(mw: "MainWindow") -> None:
    action = QAction("Strings", mw)
    action.setShortcut(QKeySequence("Shift+F12"))
    action.triggered.connect(lambda: open_strings(mw))
    mw.menu("Window").addAction(action)
    mw.menu("Search").addAction("Strings…", lambda: open_strings(mw))
