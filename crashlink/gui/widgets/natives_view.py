"""Natives table: every native function in the bytecode, sortable by column."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ... import disasm
from ...core import Bytecode, Fun
from ..themes import Theme

_COLUMNS = ["Index", "Library", "Name", "Signature", "Std"]


class _NumericItem(QTableWidgetItem):
    """Sorts by an int value instead of the displayed string."""

    def __init__(self, value: int) -> None:
        super().__init__(str(value))
        self._value = value

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, _NumericItem):
            return self._value < other._value
        return super().__lt__(other)


class NativesView(QWidget):
    """Sortable table of every native, with 'X' or double-click to see its xrefs."""

    xref_requested = Signal(int)  # native findex

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._theme: Optional[Theme] = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter natives…")
        self._search.setClearButtonEnabled(True)
        self._search.textChanged.connect(self._apply_filter)
        layout.addWidget(self._search)

        self._table = QTableWidget()
        self._table.setColumnCount(len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.verticalHeader().setVisible(False)
        self._table.setSortingEnabled(True)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._table.itemActivated.connect(self._on_activated)
        layout.addWidget(self._table)

    def set_theme(self, theme: Theme) -> None:
        self._theme = theme

    def load(self, code: Bytecode) -> None:
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(code.natives))
        for row, native in enumerate(code.natives):
            findex = native.findex.value
            lib = native.lib.resolve(code)
            name = native.name.resolve(code)
            fun_defn = native.type.resolve(code).definition
            if isinstance(fun_defn, Fun):
                args = ", ".join(disasm.type_name(code, a.resolve(code)) for a in fun_defn.args)
                ret = disasm.type_name(code, fun_defn.ret.resolve(code))
                sig = f"({args}) -> {ret}"
            else:
                sig = "(no signature found)"
            is_std = disasm.is_std(code, native)

            self._table.setItem(row, 0, _NumericItem(findex))
            self._table.setItem(row, 1, QTableWidgetItem(lib))
            self._table.setItem(row, 2, QTableWidgetItem(name))
            self._table.setItem(row, 3, QTableWidgetItem(sig))
            self._table.setItem(row, 4, QTableWidgetItem("yes" if is_std else ""))
            self._table.item(row, 0).setData(Qt.ItemDataRole.UserRole, findex)

        self._table.setSortingEnabled(True)
        self._table.resizeColumnsToContents()
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)

    def _apply_filter(self, query: str) -> None:
        query = query.lower()
        for row in range(self._table.rowCount()):
            if not query:
                self._table.setRowHidden(row, False)
                continue
            hay = " ".join(
                self._table.item(row, col).text().lower()
                for col in range(self._table.columnCount())
                if self._table.item(row, col) is not None
            )
            self._table.setRowHidden(row, query not in hay)

    def _on_activated(self, item: QTableWidgetItem) -> None:
        findex_item = self._table.item(item.row(), 0)
        if findex_item is None:
            return
        findex = findex_item.data(Qt.ItemDataRole.UserRole)
        if findex is not None:
            self.xref_requested.emit(findex)

    def keyPressEvent(self, event: object) -> None:  # type: ignore[override]
        if isinstance(event, QKeyEvent) and not event.modifiers() and event.key() == Qt.Key.Key_X:
            item = self._table.currentItem()
            if item is not None:
                self._on_activated(item)
                return
        super().keyPressEvent(event)  # type: ignore[arg-type]
