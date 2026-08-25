"""Types table: every type in the bytecode (Obj/Enum/Virtual/Abstract/Ref/Null/Packed/Fun),
with a detail pane showing its layout — fields, methods, enum constructs, vtable slots."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QLineEdit,
    QPlainTextEdit,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...core import Bytecode
from ...disasm import describe_type, type_summary
from ..themes import Theme

_COLUMNS = ["Index", "Kind", "Description"]


class _NumericItem(QTableWidgetItem):
    def __init__(self, value: int) -> None:
        super().__init__(str(value))
        self._value = value

    def __lt__(self, other: "QTableWidgetItem") -> bool:
        if isinstance(other, _NumericItem):
            return self._value < other._value
        return super().__lt__(other)


class TypesView(QWidget):
    """Sortable table of every type, with a detail pane for the selected one."""

    xref_requested = Signal(str)  # e.g. "t@12"

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._code: Optional[Bytecode] = None
        self._theme: Optional[Theme] = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter types…")
        self._search.setClearButtonEnabled(True)
        self._search.textChanged.connect(self._apply_filter)
        layout.addWidget(self._search)

        splitter = QSplitter(Qt.Orientation.Vertical)

        self._table = QTableWidget()
        self._table.setColumnCount(len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.verticalHeader().setVisible(False)
        self._table.setSortingEnabled(True)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        splitter.addWidget(self._table)

        self._detail = QPlainTextEdit()
        self._detail.setReadOnly(True)
        font = self._detail.font()
        font.setFamily("monospace")
        self._detail.setFont(font)
        splitter.addWidget(self._detail)
        splitter.setSizes([300, 300])

        layout.addWidget(splitter)

    def set_theme(self, theme: Theme) -> None:
        self._theme = theme

    def load(self, code: Bytecode) -> None:
        self._code = code
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(code.types))
        for index, typ in enumerate(code.types):
            kind = typ.definition.__class__.__name__
            try:
                summary = type_summary(code, index)
            except Exception:
                summary = ""

            self._table.setItem(index, 0, _NumericItem(index))
            self._table.setItem(index, 1, QTableWidgetItem(kind))
            self._table.setItem(index, 2, QTableWidgetItem(summary))

        self._table.setSortingEnabled(True)
        self._table.resizeColumnsToContents()
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)

    def _apply_filter(self, query: str) -> None:
        query = query.lower()
        for row in range(self._table.rowCount()):
            if not query:
                self._table.setRowHidden(row, False)
                continue
            cells = (self._table.item(row, col) for col in range(self._table.columnCount()))
            hay = " ".join(cell.text().lower() for cell in cells if cell is not None)
            self._table.setRowHidden(row, query not in hay)

    def _on_selection_changed(self) -> None:
        if self._code is None:
            return
        item = self._table.currentItem()
        if item is None:
            return
        index_item = self._table.item(item.row(), 0)
        if index_item is None:
            return
        index = index_item.data(Qt.ItemDataRole.DisplayRole)
        try:
            text = describe_type(self._code, int(index))
        except Exception as e:
            text = f"(error rendering t@{index}: {e})"
        self._detail.setPlainText(text)

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if not event.modifiers() and event.key() == Qt.Key.Key_X:
            item = self._table.currentItem()
            if item is not None:
                index_item = self._table.item(item.row(), 0)
                if index_item is not None:
                    self.xref_requested.emit(f"t@{index_item.data(Qt.ItemDataRole.DisplayRole)}")
                    return
        super().keyPressEvent(event)  # type: ignore[arg-type]
