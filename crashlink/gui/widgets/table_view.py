"""A filterable, sortable, model-backed table for large lists (strings, globals, …).

QTableWidget creates an item object per cell, which is slow for tens of thousands
of rows; this uses a plain-tuple model behind a sort/filter proxy instead."""

from __future__ import annotations

import re
from typing import Any, List, Optional, Sequence, Tuple

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QPersistentModelIndex,
    QRegularExpression,
    QSortFilterProxyModel,
    Qt,
    Signal,
)
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QTableView,
    QVBoxLayout,
    QWidget,
)

_Index = QModelIndex | QPersistentModelIndex


class RowsModel(QAbstractTableModel):
    """Rows of plain Python values; numbers sort numerically."""

    def __init__(self, headers: Sequence[str]) -> None:
        super().__init__()
        self._headers = list(headers)
        self._rows: List[Tuple[Any, ...]] = []

    def set_rows(self, rows: List[Tuple[Any, ...]]) -> None:
        self.beginResetModel()
        self._rows = rows
        self.endResetModel()

    def row_values(self, row: int) -> Tuple[Any, ...]:
        return self._rows[row]

    def update_row(self, row: int, values: Tuple[Any, ...]) -> None:
        self._rows[row] = values
        self.dataChanged.emit(self.index(row, 0), self.index(row, len(self._headers) - 1))

    def rowCount(self, parent: _Index = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: _Index = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._headers)

    def data(self, index: _Index, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        value = self._rows[index.row()][index.column()]
        if role == Qt.ItemDataRole.DisplayRole:
            return "" if value is None else str(value)
        if role == Qt.ItemDataRole.ToolTipRole and isinstance(value, str) and len(value) > 60:
            return value[:2000]
        if role == Qt.ItemDataRole.UserRole:
            return value
        if role == Qt.ItemDataRole.TextAlignmentRole and isinstance(value, int):
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return None

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self._headers[section]
        return None


class _TableView(QTableView):
    """Lets the owner consume keys first: a handler that calls `event.ignore()`
    stops the default table handling."""

    key_pressed = Signal(object)

    def keyPressEvent(self, event: QKeyEvent) -> None:
        self.key_pressed.emit(event)
        if not event.isAccepted():
            return
        super().keyPressEvent(event)


class FilterTable(QWidget):
    """Filter box (substring or regex) over a sortable table of `RowsModel` rows."""

    #: Source-model row activated (double-click / Enter).
    row_activated = Signal(int)
    #: X on a row: show its cross-references.
    xref_requested = Signal(int)
    #: F2 on a row: edit it (where the owner supports editing).
    edit_requested = Signal(int)

    def __init__(self, headers: Sequence[str], placeholder: str, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 8, 0)
        row.setSpacing(10)
        self._filter = QLineEdit()
        self._filter.setPlaceholderText(placeholder)
        self._filter.setClearButtonEnabled(True)
        self._filter.textChanged.connect(self._apply_filter)
        row.addWidget(self._filter, 1)
        self._regex = QCheckBox("regex")
        self._regex.toggled.connect(lambda _: self._apply_filter(self._filter.text()))
        row.addWidget(self._regex)
        self._count = QLabel("")
        self._count.setObjectName("findCount")
        row.addWidget(self._count)
        layout.addLayout(row)

        self.model = RowsModel(headers)
        self.proxy = QSortFilterProxyModel()
        # Sort on the raw values (UserRole): ints compare numerically, in C++.
        self.proxy.setSortRole(Qt.ItemDataRole.UserRole)
        self.proxy.setSourceModel(self.model)
        self.proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.proxy.setFilterKeyColumn(-1)
        self.table = _TableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(self.fontMetrics().height() + 8)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.doubleClicked.connect(lambda idx: self._emit_row(idx))
        self.table.key_pressed.connect(self._on_key)
        layout.addWidget(self.table, 1)
        self.proxy.rowsInserted.connect(self._update_count)
        self.proxy.rowsRemoved.connect(self._update_count)
        self.proxy.modelReset.connect(self._update_count)
        self.proxy.layoutChanged.connect(self._update_count)

    def set_rows(self, rows: List[Tuple[Any, ...]], column_widths: Sequence[int] = ()) -> None:
        """Show `rows` in the order given (callers pass them by index); sorting starts
        when a header is clicked. Pre-sorting through the proxy would call back into Python
        `data()` O(n log n) times, about a second for 20k strings."""
        self.table.setSortingEnabled(False)
        self.proxy.sort(-1)
        self.model.set_rows(rows)
        for col, width in enumerate(column_widths):
            self.table.setColumnWidth(col, width)
        self.table.horizontalHeader().setSectionResizeMode(len(column_widths), QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSortIndicator(-1, Qt.SortOrder.AscendingOrder)
        self.table.setSortingEnabled(True)
        self._update_count()

    def current_row(self) -> Optional[int]:
        idx = self.table.currentIndex()
        if not idx.isValid():
            return None
        return self.proxy.mapToSource(idx).row()

    def select_row(self, source_row: int) -> None:
        """Select (and scroll to) a source-model row, clearing a filter that hides it."""
        idx = self.proxy.mapFromSource(self.model.index(source_row, 0))
        if not idx.isValid():
            self._filter.clear()
            idx = self.proxy.mapFromSource(self.model.index(source_row, 0))
        self.table.setCurrentIndex(idx)
        self.table.scrollTo(idx, QAbstractItemView.ScrollHint.PositionAtCenter)
        self.table.setFocus()

    def set_placeholder_message(self, text: str) -> None:
        self._count.setText(text)

    def _emit_row(self, proxy_index: QModelIndex) -> None:
        if proxy_index.isValid():
            self.row_activated.emit(self.proxy.mapToSource(proxy_index).row())

    def _on_key(self, event: QKeyEvent) -> None:
        """Handles Enter / X / F2 on the current row; `event.ignore()` marks it consumed."""
        row = self.current_row()
        if row is None or event.modifiers() not in (
            Qt.KeyboardModifier.NoModifier,
            Qt.KeyboardModifier.KeypadModifier,
        ):
            return
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self.row_activated.emit(row)
        elif event.key() == Qt.Key.Key_X:
            self.xref_requested.emit(row)
        elif event.key() == Qt.Key.Key_F2:
            self.edit_requested.emit(row)
        else:
            return
        event.ignore()

    def _apply_filter(self, text: str) -> None:
        if self._regex.isChecked():
            try:
                re.compile(text)
            except re.error:
                self._count.setText("invalid regex")
                return
            self.proxy.setFilterRegularExpression(
                QRegularExpression(text, QRegularExpression.PatternOption.CaseInsensitiveOption)
            )
        else:
            self.proxy.setFilterFixedString(text)
        self._update_count()

    def _update_count(self, *_: object) -> None:
        shown, total = self.proxy.rowCount(), self.model.rowCount()
        if total and not shown:
            self._count.setText(f"No matches (of {total:,})")
        else:
            self._count.setText(f"{shown:,} of {total:,}" if shown != total else f"{total:,} rows")
        self._count.setProperty("empty", bool(total) and not shown)
        self._count.style().unpolish(self._count)
        self._count.style().polish(self._count)
