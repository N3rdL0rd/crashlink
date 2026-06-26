"""Locals panel with inline rename support."""

from __future__ import annotations

from typing import List, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

import crashlink.disasm as disasm
from crashlink.core import Bytecode
from crashlink.decomp.function import IRFunction, IRLocal


class LocalsPanel(QWidget):
    rename_requested = Signal(int, int, object, str)  # findex, reg_idx, def_op, new_name

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._findex: Optional[int] = None
        self._locals: List[IRLocal] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header_bar = QFrame()
        header_bar.setObjectName("panelHeaderBar")
        header_bar.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        hbl = QHBoxLayout(header_bar)
        hbl.setContentsMargins(0, 0, 0, 0)
        hbl.setSpacing(0)
        header = QLabel(" LOCALS")
        header.setObjectName("panelHeader")
        header.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        hbl.addWidget(header)
        layout.addWidget(header_bar)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["Reg", "Name", "Type", "Def op"])
        self._table.horizontalHeader().setStretchLastSection(False)
        self._table.horizontalHeader().setMinimumSectionSize(40)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(False)
        layout.addWidget(self._table)

        self._table.itemDoubleClicked.connect(self._on_double_click)

    def load(self, ir: IRFunction, code: Bytecode) -> None:
        self._findex = ir.func.findex.value
        self._locals = list(ir.all_locals)
        self._table.setRowCount(0)

        seen: set[tuple[int, object]] = set()
        for loc in self._locals:
            key = (loc.reg_idx, loc.defining_op_idx)
            if key in seen:
                continue
            seen.add(key)

            row = self._table.rowCount()
            self._table.insertRow(row)

            reg_item = QTableWidgetItem(str(loc.reg_idx) if loc.reg_idx is not None else "—")
            reg_item.setData(Qt.ItemDataRole.UserRole, loc)
            self._table.setItem(row, 0, reg_item)
            self._table.setItem(row, 1, QTableWidgetItem(loc.name))

            type_str = "?"
            try:
                type_str = disasm.type_name(code, loc.get_type())
            except Exception:
                pass
            self._table.setItem(row, 2, QTableWidgetItem(type_str))

            def_op = loc.defining_op_idx
            self._table.setItem(row, 3, QTableWidgetItem(str(def_op) if def_op is not None else "—"))

        self._table.resizeColumnsToContents()

    def clear(self) -> None:
        self._table.setRowCount(0)
        self._findex = None
        self._locals = []

    def _on_double_click(self, item: QTableWidgetItem) -> None:
        if self._findex is None:
            return
        row = item.row()
        loc_item = self._table.item(row, 0)
        if loc_item is None:
            return
        loc: IRLocal = loc_item.data(Qt.ItemDataRole.UserRole)
        current_name = self._table.item(row, 1).text() if self._table.item(row, 1) else loc.name

        new_name, ok = QInputDialog.getText(
            self, "Rename local", f"New name for '{current_name}':", text=current_name
        )
        if ok and new_name and new_name != current_name:
            self.rename_requested.emit(
                self._findex,
                loc.reg_idx if loc.reg_idx is not None else -1,
                loc.defining_op_idx,
                new_name,
            )
