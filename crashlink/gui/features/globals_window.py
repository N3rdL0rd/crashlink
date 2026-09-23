"""Globals window: every global with its type, constant initializer and xref count.
Double-clicking a `g@N` in the code panes opens it here."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, List, Optional, Tuple

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QMenu, QVBoxLayout, QWidget

from ... import disasm
from ...core import Bytecode
from ..widgets.table_view import FilterTable
from ..widgets.xref_panel import resolve_targets

if TYPE_CHECKING:
    from ..main_window import MainWindow

_TAB_KEY = "__globals__"


def _initial_value(code: Bytecode, gindex: int) -> str:
    try:
        return repr(code.const_str(gindex))
    except (ValueError, TypeError, KeyError):
        pass
    init = code.initialized_globals.get(gindex)
    if init is None:
        return ""
    text = repr(init)
    return text if len(text) <= 300 else text[:299] + "…"


def _global_rows(code: Bytecode) -> List[Tuple[Any, ...]]:
    xi = code.xref_index()
    rows: List[Tuple[Any, ...]] = []
    for gindex, tref in enumerate(code.global_types):
        try:
            type_label = disasm.type_name(code, tref.resolve(code))
        except Exception:
            type_label = "?"
        refs = len(xi.global_reads(gindex)) + len(xi.global_writes(gindex))
        rows.append((gindex, type_label, refs, _initial_value(code, gindex)))
    return rows


class GlobalsView(QWidget):
    def __init__(self, mw: "MainWindow", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._mw = mw
        self._pending_select: Optional[int] = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.table = FilterTable(["Index", "Type", "Xrefs", "Initial value"], "Filter globals…")
        self.table.row_activated.connect(self._show_xrefs)
        self.table.xref_requested.connect(self._show_xrefs)
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
        self._mw.run_background("Indexing globals…", lambda: _global_rows(code), self._loaded)

    def _loaded(self, rows: List[Tuple[Any, ...]]) -> None:
        self.table.set_rows(rows, column_widths=(80, 320, 60))
        if self._pending_select is not None:
            self.select(self._pending_select)

    def select(self, gindex: int) -> None:
        """Select `gindex` (after loading, if the rows aren't in yet)."""
        if self.table.model.rowCount() == 0:
            self._pending_select = gindex
            return
        self._pending_select = None
        if 0 <= gindex < self.table.model.rowCount():
            self.table.select_row(gindex)

    def _show_xrefs(self, row: int) -> None:
        code = self._mw.code
        if code is None:
            return
        gindex = self.table.model.row_values(row)[0]
        self._mw.show_xrefs(f"g@{gindex}", resolve_targets(code, f"g@{gindex}"))

    def _context_menu(self, pos: Any) -> None:
        row = self.table.current_row()
        if row is None:
            return
        gindex, type_label, _, value = self.table.model.row_values(row)
        menu = QMenu(self)
        menu.addAction("Cross-references\tX", lambda: self._show_xrefs(row))
        menu.addSeparator()
        menu.addAction("Copy index", lambda: QGuiApplication.clipboard().setText(f"g@{gindex}"))
        menu.addAction("Copy type", lambda: QGuiApplication.clipboard().setText(type_label))
        if value:
            menu.addAction("Copy value", lambda: QGuiApplication.clipboard().setText(value))
        menu.exec_(self.table.table.viewport().mapToGlobal(pos))


def open_globals(mw: "MainWindow", select: Optional[int] = None) -> None:
    if mw.code is None:
        mw.statusBar().showMessage("Open a file first", 3000)
        return
    view = mw.open_tab(_TAB_KEY, "Globals", lambda: GlobalsView(mw))
    if select is not None and isinstance(view, GlobalsView):
        view.select(select)


def install(mw: "MainWindow") -> None:
    mw.menu("Window").addAction("Globals", lambda: open_globals(mw))
    mw.add_follow_handler("g@", lambda gindex: open_globals(mw, select=gindex))
