"""Inlined Functions window: bodies the Haxe compiler inlined, found from debug positions
(see `crashlink.inlines`), with how often each was copied and its parameter types. The
lower pane has the selected body's shapes and one disassembled copy of each; Enter / X
lists every copy, grouped by shape, to jump to. Search › Inlined Copies in Function
lists the copies inside the focused function."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, List, Optional, Tuple

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QFont, QGuiApplication
from PySide6.QtWidgets import QMenu, QPlainTextEdit, QSplitter, QVBoxLayout, QWidget

from ...core import Bytecode
from ...inlines import InlinedFunction, InlineFinder, describe, location, signature
from ..widgets.table_view import FilterTable
from ..widgets.xref_panel import XrefGroup, XrefSite

if TYPE_CHECKING:
    from ..main_window import MainWindow

_TAB_KEY = "__inlines__"
#: Shapes listed (and disassembled) in the detail pane; the rest are counted.
_DETAIL_SHAPES = 8
#: Shapes that get their own group in the copies list; the rest share one.
_LISTED_SHAPES = 20

_Analysis = Tuple[InlineFinder, List[InlinedFunction], List[Tuple[Any, ...]]]


def _analyse(code: Bytecode) -> _Analysis:
    finder = InlineFinder(code)
    found = finder.find()
    rows = []
    for fn in found:
        shapes = finder.shapes(fn)
        rows.append(
            (
                location(fn),
                len(fn.sites),
                len({site.findex for site in fn.sites}),
                len(shapes),
                signature(shapes[0]),
                fn.kind,
                fn.real_name or "",
            )
        )
    return finder, found, rows


def _copies(finder: InlineFinder, fn: InlinedFunction) -> List[XrefGroup]:
    """The copies of `fn` as xref groups, one per common shape."""
    code = finder.code
    groups: List[XrefGroup] = []
    rest = XrefGroup(label="other shapes", kind="inline")
    for n, shape in enumerate(finder.shapes(fn)):
        sites = [
            XrefSite(
                source_findex=site.findex,
                source_label=f"f@{site.findex} {code.full_func_name(code.fn(site.findex))}",
                opcode_index=site.start,
                body_line=None,
                ref_kind="inlined copy",
                snippet=f"ops {site.start}-{site.end}",
            )
            for site in shape.sites
        ]
        if n < _LISTED_SHAPES:
            groups.append(XrefGroup(label=f"shape {n + 1} {signature(shape)}", kind="inline", sites=sites))
        else:
            rest.sites.extend(sites)
    if rest.sites:
        groups.append(rest)
    return groups


def _code_pane() -> QPlainTextEdit:
    pane = QPlainTextEdit()
    pane.setReadOnly(True)
    pane.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
    font = QFont("JetBrains Mono", 11)
    font.setStyleHint(QFont.StyleHint.Monospace)
    pane.setFont(font)
    return pane


class InlinesView(QWidget):
    """Table of inlined bodies over a detail pane, for one document."""

    def __init__(self, mw: "MainWindow", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._mw = mw
        self._finder: Optional[InlineFinder] = None
        self._found: List[InlinedFunction] = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.table = FilterTable(
            ["Location", "Copies", "Callers", "Shapes", "Signature", "Kind", "Also exists as"],
            "Filter inlined bodies…",
        )
        self.table.row_activated.connect(self._show_copies)
        self.table.xref_requested.connect(self._show_copies)
        self.table.table.selectionModel().currentRowChanged.connect(lambda *_: self._show_details())
        self.table.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.table.customContextMenuRequested.connect(self._context_menu)
        splitter.addWidget(self.table)
        self._details = _code_pane()
        splitter.addWidget(self._details)
        splitter.setSizes([360, 360])
        layout.addWidget(splitter)
        self.reload()

    @property
    def finder(self) -> Optional[InlineFinder]:
        return self._finder

    def reload(self) -> None:
        code = self._mw.code
        self._finder, self._found = None, []
        self._details.clear()
        if code is None:
            self.table.set_rows([])
            return
        if not code.has_debug_info:
            self.table.set_rows([])
            self.table.set_placeholder_message("no debug info")
            return
        self.table.set_placeholder_message("analysing…")
        self._mw.run_background("Finding inlined bodies…", lambda: _analyse(code), self._on_analysed)

    def _on_analysed(self, result: _Analysis) -> None:
        self._finder, self._found, rows = result
        self.table.set_rows(rows, column_widths=(260, 70, 70, 70, 320, 70))
        if not rows:
            self._details.setPlainText(
                "No inlined bodies found. They show up only in builds made with -D keep-inline-positions: "
                "otherwise the compiler gives inlined code the call site's position."
            )

    def _selected(self, row: Optional[int] = None) -> Optional[InlinedFunction]:
        row = self.table.current_row() if row is None else row
        if row is None or not 0 <= row < len(self._found):
            return None
        return self._found[row]

    def _show_details(self) -> None:
        fn = self._selected()
        if fn is None or self._finder is None:
            return
        self._details.setPlainText(describe(self._finder, fn, shapes=_DETAIL_SHAPES, annotate=True))

    def _show_copies(self, row: int) -> None:
        fn = self._selected(row)
        if fn is None or self._finder is None:
            return
        self._mw.show_xrefs(f"inlined {location(fn)}", _copies(self._finder, fn))

    def _go_to_first_copy(self, row: int) -> None:
        fn = self._selected(row)
        if fn is not None and fn.sites:
            self._mw.navigate_to(fn.sites[0].findex, fn.sites[0].start)

    def _context_menu(self, pos: Any) -> None:
        row = self.table.current_row()
        fn = self._selected(row)
        if row is None or fn is None:
            return
        menu = QMenu(self)
        menu.addAction("Copies\tX", lambda: self._show_copies(row))
        menu.addAction("Go to first copy", lambda: self._go_to_first_copy(row))
        menu.addSeparator()
        menu.addAction("Copy location", lambda: QGuiApplication.clipboard().setText(location(fn)))
        menu.addAction(
            "Copy details", lambda: QGuiApplication.clipboard().setText(self._details.toPlainText())
        )
        menu.exec_(self.table.table.viewport().mapToGlobal(pos))


def open_inlines(mw: "MainWindow") -> Optional[InlinesView]:
    if mw.code is None:
        mw.statusBar().showMessage("Open a file first", 3000)
        return None
    view = mw.open_tab(_TAB_KEY, "Inlined Functions", lambda: InlinesView(mw))
    return view if isinstance(view, InlinesView) else None


class _FocusTracker:
    """Remembers the last focused function for the per-function action."""

    def __init__(self, mw: "MainWindow") -> None:
        self.findex: Optional[int] = None
        mw.function_focused.connect(self._on_focus)
        mw.code_loaded.connect(self._on_code_loaded)

    def _on_focus(self, findex: int) -> None:
        self.findex = findex

    def _on_code_loaded(self, _code: object) -> None:
        self.findex = None


def _show_copies_in_function(mw: "MainWindow", tracker: _FocusTracker) -> None:
    code = mw.code
    if code is None or tracker.findex is None:
        mw.statusBar().showMessage("Focus a function first", 3000)
        return
    findex = tracker.findex
    view = open_inlines(mw)
    if view is None:
        return

    def show(finder: InlineFinder) -> None:
        sites = [
            XrefSite(
                source_findex=findex,
                source_label=location(fn),
                opcode_index=site.start,
                body_line=None,
                ref_kind="inlined copy",
                snippet=f"{location(fn)}  ops {site.start}-{site.end}  {signature(shape)}",
            )
            for fn in finder.find()
            for shape in finder.shapes(fn)
            for site in shape.sites
            if site.findex == findex
        ]
        sites.sort(key=lambda s: s.opcode_index or 0)
        label = f"inlined copies in f@{findex} {code.full_func_name(code.fn(findex))}"
        mw.show_xrefs(label, [XrefGroup(label=label, kind="inline", sites=sites)])

    if view.finder is not None:
        show(view.finder)
    else:
        mw.run_background("Finding inlined bodies…", lambda: _analyse(code)[0], show)


def install(mw: "MainWindow") -> None:
    tracker = _FocusTracker(mw)
    action = QAction("Inlined Functions", mw)
    action.triggered.connect(lambda: open_inlines(mw))
    mw.menu("Window").addAction(action)
    mw.menu("Search").addAction("Inlined Functions…", lambda: open_inlines(mw))
    mw.menu("Search").addAction("Inlined Copies in Function", lambda: _show_copies_in_function(mw, tracker))
