"""Main application window."""

from __future__ import annotations

import os
import re
from typing import Dict, List, Optional, Tuple

from PySide6.QtCore import QRect, QRunnable, QThread, QThreadPool, QTimer, Qt, Signal, QObject, QSize
from PySide6.QtGui import QColor, QCursor, QKeyEvent, QPainter, QPalette
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QDockWidget,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QStatusBar,
    QTabBar,
    QTabWidget,
    QToolButton,
    QWidget,
)

from crashlink.core import AnalysisWorker, Bytecode, Native, destaticify
from crashlink.database import DatabaseLoadResult, SessionState, load_database, save_database
from crashlink.decomp.function import IRFunction
from crashlink.globals import set_dbg_callback
from crashlink.pseudo import pseudo_oplines, _method_registry

from .themes import DEFAULT_THEME, THEMES, Theme, generate_qss
from .widgets.cfg_view import CfgView
from .widgets.class_view import ClassView
from .widgets.function_list import FunctionList
from .widgets.log_panel import LogPanel
from .widgets.sync_view import DISASM, PSEUDO, SPLIT, SyncView
from .widgets.xref_panel import XrefPopup, resolve_targets, XrefGroup, XrefSite, _func_label


# View mode cycling: Tab steps through split → disassembly → decompiled → …
_VIEW_MODE_CYCLE = [SPLIT, DISASM, PSEUDO]
_VIEW_MODE_NAMES = {SPLIT: "Split", DISASM: "Disassembly", PSEUDO: "Decompiled"}
_VIEW_MODE_GLYPHS = {SPLIT: "◧", DISASM: "⚙", PSEUDO: "{ }"}


# ── Async helpers ─────────────────────────────────────────────────────────────


class _LoadSignals(QObject):
    progress = Signal(float, str)
    finished = Signal(object)
    error = Signal(str)


class _LoadThread(QThread):
    def __init__(self, path: str) -> None:
        super().__init__()
        self.path = path
        self.signals = _LoadSignals()

    def run(self) -> None:
        try:

            def _cb(frac: float, status: str) -> None:
                self.signals.progress.emit(frac, status)

            code = Bytecode.from_path(self.path, progress_cb=_cb)
            self.signals.finished.emit(code)
        except Exception as e:
            self.signals.error.emit(str(e))


class _DbLoadSignals(QObject):
    finished = Signal(object)  # DatabaseLoadResult
    error = Signal(str)


class _DbLoadThread(QThread):
    """Loads and validates a .cldb off the UI thread — hashing the source file to
    check against SRCI can take a moment for larger bytecode."""

    def __init__(self, cldb_path: str, code: Bytecode, source_path: str) -> None:
        super().__init__()
        self.cldb_path = cldb_path
        self.code = code
        self.source_path = source_path
        self.signals = _DbLoadSignals()

    def run(self) -> None:
        try:
            result = load_database(self.cldb_path, code=self.code, source_path=self.source_path)
            self.signals.finished.emit(result)
        except Exception as e:
            self.signals.error.emit(str(e))


class _DecompSignals(QObject):
    finished = Signal(str, int, object)  # class_key, findex, IRFunction
    error = Signal(str, int, str)  # class_key, findex, message


class _DecompRunnable(QRunnable):
    def __init__(self, worker: AnalysisWorker, code: Bytecode, class_key: str, findex: int) -> None:
        super().__init__()
        self._worker = worker
        self._code = code
        self._class_key = class_key
        self._findex = findex
        self.signals = _DecompSignals()

    def run(self) -> None:
        try:
            ir = self._worker.decompile(self._code, self._findex).result()
            self.signals.finished.emit(self._class_key, self._findex, ir)
        except Exception as e:
            self.signals.error.emit(self._class_key, self._findex, str(e))


# ── Main window ───────────────────────────────────────────────────────────────


class _TabBar(QTabBar):
    """QTabBar that paints the empty area to the right of the last tab.

    Qt's style engine repaints the tab bar background (including the empty
    area) after our pre-fill, overriding it.  Painting only the uncovered
    region AFTER super() wins the z-order race.
    """

    _fill: QColor = QColor("#181825")

    def paintEvent(self, event: object) -> None:  # type: ignore[override]
        super().paintEvent(event)  # type: ignore[arg-type]
        # Find where the last tab ends; fill everything to the right.
        empty_x = 0
        for i in range(self.count()):
            empty_x = max(empty_x, self.tabRect(i).right() + 1)
        if empty_x < self.width():
            p = QPainter(self)
            p.fillRect(QRect(empty_x, 0, self.width() - empty_x, self.height()), self._fill)
            p.end()


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("crashlink")
        self.resize(1400, 900)

        self._code: Optional[Bytecode] = None
        self._worker = AnalysisWorker(max_workers=4)
        self._load_thread: Optional[_LoadThread] = None
        self._theme: Theme = DEFAULT_THEME

        # class_key → tab index; rebuilt on every add/remove
        self._open_tabs: Dict[str, int] = {}
        # class_key → ordered list of findices (display order)
        self._class_findices: Dict[str, List[int]] = {}
        # class_key → {findex: pseudo_text or None(pending)}
        self._class_results: Dict[str, Dict[int, Optional[str]]] = {}
        # class_key → canonical class display name
        self._class_names: Dict[str, str] = {}
        # findex → IRFunction
        self._ir_cache: Dict[int, object] = {}
        # findex → {opcode_index: body-relative pseudocode line}
        self._opline_cache: Dict[int, Dict[int, int]] = {}
        # deferred navigation when the target's op map isn't cached yet
        self._pending_op_scroll: Optional[Tuple[int, int]] = None
        # global view mode (split/disasm/decompiled), applied to every open tab
        self._view_mode: int = PSEUDO
        # findex currently shown in the CFG dock, so decompile-finished can refresh it
        self._cfg_findex: Optional[int] = None
        # path of the currently-open bytecode file, for the sibling .cldb and Save Database
        self._source_path: Optional[str] = None
        # findex → (pseudo_text, opline_map) loaded from a .cldb, consumed by _open_class_tab
        # to skip the "decompiling…" flash; a real decompile still runs to warm _ir_cache
        self._db_cache: Dict[int, Tuple[str, Dict[int, int]]] = {}
        self._db_load_thread: Optional[_DbLoadThread] = None

        self._build_ui()
        self._build_menu()
        self._apply_theme(self._theme)
        set_dbg_callback(self._log_panel.info)
        self._log_panel.set_context(mw=self, code=None)

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        # ── View mode toggle (top-right, always visible) ──────
        self._view_mode_bar = QFrame()
        mode_bar = self._view_mode_bar
        mode_bar.setObjectName("viewModeBar")
        mode_row = QHBoxLayout(mode_bar)
        mode_row.setContentsMargins(0, 0, 10, 0)
        mode_row.setSpacing(0)

        self._view_mode_group = QButtonGroup(self)
        self._view_mode_group.setExclusive(True)
        self._view_mode_buttons: Dict[int, QPushButton] = {}
        for i, mode in enumerate(_VIEW_MODE_CYCLE):
            btn = QPushButton(_VIEW_MODE_GLYPHS[mode])
            btn.setObjectName("modeBtnIcon")
            btn.setProperty("segment", "first" if i == 0 else "last" if i == len(_VIEW_MODE_CYCLE) - 1 else "mid")
            btn.setCheckable(True)
            btn.setFixedWidth(32)
            btn.setToolTip(f"{_VIEW_MODE_NAMES[mode]} view  (Tab to cycle)")
            mode_row.addWidget(btn)
            self._view_mode_group.addButton(btn, mode)
            self._view_mode_buttons[mode] = btn
        self._view_mode_group.idClicked.connect(self._set_view_mode)

        self.menuBar().setCornerWidget(mode_bar, Qt.Corner.TopRightCorner)
        self._update_view_mode_label()

        # ── Central: tab widget ───────────────────────────────
        self._tab_bar = _TabBar()
        self._tabs = QTabWidget()
        self._tabs.setTabBar(self._tab_bar)
        self._tabs.setTabsClosable(False)
        self._tabs.setMovable(True)
        self._tabs.setDocumentMode(True)
        self.setCentralWidget(self._tabs)

        # ── Dock options: allow nested + tabbed docking ───────
        self.setDockOptions(
            QMainWindow.DockOption.AllowNestedDocks
            | QMainWindow.DockOption.AllowTabbedDocks
            | QMainWindow.DockOption.AnimatedDocks
        )

        # ── Left dock: navigator ──────────────────────────────
        self._func_list = FunctionList()
        self._nav_dock = QDockWidget("Navigator", self)
        self._nav_dock.setObjectName("navDock")
        self._nav_dock.setWidget(self._func_list)
        self._nav_dock.setMinimumWidth(220)
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, self._nav_dock)

        # ── Bottom dock: log ──────────────────────────────────
        self._log_panel = LogPanel()
        self._log_dock = QDockWidget("Log", self)
        self._log_dock.setObjectName("logDock")
        self._log_dock.setWidget(self._log_panel)
        self._log_dock.setMinimumHeight(80)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self._log_dock)

        # ── Right dock: CFG viewer (off by default — opt in via Window menu) ──
        self._cfg_view = CfgView()
        self._cfg_dock = QDockWidget("CFG", self)
        self._cfg_dock.setObjectName("cfgDock")
        self._cfg_dock.setWidget(self._cfg_view)
        self._cfg_dock.setMinimumWidth(220)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self._cfg_dock)
        self._cfg_dock.hide()
        self._cfg_dock.visibilityChanged.connect(self._on_cfg_dock_visibility)

        # ── Xrefs popup (frameless, keyboard-navigable) ───────
        self._xref_popup = XrefPopup(self)
        self._xref_popup.navigate_requested.connect(self._navigate_to_xref)

        # ── Status bar ────────────────────────────────────────
        self._status_bar = QStatusBar()
        self.setStatusBar(self._status_bar)
        self._status_label = QLabel("No file loaded")
        self._progress_bar = QProgressBar()
        self._progress_bar.setFixedWidth(180)
        self._progress_bar.setFixedHeight(6)
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setVisible(False)
        self._status_bar.addWidget(self._status_label)
        self._status_bar.addPermanentWidget(self._progress_bar)

        # ── Signals ───────────────────────────────────────────
        self._func_list.function_selected.connect(self._on_function_selected)
        self._tabs.currentChanged.connect(self._on_tab_changed)

    def _build_menu(self) -> None:
        mb = self.menuBar()
        fm = mb.addMenu("File")
        fm.addAction("Open…", self._open_file, "Ctrl+O")
        fm.addSeparator()
        fm.addAction("Save Database", self._save_database, "Ctrl+S")
        fm.addAction("Load Database…", self._open_database_file)
        fm.addSeparator()
        fm.addAction("Quit", self.close, "Ctrl+Q")
        vm = mb.addMenu("View")
        tm = vm.addMenu("Theme")
        for name in THEMES:
            tm.addAction(name, lambda n=name: self._apply_theme(THEMES[n]))
        vm.addSeparator()
        vm.addAction("Cycle view (split/disasm/decompiled)\tTab", self._cycle_view_mode)
        vm.addSeparator()
        vm.addAction("Inspect widget under cursor\tCtrl+Shift+I", self._inspect_widget)

        wm = mb.addMenu("Window")
        wm.addAction(self._nav_dock.toggleViewAction())
        wm.addAction(self._log_dock.toggleViewAction())
        wm.addAction(self._cfg_dock.toggleViewAction())

    # ── File loading ──────────────────────────────────────────────────────────

    def _open_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open HashLink bytecode", "", "HashLink files (*.hl *.dat);;All files (*)"
        )
        if path:
            self._load_file(path)

    def _load_file(self, path: str) -> None:
        self._tabs.clear()
        self._open_tabs.clear()
        self._class_findices.clear()
        self._class_results.clear()
        self._class_names.clear()
        self._ir_cache.clear()
        self._opline_cache.clear()
        self._pending_op_scroll = None
        self._cfg_findex = None
        self._cfg_view.clear_view()
        self._db_cache.clear()
        self._log_panel.clear()
        self._code = None
        self._log_panel.set_context(code=None, findex=None, func=None, irf=None)
        self._source_path = path
        self._worker.invalidate()

        self._progress_bar.setVisible(True)
        self._progress_bar.setValue(0)
        self._status_label.setText(f"Loading {path}…")

        self._load_thread = _LoadThread(path)
        self._load_thread.signals.progress.connect(self._on_load_progress)
        self._load_thread.signals.finished.connect(self._on_load_finished)
        self._load_thread.signals.error.connect(self._on_load_error)
        self._load_thread.start()

    def _on_load_progress(self, frac: float, status: str) -> None:
        self._progress_bar.setValue(int(frac * 100))
        self._status_label.setText(status)

    def _on_load_finished(self, code: Bytecode) -> None:
        self._code = code
        self._progress_bar.setVisible(False)
        n = len(code.functions)
        self._status_label.setText(f"Loaded — {n} functions")
        self._log_panel.info(f"Loaded {n} functions")
        self._log_panel.set_context(code=code)
        self._func_list.load(code)

        assert self._source_path is not None
        cldb_path = self._source_path + ".cldb"
        if os.path.exists(cldb_path):
            self._load_database_from(cldb_path)

    def _on_load_error(self, msg: str) -> None:
        self._progress_bar.setVisible(False)
        self._status_label.setText(f"Error: {msg}")

    # ── Analysis database (.cldb) ───────────────────────────────────────────────

    def _open_database_file(self) -> None:
        if self._code is None or self._source_path is None:
            self._log_panel.warn("Open a bytecode file first.")
            return
        path, _ = QFileDialog.getOpenFileName(self, "Load analysis database", "", "crashlink database (*.cldb)")
        if path:
            self._load_database_from(path)

    def _load_database_from(self, cldb_path: str) -> None:
        assert self._code is not None and self._source_path is not None
        self._db_load_thread = _DbLoadThread(cldb_path, self._code, self._source_path)
        self._db_load_thread.signals.finished.connect(self._on_db_load_finished)
        self._db_load_thread.signals.error.connect(
            lambda msg: self._log_panel.error(f"Failed to load database: {msg}")
        )
        self._db_load_thread.start()

    def _on_db_load_finished(self, result: DatabaseLoadResult) -> None:
        for w in result.warnings:
            self._log_panel.warn(w)
        if not result.matched:
            return

        self._db_cache = dict(result.cache)
        self._log_panel.success(
            f"Loaded database: {result.renames_applied} renames, "
            f"{result.comments_applied} comments, {len(result.cache)} cached functions"
        )

        session = result.session
        if session is None:
            return

        theme = THEMES.get(session.theme_name)
        if theme is not None:
            self._apply_theme(theme)
        if session.view_mode in _VIEW_MODE_NAMES:
            self._set_view_mode(session.view_mode)
        for findex in session.open_findices:
            self._on_function_selected(findex)
        if session.current_tab_index is not None and 0 <= session.current_tab_index < self._tabs.count():
            self._tabs.setCurrentIndex(session.current_tab_index)

    def _save_database(self) -> None:
        if self._code is None or self._source_path is None:
            self._log_panel.warn("Open a bytecode file first.")
            return

        open_findices: List[int] = []
        for i in range(self._tabs.count()):
            w = self._tabs.widget(i)
            class_key = w.property("class_key") if w is not None else None
            fi_list = self._class_findices.get(class_key) if class_key else None
            if fi_list:
                open_findices.append(fi_list[0])

        session = SessionState(
            view_mode=self._view_mode,
            theme_name=self._theme.name,
            open_findices=open_findices,
            current_tab_index=self._tabs.currentIndex() if self._tabs.count() else None,
        )

        cldb_path = self._source_path + ".cldb"
        try:
            save_database(
                cldb_path,
                code=self._code,
                source_path=self._source_path,
                class_results=self._class_results,
                opline_cache=self._opline_cache,
                session=session,
            )
        except Exception as e:
            self._log_panel.error(f"Failed to save database: {e}")
            return
        self._log_panel.success(f"Saved database to {cldb_path}")

    # ── Tab management ────────────────────────────────────────────────────────

    def _class_key_for(self, findex: int) -> Tuple[str, str, List[int]]:
        """
        Returns (class_key, display_name, all_findices_for_class).
        Uses destaticify to unify static $Foo and instance Foo into one class.
        Falls back to a standalone key for unregistered functions.
        """
        assert self._code is not None
        reg = _method_registry(self._code)
        if findex not in reg:
            return f"func:{findex}", f"f@{findex}", [findex]

        obj, _, _ = reg[findex]
        raw_name = obj.name.resolve(self._code)
        canonical = destaticify(raw_name)
        class_key = f"class:{canonical}"

        # Gather all findices that belong to this canonical class (static + instance)
        all_fi = sorted(fi for fi, (o, _, _) in reg.items() if destaticify(o.name.resolve(self._code)) == canonical)
        return class_key, canonical, all_fi

    def _open_class_tab(self, class_key: str, display_name: str, all_fi: List[int], jump_to: int) -> None:
        assert self._code is not None

        self._class_findices[class_key] = all_fi
        self._class_names[class_key] = display_name
        self._class_results[class_key] = {fi: None for fi in all_fi}

        # Seed from a loaded .cldb where available, so cached functions render
        # immediately instead of flashing "decompiling…" — a real decompile still
        # runs below to warm _ir_cache for rename/xref support.
        for fi in all_fi:
            cached = self._db_cache.get(fi)
            if cached is not None:
                text, opmap = cached
                self._class_results[class_key][fi] = text
                self._opline_cache[fi] = opmap

        view = SyncView(self._opline_cache)
        view.setProperty("class_key", class_key)
        view.set_theme(self._theme)
        view.set_mode(self._view_mode)
        view.cycle_requested.connect(self._cycle_view_mode)
        view.class_view.function_focused.connect(self._on_function_focused)
        view.class_view.rename_requested.connect(self._on_rename_hotkey)
        view.class_view.xref_requested.connect(self._on_xref_hotkey)
        view.disasm_view.function_focused.connect(self._on_function_focused)
        view.comment_requested.connect(self._on_comment_hotkey)

        # Render immediately — cached text where a .cldb supplied it, else a placeholder.
        placeholder = [
            (fi, self._class_results[class_key][fi] or f"class {display_name} {{\n    // f@{fi}  decompiling…\n}}")
            for fi in all_fi
        ]
        view.load_pseudo(display_name, placeholder)
        # Disasm needs no decompile — render straight from opcodes.
        findex_map = self._code.get_findex_map()
        view.load_disasm(self._code, [(fi, findex_map[fi]) for fi in all_fi if fi in findex_map])

        tab_label = _tab_label(display_name)
        idx = self._tabs.addTab(view, tab_label)
        self._tabs.setTabToolTip(idx, display_name)
        self._open_tabs[class_key] = idx
        self._add_close_btn(idx, class_key)
        self._tabs.setCurrentIndex(idx)

        # Kick off decompile for every method concurrently
        for fi in all_fi:
            r = _DecompRunnable(self._worker, self._code, class_key, fi)
            r.signals.finished.connect(self._on_decompile_finished)
            r.signals.error.connect(self._on_decompile_error)
            QThreadPool.globalInstance().start(r)

        self._status_label.setText(f"Decompiling {display_name} ({len(all_fi)} methods)…")

    def _add_close_btn(self, tab_idx: int, class_key: str) -> None:
        btn = QToolButton()
        btn.setObjectName("tabCloseBtn")
        btn.setText("×")
        btn.setFixedSize(QSize(18, 18))
        btn.setToolTip("Close tab")
        btn.clicked.connect(lambda: QTimer.singleShot(0, lambda: self._close_tab_by_key(class_key)))
        self._tabs.tabBar().setTabButton(tab_idx, QTabBar.ButtonPosition.RightSide, btn)

    def _close_tab_by_key(self, class_key: str) -> None:
        idx = self._open_tabs.pop(class_key, None)
        if idx is None:
            return
        self._class_findices.pop(class_key, None)
        self._class_results.pop(class_key, None)
        self._class_names.pop(class_key, None)
        self._tabs.removeTab(idx)
        self._rebuild_tab_map()

    def _rebuild_tab_map(self) -> None:
        self._open_tabs = {}
        for i in range(self._tabs.count()):
            w = self._tabs.widget(i)
            if w is not None:
                key = w.property("class_key")
                if key:
                    self._open_tabs[key] = i

    def _on_tab_changed(self, _idx: int) -> None:
        pass  # log panel needs no per-tab update

    # ── Function selection ────────────────────────────────────────────────────

    def _on_function_selected(self, findex: int) -> None:
        if self._code is None:
            return
        class_key, display_name, all_fi = self._class_key_for(findex)

        if class_key in self._open_tabs:
            idx = self._open_tabs[class_key]
            self._tabs.setCurrentIndex(idx)
            view = self._tabs.widget(idx)
            if isinstance(view, SyncView):
                view.scroll_to_findex(findex)
        else:
            self._open_class_tab(class_key, display_name, all_fi, jump_to=findex)

    # ── Decompilation callbacks ───────────────────────────────────────────────

    def _on_decompile_finished(self, class_key: str, findex: int, ir: object) -> None:
        if not isinstance(ir, IRFunction):
            return

        self._ir_cache[findex] = ir

        if class_key not in self._class_results:
            return

        try:
            text, opmap = pseudo_oplines(ir)
            self._opline_cache[findex] = opmap
        except Exception as e:
            text = f"class ? {{\n    // f@{findex} error: {e}\n}}"

        self._class_results[class_key][findex] = text
        self._refresh_class_view(class_key)

        if findex == self._cfg_findex:
            self._update_cfg_view(findex)
            self._update_repl_focus(findex)

        if self._pending_op_scroll is not None and self._pending_op_scroll[0] == findex:
            pf, pop = self._pending_op_scroll
            self._pending_op_scroll = None
            self._navigate_to_xref(pf, pop, -1)

        # Update status when all done
        results = self._class_results.get(class_key, {})
        pending = sum(1 for v in results.values() if v is None)
        if pending == 0:
            name = self._class_names.get(class_key, class_key)
            self._status_label.setText(f"{name} — {len(results)} methods")

    def _on_decompile_error(self, class_key: str, findex: int, msg: str) -> None:
        if class_key not in self._class_results:
            return
        err_text = f"class ? {{\n    // f@{findex} error: {msg}\n}}"
        self._class_results[class_key][findex] = err_text
        self._refresh_class_view(class_key)

    def _refresh_class_view(self, class_key: str) -> None:
        idx = self._open_tabs.get(class_key)
        if idx is None:
            return
        view = self._tabs.widget(idx)
        if not isinstance(view, SyncView):
            return

        display_name = self._class_names.get(class_key, "?")
        all_fi = self._class_findices.get(class_key, [])
        results = self._class_results.get(class_key, {})

        methods = []
        for fi in all_fi:
            text = results.get(fi)
            if text is None:
                text = f"class {display_name} {{\n    // f@{fi}  decompiling…\n}}"
            methods.append((fi, text))

        view.load_pseudo(display_name, methods)

    def _refresh_disasm_view(self, class_key: str) -> None:
        """Disasm rendering needs no decompile — re-render straight from opcodes so
        an annotation change (e.g. a comment) shows up immediately, no waiting on
        the background redecompile that updates the pseudocode pane."""
        if self._code is None:
            return
        idx = self._open_tabs.get(class_key)
        if idx is None:
            return
        view = self._tabs.widget(idx)
        if not isinstance(view, SyncView):
            return
        all_fi = self._class_findices.get(class_key, [])
        findex_map = self._code.get_findex_map()
        view.load_disasm(self._code, [(fi, findex_map[fi]) for fi in all_fi if fi in findex_map])

    # ── Focus tracking ────────────────────────────────────────────────────────

    def _on_function_focused(self, findex: int) -> None:
        self._cfg_findex = findex
        self._update_cfg_view(findex)
        self._update_repl_focus(findex)

    def _update_repl_focus(self, findex: int) -> None:
        """Keep the REPL's `findex`/`func`/`irf` pointed at the focused function."""
        func = self._code.get_findex_map().get(findex) if self._code is not None else None
        self._log_panel.set_context(findex=findex, func=func, irf=self._ir_cache.get(findex))

    def _on_cfg_dock_visibility(self, visible: bool) -> None:
        if visible and self._cfg_findex is not None:
            self._update_cfg_view(self._cfg_findex)

    def _update_cfg_view(self, findex: int) -> None:
        if self._code is None or not self._cfg_dock.isVisible():
            return
        func = self._code.get_findex_map().get(findex)
        if isinstance(func, Native):
            self._cfg_view.show_native()
            return

        ir = self._ir_cache.get(findex)
        if not isinstance(ir, IRFunction):
            self._cfg_view.show_pending()
            return

        dot = ir.to_dot()
        if dot is None:
            self._cfg_view.show_native()
            return
        self._cfg_view.load_dot(dot)

    # ── Rename (N) ────────────────────────────────────────────────────────────

    def _on_rename_hotkey(self, findex: int, word: str) -> None:
        if self._code is None:
            return
        ir = self._ir_cache.get(findex)
        if not isinstance(ir, IRFunction):
            self._log_panel.error("Cannot rename — function not yet decompiled")
            return

        # Find locals matching word under cursor
        locals_matching = [loc for loc in ir.all_locals if loc.name == word and loc.reg_idx is not None]
        if not locals_matching:
            self._log_panel.warn(f"No local named '{word}' in f@{findex}")
            return

        loc = locals_matching[0]
        new_name, ok = QInputDialog.getText(self, "Rename", f"Rename '{word}' to:", text=word)
        if not ok or not new_name or new_name == word:
            return

        self._apply_rename(findex, loc.reg_idx, loc.defining_op_idx, new_name)
        self._log_panel.success(f"Renamed '{word}' → '{new_name}' in f@{findex}")

    def _apply_rename(self, findex: int, reg_idx: int, def_op: object, new_name: str) -> None:
        if self._code is None:
            return
        def_op_int = int(def_op) if def_op is not None else None
        self._code.annotations.rename(findex, reg_idx, def_op_int, new_name)
        self._invalidate_and_redecompile(findex)

    def _invalidate_and_redecompile(self, findex: int) -> None:
        """After an annotation (rename/comment) changes, drop every cache that was
        derived from the old IR for this function and kick off a fresh decompile."""
        if self._code is None:
            return
        self._worker.invalidate(findex)
        self._ir_cache.pop(findex, None)
        self._opline_cache.pop(findex, None)
        if findex == self._cfg_findex:
            self._cfg_view.show_pending()
            self._log_panel.set_context(irf=None)

        for class_key, fi_list in self._class_findices.items():
            if findex in fi_list:
                if class_key in self._class_results:
                    self._class_results[class_key][findex] = None
                r = _DecompRunnable(self._worker, self._code, class_key, findex)
                r.signals.finished.connect(self._on_decompile_finished)
                r.signals.error.connect(self._on_decompile_error)
                QThreadPool.globalInstance().start(r)
                break

    # ── Comments (/) ─────────────────────────────────────────────────────────

    def _on_comment_hotkey(self, findex: int, op_idx: int) -> None:
        if self._code is None:
            return
        existing = self._code.annotations.get_comment(findex, op_idx) or ""
        text, ok = QInputDialog.getText(self, "Comment", f"Comment on op {op_idx} in f@{findex}:", text=existing)
        if not ok:
            return
        text = text.strip()
        if text:
            self._code.annotations.set_comment(findex, op_idx, text)
            self._log_panel.success(f"Commented op {op_idx} in f@{findex}")
        else:
            self._code.annotations.clear_comment(findex, op_idx)
            self._log_panel.info(f"Cleared comment on op {op_idx} in f@{findex}")

        class_key, _, _ = self._class_key_for(findex)
        self._refresh_disasm_view(class_key)
        self._invalidate_and_redecompile(findex)

    # ── Xrefs (X) ────────────────────────────────────────────────────────────

    def _on_xref_hotkey(self, findex: int, word: str) -> None:
        if self._code is None:
            return
        word = word.strip()
        if not word:
            return

        groups = resolve_targets(self._code, word)
        local_group = self._resolve_locals(findex, word)
        if local_group is not None:
            groups.insert(0, local_group)

        view = self._current_class_view()
        if isinstance(view, ClassView):
            at = view.mapToGlobal(view.cursorRect().bottomLeft())
        else:
            at = self.mapToGlobal(self.rect().center())
        self._xref_popup.show_results(word, groups, at)
        self._log_panel.result(f"Xrefs for '{word}': {len(groups)} target(s)")

    def _resolve_locals(self, findex: int, word: str) -> Optional[XrefGroup]:
        """Build a group of every occurrence of `word` (a local) in the focused
        function's displayed pseudocode, each site carrying its body-relative line."""
        ir = self._ir_cache.get(findex)
        if not isinstance(ir, IRFunction):
            return None
        if not any(loc.name == word for loc in ir.all_locals):
            return None

        class_key, _, _ = self._class_key_for(findex)
        text = self._class_results.get(class_key, {}).get(findex)
        if not text:
            return None

        func_lines = text.split("\n")
        if len(func_lines) >= 3 and func_lines[0].startswith("class ") and func_lines[-1].strip() == "}":
            content = func_lines[1:-1]
        else:
            content = func_lines

        pat = re.compile(rf"\b{re.escape(word)}\b")
        label = _func_label(self._code, findex) if self._code else f"f@{findex}"
        sites: List[XrefSite] = []
        for j, line in enumerate(content):
            if pat.search(line):
                sites.append(
                    XrefSite(
                        source_findex=findex,
                        source_label=label,
                        opcode_index=None,
                        body_line=j,
                        ref_kind="use",
                    )
                )
        if not sites:
            return None
        return XrefGroup(label=f"local '{word}'", kind="local", sites=sites)

    def _navigate_to_xref(self, findex: int, op_idx: int, body_line: int) -> None:
        if self._code is None:
            return

        # Open / focus the class tab containing findex.
        self._on_function_selected(findex)
        view = self._current_class_view()
        if not isinstance(view, ClassView):
            return

        # Local site: body line is known directly.
        if body_line >= 0:
            view.scroll_to_op_line(findex, body_line)
            return

        if op_idx < 0:
            view.scroll_to_findex(findex)
            return

        opmap = self._opline_cache.get(findex)
        if opmap is None:
            # Map not cached yet (still decompiling) — defer to _on_decompile_finished.
            self._pending_op_scroll = (findex, op_idx)
            return

        line = opmap.get(op_idx)
        if line is None:
            # Nearest preceding mapped op.
            preceding = [v for k, v in opmap.items() if k <= op_idx]
            line = max(preceding) if preceding else None
        if line is None:
            view.scroll_to_findex(findex)
        else:
            view.scroll_to_op_line(findex, line)

    def _current_class_view(self) -> Optional[ClassView]:
        w = self._tabs.currentWidget()
        if isinstance(w, SyncView):
            return w.class_view
        return None

    def _cycle_view_mode(self) -> None:
        next_idx = (_VIEW_MODE_CYCLE.index(self._view_mode) + 1) % len(_VIEW_MODE_CYCLE)
        self._set_view_mode(_VIEW_MODE_CYCLE[next_idx])

    def _set_view_mode(self, mode: int) -> None:
        self._view_mode = mode
        for i in range(self._tabs.count()):
            view = self._tabs.widget(i)
            if isinstance(view, SyncView):
                view.set_mode(mode)
        self._update_view_mode_label()

    def _update_view_mode_label(self) -> None:
        btn = self._view_mode_buttons.get(self._view_mode)
        if btn is not None:
            btn.setChecked(True)

    # ── Theme ─────────────────────────────────────────────────────────────────

    def _apply_theme(self, theme: Theme) -> None:
        self._theme = theme
        self.setStyleSheet(generate_qss(theme))
        self._tab_bar._fill = QColor(theme.mantle)
        self._tab_bar.update()
        self._func_list.set_theme(theme)
        self._log_panel.set_theme(theme)
        self._xref_popup.set_theme(theme)
        self._cfg_view.set_theme(theme)
        for i in range(self._tabs.count()):
            view = self._tabs.widget(i)
            if isinstance(view, SyncView):
                view.set_theme(theme)

    # ── Inspector ─────────────────────────────────────────────────────────────

    def _inspect_widget(self) -> None:
        pos = QCursor.pos()
        widget = QApplication.widgetAt(pos)
        if widget is None:
            QMessageBox.information(self, "Inspector", "No widget under cursor.")
            return

        lines = []
        w: Optional[QWidget] = widget
        while w is not None:
            pal = w.palette()
            win_col = pal.color(QPalette.ColorRole.Window).name()
            btn_col = pal.color(QPalette.ColorRole.Button).name()
            lines.append(
                f"{type(w).__name__}  name={w.objectName()!r}\n"
                f"  geom={w.geometry()}  rect={w.rect()}\n"
                f"  autoFill={w.autoFillBackground()}  WA_Styled={w.testAttribute(Qt.WidgetAttribute.WA_StyledBackground)}\n"
                f"  palette.Window={win_col}  palette.Button={btn_col}\n"
                f"  styleSheet={w.styleSheet()[:80]!r}"
            )
            parent = w.parent()
            w = parent if isinstance(parent, QWidget) else None

        msg = "\n─────\n".join(lines)
        box = QMessageBox(self)
        box.setWindowTitle(f"Inspector @ {pos.x()},{pos.y()}")
        box.setText(msg)
        box.exec()

    def keyPressEvent(self, event: object) -> None:  # type: ignore[override]
        if isinstance(event, QKeyEvent):
            if event.key() == Qt.Key.Key_I and event.modifiers() == (
                Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier
            ):
                self._inspect_widget()
                return
        super().keyPressEvent(event)  # type: ignore[arg-type]

    # ── Cleanup ───────────────────────────────────────────────────────────────

    def closeEvent(self, event: object) -> None:
        set_dbg_callback(None)
        self._worker.shutdown(wait=False)
        super().closeEvent(event)  # type: ignore[arg-type]


# ── Helpers ───────────────────────────────────────────────────────────────────


def _tab_label(canonical_name: str, max_len: int = 28) -> str:
    """haxe.ds.ObjectMap → h.d.ObjectMap (abbreviated namespace prefix)."""
    parts = canonical_name.split(".")
    if len(parts) <= 2 or len(canonical_name) <= max_len:
        return canonical_name
    class_part = parts[-1]
    abbrev = ".".join(p[0] for p in parts[:-1])
    return f"{abbrev}.{class_part}"
