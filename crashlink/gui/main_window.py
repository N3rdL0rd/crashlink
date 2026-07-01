"""Main application window."""

from __future__ import annotations

import os
import re
from typing import Dict, List, Optional, Tuple

from PySide6.QtCore import QRect, QRunnable, QSettings, QThread, QThreadPool, QTimer, Qt, Signal, QObject, QSize
from PySide6.QtGui import QColor, QPainter, QTextCursor, QTextDocument
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QDialog,
    QDockWidget,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QStatusBar,
    QTabBar,
    QTabWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from crashlink.core import AnalysisWorker, Bytecode, Native, destaticify
from crashlink.database import DatabaseLoadResult, SessionState, load_database, save_database
from crashlink.decomp.function import IRFunction
from crashlink.globals import VERSION, set_dbg_callback
from crashlink.pseudo import pseudo_oplines, _method_registry

from .themes import DEFAULT_THEME, THEMES, Theme, generate_qss
from .widgets.cfg_view import CfgView
from .widgets.class_view import ClassView
from .widgets.function_list import FunctionList
from .widgets.log_panel import LogPanel
from .widgets.natives_view import NativesView
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


class _IndexBuildSignals(QObject):
    finished = Signal()
    error = Signal(str)


class _IndexBuildThread(QThread):
    """Builds the xref/search/source-map indices off the UI thread — the first
    access to any of them otherwise blocks the caller for however long the
    (uncached) build takes, which for the xref index in particular walks
    every opcode in every function."""

    def __init__(self, worker: AnalysisWorker, code: Bytecode) -> None:
        super().__init__()
        self._worker = worker
        self._code = code
        self.signals = _IndexBuildSignals()

    def run(self) -> None:
        try:
            self._worker.build_indices(self._code).result()
            self.signals.finished.emit()
        except Exception as e:
            self.signals.error.emit(str(e))


# ── Main window ───────────────────────────────────────────────────────────────


class _TabBar(QTabBar):
    """QTabBar that paints the empty area to the right of the last tab.

    Qt's style engine repaints the tab bar background (including the empty
    area) after our pre-fill, overriding it.  Painting only the uncovered
    region AFTER super() wins the z-order race.
    """

    _fill: QColor = QColor("#181825")

    def paintEvent(self, event: object) -> None:
        super().paintEvent(event)  # type: ignore[arg-type]
        # Find where the last tab ends; fill everything to the right.
        empty_x = 0
        for i in range(self.count()):
            empty_x = max(empty_x, self.tabRect(i).right() + 1)
        if empty_x < self.width():
            p = QPainter(self)
            p.fillRect(QRect(empty_x, 0, self.width() - empty_x, self.height()), self._fill)
            p.end()


class _WaitBox(QDialog):
    """A small popup with a native titlebar reading "Please wait…" and the
    current action as its body — styled distinctly (see QDialog#waitBox in
    themes.py) so it doesn't blend into the rest of the app's background."""

    def __init__(self, parent: Optional[QWidget]) -> None:
        super().__init__(parent)
        self.setObjectName("waitBox")
        self.setWindowTitle("Please wait…")
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.CustomizeWindowHint | Qt.WindowType.WindowTitleHint)
        self.setModal(False)  # informational only — never block input to the app
        self.setFixedSize(280, 70)

        layout = QVBoxLayout(self)
        self._label = QLabel()
        self._label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._label)

    def set_action(self, action: str) -> None:
        self._label.setText(action)

    def show(self) -> None:
        super().show()
        parent = self.parentWidget()
        if parent is not None:
            parent_center = parent.geometry().center()
            self.move(parent_center - self.frameGeometry().center())


class _BusyIndicator:
    """Shows a `_WaitBox` only if an operation is still running after `delay_ms`
    (default 2s) — quick operations never flash a dialog at all."""

    def __init__(self, parent: QWidget, delay_ms: int = 2000) -> None:
        self._parent = parent
        self._delay_ms = delay_ms
        self._box: Optional[_WaitBox] = None
        self._timer = QTimer(parent)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._reveal)
        self._pending_action = ""

    def start(self, action: str) -> None:
        self._pending_action = action
        if self._box is not None and self._box.isVisible():
            self._box.set_action(action)
        else:
            self._timer.start(self._delay_ms)

    def stop(self) -> None:
        self._timer.stop()
        if self._box is not None:
            self._box.hide()

    def _reveal(self) -> None:
        if self._box is None:
            self._box = _WaitBox(self._parent)
        self._box.set_action(self._pending_action)
        self._box.show()


class _FindDialog(QDialog):
    """A small non-modal find bar for whichever disasm/pseudocode pane is
    active — kept as one persistent instance and re-targeted on every Ctrl+F
    rather than rebuilt, so it remembers the last search term."""

    def __init__(self, parent: Optional[QWidget]) -> None:
        super().__init__(parent)
        self.setWindowTitle("Find")
        self.setModal(False)
        self._target: Optional[QWidget] = None

        layout = QHBoxLayout(self)
        self._input = QLineEdit()
        self._input.returnPressed.connect(self._find_next)
        layout.addWidget(self._input, 1)
        next_btn = QPushButton("Next")
        next_btn.clicked.connect(self._find_next)
        layout.addWidget(next_btn)
        prev_btn = QPushButton("Previous")
        prev_btn.clicked.connect(self._find_prev)
        layout.addWidget(prev_btn)
        self.resize(380, 60)

    def set_target(self, target: QWidget) -> None:
        self._target = target
        self._input.setFocus()
        self._input.selectAll()

    def _find_next(self) -> None:
        self._find(QTextDocument.FindFlag(0))

    def _find_prev(self) -> None:
        self._find(QTextDocument.FindFlag.FindBackward)

    def _find(self, flags: "QTextDocument.FindFlag") -> None:
        text = self._input.text()
        if self._target is None or not text:
            return
        found = self._target.find(text, flags)  # type: ignore[attr-defined]
        if found:
            return
        # No match from the current position — wrap around and retry once.
        cursor = self._target.textCursor()  # type: ignore[attr-defined]
        backward = bool(flags & QTextDocument.FindFlag.FindBackward)
        cursor.movePosition(QTextCursor.MoveOperation.End if backward else QTextCursor.MoveOperation.Start)
        self._target.setTextCursor(cursor)  # type: ignore[attr-defined]
        self._target.find(text, flags)  # type: ignore[attr-defined]


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
        self._index_build_thread: Optional[_IndexBuildThread] = None
        # Number of _DecompRunnables currently in flight, so the busy indicator
        # only hides once every concurrent decompile in a batch has finished.
        self._active_decompiles = 0
        # True once a rename/comment has been applied since the last save/load,
        # so closing/opening another file can prompt instead of discarding silently.
        self._dirty = False
        self._recent_files: List[str] = []
        self._find_dialog: Optional[_FindDialog] = None

        self._build_ui()
        self._build_menu()
        self._apply_theme(self._theme)
        set_dbg_callback(self._log_panel.info)
        self._log_panel.set_context(mw=self, code=None)
        self._busy = _BusyIndicator(self)
        self._restore_settings()

    # ── Settings (window geometry/layout/theme/view mode) ───────────────────────

    def _restore_settings(self) -> None:
        settings = QSettings("N3rdL0rd", "crashlink")
        geometry = settings.value("window/geometry")
        if geometry is not None:
            self.restoreGeometry(geometry)
        state = settings.value("window/state")
        if state is not None:
            self.restoreState(state)

        theme_name = settings.value("window/theme")
        if isinstance(theme_name, str) and theme_name in THEMES:
            self._apply_theme(THEMES[theme_name])

        view_mode = settings.value("window/view_mode")
        try:
            mode = int(view_mode) if view_mode is not None else None
        except (TypeError, ValueError):
            mode = None
        if mode is not None and mode in _VIEW_MODE_NAMES:
            self._set_view_mode(mode)

        recent = settings.value("recent_files")
        if isinstance(recent, list):
            self._recent_files = [p for p in recent if isinstance(p, str)]
        elif isinstance(recent, str):  # QSettings collapses a 1-item list to a bare string
            self._recent_files = [recent]
        self._rebuild_recent_menu()

    def _save_settings(self) -> None:
        settings = QSettings("N3rdL0rd", "crashlink")
        settings.setValue("window/geometry", self.saveGeometry())
        settings.setValue("window/state", self.saveState())
        settings.setValue("window/theme", self._theme.name)
        settings.setValue("window/view_mode", self._view_mode)
        settings.setValue("recent_files", self._recent_files)

    def _update_window_title(self) -> None:
        if self._source_path is None:
            self.setWindowTitle("crashlink")
            return
        name = os.path.basename(self._source_path)
        star = "*" if self._dirty else ""
        self.setWindowTitle(f"{name}{star} - crashlink")

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
        self._recent_menu = fm.addMenu("Open Recent")
        self._rebuild_recent_menu()
        fm.addSeparator()
        fm.addAction("Save Database", self._save_database, "Ctrl+S")
        fm.addAction("Load Database…", self._open_database_file)
        fm.addSeparator()
        fm.addAction("Export Disassembly…", self._export_disasm)
        fm.addAction("Export Pseudocode…", self._export_pseudo)
        fm.addSeparator()
        fm.addAction("Quit", self.close, "Ctrl+Q")
        vm = mb.addMenu("View")
        tm = vm.addMenu("Theme")
        for name in THEMES:
            tm.addAction(name, lambda n=name: self._apply_theme(THEMES[n]))
        vm.addSeparator()
        vm.addAction("Cycle view (split/disasm/decompiled)\tTab", self._cycle_view_mode)
        vm.addSeparator()
        vm.addAction("Find…\tCtrl+F", self._open_find)

        wm = mb.addMenu("Window")
        wm.addAction(self._nav_dock.toggleViewAction())
        wm.addAction(self._log_dock.toggleViewAction())
        wm.addAction(self._cfg_dock.toggleViewAction())
        wm.addSeparator()
        wm.addAction("Natives Table", self._open_natives_tab)

        hm = mb.addMenu("Help")
        hm.addAction("Keyboard Shortcuts…", self._show_shortcuts)
        hm.addAction("About crashlink…", self._show_about)

    # ── File loading ──────────────────────────────────────────────────────────

    def _open_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open HashLink bytecode", "", "HashLink files (*.hl *.dat);;All files (*)"
        )
        if path and self._confirm_discard_changes():
            self._load_file(path)

    def _open_recent(self, path: str) -> None:
        if not os.path.isfile(path):
            self._log_panel.warn(f"No longer exists: {path}")
            self._recent_files = [p for p in self._recent_files if p != path]
            self._rebuild_recent_menu()
            return
        if self._confirm_discard_changes():
            self._load_file(path)

    def _add_recent_file(self, path: str) -> None:
        path = os.path.abspath(path)
        self._recent_files = [path] + [p for p in self._recent_files if p != path]
        del self._recent_files[10:]
        self._rebuild_recent_menu()
        QSettings("N3rdL0rd", "crashlink").setValue("recent_files", self._recent_files)

    def _rebuild_recent_menu(self) -> None:
        self._recent_menu.clear()
        if not self._recent_files:
            action = self._recent_menu.addAction("(none yet)")
            action.setEnabled(False)
            return
        for path in self._recent_files:
            self._recent_menu.addAction(path, lambda p=path: self._open_recent(p))
        self._recent_menu.addSeparator()
        self._recent_menu.addAction("Clear Recent Files", self._clear_recent_files)

    def _clear_recent_files(self) -> None:
        self._recent_files = []
        self._rebuild_recent_menu()
        QSettings("N3rdL0rd", "crashlink").setValue("recent_files", self._recent_files)

    def _confirm_discard_changes(self) -> bool:
        """Ask to save unsaved renames/comments before discarding them (opening a
        different file or closing the app). Returns True if it's OK to proceed."""
        if not self._dirty:
            return True
        box = QMessageBox(self)
        box.setWindowTitle("Unsaved changes")
        box.setText("You have unsaved renames/comments. Save the analysis database before continuing?")
        box.setStandardButtons(
            QMessageBox.StandardButton.Save
            | QMessageBox.StandardButton.Discard
            | QMessageBox.StandardButton.Cancel
        )
        box.setDefaultButton(QMessageBox.StandardButton.Save)
        choice = box.exec()
        if choice == QMessageBox.StandardButton.Cancel:
            return False
        if choice == QMessageBox.StandardButton.Save:
            self._save_database()
        return True

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
        self._dirty = False
        self._code = None
        self._log_panel.set_context(code=None, findex=None, func=None, irf=None)
        self._source_path = path
        self._update_window_title()
        self._worker.invalidate()

        self._progress_bar.setVisible(True)
        self._progress_bar.setValue(0)
        self._status_label.setText(f"Loading {path}…")
        self._busy.start("Reading bytecode…")

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
        self._busy.stop()
        assert self._source_path is not None
        self._add_recent_file(self._source_path)
        n = len(code.functions)
        self._status_label.setText(f"Loaded, {n} functions")
        self._log_panel.info(f"Loaded, {n} functions")
        self._log_panel.set_context(code=code)
        self._func_list.load(code)

        assert self._source_path is not None
        cldb_path = self._source_path + ".cldb"
        if os.path.exists(cldb_path):
            self._load_database_from(cldb_path)

        # Pre-warm the xref/search/source-map indices in the background so the
        # first 'X' lookup doesn't stall the UI thread building them on demand.
        self._busy.start("Building xref table…")
        self._index_build_thread = _IndexBuildThread(self._worker, code)
        self._index_build_thread.signals.finished.connect(self._busy.stop)
        self._index_build_thread.signals.error.connect(lambda msg: self._busy.stop())
        self._index_build_thread.start()

    def _on_load_error(self, msg: str) -> None:
        self._progress_bar.setVisible(False)
        self._busy.stop()
        self._status_label.setText(f"Error: {msg}")

    # ── Analysis database (.cldb) ───────────────────────────────────────────────

    def _open_database_file(self) -> None:
        if self._code is None or self._source_path is None:
            self._log_panel.warn("Open a bytecode file first.")
            return
        path, _ = QFileDialog.getOpenFileName(self, "Load analysis database", "", "crashlink database (*.cldb)")
        if path:
            self._load_database_from(path)

    # ── Export ───────────────────────────────────────────────────────────────

    def _export_disasm(self) -> None:
        view = self._current_sync_view()
        if view is None:
            self._log_panel.warn("No class tab open to export.")
            return
        self._export_text(view.disasm_view.toPlainText(), "Export Disassembly", "disasm.txt")

    def _export_pseudo(self) -> None:
        view = self._current_sync_view()
        if view is None:
            self._log_panel.warn("No class tab open to export.")
            return
        self._export_text(view.class_view.toPlainText(), "Export Pseudocode", "pseudo.hx")

    def _export_text(self, text: str, title: str, default_name: str) -> None:
        path, _ = QFileDialog.getSaveFileName(self, title, default_name, "Text files (*.txt *.hx);;All files (*)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        except OSError as e:
            self._log_panel.error(f"Failed to export: {e}")
            return
        self._log_panel.success(f"Exported to {path}")

    # ── Find (Ctrl+F) ────────────────────────────────────────────────────────

    def _find_target_view(self) -> Optional[QWidget]:
        sv = self._current_sync_view()
        if sv is None:
            return None
        if self._view_mode == DISASM:
            return sv.disasm_view
        if self._view_mode == PSEUDO:
            return sv.class_view
        # SPLIT: search whichever pane currently has focus, default to pseudo.
        return sv.disasm_view if sv.disasm_view.hasFocus() else sv.class_view

    def _open_find(self) -> None:
        target = self._find_target_view()
        if target is None:
            self._log_panel.warn("No disasm/pseudocode view open to search.")
            return
        if self._find_dialog is None:
            self._find_dialog = _FindDialog(self)
        self._find_dialog.set_target(target)
        self._find_dialog.show()
        self._find_dialog.raise_()
        self._find_dialog.activateWindow()

    def _load_database_from(self, cldb_path: str) -> None:
        assert self._code is not None and self._source_path is not None
        self._db_load_thread = _DbLoadThread(cldb_path, self._code, self._source_path)
        self._db_load_thread.signals.finished.connect(self._on_db_load_finished)
        self._db_load_thread.signals.error.connect(lambda msg: self._log_panel.error(f"Failed to load database: {msg}"))
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
        self._dirty = False
        self._update_window_title()
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

    # ── Natives table ────────────────────────────────────────────────────────

    _NATIVES_TAB_KEY = "__natives__"

    def _open_natives_tab(self) -> None:
        if self._code is None:
            self._log_panel.warn("Open a bytecode file first.")
            return
        key = self._NATIVES_TAB_KEY
        if key in self._open_tabs:
            self._tabs.setCurrentIndex(self._open_tabs[key])
            return

        view = NativesView()
        view.setProperty("class_key", key)
        view.set_theme(self._theme)
        view.load(self._code)
        view.xref_requested.connect(self._on_native_xref_requested)

        idx = self._tabs.addTab(view, "Natives")
        self._tabs.setTabToolTip(idx, f"{len(self._code.natives)} natives")
        self._open_tabs[key] = idx
        self._add_close_btn(idx, key)
        self._tabs.setCurrentIndex(idx)

    def _on_native_xref_requested(self, findex: int) -> None:
        if self._code is None:
            return
        word = f"f@{findex}"
        groups = resolve_targets(self._code, word)
        at = self.mapToGlobal(self.rect().center())
        self._xref_popup.show_results(word, groups, at)
        self._log_panel.result(f"Xrefs for '{word}': {len(groups)} target(s)")

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
        view.disasm_view.xref_requested.connect(self._on_xref_hotkey)
        view.comment_requested.connect(self._on_comment_hotkey)

        placeholder = [
            (fi, self._class_results[class_key][fi] or f"class {display_name} {{\n    // f@{fi}  decompiling…\n}}")
            for fi in all_fi
        ]
        view.load_pseudo(display_name, placeholder)
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
            self._start_decompile(class_key, fi)

        self._status_label.setText(f"Decompiling {display_name} ({len(all_fi)} methods)…")

    def _start_decompile(self, class_key: str, findex: int) -> None:
        assert self._code is not None
        self._active_decompiles += 1
        self._busy.start("Decompiling…")
        r = _DecompRunnable(self._worker, self._code, class_key, findex)
        r.signals.finished.connect(self._on_decompile_finished)
        r.signals.error.connect(self._on_decompile_error)
        QThreadPool.globalInstance().start(r)

    def _decompile_batch_done(self) -> None:
        self._active_decompiles = max(0, self._active_decompiles - 1)
        if self._active_decompiles == 0:
            self._busy.stop()

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
        self._decompile_batch_done()
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
            self._status_label.setText(f"{name}, {len(results)} methods")

    def _on_decompile_error(self, class_key: str, findex: int, msg: str) -> None:
        self._decompile_batch_done()
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
            self._log_panel.error("Cannot rename, function not yet decompiled")
            return

        # Find locals matching word under cursor
        locals_matching = [loc for loc in ir.all_locals if loc.name == word and loc.reg_idx is not None]
        if not locals_matching:
            self._log_panel.warn(f"No local named '{word}' in f@{findex}")
            return

        loc = locals_matching[0]
        assert loc.reg_idx is not None
        new_name, ok = QInputDialog.getText(self, "Rename", f"Rename '{word}' to:", text=word)
        if not ok or not new_name or new_name == word:
            return

        self._apply_rename(findex, loc.reg_idx, loc.defining_op_idx, new_name)
        self._log_panel.success(f"Renamed '{word}' → '{new_name}' in f@{findex}")

    def _apply_rename(self, findex: int, reg_idx: int, def_op: Optional[int], new_name: str) -> None:
        if self._code is None:
            return
        def_op_int = def_op
        self._code.annotations.rename(findex, reg_idx, def_op_int, new_name)
        self._dirty = True
        self._update_window_title()
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
                self._start_decompile(class_key, findex)
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
        self._dirty = True
        self._update_window_title()

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

        view = self._find_target_view()  # whichever pane (disasm or pseudo) is active
        if view is not None:
            at = view.mapToGlobal(view.cursorRect().bottomLeft())  # type: ignore[attr-defined]
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

    def _current_sync_view(self) -> Optional[SyncView]:
        w = self._tabs.currentWidget()
        return w if isinstance(w, SyncView) else None

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
            if isinstance(view, (SyncView, NativesView)):
                view.set_theme(theme)

    # ── Inspector ─────────────────────────────────────────────────────────────

    # ── Help ─────────────────────────────────────────────────────────────────

    def _show_about(self) -> None:
        link_color = self._theme.accent
        QMessageBox.about(
            self,
            "About crashlink",
            f"<h3>crashlink {VERSION}</h3>"
            "<p>A pure-Python HashLink bytecode disassembler, decompiler, and analysis toolkit.</p>"
            "<p>Author: N3rdL0rd<br>"
            f'<a href="https://github.com/N3rdL0rd/crashlink" style="color: {link_color};">'
            "github.com/N3rdL0rd/crashlink</a></p>",
        )

    def _show_shortcuts(self) -> None:
        rows = [
            ("Ctrl+O", "Open a bytecode file"),
            ("Ctrl+S", "Save the analysis database (.cldb)"),
            ("Ctrl+F", "Find in the active disasm/pseudocode pane"),
            ("Ctrl+Q", "Quit"),
            ("Tab", "Cycle split / disassembly / decompiled view"),
            ("N", "Rename the local under the cursor (pseudocode pane)"),
            ("X", "Show cross-references for the word under the cursor"),
            ("/", "Add/edit a comment on the opcode under the cursor"),
            ("Up / Down", "REPL command history (when the REPL input is focused)"),
        ]
        rows_html = "".join(f"<tr><td><b>{key}</b></td><td>&nbsp;&nbsp;{desc}</td></tr>" for key, desc in rows)
        box = QMessageBox(self)
        box.setWindowTitle("Keyboard Shortcuts")
        box.setText(f"<table>{rows_html}</table>")
        # QMessageBox ignores resize()/setFixedWidth() directly — widening its
        # internal label is the standard way to give it a bit more breathing room.
        box.setStyleSheet("QLabel{min-width: 400px;}")
        box.exec()

    # ── Cleanup ───────────────────────────────────────────────────────────────

    def closeEvent(self, event: object) -> None:
        if not self._confirm_discard_changes():
            event.ignore()  # type: ignore[attr-defined]
            return
        self._save_settings()
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
