"""Main application window.

`MainWindow` keeps its state, signals and UI wiring here; behaviour is split into
focused pieces:

- `workers.py` — background threads/jobs (document load, index build, decompile render)
- `chrome.py` — the small widgets and dialogs the window is assembled from
- `mixins/` — the window's methods, one cohesive area per module

The `.cldb` load thread (`_DbLoadThread`) and the `_load_database_from` /
`_save_database` / `_start_decompile` methods stay here because tests monkeypatch
`load_database`, `save_database` and `_DecompJob` through this module's namespace.
`_start_thread`/`_release_thread` also stay: `_release_thread` needs `sender()`,
which PySide6 only provides for slots defined directly on the QObject subclass
(see the comment above them).
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from copy import copy, deepcopy
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Set, Tuple

from PySide6.QtCore import QObject, QSettings, QThread, QThreadPool, Qt, Signal, Slot
from PySide6.QtGui import QUndoStack
from PySide6.QtWidgets import (
    QButtonGroup,
    QDockWidget,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenu,
    QProgressBar,
    QPushButton,
    QStackedWidget,
    QStatusBar,
    QTabWidget,
    QUndoView,
    QVBoxLayout,
    QWidget,
)

# Re-exported so tests can keep monkeypatching `gui.QFileDialog` / `gui.Bytecode`.
from PySide6.QtWidgets import QFileDialog as QFileDialog

from crashlink.core import AnalysisWorker, Bytecode
from crashlink.database import SessionState, load_database, save_database
from crashlink.pseudo.doc import RenderedSource

from .chrome import _BusyIndicator, _FindBar, _TabBar, _WelcomePage
from .mixins import (
    AnnotateMixin,
    FileIoMixin,
    MenusMixin,
    NavigationMixin,
    TabsMixin,
    ViewsMixin,
    XrefMixin,
)
from .mixins.views import _VIEW_MODE_CYCLE, _VIEW_MODE_GLYPHS, _VIEW_MODE_NAMES
from .themes import DEFAULT_THEME, THEMES, Theme
from .widgets.cfg_view import CfgView
from .widgets.function_list import FunctionList
from .widgets.log_panel import LogPanel
from .widgets.sync_view import PSEUDO
from .widgets.xref_panel import XrefPopup
from .workers import _BackgroundRunnable, _DecompJob, _IndexBuildThread

if TYPE_CHECKING:
    from crashlink.dehlc.emit import EmitContext
    from crashlink.dehlc.lift import FunctionLifter


# ── Database load thread (kept here: tests monkeypatch `load_database` in this module) ──
class _DbLoadSignals(QObject):
    finished = Signal(object, object, object)  # token, DatabaseLoadResult, annotations
    error = Signal(object, str)


class _DbLoadThread(QThread):
    """Load against private annotations; only the UI may apply accepted results."""

    def __init__(self, cldb_path: str, code: Bytecode, source_path: str, token: tuple) -> None:
        super().__init__()
        self.cldb_path = cldb_path
        self.code = copy(code)
        self.code.annotations = deepcopy(code.annotations)
        self.source_path = source_path
        self.token = token
        self.signals = _DbLoadSignals()

    def run(self) -> None:
        try:
            if self.isInterruptionRequested():
                return
            result = load_database(self.cldb_path, code=self.code, source_path=self.source_path)
            self.signals.finished.emit(self.token, result, self.code.annotations)
        except Exception as e:
            self.signals.error.emit(self.token, str(e))


class MainWindow(
    NavigationMixin,
    XrefMixin,
    AnnotateMixin,
    FileIoMixin,
    TabsMixin,
    ViewsMixin,
    MenusMixin,
    QMainWindow,
    QMenu,
):
    #: Bytecode once a load is accepted; None when a new load starts or the document closes.
    code_loaded = Signal(object)
    #: Theme after every theme change (and once at startup).
    theme_changed = Signal(object)
    #: findex whenever the focused function changes.
    function_focused = Signal(int)

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("crashlink")
        self.resize(1400, 900)

        self._code: Optional[Bytecode] = None
        # Two threads: the post-load index build and a decompile. Analysis is pure
        # Python, so more would add no throughput, only GIL contention for the UI.
        self._worker = AnalysisWorker(max_workers=2)
        # Pseudocode for finished decompiles is rendered here, one at a time, so the
        # UI thread never runs the renderer. Jobs stay referenced until they report.
        self._render_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="crashlink-render")
        self._decomp_jobs: Dict[tuple, _DecompJob] = {}
        self._generation = 0
        self._closing = False
        self._threads: Set[QThread] = set()
        self._db_request = 0
        self._decomp_request = 0
        self._decomp_tokens: Dict[Tuple[str, int], tuple] = {}
        # Bytecode loader or de-HL/C image loader; both expose `.signals`.
        self._load_thread: Optional[QThread] = None
        self._theme: Theme = DEFAULT_THEME
        # True when the current file was opened through the de-HL/C pipeline.
        self._loaded_via_dehlc = False
        # de-HL/C images: findex -> (header, rows) rendered machine code (None =
        # no code slot), plus the one-shot PLT map, both reset on file load.
        self._native_asm_cache: Dict[int, Optional[Tuple[str, List[str]]]] = {}
        self._plt_map: Optional[Dict[int, str]] = None
        # Which content the disassembly pane shows for de-HL/C images.
        self._disasm_source = "asm"
        # On-demand lifting state (reset per file).
        self._emit_ctx: Optional["EmitContext"] = None
        self._lifter: Optional["FunctionLifter"] = None
        self._fidx_addr: Dict[int, int] = {}
        self._arm_lift_warned = False

        # class_key → tab index; rebuilt on every add/remove
        self._open_tabs: Dict[str, int] = {}
        # class_key → ordered list of findices (display order)
        self._class_findices: Dict[str, List[int]] = {}
        # class_key → {findex: pseudo_text or None(pending)}
        self._class_results: Dict[str, Dict[int, Optional[str]]] = {}
        # class_key → canonical class display name
        self._class_names: Dict[str, str] = {}
        # class_key → field declaration lines shown at the top of the class tab
        self._class_fields: Dict[str, List[str]] = {}
        # findex → IRFunction
        self._ir_cache: Dict[int, object] = {}
        # findex → {opcode_index: body-relative pseudocode line}
        self._opline_cache: Dict[int, Dict[int, int]] = {}
        # findex → the function's rendered pseudocode with the symbol each token names
        self._spans_cache: Dict[int, RenderedSource] = {}
        # deferred navigation when the target's op map isn't cached yet
        self._pending_op_scroll: Optional[Tuple[int, int]] = None
        # global view mode (split/disasm/decompiled), applied to every open tab
        self._view_mode: int = PSEUDO
        # findex currently shown in the CFG dock, so decompile-finished can refresh it
        self._cfg_findex: Optional[int] = None
        # path of the currently-open bytecode file, for the sibling .cldb and Save Database
        self._source_path: Optional[str] = None
        # findex → RenderedSource (text + spans + opline map) loaded from a .cldb,
        # consumed by _open_class_tab to skip the "decompiling..." flash; a real
        # decompile still runs to warm _ir_cache
        self._db_cache: Dict[int, RenderedSource] = {}
        self._db_load_thread: Optional[_DbLoadThread] = None
        self._index_build_thread: Optional[_IndexBuildThread] = None
        # Number of current-document decompiles still awaiting their result.
        self._active_decompiles = 0
        # True once a rename/comment has been applied since the last save/load,
        # so closing/opening another file can prompt instead of discarding silently.
        self._dirty = False
        self._recent_files: List[str] = []
        self._undo_stack = QUndoStack(self)
        self._undo_stack.cleanChanged.connect(self._on_undo_clean_changed)
        self._undo_stack.indexChanged.connect(self._on_edit_index_changed)
        # Navigation history for Esc (back) / Ctrl+Enter (forward): (findex, op_idx).
        self._back_stack: List[Tuple[int, Optional[int]]] = []
        self._forward_stack: List[Tuple[int, Optional[int]]] = []
        # Function names for the Jump dialog: display name -> findex (built per document).
        self._jump_names: Dict[str, int] = {}
        # Generic tabs opened through `open_tab` (key -> widget).
        self._generic_tabs: Dict[str, QWidget] = {}
        self._menus: Dict[str, QMenu] = {}
        # `run_background` bookkeeping: token -> (generation, on_done, on_error).
        self._bg_request = 0
        self._bg_jobs: Dict[int, Tuple[int, Callable[[Any], None], Optional[Callable[[str], None]]]] = {}
        # Separate from the decompile pool so a long export never starves decompiles.
        self._bg_pool = QThreadPool(self)
        self._bg_pool.setMaxThreadCount(2)
        # Token prefix ("g@", ...) -> handler for double-click follow; see add_follow_handler.
        self._follow_handlers: Dict[str, Callable[[int], None]] = {}
        # Whether the status bar currently shows the symbol under the caret.
        self._symbol_status_shown = False

        self._build_ui()
        self._build_menu()
        self._busy = _BusyIndicator(self, self._busy_label, self._busy_bar)
        self._apply_theme(self._theme)
        self._log_panel.set_context(mw=self, code=None)

        from .features import install_all

        install_all(self)
        file_menu = self.menu("File")
        file_menu.addSeparator()
        file_menu.addAction(self._quit_action)
        self._restore_settings()
        # Lets the features installed above pick up the starting theme.
        self.theme_changed.emit(self._theme)

    # ── Settings (window geometry/layout/theme/view mode) ───────────────────────
    def _restore_settings(self) -> None:
        settings = QSettings("N3rdL0rd", "crashlink")
        geometry = settings.value("window/geometry")
        if geometry is not None:
            self.restoreGeometry(geometry)
        state = settings.value("window/state")
        if state is not None:
            self.restoreState(state)
        else:
            # First run: keep the log compact so the code area gets the height.
            self.resizeDocks([self._log_dock], [150], Qt.Orientation.Vertical)

        debug_output = settings.value("window/debug_output", False)
        self._debug_output_action.setChecked(debug_output in (True, "true", "1"))
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
        settings.setValue("window/debug_output", self._debug_output_action.isChecked())
        settings.setValue("recent_files", self._recent_files)

    def _update_window_title(self) -> None:
        if self._source_path is None:
            self.setWindowTitle("crashlink")
            return
        name = os.path.basename(self._source_path)
        star = "*" if self._dirty else ""
        mode = " [de-HL/C]" if self._loaded_via_dehlc else ""
        self.setWindowTitle(f"{name}{star}{mode} - crashlink")

    def _on_undo_clean_changed(self, clean: bool) -> None:
        self._dirty = not clean
        self._update_window_title()

    @Slot(int)
    def _on_edit_index_changed(self, _index: int) -> None:
        # A database snapshot must never overwrite edits made while it was loading.
        self._db_request += 1

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
            btn.setProperty(
                "segment",
                "first" if i == 0 else "last" if i == len(_VIEW_MODE_CYCLE) - 1 else "mid",
            )
            btn.setCheckable(True)
            btn.setFixedWidth(32)
            btn.setToolTip(f"{_VIEW_MODE_NAMES[mode]} view  (Tab to cycle)")
            mode_row.addWidget(btn)
            self._view_mode_group.addButton(btn, mode)
            self._view_mode_buttons[mode] = btn
        self._view_mode_group.idClicked.connect(self._set_view_mode)

        # ── Disassembly source toggle (de-HL/C images only): original machine
        # code vs lifted HL opcodes ───────────────────────────────────────────
        self._disasm_source_bar = QFrame()
        self._disasm_source_bar.setObjectName("viewModeBar")
        src_row = QHBoxLayout(self._disasm_source_bar)
        src_row.setContentsMargins(0, 0, 8, 0)
        src_row.setSpacing(0)
        self._disasm_source_group = QButtonGroup(self)
        self._disasm_source_group.setExclusive(True)
        for i, (src, label, tip) in enumerate(
            (
                ("asm", "Asm", "Disassembly pane shows original compiled machine code"),
                ("ops", "Lift", "Inspection-only approximate operations; unknown operands are shown as ?"),
            )
        ):
            btn = QPushButton(label)
            btn.setObjectName("modeBtnText")
            btn.setProperty("segment", "first" if i == 0 else "last")
            btn.setCheckable(True)
            btn.setChecked(i == 0)
            btn.setToolTip(tip)
            btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            btn.setFixedHeight(22)
            # QSS pads 10px/side (+2px borders); pin min width so the label can
            # never clip under a different theme font.
            btn.setMinimumWidth(btn.fontMetrics().horizontalAdvance(label) + 26)
            src_row.addWidget(btn)
            self._disasm_source_group.addButton(btn, i)
        self._disasm_source_group.idClicked.connect(
            lambda i: self._set_disasm_source("asm" if i == 0 else "ops")
        )
        self._disasm_source_bar.hide()

        corner = QWidget()
        corner_row = QHBoxLayout(corner)
        corner_row.setContentsMargins(0, 0, 0, 0)
        corner_row.setSpacing(6)
        corner_row.addWidget(self._disasm_source_bar)
        corner_row.addWidget(mode_bar)
        # Hold the container explicitly: QMenuBar.setCornerWidget does not take
        # C++ ownership, and a local would be GC'd along with every button in it.
        self._view_mode_corner = corner
        self.menuBar().setCornerWidget(corner, Qt.Corner.TopRightCorner)
        self._update_view_mode_label()

        # ── Central: welcome page / tab widget, with the find bar below ──────
        self._tab_bar = _TabBar()
        self._tabs = QTabWidget()
        self._tabs.setTabBar(self._tab_bar)
        self._tab_bar.middle_clicked.connect(self._close_tab_at)
        self._tabs.setTabsClosable(False)
        self._tabs.setMovable(True)
        self._tabs.setDocumentMode(True)
        self._welcome = _WelcomePage()
        self._welcome.open_requested.connect(self._open_file)
        self._welcome.recent_requested.connect(self._open_recent)
        self._central_stack = QStackedWidget()
        self._central_stack.addWidget(self._welcome)
        self._central_stack.addWidget(self._tabs)
        self._find_bar = _FindBar()
        central = QWidget()
        central_layout = QVBoxLayout(central)
        central_layout.setContentsMargins(0, 0, 0, 0)
        central_layout.setSpacing(0)
        central_layout.addWidget(self._central_stack, 1)
        central_layout.addWidget(self._find_bar)
        self.setCentralWidget(central)
        self.setAcceptDrops(True)

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

        # ── Bottom dock: edit history (undo buffer) — off by default ──────────
        self._history_view = QUndoView(self._undo_stack)
        self._history_dock = QDockWidget("Edit History", self)
        self._history_dock.setObjectName("historyDock")
        self._history_dock.setWidget(self._history_view)
        self._history_dock.setMinimumHeight(80)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self._history_dock)
        self._history_dock.hide()

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
        self._busy_label = QLabel("")
        self._busy_label.setObjectName("busyLabel")
        self._busy_label.hide()
        self._busy_bar = QProgressBar()
        self._busy_bar.setObjectName("busyBar")
        self._busy_bar.setFixedWidth(120)
        self._busy_bar.setFixedHeight(6)
        self._busy_bar.setTextVisible(False)
        self._busy_bar.hide()
        self._status_bar.addWidget(self._status_label)
        self._status_bar.addPermanentWidget(self._busy_label)
        self._status_bar.addPermanentWidget(self._busy_bar)
        self._status_bar.addPermanentWidget(self._progress_bar)

        # ── Signals ───────────────────────────────────────────
        self._func_list.function_selected.connect(self.navigate_to)
        self._tabs.currentChanged.connect(self._on_tab_changed)
        self._tab_bar.tabMoved.connect(lambda *_: self._rebuild_tab_map())
        self._cfg_view.op_activated.connect(self.navigate_to)

    # ── Public API (used by crashlink.gui.features) ───────────────────────────
    @property
    def code(self) -> Optional[Bytecode]:
        return self._code

    @property
    def theme(self) -> Theme:
        return self._theme

    @property
    def log(self) -> LogPanel:
        return self._log_panel

    @property
    def source_path(self) -> Optional[str]:
        """Path of the open document, or None."""
        return self._source_path

    def open_tab(self, key: str, title: str, factory: Callable[[], QWidget]) -> QWidget:
        """Focus the tab registered under `key`, creating it with `factory` if needed."""
        existing = self._generic_tabs.get(key)
        if existing is not None and key in self._open_tabs:
            self._tabs.setCurrentIndex(self._open_tabs[key])
            return existing
        widget = factory()
        widget.setProperty("class_key", key)
        self._generic_tabs[key] = widget
        idx = self._tabs.addTab(widget, title)
        self._open_tabs[key] = idx
        self._add_close_btn(idx, key)
        self._tabs.setCurrentIndex(idx)
        return widget

    def run_background(
        self,
        label: str,
        fn: Callable[[], Any],
        on_done: Callable[[Any], None],
        on_error: Optional[Callable[[str], None]] = None,
    ) -> None:
        """Run `fn` on a worker thread with a status-bar indicator. `on_done` /
        `on_error` run on the UI thread; results for a replaced document are dropped."""
        self._bg_request += 1
        token = self._bg_request
        self._bg_jobs[token] = (self._generation, on_done, on_error)
        job = _BackgroundRunnable(token, fn)
        job.signals.done.connect(self._on_background_done)
        job.signals.failed.connect(self._on_background_failed)
        self._busy.start(label, key=("bg", token))
        self._bg_pool.start(job)

    @Slot(object, object)
    def _on_background_done(self, token: int, result: object) -> None:
        self._busy.stop(key=("bg", token))
        job = self._bg_jobs.pop(token, None)
        if job is None or not self._is_current(job[0]):
            return
        job[1](result)

    @Slot(object, str)
    def _on_background_failed(self, token: int, message: str) -> None:
        self._busy.stop(key=("bg", token))
        job = self._bg_jobs.pop(token, None)
        if job is None or not self._is_current(job[0]):
            return
        if job[2] is not None:
            job[2](message)
        else:
            self._log_panel.error(message)

    # ── Thread registry ───────────────────────────────────────────────────────
    # `_release_thread` must stay a direct MainWindow class member: with plain-Python
    # mixins in the bases, PySide6 6.11 delivers signals to inherited slots without
    # sender() context (the first connection to a direct method decides it), and this
    # is the only slot that relies on sender().

    def _start_thread(self, thread: QThread) -> None:
        self._threads.add(thread)
        thread.finished.connect(self._release_thread)
        thread.start()

    @Slot()
    def _release_thread(self) -> None:
        thread = self.sender()
        if isinstance(thread, QThread):
            thread.wait()
            self._threads.discard(thread)
            for attr in ("_load_thread", "_db_load_thread", "_index_build_thread"):
                if getattr(self, attr) is thread:
                    setattr(self, attr, None)
            thread.deleteLater()

    # ── Decompile jobs (`_DecompJob` is monkeypatched in tests) ───────────────
    def _start_decompile(self, class_key: str, findex: int) -> None:
        assert self._code is not None
        if self._code.inspection_only:
            self._log_panel.warn(
                "Inspection-only native recovery: use the approximate lift or original assembly view."
            )
            return
        self._active_decompiles += 1
        self._busy.start("Decompiling...", key="decompile")
        self._decomp_request += 1
        token = (self._generation, self._decomp_request)
        self._decomp_tokens[(class_key, findex)] = token
        job = _DecompJob(class_key, findex, token)
        job.finished.connect(self._on_decompile_finished)
        job.error.connect(self._on_decompile_error)
        self._decomp_jobs[token] = job
        job.start(self._worker, self._code, self._render_pool)

    # ── Analysis database (.cldb) ───────────────────────────────────────────────
    def _load_database_from(self, cldb_path: str) -> None:
        assert self._code is not None and self._source_path is not None
        self._db_request += 1
        token = (self._generation, self._db_request)
        self._db_load_thread = _DbLoadThread(cldb_path, self._code, self._source_path, token)
        self._db_load_thread.signals.finished.connect(self._on_db_load_finished)
        self._db_load_thread.signals.error.connect(self._on_db_load_error)
        self._start_thread(self._db_load_thread)

    def _save_database(self) -> bool:
        if self._code is None or self._source_path is None:
            self._log_panel.warn("Open a bytecode file first.")
            return False

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
                spans_cache=self._spans_cache,
                session=session,
            )
        except Exception as e:
            self._log_panel.error(f"Failed to save database: {e}")
            return False
        self._undo_stack.setClean()
        self._dirty = False
        self._db_request += 1
        self._update_window_title()
        self._log_panel.success(f"Saved database to {cldb_path}")
        return True
