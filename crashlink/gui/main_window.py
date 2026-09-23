"""Main application window."""

from __future__ import annotations

from copy import copy, deepcopy
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager
import gc
import os
import re
from typing import TYPE_CHECKING, Any, Callable, Dict, Iterator, List, Optional, Set, Tuple, cast

from PySide6.QtCore import (
    QChildEvent,
    QEvent,
    QRect,
    QRunnable,
    QSettings,
    QThread,
    QThreadPool,
    QTimer,
    Qt,
    Signal,
    Slot,
    QObject,
    QSize,
)
from PySide6.QtGui import (
    QAction,
    QCloseEvent,
    QColor,
    QDragEnterEvent,
    QDropEvent,
    QKeyEvent,
    QKeySequence,
    QPainter,
    QPaintEvent,
    QTextCursor,
    QTextDocument,
    QUndoStack,
    QMouseEvent,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QCompleter,
    QDialog,
    QDialogButtonBox,
    QDockWidget,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QStackedWidget,
    QStatusBar,
    QTabBar,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolButton,
    QUndoView,
    QVBoxLayout,
    QWidget,
)

from crashlink.core import AnalysisWorker, AnnotationStore, Bytecode, Function, Native, destaticify

if TYPE_CHECKING:
    from crashlink.asm import FunctionEdit
    from crashlink.dehlc.emit import EmitContext
    from crashlink.dehlc.lift import FunctionLifter
from crashlink.database import (
    DatabaseLoadResult,
    SessionState,
    load_database,
    save_database,
)
from crashlink.decomp.function import IRFunction, _cached_enum_global_map
from crashlink.globals import VERSION, set_dbg_callback
from crashlink.pseudo import _method_registry, class_field_lines, pseudo_oplines

from .themes import DEFAULT_THEME, THEMES, Theme, generate_qss
from .undo import CommentCommand, RenameCommand, ReplaceFunctionCommand, SetStringCommand
from .widgets.cfg_view import CfgView
from .widgets.class_view import ClassView
from .widgets.function_list import FunctionList, NavigatorData
from .widgets.log_panel import LogPanel
from .widgets.natives_view import NativesView
from .widgets.sync_view import DISASM, PSEUDO, SPLIT, SyncView
from .widgets.types_view import TypesView
from .widgets.xref_panel import (
    XrefPopup,
    resolve_targets,
    XrefGroup,
    XrefSite,
    _func_label,
)


# View mode cycling: Tab steps through split → disassembly → decompiled → …
_VIEW_MODE_CYCLE = [SPLIT, DISASM, PSEUDO]
_VIEW_MODE_NAMES = {SPLIT: "Split", DISASM: "Disassembly", PSEUDO: "Decompiled"}
_VIEW_MODE_GLYPHS = {SPLIT: "◧", DISASM: "≡", PSEUDO: "{ }"}

# Top-level menus, in menu-bar order; `MainWindow.menu()` creates them on demand.
_MENU_ORDER = ("File", "Edit", "View", "Jump", "Search", "Tools", "Window", "Help")

# Navigation history depth (Esc / Ctrl+Enter).
_HISTORY_LIMIT = 200

# Keys handled inside the code views themselves, listed in the shortcuts dialog
# alongside every menu action's shortcut.
_IN_VIEW_KEYS = [
    ("Double-click / Enter", "Follow the function, type or global under the cursor"),
    ("Hover", "Show docs for opcodes and details for f@ / g@ / t@ references"),
    ("N", "Rename the local under the cursor (pseudocode pane)"),
    ("X", "Show cross-references for the word under the cursor"),
    ("/", "Add/edit a comment on the opcode under the cursor"),
    ("Tab", "Cycle split / disassembly / decompiled view"),
    ("Middle-click", "Close a tab, or a dock by its title bar or tab"),
    ("Up / Down", "REPL command history (when the REPL input is focused)"),
    ("Click (CFG)", "Jump to the clicked block"),
    ("0 / 1 (CFG)", "Fit the whole graph / zoom to 100%"),
    ("Enter / X (tables)", "Cross-references for the selected string or global"),
    ("F2 (Strings)", "Edit the selected string"),
]


def _looks_like_native_image(path: str) -> bool:
    """True when the file is an ELF image or PE executable (HL/C-compiled binary)
    rather than serialised HashLink bytecode."""
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except OSError:
        return False
    return head[:4] == b"\x7fELF" or head[:2] == b"MZ"


# ── Async helpers ─────────────────────────────────────────────────────────────


@contextmanager
def _bulk_build() -> Iterator[None]:
    """Pause the cyclic GC while building a large, long-lived structure (the loaded
    document, its indices), then freeze the result. Otherwise the GC walks those
    millions of new objects once per generation as they age, each pass holding the
    GIL for up to a second and freezing the UI; frozen, later passes skip them.
    `_load_file` unfreezes before the next document loads."""
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        yield
    finally:
        gc.freeze()
        if was_enabled:
            gc.enable()


class _LoadSignals(QObject):
    progress = Signal(int, float, str)
    finished = Signal(int, object, object)  # generation, Bytecode, NavigatorData
    error = Signal(int, str)


class _LoadThread(QThread):
    def __init__(self, path: str, generation: int) -> None:
        super().__init__()
        self.path = path
        self.generation = generation
        self.signals = _LoadSignals()

    def run(self) -> None:
        try:

            def _cb(frac: float, status: str) -> None:
                if self.isInterruptionRequested():
                    raise InterruptedError("Document load cancelled")
                self.signals.progress.emit(self.generation, frac, status)

            with _bulk_build():
                code = Bytecode.from_path(self.path, progress_cb=_cb)
                # Navigator data is pure Python work over every function. Build it
                # here so the UI thread only creates the tree items.
                nav_data = FunctionList.prepare(code)
            self.signals.finished.emit(self.generation, code, nav_data)
        except Exception as e:
            self.signals.error.emit(self.generation, str(e))


class _DehlcLoadThread(_LoadThread):
    """Loads a native image off the UI thread, with cancellation between phases."""

    def run(self) -> None:
        try:
            from crashlink.dehlc import code_from_bin

            def _cb(status: str) -> None:
                if self.isInterruptionRequested():
                    raise InterruptedError("Document load cancelled")
                self.signals.progress.emit(self.generation, -1.0, f"de-HL/C: {status}")

            with _bulk_build():
                code = code_from_bin(path=self.path, verbose=False, progress_cb=_cb)
                nav_data = FunctionList.prepare(code)
            self.signals.finished.emit(self.generation, code, nav_data)
        except ImportError:
            self.signals.error.emit(
                self.generation,
                "de-HL/C needs crashlink[extras] (`pip install lief capstone`) to open compiled binaries.",
            )
        except Exception as e:
            self.signals.error.emit(self.generation, str(e))


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


class _DecompJob(QObject):
    """One decompile request. The IR comes from the shared AnalysisWorker; its
    pseudocode is rendered on `render_pool` too, so the UI thread only inserts text.
    No thread sits blocked waiting on the future."""

    # token, class_key, findex, IRFunction, (pseudo text, {op index: body line})
    finished = Signal(object, str, int, object, object)
    error = Signal(object, str, int, str)

    def __init__(self, class_key: str, findex: int, token: tuple) -> None:
        super().__init__()
        self.class_key = class_key
        self.findex = findex
        self.token = token

    def start(self, worker: AnalysisWorker, code: Bytecode, render_pool: ThreadPoolExecutor) -> None:
        future = worker.decompile(code, self.findex)
        # The callback may run on the decompile thread or, for a cached result,
        # right here; either way the rendering itself goes to render_pool.
        future.add_done_callback(lambda done: self._queue_render(render_pool, done))

    def _queue_render(self, render_pool: ThreadPoolExecutor, future: "Future[Any]") -> None:
        try:
            render_pool.submit(self._render, future)
        except RuntimeError:
            pass  # window closing: the render pool is shut down and nobody wants the result

    def _render(self, future: "Future[Any]") -> None:
        try:
            ir = future.result()
        except BaseException as e:  # includes CancelledError
            self.error.emit(self.token, self.class_key, self.findex, str(e) or type(e).__name__)
            return
        try:
            rendered: Tuple[str, Dict[int, int]] = pseudo_oplines(ir)
        except Exception as e:
            rendered = (f"class ? {{\n    // f@{self.findex} error: {e}\n}}", {})
        self.finished.emit(self.token, self.class_key, self.findex, ir, rendered)


class _IndexBuildSignals(QObject):
    finished = Signal(int)
    error = Signal(int, str)


class _IndexBuildThread(QThread):
    """Pre-warm document indices without blocking the UI."""

    def __init__(self, worker: AnalysisWorker, code: Bytecode, generation: int) -> None:
        super().__init__()
        self.generation = generation
        self.signals = _IndexBuildSignals()
        self._code = code
        self._future = worker.build_indices(code, self._progress)

    def _progress(self, _frac: float, _status: str) -> None:
        if self.isInterruptionRequested():
            raise InterruptedError("Index build cancelled")

    def run(self) -> None:
        try:
            with _bulk_build():
                self._future.result()
                if not self._code.inspection_only and not self.isInterruptionRequested():
                    # The first decompile would otherwise pay this whole-image scan
                    # (~1 s on large games) while the user waits for the tab.
                    _cached_enum_global_map(self._code)
            self.signals.finished.emit(self.generation)
        except Exception as e:
            self.signals.error.emit(self.generation, str(e))

    def requestInterruption(self) -> None:
        self._future.cancel()
        super().requestInterruption()


# ── Main window ───────────────────────────────────────────────────────────────


class _TabBar(QTabBar):
    """QTabBar that paints the empty area to the right of the last tab.

    Qt's style engine repaints the tab bar background (including the empty
    area) after our pre-fill, overriding it.  Painting only the uncovered
    region AFTER super() wins the z-order race.
    """

    _fill: QColor = QColor("#181825")
    #: Index of a tab middle-clicked (released over the tab it was pressed on).
    middle_clicked = Signal(int)

    def __init__(self) -> None:
        super().__init__()
        self._middle_pressed = -1

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.MiddleButton:
            self._middle_pressed = self.tabAt(event.position().toPoint())
            return
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.MiddleButton:
            index = self.tabAt(event.position().toPoint())
            if index >= 0 and index == self._middle_pressed:
                self.middle_clicked.emit(index)
            self._middle_pressed = -1
            return
        super().mouseReleaseEvent(event)

    def paintEvent(self, event: QPaintEvent) -> None:
        super().paintEvent(event)
        # Find where the last tab ends; fill everything to the right.
        empty_x = 0
        for i in range(self.count()):
            empty_x = max(empty_x, self.tabRect(i).right() + 1)
        if empty_x < self.width():
            p = QPainter(self)
            p.fillRect(QRect(empty_x, 0, self.width() - empty_x, self.height()), self._fill)
            p.end()


class _DockMiddleClose(QObject):
    """Closes a dock when its title bar, or its tab in a group of tabbed docks, is
    middle-clicked: the same as its close button."""

    def __init__(self, window: QMainWindow) -> None:
        super().__init__(window)
        self._window = window

    def watch(self, obj: QObject) -> None:
        obj.installEventFilter(self)  # Qt keeps one entry per filter

    def eventFilter(self, obj: QObject, event: QEvent) -> bool:
        if event.type() != QEvent.Type.MouseButtonRelease:
            return False
        mouse = cast(QMouseEvent, event)
        if mouse.button() != Qt.MouseButton.MiddleButton:
            return False
        pos = mouse.position().toPoint()
        dock: Optional[QDockWidget] = None
        if isinstance(obj, QDockWidget):
            # Unhandled clicks in the dock's contents bubble up here too.
            content = obj.widget()
            if pos.y() < (content.geometry().top() if content is not None else obj.height()):
                dock = obj
        elif isinstance(obj, QTabBar):
            index = obj.tabAt(pos)
            if index >= 0:
                dock = self._tabbed_dock(obj.tabText(index))
        if dock is None or not dock.features() & QDockWidget.DockWidgetFeature.DockWidgetClosable:
            return False
        dock.close()
        return True

    def _tabbed_dock(self, title: str) -> Optional[QDockWidget]:
        for dock in self._window.findChildren(QDockWidget):
            if dock.windowTitle() == title and self._window.tabifiedDockWidgets(dock):
                return dock
        return None


class _BusyIndicator:
    """Status-bar activity indicator: a label plus a thin indeterminate bar, shown
    only once an operation has run for `delay_ms` so quick ones never flash.

    Jobs are keyed so independent work (document load, decompiles, background
    tasks) can overlap; the most recently started job's label is shown."""

    def __init__(self, parent: QWidget, label: QLabel, bar: QProgressBar, delay_ms: int = 300) -> None:
        self._label = label
        self._bar = bar
        self._jobs: Dict[object, str] = {}
        self._timer = QTimer(parent)
        self._timer.setSingleShot(True)
        self._timer.setInterval(delay_ms)
        self._timer.timeout.connect(self._reveal)

    def start(self, action: str, key: object = "main") -> None:
        self._jobs.pop(key, None)
        self._jobs[key] = action
        if self._label.isVisible():
            self._label.setText(action)
        elif not self._timer.isActive():
            self._timer.start()

    def stop(self, key: object = "main") -> None:
        self._jobs.pop(key, None)
        if self._jobs:
            self._label.setText(next(reversed(self._jobs.values())))
            return
        self._timer.stop()
        self._label.hide()
        self._bar.hide()

    def stop_all(self) -> None:
        self._jobs.clear()
        self.stop()

    def _reveal(self) -> None:
        if not self._jobs:
            return
        self._label.setText(next(reversed(self._jobs.values())))
        self._label.show()
        self._bar.setRange(0, 0)
        self._bar.show()


class _FindBar(QFrame):
    """Inline find bar docked under the code tabs (Ctrl+F). Searches the pane it
    was opened on, reports `n of m`, wraps around, and closes on Esc."""

    closed = Signal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("findBar")
        self._target: Optional[QPlainTextEdit] = None

        row = QHBoxLayout(self)
        row.setContentsMargins(8, 4, 8, 4)
        row.setSpacing(6)
        row.addWidget(QLabel("Find"))
        self._input = QLineEdit()
        self._input.setPlaceholderText("Search this pane…")
        self._input.setClearButtonEnabled(True)
        self._input.textChanged.connect(self._on_text_changed)
        self._input.installEventFilter(self)
        row.addWidget(self._input, 1)
        self._count = QLabel("")
        self._count.setObjectName("findCount")
        self._count.setMinimumWidth(90)
        row.addWidget(self._count)
        self._case = QToolButton()
        self._case.setText("Aa")
        self._case.setCheckable(True)
        self._case.setToolTip("Match case")
        self._case.toggled.connect(lambda _: self._on_text_changed(self._input.text()))
        row.addWidget(self._case)
        prev_btn = QToolButton()
        prev_btn.setText("↑")
        prev_btn.setToolTip("Previous match (Shift+Enter)")
        prev_btn.clicked.connect(self.find_prev)
        row.addWidget(prev_btn)
        next_btn = QToolButton()
        next_btn.setText("↓")
        next_btn.setToolTip("Next match (Enter)")
        next_btn.clicked.connect(self.find_next)
        row.addWidget(next_btn)
        close_btn = QToolButton()
        close_btn.setText("×")
        close_btn.setToolTip("Close (Esc)")
        close_btn.clicked.connect(self.close_bar)
        row.addWidget(close_btn)
        self.hide()

    def open_on(self, target: QPlainTextEdit) -> None:
        self._target = target
        selected = target.textCursor().selectedText()
        if selected and "\u2029" not in selected:
            self._input.setText(selected)
        self.show()
        self._input.setFocus()
        self._input.selectAll()
        self._update_count()

    def close_bar(self) -> None:
        self.hide()
        if self._target is not None:
            self._target.setFocus()
        self.closed.emit()

    def find_next(self) -> None:
        self._find(backward=False)

    def find_prev(self) -> None:
        self._find(backward=True)

    def eventFilter(self, obj: QObject, event: QEvent) -> bool:
        if obj is self._input and event.type() == QEvent.Type.KeyPress:
            key_event = cast(QKeyEvent, event)
            if key_event.key() == Qt.Key.Key_Escape:
                self.close_bar()
                return True
            if key_event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                self._find(backward=bool(key_event.modifiers() & Qt.KeyboardModifier.ShiftModifier))
                return True
        return super().eventFilter(obj, event)

    def _flags(self, backward: bool = False) -> QTextDocument.FindFlag:
        flags = QTextDocument.FindFlag(0)
        if self._case.isChecked():
            flags |= QTextDocument.FindFlag.FindCaseSensitively
        if backward:
            flags |= QTextDocument.FindFlag.FindBackward
        return flags

    def _on_text_changed(self, _text: str) -> None:
        # Search-as-you-type from the start of the current selection.
        if self._target is not None and self._input.text():
            cursor = self._target.textCursor()
            cursor.setPosition(cursor.selectionStart())
            self._target.setTextCursor(cursor)
            self._find(backward=False)
        else:
            self._update_count()

    def _find(self, backward: bool) -> None:
        text = self._input.text()
        if self._target is None or not text:
            return
        flags = self._flags(backward)
        if not self._target.find(text, flags):
            # No match from the current position: wrap around and retry once.
            cursor = self._target.textCursor()
            cursor.movePosition(
                QTextCursor.MoveOperation.End if backward else QTextCursor.MoveOperation.Start
            )
            self._target.setTextCursor(cursor)
            self._target.find(text, flags)
        self._update_count()

    def _update_count(self) -> None:
        text = self._input.text()
        if self._target is None or not text:
            self._count.setText("")
            return
        doc = self._target.document()
        flags = self._flags()
        current = self._target.textCursor().selectionStart()
        total = index = 0
        cursor = doc.find(text, 0, flags)
        while not cursor.isNull():
            total += 1
            if cursor.selectionStart() == current:
                index = total
            cursor = doc.find(text, cursor, flags)
        self._count.setText("No matches" if total == 0 else f"{index or '?'} of {total}")
        self._count.setProperty("empty", total == 0)
        self._count.style().unpolish(self._count)
        self._count.style().polish(self._count)


class _WelcomePage(QWidget):
    """Shown in place of the tab area when no tabs are open: how to open a file,
    plus the recent-files list."""

    open_requested = Signal()
    recent_requested = Signal(str)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("welcomePage")
        outer = QVBoxLayout(self)
        outer.addStretch(2)
        column = QVBoxLayout()
        column.setSpacing(10)
        title = QLabel("crashlink")
        title.setObjectName("welcomeTitle")
        column.addWidget(title)
        open_btn = QPushButton("Open file…  (Ctrl+O)")
        open_btn.setObjectName("welcomeOpen")
        open_btn.clicked.connect(self.open_requested)
        column.addWidget(open_btn, 0, Qt.AlignmentFlag.AlignLeft)
        self._recent_title = QLabel("Recent files")
        self._recent_title.setObjectName("welcomeSection")
        column.addSpacing(12)
        column.addWidget(self._recent_title)
        self._recent = QListWidget()
        self._recent.setObjectName("welcomeRecent")
        self._recent.setMaximumWidth(720)
        self._recent.setMaximumHeight(260)
        # Double-click (or Enter) opens: itemActivated fires on a single click under
        # some desktop styles, which makes it too easy to open a file by accident.
        self._recent.itemDoubleClicked.connect(self._open_item)
        self._recent.installEventFilter(self)
        column.addWidget(self._recent)
        row = QHBoxLayout()
        row.addStretch(1)
        row.addLayout(column, 3)
        row.addStretch(1)
        outer.addLayout(row)
        outer.addStretch(3)

    def _open_item(self, item: QListWidgetItem) -> None:
        self.recent_requested.emit(item.data(Qt.ItemDataRole.UserRole))

    def eventFilter(self, obj: QObject, event: QEvent) -> bool:
        if obj is self._recent and event.type() == QEvent.Type.KeyPress:
            if cast(QKeyEvent, event).key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                item = self._recent.currentItem()
                if item is not None:
                    self._open_item(item)
                return True
        return super().eventFilter(obj, event)

    def set_recent(self, paths: List[str]) -> None:
        self._recent.clear()
        for path in paths:
            item = QListWidgetItem(f"{os.path.basename(path)}    {os.path.dirname(path)}")
            item.setData(Qt.ItemDataRole.UserRole, path)
            item.setToolTip(path)
            self._recent.addItem(item)
        self._recent_title.setVisible(bool(paths))
        self._recent.setVisible(bool(paths))


class _JumpDialog(QDialog):
    """IDA-style "Jump to" (G): accepts `f@N`, a bare findex, or a function name
    (with completion over every function)."""

    def __init__(self, parent: QWidget, names: List[str], resolve: Callable[[str], "int | str"]) -> None:
        super().__init__(parent)
        self.setWindowTitle("Jump to function")
        self.setMinimumWidth(520)
        self._resolve = resolve
        self.findex: Optional[int] = None
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Function index (f@123 or 123) or name:"))
        self.input = QLineEdit()
        completer = QCompleter(names, self)
        completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        completer.setFilterMode(Qt.MatchFlag.MatchContains)
        completer.setMaxVisibleItems(15)
        self.input.setCompleter(completer)
        layout.addWidget(self.input)
        self.error = QLabel("")
        self.error.setObjectName("dialogError")
        layout.addWidget(self.error)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def accept(self) -> None:
        result = self._resolve(self.input.text().strip())
        if isinstance(result, str):
            self.error.setText(result)
            return
        self.findex = result
        super().accept()


class _BackgroundSignals(QObject):
    done = Signal(object, object)  # token, result
    failed = Signal(object, str)  # token, message


class _BackgroundRunnable(QRunnable):
    """Runs one `MainWindow.run_background` job on the shared thread pool."""

    def __init__(self, token: object, fn: Callable[[], Any]) -> None:
        super().__init__()
        self._token = token
        self._fn = fn
        self.signals = _BackgroundSignals()

    def run(self) -> None:
        try:
            result = self._fn()
        except Exception as e:
            self.signals.failed.emit(self._token, f"{type(e).__name__}: {e}")
            return
        self.signals.done.emit(self._token, result)


class MainWindow(QMainWindow):
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

    def _build_menu(self) -> None:
        fm = self.menu("File")
        fm.addAction("Open…", QKeySequence("Ctrl+O"), self._open_file)
        self._recent_menu = fm.addMenu("Open Recent")
        self._rebuild_recent_menu()
        fm.addSeparator()
        fm.addAction("Save Database", QKeySequence("Ctrl+S"), self._save_database)
        fm.addAction("Load Database…", self._open_database_file)
        fm.addSeparator()
        export_menu = self.menu("File/Export")
        export_menu.addAction("Disassembly of Current Tab…", self._export_disasm)
        export_menu.addAction("Pseudocode of Current Tab…", self._export_pseudo)
        export_menu.addSeparator()
        self._quit_action = QAction("Quit", self)
        self._quit_action.setShortcut(QKeySequence("Ctrl+Q"))
        self._quit_action.triggered.connect(self.close)

        em = self.menu("Edit")
        undo_action = self._undo_stack.createUndoAction(self, "Undo")
        undo_action.setShortcut("Ctrl+Z")
        redo_action = self._undo_stack.createRedoAction(self, "Redo")
        redo_action.setShortcut("Ctrl+Shift+Z")
        em.addAction(undo_action)
        em.addAction(redo_action)

        vm = self.menu("View")
        tm = vm.addMenu("Theme")
        for name in THEMES:
            tm.addAction(name, lambda n=name: self._apply_theme(THEMES[n]))
        vm.addSeparator()
        vm.addAction("Cycle View\tTab", self._cycle_view_mode)
        self._debug_output_action = vm.addAction("Decompiler Debug Output")
        self._debug_output_action.setCheckable(True)
        self._debug_output_action.setToolTip("Stream the decompiler's internal debug messages into the Log")
        self._debug_output_action.toggled.connect(self._set_debug_output)

        # Single-key, IDA-style navigation keys only fire while the code area has
        # focus, so typing in line edits (REPL, filters, the find bar) is unaffected.
        jm = self.menu("Jump")
        self._back_action = self._central_action("Back", ["Esc", "Alt+Left"], self.navigate_back)
        self._forward_action = self._central_action(
            "Forward", ["Ctrl+Return", "Alt+Right"], self.navigate_forward
        )
        self._jump_action = self._central_action("Jump to Function…", ["G"], self._open_jump_dialog)
        jm.addAction(self._back_action)
        jm.addAction(self._forward_action)
        jm.addSeparator()
        jm.addAction(self._jump_action)
        self._update_history_actions()

        sm = self.menu("Search")
        find_action = QAction("Find in Pane…", self)
        find_action.setShortcut(QKeySequence("Ctrl+F"))
        find_action.triggered.connect(self._open_find)
        sm.addAction(find_action)
        sm.addSeparator()

        wm = self.menu("Window")
        wm.addAction(self._nav_dock.toggleViewAction())
        wm.addAction(self._log_dock.toggleViewAction())
        cfg_toggle = self._cfg_dock.toggleViewAction()
        wm.addAction(cfg_toggle)
        self._cfg_space_action = self._central_action("Toggle CFG", ["Space"], self._toggle_cfg_dock)
        wm.addAction(self._cfg_space_action)
        wm.addAction(self._history_dock.toggleViewAction())
        wm.addSection("Views")
        wm.addAction("Natives", self._open_natives_tab)
        wm.addAction("Types", self._open_types_tab)

        hm = self.menu("Help")
        hm.addAction("Keyboard Shortcuts…", self._show_shortcuts)
        hm.addAction("About crashlink…", self._show_about)

    def _central_action(self, text: str, keys: List[str], slot: Callable[[], None]) -> QAction:
        """A QAction whose shortcut is live only while the central code area has focus."""
        action = QAction(text, self)
        action.setShortcuts([QKeySequence(k) for k in keys])
        action.setShortcutContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        action.triggered.connect(slot)
        self._central_stack.addAction(action)
        return action

    def _toggle_cfg_dock(self) -> None:
        self._cfg_dock.setVisible(not self._cfg_dock.isVisible())

    def _set_debug_output(self, enabled: bool) -> None:
        # Off by default: the decompiler emits over a thousand debug lines per class.
        set_dbg_callback(self._log_panel.debug if enabled else None)

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

    def menu(self, name: str) -> QMenu:
        """Get or create a menu. `name` is a top-level menu title, or a
        slash-separated path to a submenu (e.g. "File/Export")."""
        existing = self._menus.get(name)
        if existing is not None:
            return existing
        parent_name, _, leaf = name.rpartition("/")
        if parent_name:
            created = self.menu(parent_name).addMenu(leaf)
        else:
            created = QMenu(leaf, self)
            mb = self.menuBar()
            # Keep top-level menus in _MENU_ORDER; unknown names go before Help.
            order = _MENU_ORDER.index(leaf) if leaf in _MENU_ORDER else _MENU_ORDER.index("Help")
            before = next(
                (
                    self._menus[other].menuAction()
                    for other in _MENU_ORDER[order + 1 :]
                    if other in self._menus
                ),
                None,
            )
            if before is None:
                mb.addMenu(created)
            else:
                mb.insertMenu(before, created)
        self._menus[name] = created
        return created

    def add_dock(self, dock: QDockWidget, area: Qt.DockWidgetArea, visible: bool = False) -> None:
        """Add a feature dock (its objectName must be set so layout state restores)."""
        assert dock.objectName(), "feature docks need an objectName for saveState/restoreState"
        self.addDockWidget(area, dock)
        dock.setVisible(visible)
        self.menu("Window").insertAction(self._history_dock.toggleViewAction(), dock.toggleViewAction())

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

    def show_xrefs(self, title: str, groups: List[XrefGroup]) -> None:
        """Show `groups` in the xref popup, under the text cursor of the active pane if any."""
        view = self._find_target_view()
        if view is not None and view.isVisible():
            at = view.mapToGlobal(view.cursorRect().bottomLeft())
        else:
            at = self.mapToGlobal(self.rect().center())
        self._xref_popup.show_results(title, groups, at)

    def add_follow_handler(self, prefix: str, handler: Callable[[int], None]) -> None:
        """Handle double-click/Enter on `<prefix><index>` tokens (e.g. "g@" -> globals window)."""
        self._follow_handlers[prefix] = handler

    # ── Navigation (history, jump, follow) ────────────────────────────────────

    def navigate_to(self, findex: int, op_idx: Optional[int] = None) -> None:
        """Open the class tab containing `findex`, scroll to it (and to `op_idx` if
        given), focus the code, and record the jump for Back/Forward."""
        if self._code is None or findex not in self._code.get_findex_map():
            return
        self._push_history()
        self._forward_stack.clear()
        self._show_location(findex, -1 if op_idx is None else op_idx, -1)
        self._update_history_actions()

    def navigate_back(self) -> None:
        if not self._back_stack:
            return
        current = self._current_location()
        if current is not None:
            self._forward_stack.append(current)
        findex, op_idx = self._back_stack.pop()
        self._show_location(findex, -1 if op_idx is None else op_idx, -1)
        self._update_history_actions()

    def navigate_forward(self) -> None:
        if not self._forward_stack:
            return
        self._push_history()
        findex, op_idx = self._forward_stack.pop()
        self._show_location(findex, -1 if op_idx is None else op_idx, -1)
        self._update_history_actions()

    def _current_location(self) -> Optional[Tuple[int, Optional[int]]]:
        view = self._current_sync_view()
        if view is None or self._cfg_findex is None:
            return None
        op = view.disasm_view.op_at_cursor() if view.disasm_view.hasFocus() else None
        if op is not None and op[0] == self._cfg_findex:
            return (op[0], op[1])
        return (self._cfg_findex, None)

    def _push_history(self) -> None:
        current = self._current_location()
        if current is None or (self._back_stack and self._back_stack[-1] == current):
            return
        self._back_stack.append(current)
        del self._back_stack[:-_HISTORY_LIMIT]

    def _update_history_actions(self) -> None:
        self._back_action.setEnabled(bool(self._back_stack))
        self._forward_action.setEnabled(bool(self._forward_stack))

    def _open_jump_dialog(self) -> None:
        if self._code is None:
            self._status_bar.showMessage("Open a file first", 3000)
            return
        if not self._jump_names:
            self._jump_names = {f"{name}  f@{fi}": fi for fi, name in self._func_list.entries()}
        dialog = _JumpDialog(self, list(self._jump_names), self._resolve_jump)
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.findex is not None:
            self.navigate_to(dialog.findex)

    def _resolve_jump(self, text: str) -> "int | str":
        """findex for a Jump dialog entry, or an error message."""
        assert self._code is not None
        if not text:
            return "Enter a function index or name."
        match = re.fullmatch(r"(?:.*\s)?f@(\d+)|(\d+)", text)
        if match:
            findex = int(match.group(1) or match.group(2))
            if findex in self._code.get_findex_map():
                return findex
            return f"No function f@{findex}."
        lowered = text.lower()
        exact = [fi for name, fi in self._jump_names.items() if name.rsplit("  f@", 1)[0].lower() == lowered]
        if exact:
            return exact[0]
        partial = [fi for name, fi in self._jump_names.items() if lowered in name.lower()]
        if len(partial) == 1:
            return partial[0]
        return f"{len(partial)} functions match. Pick one from the list." if partial else "No such function."

    def _on_follow_requested(self, findex: int, word: str) -> None:
        """Double-click / Enter in a code pane: jump to what the word names."""
        if self._code is None:
            return
        word = word.strip()
        if not word:
            return
        ref = re.fullmatch(r"([a-z]+@)(\d+)", word)
        if ref is not None:
            prefix, index = ref.group(1), int(ref.group(2))
            if prefix == "f@":
                self.navigate_to(index)
            elif prefix == "t@":
                self._open_types_tab(select=index)
            elif prefix in self._follow_handlers:
                self._follow_handlers[prefix](index)
            else:
                self._status_bar.showMessage(f"Nothing to follow for {word}", 3000)
            return

        # A local in the current function: list its uses.
        local_group = self._resolve_locals(findex, word)
        if local_group is not None:
            self.show_xrefs(word, [local_group])
            return

        # A function or method name: jump when unambiguous, preferring this class.
        si = self._code.search_index()
        candidates: Dict[int, Function | Native] = {}
        for func in [*si.find_partial(word), *si.find(word)]:
            candidates.setdefault(func.findex.value, func)
        if len(candidates) > 1:
            here, _, class_fis = self._class_key_for(findex)
            same_class = [fi for fi in candidates if fi in class_fis]
            if len(same_class) == 1:
                self.navigate_to(same_class[0])
                return
        if len(candidates) == 1:
            self.navigate_to(next(iter(candidates)))
            return
        if candidates:
            groups = [
                XrefGroup(
                    label=f"function {_func_label(self._code, fi)}",
                    kind="function",
                    sites=[XrefSite(fi, _func_label(self._code, fi), None, None, "definition")],
                )
                for fi in candidates
            ]
            self.show_xrefs(f"{word}: {len(groups)} definitions", groups)
            return

        # A class/enum name: open its type.
        for tindex, typ in enumerate(self._code.types):
            name_ref = getattr(typ.definition, "name", None)
            try:
                if name_ref is not None and destaticify(name_ref.resolve(self._code)) == word:
                    self._open_types_tab(select=tindex)
                    return
            except Exception:
                continue
        self._status_bar.showMessage(f"Nothing to follow for '{word}'", 3000)

    # ── Drag and drop ─────────────────────────────────────────────────────────

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        urls = event.mimeData().urls() if event.mimeData().hasUrls() else []
        if len(urls) == 1 and urls[0].isLocalFile():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        urls = event.mimeData().urls()
        if not urls:
            return
        path = urls[0].toLocalFile()
        if os.path.isfile(path) and self._confirm_discard_changes():
            event.acceptProposedAction()
            self._load_file(path)

    # ── File loading ──────────────────────────────────────────────────────────

    def _open_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open HashLink bytecode or HL/C-compiled binary",
            "",
            "HashLink files (*.hl *.dat);;Executables (*.exe *.elf);;All files (*)",
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
        self._welcome.set_recent(self._recent_files)
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
            return self._save_database()
        return choice == QMessageBox.StandardButton.Discard

    def _load_file(self, path: str) -> None:
        self._generation += 1
        for old_thread in self._threads:
            old_thread.requestInterruption()
        self._active_decompiles = 0
        self._decomp_tokens.clear()
        self._busy.stop_all()
        self._decomp_jobs.clear()
        self._tabs.clear()
        self._open_tabs.clear()
        self._generic_tabs.clear()
        self._back_stack.clear()
        self._forward_stack.clear()
        self._update_history_actions()
        self._jump_names.clear()
        self._find_bar.hide()
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
        self._undo_stack.clear()
        self._dirty = False
        self._code = None
        self._loaded_via_dehlc = _looks_like_native_image(path)
        self._native_asm_cache.clear()
        self._plt_map = None
        self._disasm_source = "asm"
        self._emit_ctx = None
        self._lifter = None
        self._fidx_addr.clear()
        self._arm_lift_warned = False
        self._set_disasm_toggle_visible(self._loaded_via_dehlc)
        self._log_panel.set_context(code=None, findex=None, func=None, irf=None)
        self._source_path = path
        self._update_window_title()
        self._worker.invalidate()
        self._xref_popup.set_code(None)
        self.code_loaded.emit(None)
        self._update_central_page()
        # The previous document was frozen out of cyclic GC as it loaded (see
        # _bulk_build); unfreeze so its reference cycles become collectable.
        gc.unfreeze()
        gc.collect()

        self._progress_bar.setVisible(True)
        self._progress_bar.setValue(0)
        self._status_label.setText(f"Loading {path}…")
        self._busy.start("Reading bytecode…" if not self._loaded_via_dehlc else "Reading binary…", key="load")

        if self._loaded_via_dehlc:
            thread: QThread = _DehlcLoadThread(path, self._generation)
            self._log_panel.info("De-HL/C: Loading binary...")
        else:
            thread = _LoadThread(path, self._generation)
        self._load_thread = thread
        thread.signals.progress.connect(self._on_load_progress)
        thread.signals.finished.connect(self._on_load_finished)
        thread.signals.error.connect(self._on_load_error)
        self._start_thread(thread)

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

    def _is_current(self, generation: int) -> bool:
        return not self._closing and generation == self._generation

    @Slot(int, float, str)
    def _on_load_progress(self, generation: int, frac: float, status: str) -> None:
        if not self._is_current(generation):
            return
        if frac < 0:
            # Indeterminate progress (de-HL/C passes): hide the bar, show phase text.
            self._progress_bar.setVisible(False)
            self._status_label.setText(status)
            return
        self._progress_bar.setValue(int(frac * 100))
        self._status_label.setText(status)

    @Slot(int, object, object)
    def _on_load_finished(self, generation: int, code: Bytecode, nav_data: object = None) -> None:
        if not self._is_current(generation):
            return
        self._code = code
        self._progress_bar.setVisible(False)
        self._busy.stop(key="load")
        assert self._source_path is not None
        self._add_recent_file(self._source_path)
        n = len(code.functions)
        label = "Loaded (inspection-only native recovery)" if code.inspection_only else "Loaded"
        self._status_label.setText(f"{label}, {n} functions")
        self._log_panel.info(f"{label} {os.path.basename(self._source_path)}: {n} functions")
        if code.inspection_only:
            for diagnostic in code.recovery_diagnostics:
                self._log_panel.warn(diagnostic)
        self._log_panel.set_context(code=code)
        self._func_list.load(code, cast(Optional[NavigatorData], nav_data))
        self._xref_popup.set_code(code)
        self.code_loaded.emit(code)

        assert self._source_path is not None
        cldb_path = self._source_path + ".cldb"
        if os.path.exists(cldb_path):
            self._load_database_from(cldb_path)

        # Pre-warm the xref/search/source-map indices in the background so the
        # first 'X' lookup doesn't stall the UI thread building them on demand.
        self._busy.start("Building xref table…", key="index")
        self._index_build_thread = _IndexBuildThread(self._worker, code, generation)
        self._index_build_thread.signals.finished.connect(self._on_index_finished)
        self._index_build_thread.signals.error.connect(self._on_index_error)
        self._start_thread(self._index_build_thread)

    @Slot(int)
    def _on_index_finished(self, generation: int) -> None:
        if self._is_current(generation):
            self._busy.stop(key="index")

    @Slot(int, str)
    def _on_index_error(self, generation: int, msg: str) -> None:
        if self._is_current(generation):
            self._on_index_finished(generation)
            self._log_panel.error(f"Failed to build indices: {msg}")

    @Slot(int, str)
    def _on_load_error(self, generation: int, msg: str) -> None:
        if not self._is_current(generation):
            return
        self._progress_bar.setVisible(False)
        self._busy.stop(key="load")
        self._status_label.setText(f"Error: {msg}")
        path = self._source_path or "file"
        self._log_panel.error(f"Couldn't open {path}: {msg}")
        box = QMessageBox(
            QMessageBox.Icon.Warning, "Couldn't open file", f"Couldn't open {path}", parent=self
        )
        box.setInformativeText(msg)
        box.open()  # non-blocking: the load threads' queued signals keep flowing

    # ── Analysis database (.cldb) ───────────────────────────────────────────────

    def _open_database_file(self) -> None:
        if self._code is None or self._source_path is None:
            self._log_panel.warn("Open a bytecode file first.")
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "Load analysis database", "", "crashlink database (*.cldb)"
        )
        if path and self._confirm_discard_changes():
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
        path, _ = QFileDialog.getSaveFileName(
            self, title, default_name, "Text files (*.txt *.hx);;All files (*)"
        )
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

    def _find_target_view(self) -> Optional[QPlainTextEdit]:
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
            self._status_bar.showMessage("Open a class tab to search its code", 3000)
            return
        self._find_bar.open_on(target)

    def _load_database_from(self, cldb_path: str) -> None:
        assert self._code is not None and self._source_path is not None
        self._db_request += 1
        token = (self._generation, self._db_request)
        self._db_load_thread = _DbLoadThread(cldb_path, self._code, self._source_path, token)
        self._db_load_thread.signals.finished.connect(self._on_db_load_finished)
        self._db_load_thread.signals.error.connect(self._on_db_load_error)
        self._start_thread(self._db_load_thread)

    def _accept_db_token(self, token: tuple) -> bool:
        return self._is_current(token[0]) and token[1] == self._db_request

    @Slot(object, str)
    def _on_db_load_error(self, token: tuple, msg: str) -> None:
        if self._accept_db_token(token):
            self._log_panel.error(f"Failed to load database: {msg}")

    @Slot(object, object, object)
    def _on_db_load_finished(
        self, token: tuple, result: DatabaseLoadResult, annotations: AnnotationStore
    ) -> None:
        if not self._accept_db_token(token) or self._code is None:
            return
        for w in result.warnings:
            self._log_panel.warn(w)
        if not result.matched:
            return
        self._code.annotations = annotations
        self._worker.invalidate()
        self._ir_cache.clear()
        self._opline_cache.clear()
        self._undo_stack.clear()
        self._dirty = False
        self._update_window_title()
        for class_key, findices in self._class_findices.items():
            for findex in findices:
                self._start_decompile(class_key, findex)

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
        all_fi = sorted(
            fi for fi, (o, _, _) in reg.items() if destaticify(o.name.resolve(self._code)) == canonical
        )
        # Constructor first (as in `decompile --class`), then declaration (findex) order.
        ctors = [fi for fi in all_fi if reg[fi][1] == "__constructor__"]
        return class_key, canonical, ctors + [fi for fi in all_fi if fi not in ctors]

    # ── Natives table ────────────────────────────────────────────────────────

    def _open_natives_tab(self) -> None:
        code = self._code
        if code is None:
            self._status_bar.showMessage("Open a file first", 3000)
            return

        def build() -> QWidget:
            view = NativesView()
            view.set_theme(self._theme)
            view.load(code)
            view.xref_requested.connect(self._on_native_xref_requested)
            return view

        self.open_tab("__natives__", "Natives", build)

    def _on_native_xref_requested(self, findex: int) -> None:
        self._show_xrefs_for(f"f@{findex}")

    def _show_xrefs_for(self, word: str) -> None:
        if self._code is None:
            return
        code = self._code

        def show(groups: List[XrefGroup]) -> None:
            self.show_xrefs(word, groups)
            self._log_panel.result(f"Xrefs for '{word}': {len(groups)} target(s)")

        self.run_background(f"Finding references to {word}…", lambda: resolve_targets(code, word), show)

    # ── Types table ──────────────────────────────────────────────────────────

    def _open_types_tab(self, select: Optional[int] = None) -> None:
        code = self._code
        if code is None:
            self._status_bar.showMessage("Open a file first", 3000)
            return

        def build() -> QWidget:
            view = TypesView()
            view.set_theme(self._theme)
            view.load(code)
            view.xref_requested.connect(self._show_xrefs_for)
            return view

        view = self.open_tab("__types__", "Types", build)
        if select is not None and isinstance(view, TypesView):
            view.select_type(select)

    # ── Native assembly (de-HL/C images) ─────────────────────────────────────

    def _native_asm_blocks(self, findices: List[int]) -> List[Tuple[int, str, List[str]]]:
        """(findex, header, rows) machine-code blocks for a tab's disassembly pane.
        Cached per findex; slots without code (natives) are skipped."""
        bin_view = self._code.hlc_binary if self._code is not None else None
        if bin_view is None:
            return []
        from crashlink.dehlc.asmview import function_asm_block
        from crashlink.dehlc.binary import _resolve_plt_targets

        if self._plt_map is None:
            self._plt_map = _resolve_plt_targets(bin_view)
        blocks: List[Tuple[int, str, List[str]]] = []
        for fi in findices:
            if fi not in self._native_asm_cache:
                self._native_asm_cache[fi] = function_asm_block(bin_view, fi, plt_map=self._plt_map)
            block = self._native_asm_cache[fi]
            if block is not None:
                blocks.append((fi, block[0], block[1]))
        return blocks

    def _recovery_text(self, findex: int) -> str:
        """Approximate native operations, never invented executable dataflow."""
        assert self._code is not None
        from crashlink.dehlc.emit import format_recovered_ops

        ops = self._code.recovery_opcodes.get(findex, [])
        text = format_recovered_ops(ops)
        if not ops:
            text += "\nNo HL-shaped operations recovered; see original machine-code disassembly."
        events = self._code.recovery_lifts.get(findex, [])
        if events:
            text += "\nNative lift events (including unmapped events):\n"
            text += "\n".join(f"{event.src_addr:#x} {event!r}" for event in events)
        return text

    def _load_disasm_pane(self, view: SyncView, all_fi: List[int]) -> None:
        """Fills a SyncView's disassembly pane: for de-HL/C images either the
        original machine code or inspection-only approximate operations,
        HL opcodes for ordinary bytecode."""
        assert self._code is not None
        if self._code.hlc_binary is None:
            findex_map = self._code.get_findex_map()
            view.load_disasm(self._code, [(fi, findex_map[fi]) for fi in all_fi if fi in findex_map])
            return
        if self._disasm_source == "ops":
            self._ensure_lifted(all_fi)
            view.disasm_view.load_native(
                [(fi, f"f@{fi} approximate lift", self._recovery_text(fi).splitlines()) for fi in all_fi]
            )
        else:
            view.disasm_view.load_native(self._native_asm_blocks(all_fi))

    def _ensure_lifted(self, findices: List[int]) -> None:
        """
        Recover inspection records without changing Function.ops or register types.
        Unsupported architectures remain browsable as original machine code.
        """
        assert self._code is not None
        bin_view = self._code.hlc_binary
        assert bin_view is not None
        findex_map = self._code.get_findex_map()
        todo = []
        for fi in findices:
            fn = findex_map.get(fi)
            if isinstance(fn, Function) and fi not in self._code.recovery_opcodes:
                todo.append(fi)
        if not todo:
            return
        if bin_view.arch not in ("x86_64", "x86", "aarch64"):
            if not self._arm_lift_warned:
                self._arm_lift_warned = True
                self._log_panel.warn(
                    f"Opcode lifting supports x86 and aarch64 - {bin_view.arch} bodies stay empty."
                )
            return
        from crashlink.dehlc.binary import _resolve_plt_targets
        from crashlink.dehlc.emit import EmitContext, emit_function
        from crashlink.dehlc.lift import FunctionLifter

        if self._emit_ctx is None or self._lifter is None:
            if self._plt_map is None:
                self._plt_map = _resolve_plt_targets(bin_view)
            self._emit_ctx = EmitContext(self._code, bin_view)
            self._fidx_addr = {v: k for k, v in self._emit_ctx.addr2findex.items()}
            self._lifter = FunctionLifter.for_binary(bin_view, self._plt_map)
        ctx = self._emit_ctx
        lifter = self._lifter
        lifted = 0
        for fi in todo:
            addr = self._fidx_addr.get(fi)
            if not addr:
                continue  # native slot / padding entry
            try:
                stream = lifter.lift(addr)
                ops = emit_function(ctx, stream)
            except Exception as e:
                self._log_panel.warn(f"lifting failed for f@{fi}: {e}")
                continue
            self._code.recovery_lifts[fi] = stream
            self._code.recovery_opcodes[fi] = ops
            lifted += 1
        if lifted:
            self._log_panel.info(f"Recovered inspection-only approximations for {lifted} function(s).")

    def _set_disasm_source(self, source: str) -> None:
        """Toolbar toggle: original assembly vs inspection-only approximate operations."""
        if source == self._disasm_source:
            return
        self._disasm_source = source
        for class_key in list(self._open_tabs):
            self._refresh_disasm_view(class_key)

    def _set_disasm_toggle_visible(self, visible: bool) -> None:
        """Shows/hides the Asm/Ops toggle. QMenuBar sizes AND positions its corner
        widget from a cached size hint, so merely toggling an inner bar's visibility
        leaves the corner clipped/overflowing - re-registering the corner forces the
        menubar to re-measure it."""
        self._disasm_source_bar.setVisible(visible)
        mb = self.menuBar()
        corner = self._view_mode_corner
        if mb.cornerWidget(Qt.Corner.TopRightCorner) is corner:
            # Qt's C++ API takes nullptr here to release the widget; the PySide6
            # stubs only type the non-null overload.
            mb.setCornerWidget(cast("QWidget", None), Qt.Corner.TopRightCorner)
        mb.setCornerWidget(corner, Qt.Corner.TopRightCorner)

    def _open_class_tab(self, class_key: str, display_name: str, all_fi: List[int], jump_to: int) -> None:
        assert self._code is not None

        self._class_findices[class_key] = all_fi
        self._class_names[class_key] = display_name
        self._class_results[class_key] = {fi: None for fi in all_fi}
        self._class_fields[class_key] = self._class_field_lines(all_fi)

        # Seed from a loaded .cldb where available, so cached functions render
        # immediately instead of flashing "decompiling…" — a real decompile still
        # runs below to warm _ir_cache for rename/xref support.
        if not self._code.inspection_only:
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
        view.follow_requested.connect(self._on_follow_requested)
        view.disasm_view.op_focused.connect(self._on_op_focused)

        # Native bodies remain separate from bytecode and never enter the IR pipeline.
        if self._code.hlc_binary is not None:
            self._ensure_lifted(all_fi)

        findex_map = self._code.get_findex_map()
        methods: List[Tuple[int, str]] = []
        to_decompile: List[int] = []
        for fi in all_fi:
            if self._code.inspection_only:
                self._ir_cache.pop(fi, None)
                self._opline_cache.pop(fi, None)
                text = self._recovery_text(fi)
                self._class_results[class_key][fi] = text
                methods.append((fi, text))
                continue
            cached = self._db_cache.get(fi)
            if cached is not None:
                # Seed from a loaded .cldb so cached functions render immediately
                # instead of flashing "decompiling…" — a real decompile still runs
                # below to warm _ir_cache for rename/xref support.
                text, opmap = cached
                self._class_results[class_key][fi] = text
                self._opline_cache[fi] = opmap
                to_decompile.append(fi)
                methods.append((fi, text))
                continue
            fn = findex_map.get(fi)
            if isinstance(fn, Native):
                methods.append(
                    (fi, f"// f@{fi}  native primitive (implemented in an hdll)\n// signature only")
                )
            elif isinstance(fn, Function) and not fn.ops:
                methods.append((fi, f"f@{fi}() {{\n  // body not recovered\n}}"))
            else:
                to_decompile.append(fi)
                methods.append(
                    (
                        fi,
                        f"class {display_name} {{\n    // f@{fi}  decompiling…\n}}",
                    )
                )

        view.load_pseudo(display_name, methods, fields=self._class_fields[class_key])
        self._load_disasm_pane(view, all_fi)

        tab_label = _tab_label(display_name)
        idx = self._tabs.addTab(view, tab_label)
        self._tabs.setTabToolTip(idx, display_name)
        self._open_tabs[class_key] = idx
        self._add_close_btn(idx, class_key)
        self._tabs.setCurrentIndex(idx)
        if jump_to in all_fi:
            view.scroll_to_findex(jump_to)

        # Kick off decompile for every method that actually has opcodes.
        for fi in to_decompile:
            self._start_decompile(class_key, fi)

        pending = len(to_decompile)
        if pending:
            self._status_label.setText(f"Decompiling {display_name} ({pending}/{len(all_fi)} methods)…")
        else:
            self._status_label.setText(f"{display_name}, {len(all_fi)} methods")

    def _start_decompile(self, class_key: str, findex: int) -> None:
        assert self._code is not None
        if self._code.inspection_only:
            self._log_panel.warn(
                "Inspection-only native recovery: use the approximate lift or original assembly view."
            )
            return
        self._active_decompiles += 1
        self._busy.start("Decompiling…", key="decompile")
        self._decomp_request += 1
        token = (self._generation, self._decomp_request)
        self._decomp_tokens[(class_key, findex)] = token
        job = _DecompJob(class_key, findex, token)
        job.finished.connect(self._on_decompile_finished)
        job.error.connect(self._on_decompile_error)
        self._decomp_jobs[token] = job
        job.start(self._worker, self._code, self._render_pool)

    def _class_field_lines(self, all_fi: List[int]) -> List[str]:
        """Field declarations for a class tab, from the class's Obj (no decompile needed)."""
        assert self._code is not None
        if self._code.inspection_only or not all_fi:
            return []
        info = _method_registry(self._code).get(all_fi[0])
        if info is None:
            return []
        try:
            return class_field_lines(self._code, info[0])
        except Exception as e:
            return [f"// fields unavailable: {e}"]

    def _decompile_batch_done(self) -> None:
        self._active_decompiles = max(0, self._active_decompiles - 1)
        if self._active_decompiles == 0:
            self._busy.stop(key="decompile")

    def _add_close_btn(self, tab_idx: int, class_key: str) -> None:
        btn = QToolButton()
        btn.setObjectName("tabCloseBtn")
        btn.setText("×")
        btn.setFixedSize(QSize(18, 18))
        btn.setToolTip("Close tab")
        btn.clicked.connect(lambda: QTimer.singleShot(0, lambda: self._close_tab_by_key(class_key)))
        self._tabs.tabBar().setTabButton(tab_idx, QTabBar.ButtonPosition.RightSide, btn)

    def _close_tab_at(self, index: int) -> None:
        widget = self._tabs.widget(index)
        key = widget.property("class_key") if widget is not None else None
        if key:
            self._close_tab_by_key(key)

    def childEvent(self, event: QChildEvent) -> None:
        super().childEvent(event)
        # Docks, and the tab bars Qt creates when docks are tabbed together, are
        # children of the window; watch them for middle-click closes once they
        # are fully constructed (polished).
        if event.type() == QEvent.Type.ChildPolished:
            child = event.child()
            if isinstance(child, (QDockWidget, QTabBar)):
                closer = self.__dict__.get("_dock_middle_close")
                if closer is None:
                    closer = self._dock_middle_close = _DockMiddleClose(self)
                closer.watch(child)

    def _close_tab_by_key(self, class_key: str) -> None:
        idx = self._open_tabs.pop(class_key, None)
        if idx is None:
            return
        self._class_findices.pop(class_key, None)
        self._class_results.pop(class_key, None)
        self._class_names.pop(class_key, None)
        self._class_fields.pop(class_key, None)
        self._generic_tabs.pop(class_key, None)
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
        self._update_central_page()

    def _on_tab_changed(self, _idx: int) -> None:
        self._update_central_page()

    def _update_central_page(self) -> None:
        """Welcome page when no tabs are open, the tab widget otherwise."""
        self._central_stack.setCurrentWidget(self._tabs if self._tabs.count() else self._welcome)
        if not self._tabs.count():
            self._find_bar.hide()

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

    def _accept_decompile(self, token: tuple, class_key: str, findex: int) -> bool:
        self._decomp_jobs.pop(token, None)
        if not self._is_current(token[0]):
            return False
        self._decompile_batch_done()
        return self._decomp_tokens.get((class_key, findex)) == token

    @Slot(object, str, int, object, object)
    def _on_decompile_finished(
        self, token: tuple, class_key: str, findex: int, ir: object, rendered: Tuple[str, Dict[int, int]]
    ) -> None:
        if not self._accept_decompile(token, class_key, findex):
            return
        if not isinstance(ir, IRFunction):
            return

        self._ir_cache[findex] = ir

        if class_key not in self._class_results:
            return

        text, opmap = rendered
        self._opline_cache[findex] = opmap
        self._class_results[class_key][findex] = text
        self._show_method_text(class_key, findex, text)

        if findex == self._cfg_findex:
            self._update_cfg_view(findex)
            self._update_repl_focus(findex)

        if self._pending_op_scroll is not None and self._pending_op_scroll[0] == findex:
            pf, pop = self._pending_op_scroll
            self._pending_op_scroll = None
            self._show_location(pf, pop, -1)

        # Update status when all done
        results = self._class_results.get(class_key, {})
        pending = sum(1 for v in results.values() if v is None)
        if pending == 0:
            name = self._class_names.get(class_key, class_key)
            self._status_label.setText(f"{name}, {len(results)} methods")

    @Slot(object, str, int, str)
    def _on_decompile_error(self, token: tuple, class_key: str, findex: int, msg: str) -> None:
        if not self._accept_decompile(token, class_key, findex):
            return
        if class_key not in self._class_results:
            return
        err_text = f"class ? {{\n    // f@{findex} error: {msg}\n}}"
        self._class_results[class_key][findex] = err_text
        self._show_method_text(class_key, findex, err_text)

    def _show_method_text(self, class_key: str, findex: int, text: str) -> None:
        """Put one method's new pseudocode into its open class tab, in place."""
        idx = self._open_tabs.get(class_key)
        view = self._tabs.widget(idx) if idx is not None else None
        if isinstance(view, SyncView):
            view.update_method(findex, text)

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

        view.load_pseudo(display_name, methods, fields=self._class_fields.get(class_key))

    def _refresh_disasm_view(self, class_key: str) -> None:
        """Disasm rendering needs no decompile — re-render straight from opcodes (or
        cached machine code) so an annotation change (e.g. a comment) shows up
        immediately, no waiting on the background redecompile that updates the
        pseudocode pane."""
        if self._code is None:
            return
        idx = self._open_tabs.get(class_key)
        if idx is None:
            return
        view = self._tabs.widget(idx)
        if not isinstance(view, SyncView):
            return
        all_fi = self._class_findices.get(class_key, [])
        self._load_disasm_pane(view, all_fi)

    # ── Focus tracking ────────────────────────────────────────────────────────

    def _on_function_focused(self, findex: int) -> None:
        if findex == self._cfg_findex:
            return
        self._cfg_findex = findex
        self._update_cfg_view(findex)
        self._update_repl_focus(findex)
        self.function_focused.emit(findex)

    def _on_op_focused(self, findex: int, op_idx: int) -> None:
        """Disasm cursor moved onto an opcode: outline its block in the CFG."""
        if self._cfg_dock.isVisible():
            self._cfg_view.highlight_op(findex, op_idx)

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
        if self._code.inspection_only:
            self._cfg_view.show_native()
            return
        func = self._code.get_findex_map().get(findex)
        if isinstance(func, Native):
            self._cfg_view.show_native()
            return

        ir = self._ir_cache.get(findex)
        if not isinstance(ir, IRFunction):
            self._cfg_view.show_pending()
            return
        # Graphviz layout can take seconds on big functions; CfgView runs it off-thread.
        self._cfg_view.request(findex, ir)

    # ── Rename (N) ────────────────────────────────────────────────────────────

    def _on_rename_hotkey(self, findex: int, word: str) -> None:
        if self._code is None:
            return
        if not word.strip():
            self._status_bar.showMessage("Place the cursor on a local variable to rename it", 3000)
            return
        ir = self._ir_cache.get(findex)
        if not isinstance(ir, IRFunction):
            self._status_bar.showMessage("Still decompiling, try again in a moment", 3000)
            return

        # Find locals matching word under cursor
        locals_matching = [loc for loc in ir.all_locals if loc.name == word and loc.reg_idx is not None]
        if not locals_matching:
            self._status_bar.showMessage(f"'{word}' isn't a local variable of this function", 3000)
            return

        loc = locals_matching[0]
        assert loc.reg_idx is not None
        new_name, ok = QInputDialog.getText(self, "Rename", f"Rename '{word}' to:", text=word)
        if not ok or not new_name or new_name == word:
            return

        self.apply_rename(findex, loc.reg_idx, loc.defining_op_idx, new_name)
        self._log_panel.success(f"Renamed '{word}' → '{new_name}' in f@{findex}")

    def apply_rename(self, findex: int, reg_idx: int, def_op: Optional[int], new_name: Optional[str]) -> None:
        """new_name=None clears the rename (used by the CLI bridge's `unrename`)."""
        if self._code is None:
            return
        old_name = self._code.annotations.get_rename(findex, reg_idx, def_op)
        cmd = RenameCommand(
            self._code, findex, reg_idx, def_op, old_name, new_name, self._on_annotation_applied
        )
        self._undo_stack.push(cmd)

    def apply_comment(self, findex: int, op_idx: int, text: Optional[str]) -> None:
        """text=None clears the comment (used by the CLI bridge's `rmcomment`)."""
        if self._code is None:
            return
        old_text = self._code.annotations.get_comment(findex, op_idx)
        cmd = CommentCommand(self._code, findex, op_idx, old_text, text, self._on_annotation_applied)
        self._undo_stack.push(cmd)

    def apply_setstring(self, index: int, new_value: str) -> None:
        if self._code is None:
            return
        old_value = self._code.strings.value[index]
        cmd = SetStringCommand(self._code, index, old_value, new_value, self._on_annotation_applied)
        self._undo_stack.push(cmd)

    def apply_function_edit(self, edit: "FunctionEdit") -> None:
        """Swap in an edited function (from crashlink.asm.edit_function), undoably."""
        if self._code is None:
            return
        self._undo_stack.push(ReplaceFunctionCommand(self._code, edit, self._on_annotation_applied))

    def _on_annotation_applied(self, findex: Optional[int]) -> None:
        """Shared undo/redo callback for rename and comment commands."""
        if findex is None:
            return
        class_key, _, _ = self._class_key_for(findex)
        self._refresh_disasm_view(class_key)
        self._invalidate_and_redecompile(findex)

    def _invalidate_and_redecompile(self, findex: int) -> None:
        """After an annotation (rename/comment) changes, drop every cache that was
        derived from the old IR for this function and kick off a fresh decompile."""
        if self._code is None:
            return
        if self._code.inspection_only:
            self._update_cfg_view(findex)
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
        existing = self._code.annotations.get_comment(findex, op_idx)
        text, ok = QInputDialog.getText(
            self, "Comment", f"Comment on op {op_idx} in f@{findex}:", text=existing or ""
        )
        if not ok:
            return
        text = text.strip()
        new_text = text or None
        self.apply_comment(findex, op_idx, new_text)
        if new_text:
            self._log_panel.success(f"Commented op {op_idx} in f@{findex}")
        else:
            self._log_panel.info(f"Cleared comment on op {op_idx} in f@{findex}")

    # ── Xrefs (X) ────────────────────────────────────────────────────────────

    def _on_xref_hotkey(self, findex: int, word: str) -> None:
        if self._code is None:
            return
        word = word.strip()
        if not word:
            return

        local_group = self._resolve_locals(findex, word)
        code = self._code

        def show(groups: List[XrefGroup]) -> None:
            if local_group is not None:
                groups.insert(0, local_group)
            self.show_xrefs(word, groups)
            self._log_panel.result(f"Xrefs for '{word}': {len(groups)} target(s)")

        # Name resolution scans every type/field/string: keep it off the UI thread.
        self.run_background(f"Finding references to {word}…", lambda: resolve_targets(code, word), show)

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
                        snippet=line.strip(),
                    )
                )
        if not sites:
            return None
        return XrefGroup(label=f"local '{word}'", kind="local", sites=sites)

    def _navigate_to_xref(self, findex: int, op_idx: int, body_line: int) -> None:
        """Xref popup activation: a navigation, so it's recorded for Back."""
        if self._code is None:
            return
        self._push_history()
        self._forward_stack.clear()
        self._show_location(findex, op_idx, body_line)
        self._update_history_actions()

    def _show_location(self, findex: int, op_idx: int, body_line: int) -> None:
        """Open/focus `findex`'s class tab and scroll both panes to the op or line."""
        if self._code is None:
            return
        self._on_function_selected(findex)
        sync = self._current_sync_view()
        if sync is None:
            return
        view = sync.class_view
        if op_idx >= 0:
            sync.disasm_view.scroll_to_op(findex, op_idx)
        # Focus whichever pane is showing so keys (Esc, X, N, …) act on it.
        (sync.disasm_view if self._view_mode == DISASM else view).setFocus()
        self._on_function_focused(findex)

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
            set_theme = getattr(view, "set_theme", None)
            if callable(set_theme):
                set_theme(theme)
        self.theme_changed.emit(theme)

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
        """Every menu action with a shortcut, plus the keys the code views handle."""
        rows: List[Tuple[str, str]] = []

        def collect(menu: QMenu, path: str) -> None:
            for action in menu.actions():
                sub = action.menu()
                if isinstance(sub, QMenu):
                    collect(sub, f"{path} › {action.text()}")
                    continue
                keys = [s.toString(QKeySequence.SequenceFormat.NativeText) for s in action.shortcuts()]
                if keys and action.text():
                    rows.append((" / ".join(keys), f"{action.text().replace('&', '')}   ({path})"))

        for name in _MENU_ORDER:
            if name in self._menus:
                collect(self._menus[name], name)
        rows.extend(_IN_VIEW_KEYS)

        dialog = QDialog(self)
        dialog.setWindowTitle("Keyboard Shortcuts")
        layout = QVBoxLayout(dialog)
        table = QTableWidget(len(rows), 2)
        table.setHorizontalHeaderLabels(["Keys", "Action"])
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setShowGrid(False)
        for row, (keys, desc) in enumerate(rows):
            key_item = QTableWidgetItem(keys)
            font = key_item.font()
            font.setBold(True)
            key_item.setFont(font)
            table.setItem(row, 0, key_item)
            table.setItem(row, 1, QTableWidgetItem(desc))
        table.resizeColumnsToContents()
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(table)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        width = table.horizontalHeader().length() + 60
        dialog.resize(max(640, width), min(720, 80 + table.verticalHeader().length()))
        dialog.exec()

    # ── Cleanup ───────────────────────────────────────────────────────────────

    def closeEvent(self, event: QCloseEvent) -> None:
        if not self._confirm_discard_changes():
            event.ignore()
            return
        self._save_settings()
        set_dbg_callback(None)
        self._closing = True
        self._generation += 1
        self._busy.stop_all()
        self._decomp_jobs.clear()
        self._bg_pool.clear()
        self._bg_jobs.clear()
        self._worker.invalidate()
        for thread in self._threads:
            thread.requestInterruption()
        for thread in self._threads:
            thread.wait()
        self._bg_pool.waitForDone()
        self._worker.shutdown(wait=True)
        self._render_pool.shutdown(wait=True, cancel_futures=True)
        self._threads.clear()
        # Hand the document back to the cyclic GC (frozen since it loaded).
        gc.unfreeze()
        super().closeEvent(event)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _tab_label(canonical_name: str, max_len: int = 28) -> str:
    """haxe.ds.ObjectMap → h.d.ObjectMap (abbreviated namespace prefix)."""
    parts = canonical_name.split(".")
    if len(parts) <= 2 or len(canonical_name) <= max_len:
        return canonical_name
    class_part = parts[-1]
    abbrev = ".".join(p[0] for p in parts[:-1])
    return f"{abbrev}.{class_part}"
