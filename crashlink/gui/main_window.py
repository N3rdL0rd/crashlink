"""Main application window."""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from PySide6.QtCore import QRect, QRunnable, QThread, QThreadPool, QTimer, Qt, Signal, QObject, QSize
from PySide6.QtGui import QColor, QCursor, QKeyEvent, QPainter, QPalette
from PySide6.QtWidgets import (
    QApplication,
    QDockWidget,
    QFileDialog,
    QInputDialog,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QStatusBar,
    QTabBar,
    QTabWidget,
    QToolButton,
    QWidget,
)

from crashlink.core import AnalysisWorker, Bytecode, destaticify
from crashlink.decomp.function import IRFunction
from crashlink.globals import set_dbg_callback
from crashlink.pseudo import pseudo_oplines, _method_registry

from .themes import DEFAULT_THEME, THEMES, Theme, generate_qss
from .widgets.class_view import ClassView
from .widgets.function_list import FunctionList
from .widgets.log_panel import LogPanel
from .widgets.xref_panel import XrefPopup, resolve_targets, XrefGroup, XrefSite, _func_label


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

        self._build_ui()
        self._build_menu()
        self._apply_theme(self._theme)
        set_dbg_callback(self._log_panel.info)

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
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
        nav_dock = QDockWidget("Navigator", self)
        nav_dock.setObjectName("navDock")
        nav_dock.setWidget(self._func_list)
        nav_dock.setMinimumWidth(220)
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, nav_dock)

        # ── Bottom dock: log ──────────────────────────────────
        self._log_panel = LogPanel()
        log_dock = QDockWidget("Log", self)
        log_dock.setObjectName("logDock")
        log_dock.setWidget(self._log_panel)
        log_dock.setMinimumHeight(80)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, log_dock)

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
        fm.addAction("Quit", self.close, "Ctrl+Q")
        vm = mb.addMenu("View")
        tm = vm.addMenu("Theme")
        for name in THEMES:
            tm.addAction(name, lambda n=name: self._apply_theme(THEMES[n]))
        vm.addSeparator()
        vm.addAction("Inspect widget under cursor\tCtrl+Shift+I", self._inspect_widget)

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
        self._log_panel.clear()
        self._code = None
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
        self._func_list.load(code)

    def _on_load_error(self, msg: str) -> None:
        self._progress_bar.setVisible(False)
        self._status_label.setText(f"Error: {msg}")

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

        view = ClassView()
        view.setProperty("class_key", class_key)
        view.set_theme(self._theme)
        view.function_focused.connect(self._on_function_focused)
        view.rename_requested.connect(self._on_rename_hotkey)
        view.xref_requested.connect(self._on_xref_hotkey)

        # Render immediately with placeholders
        placeholder = [(fi, f"class {display_name} {{\n    // f@{fi}  decompiling…\n}}") for fi in all_fi]
        view.load_methods(display_name, placeholder)

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
            if isinstance(view, ClassView):
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
        if not isinstance(view, ClassView):
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

        view.load_methods(display_name, methods)

    # ── Focus tracking ────────────────────────────────────────────────────────

    def _on_function_focused(self, _findex: int) -> None:
        pass

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
        self._worker.invalidate(findex)
        self._ir_cache.pop(findex, None)
        self._opline_cache.pop(findex, None)

        for class_key, fi_list in self._class_findices.items():
            if findex in fi_list:
                if class_key in self._class_results:
                    self._class_results[class_key][findex] = None
                r = _DecompRunnable(self._worker, self._code, class_key, findex)
                r.signals.finished.connect(self._on_decompile_finished)
                r.signals.error.connect(self._on_decompile_error)
                QThreadPool.globalInstance().start(r)
                break

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
        return w if isinstance(w, ClassView) else None

    # ── Theme ─────────────────────────────────────────────────────────────────

    def _apply_theme(self, theme: Theme) -> None:
        self._theme = theme
        self.setStyleSheet(generate_qss(theme))
        self._tab_bar._fill = QColor(theme.mantle)
        self._tab_bar.update()
        self._func_list.set_theme(theme)
        self._log_panel.set_theme(theme)
        self._xref_popup.set_theme(theme)
        for i in range(self._tabs.count()):
            view = self._tabs.widget(i)
            if isinstance(view, ClassView):
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
