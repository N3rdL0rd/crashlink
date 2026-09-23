"""Decompiler Internals dock: for the focused function, every optimizer pass with
what it changed (unified diff of the IR before/after), each pass's full IR
snapshot, and the final IR tree (CLI `ir`, `IRFunction(capture_layers=True)`)."""

from __future__ import annotations

import difflib
from typing import TYPE_CHECKING, List, Optional, Tuple

from PySide6.QtCore import Qt
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QShowEvent,
    QSyntaxHighlighter,
    QTextCharFormat,
    QTextDocument,
)
from PySide6.QtWidgets import (
    QDockWidget,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ...core import Bytecode, Function
from ...decomp.function import IRFunction
from ..ansi import strip_ansi
from ..themes import Theme

if TYPE_CHECKING:
    from ..main_window import MainWindow

# (pass name, IR text after the pass, whether the pass reported running)
_Layer = Tuple[str, str, bool]


class _DiffHighlighter(QSyntaxHighlighter):
    def __init__(self, document: QTextDocument, theme: Theme) -> None:
        super().__init__(document)
        self.set_theme(theme)

    def set_theme(self, theme: Theme) -> None:
        def fmt(colour: str) -> QTextCharFormat:
            f = QTextCharFormat()
            f.setForeground(QColor(colour))
            return f

        self._added, self._removed, self._hunk = fmt(theme.green), fmt(theme.red), fmt(theme.accent)
        self.rehighlight()

    def highlightBlock(self, text: str) -> None:
        if text.startswith("@@"):
            self.setFormat(0, len(text), self._hunk)
        elif text.startswith("+") and not text.startswith("+++"):
            self.setFormat(0, len(text), self._added)
        elif text.startswith("-") and not text.startswith("---"):
            self.setFormat(0, len(text), self._removed)


def _code_pane() -> QPlainTextEdit:
    pane = QPlainTextEdit()
    pane.setReadOnly(True)
    pane.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
    font = QFont("JetBrains Mono", 11)
    font.setStyleHint(QFont.StyleHint.Monospace)
    pane.setFont(font)
    return pane


def _capture(code: Bytecode, func: Function) -> Tuple[List[_Layer], str]:
    ir = IRFunction(code, func, capture_layers=True)
    # pprint colours its output for terminals.
    return list(ir.layer_snapshots), strip_ansi(ir.block.pprint())


class InternalsView(QWidget):
    def __init__(self, mw: "MainWindow", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._mw = mw
        self._layers: List[_Layer] = []
        self._request = 0
        self._findex: Optional[int] = None
        # Focus that arrived while the dock was hidden; captured when it's shown.
        self._pending: Optional[int] = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self._passes = QListWidget()
        self._passes.currentRowChanged.connect(self._show_pass)
        splitter.addWidget(self._passes)

        self._tabs = QTabWidget()
        self._diff = _code_pane()
        self._snapshot = _code_pane()
        self._final = _code_pane()
        self._tabs.addTab(self._diff, "Diff")
        self._tabs.addTab(self._snapshot, "Snapshot")
        self._tabs.addTab(self._final, "Final IR")
        splitter.addWidget(self._tabs)
        splitter.setSizes([220, 500])
        layout.addWidget(splitter, 1)

        self._highlighter = _DiffHighlighter(self._diff.document(), mw.theme)
        mw.theme_changed.connect(self._on_theme_changed)
        mw.function_focused.connect(self._on_focus)
        mw.code_loaded.connect(self._on_code_loaded)

    def _on_theme_changed(self, theme: Theme) -> None:
        self._highlighter.set_theme(theme)
        self._fill_passes()

    def _on_code_loaded(self, _code: object) -> None:
        self._request += 1
        self._findex = None
        self._pending = None
        self._layers = []
        self._passes.clear()
        for pane in (self._diff, self._snapshot, self._final):
            pane.clear()
        self._set_title(None)

    def _on_focus(self, findex: int) -> None:
        # Capturing every pass is expensive: only do it while the dock is open.
        if not self.isVisible():
            self._pending = findex
            return
        if findex == self._findex:
            return
        code = self._mw.code
        if code is None:
            return
        self._findex = findex
        func = code.get_findex_map().get(findex)
        if code.inspection_only or not isinstance(func, Function) or not func.ops:
            self._set_title(f"f@{findex}")
            self._layers = []
            self._passes.clear()
            self._diff.setPlainText("No bytecode to decompile (native or inspection-only).")
            return
        self._request += 1
        request = self._request
        self._set_title(f"f@{findex} {code.full_func_name(func)}")
        self._layers = []
        self._passes.clear()
        self._diff.setPlainText("Capturing optimizer passes…")

        def done(result: Tuple[List[_Layer], str]) -> None:
            if request == self._request:
                self._loaded(findex, *result)

        def failed(message: str) -> None:
            if request == self._request:
                self._diff.setPlainText(f"Decompiling failed: {message}")

        self._mw.run_background(
            f"Capturing passes for f@{findex}…", lambda: _capture(code, func), done, failed
        )

    def _loaded(self, findex: int, layers: List[_Layer], final_ir: str) -> None:
        self._layers = layers
        code = self._mw.code
        name = code.full_func_name(code.get_findex_map()[findex]) if code is not None else ""
        changed = sum(1 for i in range(1, len(layers)) if layers[i][1] != layers[i - 1][1])
        self._set_title(f"f@{findex} {name} ({changed}/{len(layers) - 1} passes changed it)")
        self._final.setPlainText(final_ir)
        self._fill_passes()
        first_change = next((i for i in range(1, len(layers)) if layers[i][1] != layers[i - 1][1]), 0)
        self._passes.setCurrentRow(first_change)

    def _set_title(self, subject: Optional[str]) -> None:
        """Name the function being shown in the dock's title bar."""
        dock = self.parentWidget()
        if isinstance(dock, QDockWidget):
            dock.setWindowTitle(f"Decompiler Internals: {subject}" if subject else "Decompiler Internals")

    def _fill_passes(self) -> None:
        theme = self._mw.theme
        current = self._passes.currentRow()
        self._passes.blockSignals(True)
        self._passes.clear()
        for i, (name, text, ran) in enumerate(self._layers):
            changed = i > 0 and text != self._layers[i - 1][1]
            if i == 0:
                label, colour = f"{name}  (lifted)", theme.text
            elif changed:
                label, colour = f"● {name}", theme.green
            elif ran:
                label, colour = f"○ {name}  (no change)", theme.subtext
            else:
                label, colour = f"– {name}  (not applicable)", theme.overlay
            item = QListWidgetItem(label)
            item.setForeground(QBrush(QColor(colour)))
            self._passes.addItem(item)
        self._passes.blockSignals(False)
        if 0 <= current < self._passes.count():
            self._passes.setCurrentRow(current)

    def _show_pass(self, row: int) -> None:
        if not 0 <= row < len(self._layers):
            return
        name, text, _ = self._layers[row]
        self._snapshot.setPlainText(text)
        if row == 0:
            self._diff.setPlainText("(initial lifted IR, see Snapshot)")
            return
        before = self._layers[row - 1][1].splitlines()
        diff = list(
            difflib.unified_diff(
                before, text.splitlines(), f"before {name}", f"after {name}", n=3, lineterm=""
            )
        )
        self._diff.setPlainText("\n".join(diff) if diff else f"{name} made no change.")

    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        if self._pending is not None:
            pending, self._pending = self._pending, None
            self._on_focus(pending)


def install(mw: "MainWindow") -> None:
    dock = QDockWidget("Decompiler Internals", mw)
    dock.setObjectName("internalsDock")
    dock.setWidget(InternalsView(mw))
    mw.add_dock(dock, Qt.DockWidgetArea.RightDockWidgetArea, visible=False)
