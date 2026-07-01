"""Sync view: disasm and pseudocode panes with line synchronization."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from PySide6.QtCore import QEvent, Qt, Signal
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import QHBoxLayout, QSplitter, QWidget

from ...core import Bytecode
from ..themes import Theme
from .class_view import ClassView
from .disasm_view import DisasmView

# Display modes
PSEUDO = 0
DISASM = 1
SPLIT = 2


class SyncView(QWidget):
    """Pairs a DisasmView (left) and ClassView (right) with bidirectional line sync.

    The active mode (PSEUDO/DISASM/SPLIT) is driven externally via `set_mode` —
    MainWindow keeps one global mode applied to every open SyncView, cycled with Tab.
    """

    cycle_requested = Signal()
    comment_requested = Signal(int, int)  # findex, op_idx — from either pane, via ';'

    def __init__(self, opline_cache: Dict[int, Dict[int, int]], parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._opline_cache = opline_cache
        # findex -> {body_line: first_op_idx}, rebuilt lazily per findex
        self._rev_cache: Dict[int, Dict[int, int]] = {}
        self._mode = PSEUDO

        self.disasm_view = DisasmView()
        self.class_view = ClassView()

        self._splitter = QSplitter(Qt.Orientation.Horizontal)
        self._splitter.addWidget(self.disasm_view)
        self._splitter.addWidget(self.class_view)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._splitter)

        self.disasm_view.installEventFilter(self)
        self.class_view.installEventFilter(self)
        self.class_view.cursorPositionChanged.connect(self._drive_from_pseudo)
        self.disasm_view.cursorPositionChanged.connect(self._drive_from_disasm)

        self._apply_mode()

    # ── Loading ────────────────────────────────────────────────────────────────

    def set_theme(self, theme: Theme) -> None:
        self.disasm_view.set_theme(theme)
        self.class_view.set_theme(theme)

    def load_pseudo(self, display_name: str, methods: List[Tuple[int, str]]) -> None:
        self.class_view.load_methods(display_name, methods)
        self._rev_cache.clear()

    def load_disasm(self, code: Bytecode, methods: List[Tuple[int, object]]) -> None:
        self.disasm_view.load(code, methods)

    # ── Navigation (delegates to pseudo; sync engine mirrors disasm) ────────────

    def scroll_to_findex(self, findex: int) -> None:
        self.class_view.scroll_to_findex(findex)

    def scroll_to_op_line(self, findex: int, body_line: int) -> None:
        self.class_view.scroll_to_op_line(findex, body_line)

    # ── Mode / keys ─────────────────────────────────────────────────────────────

    def _apply_mode(self) -> None:
        if self._mode == SPLIT:
            self.disasm_view.show()
            self.class_view.show()
        elif self._mode == DISASM:
            self.disasm_view.show()
            self.class_view.hide()
            self.disasm_view.setFocus()
        else:  # PSEUDO
            self.disasm_view.hide()
            self.class_view.show()
            self.class_view.setFocus()

    def set_mode(self, mode: int) -> None:
        self._mode = mode
        self._apply_mode()

    def eventFilter(self, obj: object, event: object) -> bool:
        if isinstance(event, QKeyEvent) and event.type() == QEvent.Type.KeyPress and not event.modifiers():
            if event.key() == Qt.Key.Key_Tab:
                self.cycle_requested.emit()
                return True
            if event.key() == Qt.Key.Key_Slash:
                self._request_comment(obj)
                return True
        return super().eventFilter(obj, event)  # type: ignore[arg-type]

    def _request_comment(self, obj: object) -> None:
        """Resolve (findex, op_idx) for the current cursor in whichever pane sent
        the ';' key and emit comment_requested — reusing the same op<->line
        machinery as the sync engine below, so it always agrees with what's synced."""
        if obj is self.disasm_view:
            at = self.disasm_view.op_at_cursor()
            if at is not None:
                self.comment_requested.emit(*at)
            return
        if obj is self.class_view:
            findex = self.class_view.findex_at_cursor()
            if findex is None:
                return
            line = self.class_view.textCursor().blockNumber()
            start = next((s for s, _, fi in self.class_view._line_ranges if fi == findex), None)
            if start is None:
                return
            op_idx = self._reverse_map(findex).get(line - start)
            if op_idx is not None:
                self.comment_requested.emit(findex, op_idx)

    # ── Sync engine ─────────────────────────────────────────────────────────────

    def _reverse_map(self, findex: int) -> Dict[int, int]:
        cached = self._rev_cache.get(findex)
        if cached is not None:
            return cached
        rev: Dict[int, int] = {}
        for op_idx, line in self._opline_cache.get(findex, {}).items():
            if line not in rev or op_idx < rev[line]:
                rev[line] = op_idx
        self._rev_cache[findex] = rev
        return rev

    def _scroll_silently(self, view: object, block_no: int) -> None:
        view.blockSignals(True)  # type: ignore[attr-defined]
        cursor = view.textCursor()  # type: ignore[attr-defined]
        block = view.document().findBlockByNumber(block_no)  # type: ignore[attr-defined]
        if block.isValid():
            cursor.setPosition(block.position())
            view.setTextCursor(cursor)  # type: ignore[attr-defined]
            view.centerCursor()  # type: ignore[attr-defined]
        view.blockSignals(False)  # type: ignore[attr-defined]

    def _drive_from_pseudo(self) -> None:
        cv = self.class_view
        findex = cv.findex_at_cursor()
        line = cv.textCursor().blockNumber()
        cv.set_sync_line(line)
        if findex is None:
            self.disasm_view.set_sync_line(None)
            return
        start = next((s for s, _, fi in cv._line_ranges if fi == findex), None)
        if start is None:
            self.disasm_view.set_sync_line(None)
            return
        body_line = line - start
        op_idx = self._reverse_map(findex).get(body_line)
        if op_idx is None:
            self.disasm_view.set_sync_line(None)
            return
        dline = self.disasm_view.combined_line_for_op(findex, op_idx)
        if dline is None:
            self.disasm_view.set_sync_line(None)
            return
        self._scroll_silently(self.disasm_view, dline)
        self.disasm_view.set_sync_line(dline)

    def _drive_from_disasm(self) -> None:
        dv = self.disasm_view
        at = dv.op_at_cursor()
        line = dv.textCursor().blockNumber()
        dv.set_sync_line(line)
        if at is None:
            self.class_view.set_sync_line(None)
            return
        findex, op_idx = at
        opmap = self._opline_cache.get(findex)
        if not opmap:
            self.class_view.set_sync_line(None)
            return
        body_line = opmap.get(op_idx)
        if body_line is None:
            preceding = [v for k, v in opmap.items() if k <= op_idx]
            body_line = max(preceding) if preceding else None
        if body_line is None:
            self.class_view.set_sync_line(None)
            return
        cline = self._combined_pseudo_line(findex, body_line)
        if cline is None:
            self.class_view.set_sync_line(None)
            return
        self._scroll_silently(self.class_view, cline)
        self.class_view.set_sync_line(cline)

    def _combined_pseudo_line(self, findex: int, body_line: int) -> Optional[int]:
        for start, end, fi in self.class_view._line_ranges:
            if fi == findex:
                return max(start, min(start + body_line, end))
        return None
