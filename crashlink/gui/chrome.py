"""Window chrome: the small widgets and dialogs `MainWindow` is assembled from."""

from __future__ import annotations

import os
from typing import Callable, Dict, List, Optional, cast

from PySide6.QtCore import QEvent, QObject, QRect, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QKeyEvent, QMouseEvent, QPainter, QPaintEvent, QTextCursor, QTextDocument
from PySide6.QtWidgets import (
    QCompleter,
    QDialog,
    QDialogButtonBox,
    QDockWidget,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QTabBar,
    QToolButton,
    QVBoxLayout,
    QWidget,
)


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
        self._input.setPlaceholderText("Search this pane...")
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
        open_btn = QPushButton("Open file...  (Ctrl+O)")
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


def _tab_label(canonical_name: str, max_len: int = 28) -> str:
    """haxe.ds.ObjectMap → h.d.ObjectMap (abbreviated namespace prefix)."""
    parts = canonical_name.split(".")
    if len(parts) <= 2 or len(canonical_name) <= max_len:
        return canonical_name
    class_part = parts[-1]
    abbrev = ".".join(p[0] for p in parts[:-1])
    return f"{abbrev}.{class_part}"
