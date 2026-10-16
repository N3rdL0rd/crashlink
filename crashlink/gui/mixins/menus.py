"""Menu bar construction, docks, the theme submenu and the help dialogs for `MainWindow`."""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable, List, Tuple

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QDockWidget,
    QHeaderView,
    QMenu,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from crashlink.globals import VERSION, set_dbg_callback

from ..themes import THEMES

if TYPE_CHECKING:
    from ._host import MainWindowHost as _Base
else:
    _Base = object


# Top-level menus, in menu-bar order; `menu()` creates them on demand.
_MENU_ORDER = ("File", "Edit", "View", "Jump", "Search", "Tools", "Window", "Help")

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


class MenusMixin(_Base):
    """Menu bar construction, docks, the theme submenu and the help dialogs for `MainWindow`.

    State is set up by ``MainWindow.__init__``/``_build_ui`` (see ``._host`` for
    the typed surface); this area relies on:

    ``_menus``, ``_recent_menu``, ``_undo_stack``, ``_debug_output_action``, ``_quit_action``,
    ``_back_action``, ``_forward_action``, ``_jump_action``, ``_cfg_space_action``,
    ``_nav_dock``, ``_log_dock``, ``_cfg_dock``, ``_history_dock``, ``_central_stack``,
    ``_theme``, ``_log_panel``
    plus sibling-area methods resolved through ``MainWindow``.
    """

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

    def _build_menu(self) -> None:
        fm = self.menu("File")
        fm.addAction("Open...", QKeySequence("Ctrl+O"), self._open_file)
        self._recent_menu = fm.addMenu("Open Recent")
        self._rebuild_recent_menu()
        fm.addSeparator()
        fm.addAction("Save Database", QKeySequence("Ctrl+S"), self._save_database)
        fm.addAction("Load Database...", self._open_database_file)
        fm.addSeparator()
        export_menu = self.menu("File/Export")
        export_menu.addAction("Disassembly of Current Tab...", self._export_disasm)
        export_menu.addAction("Pseudocode of Current Tab...", self._export_pseudo)
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
        self._jump_action = self._central_action("Jump to Function...", ["G"], self._open_jump_dialog)
        jm.addAction(self._back_action)
        jm.addAction(self._forward_action)
        jm.addSeparator()
        jm.addAction(self._jump_action)
        self._update_history_actions()

        sm = self.menu("Search")
        find_action = QAction("Find in Pane...", self)
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
        hm.addAction("Keyboard Shortcuts...", self._show_shortcuts)
        hm.addAction("About crashlink...", self._show_about)

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
