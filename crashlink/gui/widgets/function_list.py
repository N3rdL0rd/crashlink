"""Function browser: package tree, file tree, and flat search results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

import crashlink.disasm as disasm
from PySide6.QtCore import QRect, Qt, QTimer, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QStackedWidget,
    QToolButton,
    QTreeWidget,
    QTreeWidgetItem,
    QTreeWidgetItemIterator,
    QVBoxLayout,
    QWidget,
)

from crashlink.core import Bytecode, Function, destaticify
from crashlink.disasm import ClassEntry, MethodEntry, file_class_map
from crashlink.pseudo import _method_registry
from ..themes import Theme

_PAGE_CLASS = 0
_PAGE_LIST = 1
_PAGE_FILE = 2

_SEARCH_CAP = 300

# Item roles: findex to open (UserRole) and a colour role (Theme attribute) so
# theme changes recolour items in place instead of rebuilding the trees.
_ROLE_COLOUR = Qt.ItemDataRole.UserRole + 1
# Theme attributes navigator items are coloured with (stored under _ROLE_COLOUR).
_COLOUR_ROLES = ("subtext", "teal", "pink", "overlay")


def _method_label(method_name: str) -> str:
    """Constructors show as `new`, as in Haxe source."""
    return "new" if method_name == "__constructor__" else method_name


@dataclass
class NavigatorData:
    """Everything the navigator needs, computed off the UI thread by `FunctionList.prepare`."""

    #: (findex, display name, lowercase display name, is_std) for every bytecode function.
    entries: List[Tuple[int, str, str, bool]]
    #: canonical class name -> [(findex, method label)] in findex order.
    classes: Dict[str, List[Tuple[int, str]]]
    #: Functions not registered on any class: (findex, display name).
    standalone: List[Tuple[int, str]]
    #: findices of standard-library functions.
    std: Set[int]
    #: Debug file path -> classes defined in it.
    file_map: Dict[str, List[ClassEntry]]


@dataclass
class _PkgNode:
    """Trie node: package (has children, no methods) or class (has methods, no children)."""

    children: Dict[str, "_PkgNode"] = field(default_factory=dict)
    methods: Optional[List[Tuple[int, str]]] = None  # None → package node
    canonical: Optional[str] = None  # full dotted name for class nodes


@dataclass
class _DirNode:
    """Trie node for a directory tree: subfolders plus files that live directly in it."""

    children: Dict[str, "_DirNode"] = field(default_factory=dict)
    files: List[str] = field(default_factory=list)  # full file_path keys into the file map


class FunctionList(QWidget):
    function_selected = Signal(int)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._code: Optional[Bytecode] = None
        self._theme: Optional[Theme] = None
        self._brushes: Dict[str, QBrush] = {}
        self._show_std = False
        self._data: Optional[NavigatorData] = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Search ────────────────────────────────────────────
        self._search = QLineEdit()
        self._search.setPlaceholderText("Search functions and classes…")
        self._search.setClearButtonEnabled(True)
        self._search.setContentsMargins(8, 4, 8, 4)
        layout.addWidget(self._search)
        self._clear_btns = self._search.findChildren(QToolButton)

        # Debounce: only run the search 150 ms after the last keystroke
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(150)
        self._search_timer.timeout.connect(self._do_search)

        # ── Mode toggle ───────────────────────────────────────
        self._mode_bar = QFrame()
        self._mode_bar.setObjectName("modeBar")
        mrow = QHBoxLayout(self._mode_bar)
        mrow.setContentsMargins(8, 4, 8, 4)
        mrow.setSpacing(4)

        self._btn_by_class = QPushButton("By Class")
        self._btn_by_class.setObjectName("modeBtn")
        self._btn_by_class.setCheckable(True)
        self._btn_by_class.setChecked(True)

        self._btn_by_file = QPushButton("By File")
        self._btn_by_file.setObjectName("modeBtn")
        self._btn_by_file.setCheckable(True)

        grp = QButtonGroup(self)
        grp.setExclusive(True)
        grp.addButton(self._btn_by_class, _PAGE_CLASS)
        grp.addButton(self._btn_by_file, _PAGE_FILE)
        self._mode_group = grp

        mrow.addWidget(self._btn_by_class)
        mrow.addWidget(self._btn_by_file)
        mrow.addStretch()

        self._expand_btn = QPushButton("⊕")
        self._expand_btn.setObjectName("smallBtn")
        self._expand_btn.setToolTip("Expand all")
        self._expand_btn.setFixedSize(20, 20)
        self._collapse_btn = QPushButton("⊖")
        self._collapse_btn.setObjectName("smallBtn")
        self._collapse_btn.setToolTip("Collapse all")
        self._collapse_btn.setFixedSize(20, 20)
        mrow.addWidget(self._expand_btn)
        mrow.addWidget(self._collapse_btn)

        self._std_toggle = QCheckBox("stdlib")
        self._std_toggle.setChecked(False)
        self._std_toggle.setToolTip("Show standard library functions (also applies to search)")
        mrow.addWidget(self._std_toggle)

        layout.addWidget(self._mode_bar)

        # ── Stacked views ─────────────────────────────────────
        self._stack = QStackedWidget()

        self._tree = _make_tree()
        self._stack.addWidget(self._tree)  # page 0

        self._list = QListWidget()
        self._list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._stack.addWidget(self._list)  # page 1

        self._file_tree = _make_tree()
        self._stack.addWidget(self._file_tree)  # page 2

        layout.addWidget(self._stack)

        # ── Signals ───────────────────────────────────────────
        self._search.textChanged.connect(self._on_search_changed)
        self._std_toggle.toggled.connect(self._on_std_toggled)
        self._tree.itemClicked.connect(self._on_tree_click)
        self._file_tree.itemClicked.connect(self._on_tree_click)
        self._list.itemClicked.connect(self._on_list_activate)
        self._list.itemActivated.connect(self._on_list_activate)
        self._expand_btn.clicked.connect(self._expand_all)
        self._collapse_btn.clicked.connect(self._collapse_all)
        self._btn_by_class.clicked.connect(lambda: self._set_mode(_PAGE_CLASS))
        self._btn_by_file.clicked.connect(lambda: self._set_mode(_PAGE_FILE))

    # ── Public API ────────────────────────────────────────────

    @staticmethod
    def prepare(code: Bytecode) -> NavigatorData:
        """Compute the navigator's contents. Pure Python, no Qt: safe on a worker thread."""
        fmap = code.get_findex_map()
        reg = _method_registry(code)
        entries: List[Tuple[int, str, str, bool]] = []
        classes: Dict[str, List[Tuple[int, str]]] = {}
        standalone: List[Tuple[int, str]] = []
        std: Set[int] = set()
        for findex, func in sorted(fmap.items()):
            if not isinstance(func, Function):
                continue
            is_std = disasm.is_std(code, func)
            if is_std:
                std.add(findex)
            if findex in reg:
                obj, method_name, _ = reg[findex]
                canonical = destaticify(obj.name.resolve(code))
                label = _method_label(method_name)
                classes.setdefault(canonical, []).append((findex, label))
                display = f"{canonical}.{label}"
            else:
                display = _func_name(code, func)
                standalone.append((findex, display))
            entries.append((findex, display, display.lower(), is_std))
        return NavigatorData(entries, classes, standalone, std, file_class_map(code))

    def load(self, code: Bytecode, data: Optional[NavigatorData] = None) -> None:
        self._code = code
        self._data = data if data is not None else self.prepare(code)
        self._rebuild_tree()
        self._rebuild_file_tree()
        if self._search.text():
            self._do_search()

    def entries(self) -> List[Tuple[int, str]]:
        """(findex, display name) of every function, e.g. for jump-to completion."""
        if self._data is None:
            return []
        return [(fi, name) for fi, name, _, _ in self._data.entries]

    def set_theme(self, theme: Theme) -> None:
        self._theme = theme
        self._brushes = {role: QBrush(QColor(getattr(theme, role))) for role in _COLOUR_ROLES}
        icon = _make_x_icon(theme.overlay)
        for btn in self._clear_btns:
            btn.setIcon(icon)
        brushes = self._brushes
        for tree in (self._tree, self._file_tree):
            for item in _iter_items(tree):
                role = item.data(0, _ROLE_COLOUR)
                if role:
                    item.setForeground(0, brushes[role])
        for row in range(self._list.count()):
            item = self._list.item(row)
            role = item.data(_ROLE_COLOUR)
            if role:
                item.setForeground(brushes[role])

    # ── Tree rebuild (package hierarchy) ──────────────────────

    def _visible(self, findex: int) -> bool:
        return self._show_std or self._data is None or findex not in self._data.std

    def _rebuild_tree(self) -> None:
        self._tree.clear()
        data = self._data
        if data is None:
            return

        # Build package trie from canonical class names
        root = _PkgNode()
        for canonical, methods in data.classes.items():
            visible = [(fi, name) for fi, name in methods if self._visible(fi)]
            if not visible:
                continue
            parts = canonical.split(".")
            node = root
            for part in parts[:-1]:
                node = node.children.setdefault(part, _PkgNode())
            node.children[parts[-1]] = _PkgNode(methods=visible, canonical=canonical)

        bold = QFont()
        bold.setBold(True)
        brushes = self._brushes
        self._tree.setUpdatesEnabled(False)
        _build_tree_items(self._tree, root, bold, brushes, top_level=True)

        standalone = [(fi, name) for fi, name in data.standalone if self._visible(fi)]
        if standalone:
            stub = QTreeWidgetItem(["(standalone)"])
            stub.setFont(0, bold)
            _tint(stub, "subtext", brushes)
            stub.setData(0, Qt.ItemDataRole.UserRole, None)
            for fi, display in standalone:
                child = QTreeWidgetItem([display])
                child.setData(0, Qt.ItemDataRole.UserRole, fi)
                _tint(child, "pink", brushes)
                stub.addChild(child)
            self._tree.addTopLevelItem(stub)
            stub.setExpanded(True)
        self._tree.setUpdatesEnabled(True)

    # ── File tree rebuild ─────────────────────────────────────

    def _rebuild_file_tree(self) -> None:
        self._file_tree.clear()
        data = self._data
        if data is None or not data.file_map:
            return

        bold = QFont()
        bold.setBold(True)
        italic = QFont()
        italic.setItalic(True)
        regular = QFont()
        brushes = self._brushes

        # Pre-filter to the set of files that actually have visible classes/methods,
        # keyed by full path so we can build a directory trie out of them.
        visible_files: Dict[str, List[Tuple[ClassEntry, List[MethodEntry]]]] = {}
        for file_path, classes in data.file_map.items():
            is_std_file = "std" in file_path
            if is_std_file and not self._show_std:
                continue

            visible_classes = []
            for cls in classes:
                methods = cls.methods
                if not self._show_std and not is_std_file:
                    methods = [m for m in cls.methods if m.findex not in data.std]
                if methods:
                    visible_classes.append((cls, methods))

            if visible_classes:
                visible_files[file_path] = visible_classes

        # Build a directory trie so shared parent folders (e.g. /a/b containing
        # both c.hx and d.hx) collapse into a single expand level.
        root = _DirNode()
        for file_path in visible_files:
            parts = file_path.replace("\\", "/").split("/")
            dirs, _filename = parts[:-1], parts[-1]
            node = root
            for part in dirs:
                node = node.children.setdefault(part, _DirNode())
            node.files.append(file_path)

        def add_file_item(parent: Any, file_path: str) -> None:
            display_name = file_path.replace("\\", "/").split("/")[-1]
            file_item = QTreeWidgetItem([display_name])
            file_item.setFont(0, regular)
            _tint(file_item, "teal", brushes)
            file_item.setToolTip(0, file_path)
            file_item.setData(0, Qt.ItemDataRole.UserRole, None)

            for cls, methods in visible_files[file_path]:
                cls_item = QTreeWidgetItem([cls.canonical_name])
                cls_item.setFont(0, italic)
                cls_item.setData(0, Qt.ItemDataRole.UserRole, methods[0].findex)
                cls_item.setToolTip(0, f"{cls.canonical_name}  line {cls.first_line}")
                for m in methods:
                    label = _method_label(m.method_name)
                    m_item = QTreeWidgetItem([label])
                    m_item.setData(0, Qt.ItemDataRole.UserRole, m.findex)
                    m_item.setToolTip(0, f"f@{m.findex}  {cls.canonical_name}.{label}  line {m.first_line}")
                    cls_item.addChild(m_item)
                file_item.addChild(cls_item)
                cls_item.setExpanded(True)

            _add_item(parent, file_item)
            file_item.setExpanded(True)

        def add_dir_items(parent: Any, node: _DirNode, name: str) -> None:
            # Collapse runs of single-child, file-less directories into one label,
            # e.g. /a/b/c.hx and /a/b/d.hx share a single "a/b" expand level.
            label_parts = [name]
            while not node.files and len(node.children) == 1:
                ((child_name, child_node),) = node.children.items()
                label_parts.append(child_name)
                node = child_node

            dir_item = QTreeWidgetItem(["/".join(label_parts)])
            dir_item.setFont(0, bold)
            _tint(dir_item, "subtext", brushes)  # matches package nodes in By Class
            dir_item.setData(0, Qt.ItemDataRole.UserRole, None)
            _add_item(parent, dir_item)
            dir_item.setExpanded(True)

            for child_name in sorted(node.children):
                add_dir_items(dir_item, node.children[child_name], child_name)
            for file_path in sorted(node.files):
                add_file_item(dir_item, file_path)

        self._file_tree.setUpdatesEnabled(False)
        for dir_name in sorted(root.children):
            add_dir_items(self._file_tree, root.children[dir_name], dir_name)
        for file_path in sorted(root.files):
            add_file_item(self._file_tree, file_path)
        self._file_tree.setUpdatesEnabled(True)

    # ── Search ────────────────────────────────────────────────

    def _on_search_changed(self, query: str) -> None:
        # While searching, the tree-only controls hide; the stdlib toggle stays
        # visible because it also filters results.
        searching = bool(query)
        for widget in (self._btn_by_class, self._btn_by_file, self._expand_btn, self._collapse_btn):
            widget.setVisible(not searching)
        if searching:
            self._stack.setCurrentIndex(_PAGE_LIST)
            self._search_timer.start()
        else:
            self._search_timer.stop()
            mode = _PAGE_CLASS if self._btn_by_class.isChecked() else _PAGE_FILE
            self._stack.setCurrentIndex(mode)

    def _do_search(self) -> None:
        q = self._search.text().lower()
        if not q or self._data is None:
            return
        self._list.setUpdatesEnabled(False)
        self._list.clear()
        count = 0
        for findex, name, name_lower, is_std in self._data.entries:
            if is_std and not self._show_std:
                continue
            if q in name_lower:
                item = QListWidgetItem(name)
                item.setData(Qt.ItemDataRole.UserRole, findex)
                item.setToolTip(f"f@{findex}  {name}")
                self._list.addItem(item)
                count += 1
                if count >= _SEARCH_CAP:
                    self._add_note(f"… {_SEARCH_CAP}+ results, refine your query")
                    break
        if count == 0:
            hint = "" if self._show_std else " (tick stdlib to include the standard library)"
            self._add_note(f"No matches{hint}")
        self._list.setUpdatesEnabled(True)

    def _add_note(self, text: str) -> None:
        note = QListWidgetItem(text)
        note.setData(Qt.ItemDataRole.UserRole, None)
        note.setFlags(Qt.ItemFlag.NoItemFlags)
        note.setData(_ROLE_COLOUR, "overlay")
        if "overlay" in self._brushes:
            note.setForeground(self._brushes["overlay"])
        self._list.addItem(note)

    # ── Misc ──────────────────────────────────────────────────

    def _on_std_toggled(self, checked: bool) -> None:
        self._show_std = checked
        self._rebuild_tree()
        self._rebuild_file_tree()
        if self._search.text():
            self._do_search()

    def _set_mode(self, page: int) -> None:
        self._stack.setCurrentIndex(page)

    def _expand_all(self) -> None:
        w = self._stack.currentWidget()
        if isinstance(w, QTreeWidget):
            w.expandAll()

    def _collapse_all(self) -> None:
        w = self._stack.currentWidget()
        if isinstance(w, QTreeWidget):
            w.collapseAll()

    def _on_tree_click(self, item: QTreeWidgetItem, _col: int) -> None:
        findex = item.data(0, Qt.ItemDataRole.UserRole)
        if findex is not None:
            self.function_selected.emit(findex)

    def _on_list_activate(self, item: QListWidgetItem) -> None:
        findex = item.data(Qt.ItemDataRole.UserRole)
        if findex is not None:
            self.function_selected.emit(findex)


# ── Tree builder ──────────────────────────────────────────────────────────────


def _build_tree_items(
    parent: Any, node: _PkgNode, bold: QFont, brushes: Dict[str, QBrush], top_level: bool = False
) -> None:
    italic = QFont()
    italic.setItalic(True)
    for name in sorted(node.children):
        child = node.children[name]
        if child.methods is not None:
            # Class node
            item = QTreeWidgetItem([name])
            item.setFont(0, italic)
            _tint(item, "teal", brushes)
            item.setToolTip(0, child.canonical or name)
            fi0 = child.methods[0][0] if child.methods else None
            item.setData(0, Qt.ItemDataRole.UserRole, fi0)
            for fi, method_name in child.methods:
                m = QTreeWidgetItem([method_name])
                m.setData(0, Qt.ItemDataRole.UserRole, fi)
                _tint(m, "pink", brushes)
                m.setToolTip(0, f"f@{fi}  {child.canonical}.{method_name}")
                item.addChild(m)
            _add_item(parent, item)
            if top_level:
                item.setExpanded(True)
        else:
            # Package / module node — bold, always expanded
            item = QTreeWidgetItem([name])
            item.setFont(0, bold)
            _tint(item, "subtext", brushes)
            item.setData(0, Qt.ItemDataRole.UserRole, _first_findex(child))
            _build_tree_items(item, child, bold, brushes, top_level=False)
            _add_item(parent, item)
            item.setExpanded(True)


def _tint(item: QTreeWidgetItem, role: str, brushes: Dict[str, QBrush]) -> None:
    """Colour an item with a theme role, remembered so theme changes can recolour it."""
    item.setData(0, _ROLE_COLOUR, role)
    brush = brushes.get(role)
    if brush is not None:
        item.setForeground(0, brush)


def _add_item(parent: Any, item: QTreeWidgetItem) -> None:
    if isinstance(parent, QTreeWidget):
        parent.addTopLevelItem(item)
    else:
        parent.addChild(item)


def _iter_items(tree: QTreeWidget) -> Iterator[QTreeWidgetItem]:
    it = QTreeWidgetItemIterator(tree)
    while it.value() is not None:
        yield it.value()
        it += 1


def _first_findex(node: _PkgNode) -> Optional[int]:
    if node.methods:
        return node.methods[0][0]
    for child in node.children.values():
        fi = _first_findex(child)
        if fi is not None:
            return fi
    return None


# ── Misc helpers ──────────────────────────────────────────────────────────────


def _make_tree() -> QTreeWidget:
    t = QTreeWidget()
    t.setHeaderHidden(True)
    t.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    t.setIndentation(14)
    t.setAnimated(False)
    # Every row is one line of text; without this Qt measures each of the tens of
    # thousands of rows when laying out the tree, a visible freeze after a load.
    t.setUniformRowHeights(True)
    return t


def _make_x_icon(color: str, size: int = 14, right_pad: int = 10) -> QIcon:
    px = QPixmap(size + right_pad, size)
    px.fill(Qt.GlobalColor.transparent)
    p = QPainter(px)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setPen(QColor(color))
    font = p.font()
    font.setPixelSize(size)
    font.setBold(True)
    p.setFont(font)
    p.drawText(QRect(0, 0, size, size), Qt.AlignmentFlag.AlignCenter, "×")
    p.end()
    return QIcon(px)


def _func_name(code: Bytecode, func: Function) -> str:
    try:
        name = code.full_func_name(func)
        if name:
            return f"f@{func.findex.value}  {name}"
    except Exception:
        pass
    return f"f@{func.findex.value}"
