"""Function browser: package tree, file tree, and flat search results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import crashlink.disasm as disasm
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtCore import QRect
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
    QVBoxLayout,
    QWidget,
)

from crashlink.core import Bytecode, Function, Native, destaticify
from crashlink.disasm import ClassEntry, MethodEntry, file_class_map
from crashlink.pseudo import _method_registry
from ..themes import Theme

_PAGE_CLASS = 0
_PAGE_LIST = 1
_PAGE_FILE = 2

_SEARCH_CAP = 300


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
    files: List[str] = field(default_factory=list)  # full file_path keys into self._file_map


class FunctionList(QWidget):
    function_selected = Signal(int)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._code: Optional[Bytecode] = None
        self._theme: Optional[Theme] = None
        self._show_std = False
        # (findex, display_name, name_lower, is_std)
        self._all_entries: List[Tuple[int, str, str, bool]] = []
        self._file_map: Dict[str, List[ClassEntry]] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Search ────────────────────────────────────────────
        self._search = QLineEdit()
        self._search.setPlaceholderText("Search functions…")
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
        self._std_toggle.setToolTip("Show standard library functions")
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
        self._list.itemActivated.connect(self._on_list_activate)
        self._expand_btn.clicked.connect(self._expand_all)
        self._collapse_btn.clicked.connect(self._collapse_all)
        self._btn_by_class.clicked.connect(lambda: self._set_mode(_PAGE_CLASS))
        self._btn_by_file.clicked.connect(lambda: self._set_mode(_PAGE_FILE))

    # ── Public API ────────────────────────────────────────────

    def load(self, code: Bytecode) -> None:
        self._code = code
        self._all_entries.clear()

        fmap = code.get_findex_map()
        reg = _method_registry(code)
        for findex, func in sorted(fmap.items()):
            if isinstance(func, Function):
                if findex in reg:
                    obj, method_name, _ = reg[findex]
                    canonical = destaticify(obj.name.resolve(code))
                    display = f"{canonical}.{method_name}"
                else:
                    display = _func_name(code, func)
                is_std = disasm.is_std(code, func)
                self._all_entries.append((findex, display, display.lower(), is_std))

        self._file_map = file_class_map(code)
        self._rebuild_tree()
        self._rebuild_file_tree()

    def set_theme(self, theme: Theme) -> None:
        self._theme = theme
        icon = _make_x_icon(theme.overlay)
        for btn in self._clear_btns:
            btn.setIcon(icon)
        if self._code is not None:
            self._rebuild_tree()
            self._rebuild_file_tree()

    # ── Tree rebuild (package hierarchy) ──────────────────────

    def _rebuild_tree(self) -> None:
        self._tree.clear()
        if self._code is None:
            return

        reg = _method_registry(self._code)
        fmap = self._code.get_findex_map()

        class_methods: Dict[str, List[Tuple[int, str]]] = {}
        standalone: List[Tuple[int, str]] = []

        for findex, func in sorted(fmap.items()):
            if not isinstance(func, Function):
                continue
            if disasm.is_std(self._code, func) and not self._show_std:
                continue
            if findex in reg:
                obj, method_name, _ = reg[findex]
                canonical = destaticify(obj.name.resolve(self._code))
                class_methods.setdefault(canonical, []).append((findex, method_name))
            else:
                standalone.append((findex, _func_name(self._code, func)))

        # Build package trie from canonical class names
        root = _PkgNode()
        for canonical, methods in class_methods.items():
            methods.sort(key=lambda x: x[0])
            parts = canonical.split(".")
            node = root
            for part in parts[:-1]:
                if part not in node.children:
                    node.children[part] = _PkgNode()
                node = node.children[part]
            node.children[parts[-1]] = _PkgNode(methods=methods, canonical=canonical)

        bold = QFont()
        bold.setBold(True)
        t = self._theme
        pkg_color = QColor(t.subtext) if t else None
        cls_color = QColor(t.teal) if t else None
        meth_color = QColor(t.pink) if t else None
        _build_tree_items(
            self._tree, root, bold, top_level=True, pkg_color=pkg_color, cls_color=cls_color, meth_color=meth_color
        )

        if standalone:
            stub = QTreeWidgetItem(["(standalone)"])
            stub.setFont(0, bold)
            if pkg_color:
                stub.setForeground(0, QBrush(pkg_color))
            stub.setData(0, Qt.ItemDataRole.UserRole, None)
            for fi, display in standalone:
                child = QTreeWidgetItem([display])
                child.setData(0, Qt.ItemDataRole.UserRole, fi)
                if meth_color:
                    child.setForeground(0, QBrush(meth_color))
                stub.addChild(child)
            self._tree.addTopLevelItem(stub)
            stub.setExpanded(True)

    # ── File tree rebuild ─────────────────────────────────────

    def _rebuild_file_tree(self) -> None:
        self._file_tree.clear()
        if self._code is None or not self._file_map:
            return

        bold = QFont()
        bold.setBold(True)
        italic = QFont()
        italic.setItalic(True)
        regular = QFont()
        fmap = self._code.get_findex_map()

        t = self._theme
        dir_color = QColor(t.subtext) if t else None  # matches package nodes in By Class
        file_color = QColor(t.teal) if t else None  # matches class nodes in By Class

        # Pre-filter to the set of files that actually have visible classes/methods,
        # keyed by full path so we can build a directory trie out of them.
        visible_files: Dict[str, List[Tuple[ClassEntry, List[MethodEntry]]]] = {}
        for file_path, classes in self._file_map.items():
            is_std_file = "std" in file_path
            if is_std_file and not self._show_std:
                continue

            visible_classes = []
            for cls in classes:
                methods = cls.methods
                if not self._show_std and not is_std_file:
                    methods = [m for m in cls.methods if not _method_is_std(self._code, fmap, m.findex)]
                if methods:
                    visible_classes.append((cls, methods))

            if visible_classes:
                visible_files[file_path] = visible_classes

        # Build a directory trie so shared parent folders (e.g. /a/b containing
        # both c.hx and d.hx) collapse into a single expand level.
        root = _DirNode()
        for file_path in visible_files:
            parts = file_path.replace("\\", "/").split("/")
            dirs, filename = parts[:-1], parts[-1]
            node = root
            for part in dirs:
                node = node.children.setdefault(part, _DirNode())
            node.files.append(file_path)

        def add_file_item(parent: Any, file_path: str) -> None:
            display_name = file_path.replace("\\", "/").split("/")[-1]
            file_item = QTreeWidgetItem([display_name])
            file_item.setFont(0, regular)
            if file_color:
                file_item.setForeground(0, QBrush(file_color))
            file_item.setToolTip(0, file_path)
            file_item.setData(0, Qt.ItemDataRole.UserRole, None)

            for cls, methods in visible_files[file_path]:
                cls_item = QTreeWidgetItem([cls.canonical_name])
                cls_item.setFont(0, italic)
                cls_item.setData(0, Qt.ItemDataRole.UserRole, methods[0].findex)
                cls_item.setToolTip(0, f"{cls.canonical_name}  line {cls.first_line}")
                for m in methods:
                    m_item = QTreeWidgetItem([m.method_name])
                    m_item.setData(0, Qt.ItemDataRole.UserRole, m.findex)
                    m_item.setToolTip(0, f"f@{m.findex}  {cls.canonical_name}.{m.method_name}  line {m.first_line}")
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
            if dir_color:
                dir_item.setForeground(0, QBrush(dir_color))
            dir_item.setData(0, Qt.ItemDataRole.UserRole, None)
            _add_item(parent, dir_item)
            dir_item.setExpanded(True)

            for child_name in sorted(node.children):
                add_dir_items(dir_item, node.children[child_name], child_name)
            for file_path in sorted(node.files):
                add_file_item(dir_item, file_path)

        for dir_name in sorted(root.children):
            add_dir_items(self._file_tree, root.children[dir_name], dir_name)
        for file_path in sorted(root.files):
            add_file_item(self._file_tree, file_path)

    # ── Search ────────────────────────────────────────────────

    def _on_search_changed(self, query: str) -> None:
        if query:
            self._stack.setCurrentIndex(_PAGE_LIST)
            self._mode_bar.setVisible(False)
            self._search_timer.start()
        else:
            self._search_timer.stop()
            mode = _PAGE_CLASS if self._btn_by_class.isChecked() else _PAGE_FILE
            self._stack.setCurrentIndex(mode)
            self._mode_bar.setVisible(True)

    def _do_search(self) -> None:
        q = self._search.text().lower()
        if not q:
            return
        self._list.setUpdatesEnabled(False)
        self._list.clear()
        count = 0
        for findex, name, name_lower, is_std in self._all_entries:
            if is_std and not self._show_std:
                continue
            if q in name_lower:
                item = QListWidgetItem(name)
                item.setData(Qt.ItemDataRole.UserRole, findex)
                self._list.addItem(item)
                count += 1
                if count >= _SEARCH_CAP:
                    tip = QListWidgetItem(f"… {_SEARCH_CAP}+ results — refine your query")
                    tip.setData(Qt.ItemDataRole.UserRole, None)
                    tip.setFlags(Qt.ItemFlag.NoItemFlags)
                    self._list.addItem(tip)
                    break
        self._list.setUpdatesEnabled(True)

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
    parent: Any,
    node: _PkgNode,
    bold: QFont,
    top_level: bool = False,
    pkg_color: Optional[QColor] = None,
    cls_color: Optional[QColor] = None,
    meth_color: Optional[QColor] = None,
) -> None:
    italic = QFont()
    italic.setItalic(True)
    for name in sorted(node.children):
        child = node.children[name]
        if child.methods is not None:
            # Class node
            item = QTreeWidgetItem([name])
            item.setFont(0, italic)
            if cls_color:
                item.setForeground(0, QBrush(cls_color))
            item.setToolTip(0, child.canonical or name)
            fi0 = child.methods[0][0] if child.methods else None
            item.setData(0, Qt.ItemDataRole.UserRole, fi0)
            for fi, method_name in child.methods:
                m = QTreeWidgetItem([method_name])
                m.setData(0, Qt.ItemDataRole.UserRole, fi)
                m.setToolTip(0, f"f@{fi}  {child.canonical}.{method_name}")
                if meth_color:
                    m.setForeground(0, QBrush(meth_color))
                item.addChild(m)
            _add_item(parent, item)
            if top_level:
                item.setExpanded(True)
        else:
            # Package / module node — bold, always expanded
            item = QTreeWidgetItem([name])
            item.setFont(0, bold)
            if pkg_color:
                item.setForeground(0, QBrush(pkg_color))
            item.setData(0, Qt.ItemDataRole.UserRole, _first_findex(child))
            _build_tree_items(
                item, child, bold, top_level=False, pkg_color=pkg_color, cls_color=cls_color, meth_color=meth_color
            )
            _add_item(parent, item)
            item.setExpanded(True)


def _add_item(parent: Any, item: QTreeWidgetItem) -> None:
    if isinstance(parent, QTreeWidget):
        parent.addTopLevelItem(item)
    else:
        parent.addChild(item)


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
    return t


def _method_is_std(code: Bytecode, fmap: "dict[int, Function | Native]", findex: int) -> bool:
    func = fmap.get(findex)
    return isinstance(func, Function) and disasm.is_std(code, func)


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
