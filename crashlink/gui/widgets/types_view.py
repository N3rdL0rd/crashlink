"""Types table: every type in the bytecode (Obj/Enum/Virtual/Abstract/Ref/Null/Packed/Fun),
with a detail pane showing its layout — fields, methods, enum constructs, vtable slots."""

from __future__ import annotations

from typing import List, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QLineEdit,
    QPlainTextEdit,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ... import disasm
from ...core import Abstract, Bytecode, Enum, Fun, Null, Obj, Packed, Ref, Virtual
from ..themes import Theme

_COLUMNS = ["Index", "Kind", "Description"]


class _NumericItem(QTableWidgetItem):
    def __init__(self, value: int) -> None:
        super().__init__(str(value))
        self._value = value

    def __lt__(self, other: "QTableWidgetItem") -> bool:
        if isinstance(other, _NumericItem):
            return self._value < other._value
        return super().__lt__(other)


def type_summary(code: Bytecode, index: int) -> str:
    """One-line description of type t@index, e.g. 'fun(Foo) -> Bar' or 'class my.pack.Foo'.
    Used as the table's Description column and as the detail pane's heading."""
    defn = code.types[index].definition

    if isinstance(defn, Obj):
        return f"class {defn.name.resolve(code)}"
    if isinstance(defn, Enum):
        return f"enum {defn.name.resolve(code)}"
    if isinstance(defn, Virtual):
        return "virtual"
    if isinstance(defn, Fun):
        args = ", ".join(disasm.type_name(code, a.resolve(code)) for a in defn.args)
        ret = disasm.type_name(code, defn.ret.resolve(code))
        return f"fun({args}) -> {ret}"
    if isinstance(defn, Abstract):
        return f"abstract {defn.name.resolve(code)}"
    if isinstance(defn, Ref):
        return f"ref -> {disasm.type_name(code, defn.type.resolve(code))}"
    if isinstance(defn, Null):
        return f"null of {disasm.type_name(code, defn.type.resolve(code))}"
    if isinstance(defn, Packed):
        return f"packed of {disasm.type_name(code, defn.inner.resolve(code))}"
    return disasm.type_name(code, code.types[index])


def _fun_users(code: Bytecode, index: int) -> List[str]:
    """Everything whose declared type is Fun t@index: functions/natives with this
    signature, fields typed as this Fun, globals typed as this Fun, and any opcode-level
    references (closures, calls) picked up by the xref index."""
    out: List[str] = []

    for func in code.functions:
        if func.type.value == index:
            out.append(f"  function {disasm.func_header(code, func)}")
    for native in code.natives:
        if native.type.value == index:
            out.append(f"  native {native.lib.resolve(code)}.{native.name.resolve(code)}")

    for ti, typ in enumerate(code.types):
        defn = typ.definition
        if isinstance(defn, (Obj, Virtual)):
            for field in defn.fields:
                if field.type.value == index:
                    owner = getattr(defn, "name", None)
                    owner_name = owner.resolve(code) if owner is not None else f"t@{ti}"
                    out.append(f"  field {owner_name}.{field.name.resolve(code)}")

    for gi, gtype in enumerate(code.global_types):
        if gtype.value == index:
            out.append(f"  global g@{gi}")

    xi = code.xref_index()
    for ref in xi.type_refs(index):
        if ref.source_kind.value == "function":
            label = disasm.func_header(code, code.get_findex_map()[ref.source_index])
        else:
            label = f"{ref.source_kind.value}@{ref.source_index}"
        out.append(f"  {ref.ref_kind.value} in {label}")

    return out


def describe_type(code: Bytecode, index: int) -> str:
    """Render a human-readable layout for type t@index. Shared by GUI and any future callers."""
    typ = code.types[index]
    defn = typ.definition
    lines = [f"t@{index}  {type_summary(code, index)}  ({defn.__class__.__name__})"]

    if isinstance(defn, Obj):
        if defn.super and defn.super.value is not None:
            try:
                lines.append(f"extends {disasm.type_name(code, defn.super.resolve(code))}")
            except Exception:
                lines.append(f"extends t@{defn.super.value}")
        lines.append("")
        lines.append("Fields:")
        if defn.fields:
            for field in defn.fields:
                try:
                    ft = disasm.type_name(code, field.type.resolve(code))
                except Exception:
                    ft = f"t@{field.type.value}"
                lines.append(f"  {field.name.resolve(code)}: {ft}")
        else:
            lines.append("  (none)")
        lines.append("")
        lines.append("Protos (instance methods):")
        if defn.protos:
            for proto in defn.protos:
                header = disasm.func_header(code, proto.findex.resolve(code))
                lines.append(f"  {header.replace(' static ', ' ')}")
        else:
            lines.append("  (none)")
        lines.append("")
        lines.append("Bindings (static methods):")
        if defn.bindings:
            for binding in defn.bindings:
                lines.append(f"  {disasm.func_header(code, binding.findex.resolve(code))}")
        else:
            lines.append("  (none)")

    elif isinstance(defn, Enum):
        lines.append(f"global: g@{defn._global.value}")
        lines.append("")
        lines.append(f"Constructs ({defn.nconstructs.value}):")
        if defn.constructs:
            for i, construct in enumerate(defn.constructs):
                if construct.params:
                    params = ", ".join(disasm.type_name(code, p.resolve(code)) for p in construct.params)
                    lines.append(f"  {i}: {construct.name.resolve(code)}({params})")
                else:
                    lines.append(f"  {i}: {construct.name.resolve(code)}")
        else:
            lines.append("  (none)")

    elif isinstance(defn, Virtual):
        lines.append("Fields:")
        for field in defn.fields:
            try:
                ft = disasm.type_name(code, field.type.resolve(code))
            except Exception:
                ft = f"t@{field.type.value}"
            lines.append(f"  {field.name.resolve(code)}: {ft}")

    elif isinstance(defn, Fun):
        lines.append("")
        lines.append("Used by:")
        users = _fun_users(code, index)
        lines.extend(users if users else ["  (nothing found)"])

    return "\n".join(lines)


class TypesView(QWidget):
    """Sortable table of every type, with a detail pane for the selected one."""

    xref_requested = Signal(str)  # e.g. "t@12"

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._code: Optional[Bytecode] = None
        self._theme: Optional[Theme] = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter types…")
        self._search.setClearButtonEnabled(True)
        self._search.textChanged.connect(self._apply_filter)
        layout.addWidget(self._search)

        splitter = QSplitter(Qt.Orientation.Vertical)

        self._table = QTableWidget()
        self._table.setColumnCount(len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.verticalHeader().setVisible(False)
        self._table.setSortingEnabled(True)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        splitter.addWidget(self._table)

        self._detail = QPlainTextEdit()
        self._detail.setReadOnly(True)
        font = self._detail.font()
        font.setFamily("monospace")
        self._detail.setFont(font)
        splitter.addWidget(self._detail)
        splitter.setSizes([300, 300])

        layout.addWidget(splitter)

    def set_theme(self, theme: Theme) -> None:
        self._theme = theme

    def load(self, code: Bytecode) -> None:
        self._code = code
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(code.types))
        for index, typ in enumerate(code.types):
            kind = typ.definition.__class__.__name__
            try:
                summary = type_summary(code, index)
            except Exception:
                summary = ""

            self._table.setItem(index, 0, _NumericItem(index))
            self._table.setItem(index, 1, QTableWidgetItem(kind))
            self._table.setItem(index, 2, QTableWidgetItem(summary))

        self._table.setSortingEnabled(True)
        self._table.resizeColumnsToContents()
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)

    def _apply_filter(self, query: str) -> None:
        query = query.lower()
        for row in range(self._table.rowCount()):
            if not query:
                self._table.setRowHidden(row, False)
                continue
            cells = (self._table.item(row, col) for col in range(self._table.columnCount()))
            hay = " ".join(cell.text().lower() for cell in cells if cell is not None)
            self._table.setRowHidden(row, query not in hay)

    def _on_selection_changed(self) -> None:
        if self._code is None:
            return
        item = self._table.currentItem()
        if item is None:
            return
        index_item = self._table.item(item.row(), 0)
        if index_item is None:
            return
        index = index_item.data(Qt.ItemDataRole.DisplayRole)
        try:
            text = describe_type(self._code, int(index))
        except Exception as e:
            text = f"(error rendering t@{index}: {e})"
        self._detail.setPlainText(text)

    def keyPressEvent(self, event: object) -> None:
        if isinstance(event, QKeyEvent) and not event.modifiers() and event.key() == Qt.Key.Key_X:
            item = self._table.currentItem()
            if item is not None:
                index_item = self._table.item(item.row(), 0)
                if index_item is not None:
                    self.xref_requested.emit(f"t@{index_item.data(Qt.ItemDataRole.DisplayRole)}")
                    return
        super().keyPressEvent(event)  # type: ignore[arg-type]
