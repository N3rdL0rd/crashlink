"""Jump/Search lookups: go to a file offset or a source location, cross-references
by kind and index (CLI `offset`, `srcloc`, `xref`), and the opcode reference."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Callable, List, Optional, Tuple, Union

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (
    QComboBox,
    QCompleter,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from ...core import Bytecode, TargetKind
from ...opcodes import opcode_docs, opcodes
from ..widgets.table_view import FilterTable
from ..widgets.xref_panel import XrefGroup, XrefSite, site_from_ref

if TYPE_CHECKING:
    from ..main_window import MainWindow

# kind label -> (TargetKind, needs an aux index, aux label)
_XREF_KINDS = {
    "Function (f@)": (TargetKind.FUNCTION, False, ""),
    "Type (t@)": (TargetKind.TYPE, False, ""),
    "Field (t@ + slot)": (TargetKind.FIELD, True, "Field slot:"),
    "Global (g@)": (TargetKind.GLOBAL, False, ""),
    "String (#)": (TargetKind.STRING, False, ""),
    "Enum construct (t@ + index)": (TargetKind.ENUM_CONSTRUCT, True, "Construct index:"),
}


class _FormDialog(QDialog):
    """Small form dialog whose accept runs `validate`; a returned string is shown
    as an inline error and keeps the dialog open."""

    def __init__(self, parent: QWidget, title: str) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(460)
        self.form = QFormLayout()
        layout = QVBoxLayout(self)
        layout.addLayout(self.form)
        self.error = QLabel("")
        self.error.setObjectName("dialogError")
        layout.addWidget(self.error)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._try_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.validate: Callable[[], Optional[str]] = lambda: None

    def _try_accept(self) -> None:
        problem = self.validate()
        if problem:
            self.error.setText(problem)
            return
        self.accept()


def _parse_int(text: str) -> Optional[int]:
    text = text.strip().lower()
    text = re.sub(r"^[a-z]@", "", text).lstrip("#")
    try:
        return int(text, 16) if text.startswith("0x") else int(text)
    except ValueError:
        return None


def _code(mw: "MainWindow") -> Optional[Bytecode]:
    if mw.code is None:
        mw.statusBar().showMessage("Open a file first", 3000)
    return mw.code


# ── Go to offset ──────────────────────────────────────────────────────────────


def go_to_offset(mw: "MainWindow") -> None:
    code = _code(mw)
    if code is None:
        return
    dialog = _FormDialog(mw, "Go to File Offset")
    field = QLineEdit()
    field.setPlaceholderText("0x1a2b or 6699")
    dialog.form.addRow("Offset:", field)

    def validate() -> Optional[str]:
        offset = _parse_int(field.text())
        if offset is None or offset < 0:
            return "Enter a decimal or 0x-prefixed hex offset."
        section = code.section_at(offset)
        if section is None:
            return f"{offset:#x} is before the first section."
        mw.log.result(f"Offset {offset:#x} is in the '{section}' section")
        mw.statusBar().showMessage(f"{offset:#x}: {section} section", 5000)
        return None

    dialog.validate = validate
    dialog.exec()


# ── Go to source location ─────────────────────────────────────────────────────


def go_to_source(mw: "MainWindow") -> None:
    code = _code(mw)
    if code is None:
        return
    sm = code.source_map()
    files = sorted(sm.files())
    if not files:
        mw.statusBar().showMessage("No debug info: source locations are unavailable", 4000)
        return
    dialog = _FormDialog(mw, "Go to Source Location")
    field = QLineEdit()
    field.setPlaceholderText("Player.hx:120")
    completer = QCompleter([f"{name}:" for name in files], dialog)
    completer.setFilterMode(Qt.MatchFlag.MatchContains)
    completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
    field.setCompleter(completer)
    dialog.form.addRow("File:line", field)
    hits: List[Tuple[int, int]] = []

    def validate() -> Optional[str]:
        match = re.fullmatch(r"\s*(.+?):(\d+)\s*", field.text())
        if not match:
            return "Use file:line, e.g. Player.hx:120"
        file_idx = sm.file_index(match.group(1))
        if file_idx is None:
            return f"No debug file matches {match.group(1)!r}."
        found = sm.ops_at(file_idx, int(match.group(2)))
        if not found:
            return f"No opcodes at {match.group(1)}:{match.group(2)}."
        hits[:] = [(func.findex.value, op_idx) for func, op_idx in found]
        return None

    dialog.validate = validate
    if dialog.exec() != QDialog.DialogCode.Accepted:
        return
    functions = {findex for findex, _ in hits}
    if len(functions) == 1:
        mw.navigate_to(hits[0][0], hits[0][1])
        return
    sites = [XrefSite(findex, f"f@{findex}", op_idx, None, "at line") for findex, op_idx in hits]
    mw.show_xrefs(
        field.text(),
        [XrefGroup(label=f"{field.text()} ({len(functions)} functions)", kind="function", sites=sites)],
    )


# ── Cross-references by kind/index ────────────────────────────────────────────


def xrefs_by_index(mw: "MainWindow") -> None:
    code = _code(mw)
    if code is None:
        return
    bytecode: Bytecode = code
    dialog = _FormDialog(mw, "Cross-References")
    kind = QComboBox()
    kind.addItems(list(_XREF_KINDS))
    index = QLineEdit()
    index.setPlaceholderText("index, e.g. 123 or f@123")
    aux = QLineEdit()
    aux_label = QLabel("")
    dialog.form.addRow("Kind:", kind)
    dialog.form.addRow("Index:", index)
    dialog.form.addRow(aux_label, aux)

    def kind_changed() -> None:
        _, needs_aux, label = _XREF_KINDS[kind.currentText()]
        aux.setVisible(needs_aux)
        aux_label.setVisible(needs_aux)
        aux_label.setText(label)

    kind.currentTextChanged.connect(lambda _: kind_changed())
    kind_changed()
    result: List[XrefGroup] = []

    def validate() -> Optional[str]:
        target, needs_aux, _ = _XREF_KINDS[kind.currentText()]
        value = _parse_int(index.text())
        if value is None:
            return "Enter a numeric index."
        aux_value: Union[int, None] = None
        if needs_aux:
            aux_value = _parse_int(aux.text())
            if aux_value is None:
                return "Enter the second index."
        refs = bytecode.xref_index().refs_to(target, value, aux_value)
        label = f"{kind.currentText().split(' (')[0].lower()} {value}" + (
            f"/{aux_value}" if needs_aux else ""
        )
        result[:] = [
            XrefGroup(label=label, kind=target.value, sites=[site_from_ref(bytecode, r) for r in refs])
        ]
        return None

    dialog.validate = validate
    if dialog.exec() == QDialog.DialogCode.Accepted and result:
        mw.show_xrefs(result[0].label, result)


# ── Opcode reference ──────────────────────────────────────────────────────────


def open_opcode_reference(mw: "MainWindow") -> None:
    def build() -> QWidget:
        table = FilterTable(["Opcode", "Operands", "Description"], "Filter opcodes…")
        rows = []
        for name, schema in opcodes.items():
            operands = ", ".join(f"{param}: {kind}" for param, kind in schema.items())
            rows.append((name, operands, opcode_docs.get(name, "")))
        table.set_rows(rows, column_widths=(140, 360))
        return table

    mw.open_tab("__opcodes__", "Opcode Reference", build)


def install(mw: "MainWindow") -> None:
    def action(text: str, shortcut: str, slot: Callable[[], None]) -> QAction:
        act = QAction(text, mw)
        act.setShortcut(QKeySequence(shortcut))
        act.triggered.connect(slot)
        return act

    jump = mw.menu("Jump")
    jump.addSeparator()
    jump.addAction(action("Go to File Offset…", "Ctrl+Shift+O", lambda: go_to_offset(mw)))
    jump.addAction(action("Go to Source Location…", "Ctrl+L", lambda: go_to_source(mw)))
    mw.menu("Search").addAction(action("Cross-References…", "Ctrl+Shift+X", lambda: xrefs_by_index(mw)))
    help_menu = mw.menu("Help")
    reference = QAction("Opcode Reference", mw)
    reference.triggered.connect(lambda: open_opcode_reference(mw))
    help_menu.insertAction(help_menu.actions()[0], reference)
