"""Xrefs panel: resolves a word to all matching targets and lists references grouped by target."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, cast

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QKeyEvent
from PySide6.QtWidgets import (
    QFrame,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ... import disasm
from ...core import (
    Abstract,
    Bytecode,
    Enum,
    Obj,
    SourceKind,
    XRef,
)
from ..themes import Theme


@dataclass
class XrefSite:
    """A single reference location."""

    source_findex: Optional[int]  # function the reference lives in (None for non-function sources)
    source_label: str
    opcode_index: Optional[int]  # opcode within the source function, if known
    body_line: Optional[int]  # body-relative pseudocode line, for locals (resolved directly)
    ref_kind: str  # human label for the kind of reference


@dataclass
class XrefGroup:
    """A resolved target and all of its reference sites."""

    label: str
    kind: str  # "function" | "type" | "field" | "enum" | "string" | "local" | "global"
    sites: List[XrefSite] = field(default_factory=list)


# ── Pure resolver (no Qt) ──────────────────────────────────────────────────────


def _func_label(code: Bytecode, findex: int) -> str:
    try:
        f = code.get_findex_map()[findex]
        return disasm.func_header(code, f)
    except Exception:
        return f"f@{findex}"


def _site_from_ref(code: Bytecode, ref: XRef) -> XrefSite:
    if ref.source_kind == SourceKind.FUNCTION:
        label = _func_label(code, ref.source_index)
        findex: Optional[int] = ref.source_index
    else:
        label = f"{ref.source_kind.value}@{ref.source_index}"
        findex = None
    return XrefSite(
        source_findex=findex,
        source_label=label,
        opcode_index=ref.opcode_index,
        body_line=None,
        ref_kind=ref.ref_kind.value,
    )


def resolve_targets(code: Bytecode, word: str) -> List[XrefGroup]:
    """Resolve `word` to every matching program-wide target (functions, types, fields,
    enum constructs, strings) and gather their references. Locals are handled by the caller."""
    word = word.strip()
    groups: List[XrefGroup] = []
    if not word:
        return groups

    xi = code.xref_index()
    si = code.search_index()

    # A literal "f@N" token (as rendered in disasm — this is the only way a
    # native, or any anonymous/ambiguously-named function, ever shows up as
    # text) resolves directly by findex instead of going through name search,
    # which is otherwise useless for natives: many share the same partial
    # name (or none at all) and can't be told apart by name alone.
    fref_match = re.fullmatch(r"f@(\d+)", word)
    if fref_match:
        findex = int(fref_match.group(1))
        target = code.get_findex_map().get(findex)
        if target is not None:
            callers = xi.callers_of(findex)
            groups.append(
                XrefGroup(
                    label=f"function {_func_label(code, findex)}",
                    kind="function",
                    sites=[_site_from_ref(code, r) for r in callers],
                )
            )
        return groups

    # A "g@N" (disasm) or "globalN" (pseudocode's `untyped $globalN(...)`
    # idiom for a raw HL global with no source-level name — see
    # pseudo.global_name) token resolves directly by global index.
    gref_match = re.fullmatch(r"g@(\d+)", word) or re.fullmatch(r"global(\d+)", word)
    if gref_match:
        gindex = int(gref_match.group(1))
        if 0 <= gindex < len(code.global_types):
            try:
                type_label = disasm.type_name(code, code.global_types[gindex].resolve(code))
            except Exception:
                type_label = "?"
            refs = xi.global_reads(gindex) + xi.global_writes(gindex)
            groups.append(
                XrefGroup(
                    label=f"global g@{gindex} ({type_label})",
                    kind="global",
                    sites=[_site_from_ref(code, r) for r in refs],
                )
            )
        return groups

    # Functions — partial (method) and full name matches, deduped by findex.
    seen_findex: set[int] = set()
    for func in [*si.find_partial(word), *si.find(word)]:
        findex = func.findex.value
        if findex in seen_findex:
            continue
        seen_findex.add(findex)
        callers = xi.callers_of(findex)
        groups.append(
            XrefGroup(
                label=f"function {_func_label(code, findex)}",
                kind="function",
                sites=[_site_from_ref(code, r) for r in callers],
            )
        )

    # Types, fields, enum constructs.
    for ti, t in enumerate(code.types):
        defn = t.definition
        if isinstance(defn, (Obj, Enum, Abstract)):
            try:
                tname = defn.name.resolve(code)
            except Exception:
                tname = None
            if tname == word:
                refs = xi.type_refs(ti)
                groups.append(
                    XrefGroup(
                        label=f"type {disasm.type_name(code, t)}",
                        kind="type",
                        sites=[_site_from_ref(code, r) for r in refs],
                    )
                )

        if isinstance(defn, Obj):
            for slot, fld in enumerate(defn.fields):
                try:
                    fname = fld.name.resolve(code)
                except Exception:
                    continue
                if fname != word:
                    continue
                refs = xi.all_field_accesses(ti, slot)
                groups.append(
                    XrefGroup(
                        label=f"field {disasm.type_name(code, t)}.{fname}",
                        kind="field",
                        sites=[_site_from_ref(code, r) for r in refs],
                    )
                )

        if isinstance(defn, Enum):
            for ci, construct in enumerate(defn.constructs):
                try:
                    cname = construct.name.resolve(code)
                except Exception:
                    continue
                if cname != word:
                    continue
                refs = xi.construct_uses(ti, ci)
                groups.append(
                    XrefGroup(
                        label=f"enum {disasm.type_name(code, t)}.{cname}",
                        kind="enum",
                        sites=[_site_from_ref(code, r) for r in refs],
                    )
                )

    # Strings — exact full-string match (cheap, rarely fires).
    try:
        strings = code.strings.value
    except Exception:
        strings = []
    for i, s in enumerate(strings):
        if s == word:
            refs = xi.string_uses(i)
            groups.append(
                XrefGroup(
                    label=f"string {s!r}",
                    kind="string",
                    sites=[_site_from_ref(code, r) for r in refs],
                )
            )

    return groups


# ── Panel widget ───────────────────────────────────────────────────────────────


def _ref_summary(group: XrefGroup) -> str:
    if group.kind == "field":
        reads = sum(1 for s in group.sites if s.ref_kind == "field_read")
        writes = sum(1 for s in group.sites if s.ref_kind == "field_write")
        return f"{reads} read, {writes} write"
    if group.kind == "global":
        reads = sum(1 for s in group.sites if s.ref_kind == "global_read")
        writes = sum(1 for s in group.sites if s.ref_kind == "global_write")
        return f"{reads} read, {writes} write"
    n = len(group.sites)
    if group.kind == "function":
        return f"{n} caller" + ("s" if n != 1 else "")
    return f"{n}"


_KIND_COLOR = {
    "function": "pink",
    "type": "teal",
    "field": "yellow",
    "enum": "mauve",
    "string": "green",
    "local": "peach",
    "global": "accent",
}


class XrefPopup(QFrame):
    """Frameless popup of xref sites. Esc dismisses, Enter jumps, arrows move."""

    # (findex, opcode_index_or_-1, body_line_or_-1)
    navigate_requested = Signal(int, int, int)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent, Qt.WindowType.Popup)
        self._theme: Optional[Theme] = None
        self.setFrameShape(QFrame.Shape.StyledPanel)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(1, 1, 1, 1)
        layout.setSpacing(0)

        self._title = QLabel()
        self._title.setObjectName("panelHeader")
        font = QFont()
        font.setBold(True)
        self._title.setFont(font)
        layout.addWidget(self._title)

        self._list = QListWidget()
        self._list.setUniformItemSizes(True)
        self._list.itemActivated.connect(self._on_item_activated)
        self._list.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        layout.addWidget(self._list)

        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)

    def set_theme(self, theme: Theme) -> None:
        self._theme = theme
        self.setStyleSheet(
            f"QFrame {{ background: {theme.mantle}; border: 1px solid {theme.overlay}; }}"
            f"QLabel#panelHeader {{ color: {theme.subtext}; padding: 4px 6px; }}"
            f"QListWidget {{ background: {theme.mantle}; border: none; padding: 2px; }}"
            f"QListWidget::item:selected {{ background: {theme.accent}; color: {theme.base}; }}"
        )

    def show_results(self, word: str, groups: List[XrefGroup], at: QPoint) -> None:
        self._list.clear()
        t = self._theme

        total = sum(len(g.sites) for g in groups)
        self._title.setText(f"Xrefs for '{word}' — {total} site(s)")

        bold = QFont()
        bold.setBold(True)

        for group in groups:
            head = QListWidgetItem(f"{group.label}  ({_ref_summary(group)})")
            head.setFlags(Qt.ItemFlag.NoItemFlags)
            head.setFont(bold)
            if t:
                head.setForeground(QBrush(QColor(getattr(t, _KIND_COLOR.get(group.kind, "text"), t.text))))
            self._list.addItem(head)

            for site in group.sites:
                if site.body_line is not None:
                    loc = f"line {site.body_line}"
                elif site.opcode_index is not None:
                    loc = f"op@{site.opcode_index}"
                else:
                    loc = ""
                text = f"    {site.source_label}   {site.ref_kind}  {loc}".rstrip()
                item = QListWidgetItem(text)
                if t:
                    item.setForeground(QBrush(QColor(t.subtext)))
                findex = site.source_findex if site.source_findex is not None else -1
                op = site.opcode_index if site.opcode_index is not None else -1
                line = site.body_line if site.body_line is not None else -1
                item.setData(Qt.ItemDataRole.UserRole, (findex, op, line))
                self._list.addItem(item)

        if total == 0:
            empty = QListWidgetItem(f"no xrefs for '{word}'")
            empty.setFlags(Qt.ItemFlag.NoItemFlags)
            if t:
                empty.setForeground(QBrush(QColor(t.overlay)))
            self._list.addItem(empty)

        self.adjustSize()
        self.resize(max(self.width(), 360), min(self.sizeHint().height(), 480))
        self.move(at)
        self.show()
        self._select_first()
        self.setFocus()

    def _select_first(self) -> None:
        for row in range(self._list.count()):
            if self._list.item(row).flags() & Qt.ItemFlag.ItemIsSelectable:
                self._list.setCurrentRow(row)
                return

    def _move(self, delta: int) -> None:
        count = self._list.count()
        row = self._list.currentRow() + delta
        while 0 <= row < count:
            if self._list.item(row).flags() & Qt.ItemFlag.ItemIsSelectable:
                self._list.setCurrentRow(row)
                return
            row += delta

    def _activate_current(self) -> None:
        item = self._list.currentItem()
        if item is not None:
            self._on_item_activated(item)

    def _on_item_activated(self, item: QListWidgetItem) -> None:
        data = item.data(Qt.ItemDataRole.UserRole)
        if not data:
            return
        findex, op, line = data
        if findex < 0:
            return
        self.close()
        self.navigate_requested.emit(findex, op, line)

    def keyPressEvent(self, event: object) -> None:
        if isinstance(event, QKeyEvent):
            key = event.key()
            if key == Qt.Key.Key_Escape:
                self.close()
                return
            if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                self._activate_current()
                return
            if key == Qt.Key.Key_Up:
                self._move(-1)
                return
            if key == Qt.Key.Key_Down:
                self._move(1)
                return
        super().keyPressEvent(cast(QKeyEvent, event))
