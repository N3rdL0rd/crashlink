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
    Function,
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
    snippet: Optional[str] = None  # one-line code at the site; derived from the opcode when None


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


def site_from_ref(code: Bytecode, ref: XRef) -> XrefSite:
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
                    sites=[site_from_ref(code, r) for r in callers],
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
                    sites=[site_from_ref(code, r) for r in refs],
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
                sites=[site_from_ref(code, r) for r in callers],
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
                        sites=[site_from_ref(code, r) for r in refs],
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
                        sites=[site_from_ref(code, r) for r in refs],
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
                        sites=[site_from_ref(code, r) for r in refs],
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
                    sites=[site_from_ref(code, r) for r in refs],
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


# Sites past this many get no code snippet line.
_SNIPPET_LIMIT = 400

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
    """Frameless popup of xref sites. Esc dismisses, Enter jumps, arrows move.

    Each site shows `f@N Class.method  op K  kind` with the code at that site on a
    second, dimmed line, so several references from one function stay distinguishable."""

    # (findex, opcode_index_or_-1, body_line_or_-1)
    navigate_requested = Signal(int, int, int)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent, Qt.WindowType.Popup)
        self._theme: Optional[Theme] = None
        self._code: Optional[Bytecode] = None
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
        self._list.setUniformItemSizes(False)
        self._list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._list.setTextElideMode(Qt.TextElideMode.ElideRight)
        self._list.itemActivated.connect(self._on_item_activated)
        self._list.itemClicked.connect(self._on_item_activated)
        self._list.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        layout.addWidget(self._list)

        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)

    def set_code(self, code: Optional[Bytecode]) -> None:
        """Document used to label sites and render their code snippets."""
        self._code = code

    def set_theme(self, theme: Theme) -> None:
        self._theme = theme
        self.setStyleSheet(
            f"QFrame {{ background: {theme.mantle}; border: 1px solid {theme.overlay}; }}"
            f"QLabel#panelHeader {{ color: {theme.subtext}; padding: 4px 6px; }}"
            f"QListWidget {{ background: {theme.mantle}; border: none; padding: 2px; }}"
            f"QListWidget::item {{ padding: 2px 4px; }}"
            f"QListWidget::item:selected {{ background: {theme.surface1}; color: {theme.text}; }}"
        )

    def _site_label(self, site: XrefSite) -> str:
        if site.source_findex is None or self._code is None:
            return site.source_label
        fn = self._code.get_findex_map().get(site.source_findex)
        name = None
        if isinstance(fn, Function):
            try:
                name = self._code.full_func_name(fn)
            except Exception:
                name = None
        return f"f@{site.source_findex}  {name}" if name else site.source_label

    def _site_snippet(self, site: XrefSite) -> Optional[str]:
        if site.snippet is not None:
            return site.snippet
        if site.source_findex is None or site.opcode_index is None or self._code is None:
            return None
        fn = self._code.get_findex_map().get(site.source_findex)
        if not isinstance(fn, Function) or not 0 <= site.opcode_index < len(fn.ops):
            return None
        try:
            row = disasm.fmt_op_compact(self._code, fn.regs, fn.ops[site.opcode_index], site.opcode_index)
        except Exception:
            return None
        return row.split(". ", 1)[-1].strip()

    def show_results(self, word: str, groups: List[XrefGroup], at: QPoint) -> None:
        self._list.clear()
        t = self._theme

        total = sum(len(g.sites) for g in groups)
        self._title.setText(f"Xrefs for '{word}': {total} site(s)")

        bold = QFont()
        bold.setBold(True)
        metrics = self._list.fontMetrics()
        widest = metrics.horizontalAdvance(self._title.text())

        shown_sites = 0
        for group in groups:
            head = QListWidgetItem(f"{group.label}  ({_ref_summary(group)})")
            head.setFlags(Qt.ItemFlag.NoItemFlags)
            head.setFont(bold)
            if t:
                head.setForeground(QBrush(QColor(getattr(t, _KIND_COLOR.get(group.kind, "text"), t.text))))
            self._list.addItem(head)
            widest = max(widest, metrics.horizontalAdvance(head.text()))

            for site in group.sites:
                if site.body_line is not None:
                    loc = f"line {site.body_line + 1}"
                elif site.opcode_index is not None:
                    loc = f"op {site.opcode_index}"
                else:
                    loc = ""
                first = f"  {self._site_label(site)}    {loc}  {site.ref_kind}".rstrip()
                # Snippets are rendered per site; past a few hundred they cost more than
                # they help (a busy field can have thousands of sites).
                snippet = self._site_snippet(site) if shown_sites < _SNIPPET_LIMIT else None
                shown_sites += 1
                text = f"{first}\n      {snippet}" if snippet else first
                item = QListWidgetItem(text)
                if t:
                    item.setForeground(QBrush(QColor(t.text)))
                item.setToolTip(text)
                findex = site.source_findex if site.source_findex is not None else -1
                op = site.opcode_index if site.opcode_index is not None else -1
                line = site.body_line if site.body_line is not None else -1
                item.setData(Qt.ItemDataRole.UserRole, (findex, op, line))
                self._list.addItem(item)
                widest = max(widest, *(metrics.horizontalAdvance(part) for part in text.split("\n")))

        if total == 0:
            empty = QListWidgetItem(f"no xrefs for '{word}'")
            empty.setFlags(Qt.ItemFlag.NoItemFlags)
            if t:
                empty.setForeground(QBrush(QColor(t.overlay)))
            self._list.addItem(empty)

        # As wide as the content, between 520 px and 70% of the window.
        parent = self.parentWidget()
        max_width = int(parent.window().width() * 0.7) if parent is not None else 900
        width = max(520, min(widest + 48, max_width))
        rows_height = sum(self._list.sizeHintForRow(row) for row in range(self._list.count()))
        height = min(rows_height + self._title.sizeHint().height() + 12, 520)
        self.resize(width, max(height, 120))
        # Keep the popup on screen.
        screen = self.screen().availableGeometry() if self.screen() is not None else None
        if screen is not None:
            at = QPoint(
                max(screen.left(), min(at.x(), screen.right() - self.width())),
                max(screen.top(), min(at.y(), screen.bottom() - self.height())),
            )
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
