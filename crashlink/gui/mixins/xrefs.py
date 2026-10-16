"""Cross-reference lookups (`X`, double-click on a definition) for `MainWindow`."""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable, List, Optional

from crashlink.pseudo.symbols import SymbolKind, SymbolRef

from ..widgets.xref_panel import (
    XrefGroup,
    XrefSite,
    _func_label,
    describe_symbol,
    resolve_symbol,
    resolve_targets,
)

if TYPE_CHECKING:
    from ._host import MainWindowHost as _Base
else:
    _Base = object


class XrefMixin(_Base):
    """Cross-reference lookups (`X`, double-click on a definition) for `MainWindow`.

    State is set up by ``MainWindow.__init__``/``_build_ui`` (see ``._host`` for
    the typed surface); this area relies on:

    ``_code``, ``_xref_popup``, ``_log_panel``, ``_spans_cache``, ``_status_bar``,
    ``_follow_handlers``
    plus sibling-area methods resolved through ``MainWindow``.
    """

    def show_xrefs(self, title: str, groups: List[XrefGroup]) -> None:
        """Show `groups` in the xref popup, under the text cursor of the active pane if any."""
        view = self._find_target_view()
        if view is not None and view.isVisible():
            at = view.mapToGlobal(view.cursorRect().bottomLeft())
        else:
            at = self.mapToGlobal(self.rect().center())
        self._xref_popup.show_results(title, groups, at)

    def add_follow_handler(self, prefix: str, handler: Callable[[int], None]) -> None:
        """Handle double-click/Enter on `<prefix><index>` tokens (e.g. "g@" -> globals window)."""
        self._follow_handlers[prefix] = handler

    def _on_native_xref_requested(self, findex: int) -> None:
        self._show_xrefs_for(f"f@{findex}")

    def _show_xrefs_for(self, word: str) -> None:
        if self._code is None:
            return
        code = self._code

        def show(groups: List[XrefGroup]) -> None:
            self.show_xrefs(word, groups)
            self._log_panel.result(f"Xrefs for '{word}': {len(groups)} target(s)")

        self.run_background(f"Finding references to {word}...", lambda: resolve_targets(code, word), show)

    def _on_xref_hotkey(self, findex: int, target: "SymbolRef | str | None") -> None:
        """`X`: references to the symbol under the caret, or, for selected text that isn't
        a symbol, to everything by that name."""
        if self._code is None:
            return
        if target is None:
            self._status_bar.showMessage("No symbol here to find references to", 3000)
            return
        if isinstance(target, SymbolRef):
            self._show_symbol_xrefs(findex, target)
            return
        word = target.strip()
        if not word:
            return
        code = self._code

        def show(groups: List[XrefGroup]) -> None:
            self.show_xrefs(word, groups)
            self._log_panel.result(f"Xrefs for '{word}': {len(groups)} target(s)")

        # Name resolution scans every type/field/string: keep it off the UI thread.
        self.run_background(f"Finding references to {word}...", lambda: resolve_targets(code, word), show)

    def _show_symbol_xrefs(self, findex: int, ref: SymbolRef) -> None:
        """List the references to exactly `ref`."""
        if self._code is None:
            return
        code = self._code
        title = describe_symbol(code, ref)
        if ref.kind == SymbolKind.LOCAL:
            group = self._local_uses_group(ref)
            self.show_xrefs(title, [group] if group is not None else [])
            return

        def show(groups: List[XrefGroup]) -> None:
            self.show_xrefs(title, groups)
            self._log_panel.result(f"Xrefs for {title}: {sum(len(g.sites) for g in groups)} site(s)")

        self.run_background(f"Finding references to {title}...", lambda: resolve_symbol(code, ref), show)

    def _local_uses_group(self, ref: SymbolRef) -> Optional[XrefGroup]:
        """Every line of the local's function that has a token naming it, each site
        carrying its body-relative line."""
        rendered = self._spans_cache.get(ref.scope)
        if rendered is None:
            return None
        lines = rendered.text.split("\n")
        offset = rendered.body_start
        label = _func_label(self._code, ref.scope) if self._code else f"f@{ref.scope}"
        sites: List[XrefSite] = []
        seen: set[int] = set()
        for span in rendered.spans_of(ref):
            body_line = span.line - offset
            if span.line in seen or body_line < 0:
                continue
            seen.add(span.line)
            sites.append(
                XrefSite(
                    source_findex=ref.scope,
                    source_label=label,
                    opcode_index=None,
                    body_line=body_line,
                    ref_kind="definition" if span.is_def else "use",
                    snippet=lines[span.line].strip(),
                )
            )
        if not sites:
            return None
        return XrefGroup(label=f"local '{ref.name}'", kind="local", sites=sites)
