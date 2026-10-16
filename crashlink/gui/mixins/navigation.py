"""Navigation, history and jump-to-function behaviour for `MainWindow`."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Optional, Tuple

from PySide6.QtWidgets import QDialog

from crashlink.pseudo.symbols import SymbolKind, SymbolSpan

from ..chrome import _JumpDialog
from ..widgets.sync_view import DISASM, SyncView
from ..widgets.xref_panel import describe_symbol

if TYPE_CHECKING:
    from ._host import MainWindowHost as _Base
else:
    _Base = object


# Navigation history depth (Esc / Ctrl+Enter).
_HISTORY_LIMIT = 200


class NavigationMixin(_Base):
    """Navigation, history and jump-to-function behaviour for `MainWindow`.

    State is set up by ``MainWindow.__init__``/``_build_ui`` (see ``._host`` for
    the typed surface); this area relies on:

    ``_code``, ``_back_stack``, ``_forward_stack``, ``_back_action``, ``_forward_action``,
    ``_jump_names``, ``_func_list``, ``_open_tabs``, ``_tabs``, ``_cfg_findex``,
    ``_view_mode``, ``_opline_cache``, ``_pending_op_scroll``, ``_follow_handlers``,
    ``_symbol_status_shown``, ``_status_bar``
    plus sibling-area methods resolved through ``MainWindow``.
    """

    def navigate_to(self, findex: int, op_idx: Optional[int] = None) -> None:
        """Open the class tab containing `findex`, scroll to it (and to `op_idx` if
        given), focus the code, and record the jump for Back/Forward."""
        if self._code is None or findex not in self._code.get_findex_map():
            return
        self._push_history()
        self._forward_stack.clear()
        self._show_location(findex, -1 if op_idx is None else op_idx, -1)
        self._update_history_actions()

    def navigate_back(self) -> None:
        if not self._back_stack:
            return
        current = self._current_location()
        if current is not None:
            self._forward_stack.append(current)
        findex, op_idx = self._back_stack.pop()
        self._show_location(findex, -1 if op_idx is None else op_idx, -1)
        self._update_history_actions()

    def navigate_forward(self) -> None:
        if not self._forward_stack:
            return
        self._push_history()
        findex, op_idx = self._forward_stack.pop()
        self._show_location(findex, -1 if op_idx is None else op_idx, -1)
        self._update_history_actions()

    def _current_location(self) -> Optional[Tuple[int, Optional[int]]]:
        view = self._current_sync_view()
        if view is None or self._cfg_findex is None:
            return None
        op = view.disasm_view.op_at_cursor() if view.disasm_view.hasFocus() else None
        if op is not None and op[0] == self._cfg_findex:
            return (op[0], op[1])
        return (self._cfg_findex, None)

    def _push_history(self) -> None:
        current = self._current_location()
        if current is None or (self._back_stack and self._back_stack[-1] == current):
            return
        self._back_stack.append(current)
        del self._back_stack[:-_HISTORY_LIMIT]

    def _update_history_actions(self) -> None:
        self._back_action.setEnabled(bool(self._back_stack))
        self._forward_action.setEnabled(bool(self._forward_stack))

    def _open_jump_dialog(self) -> None:
        if self._code is None:
            self._status_bar.showMessage("Open a file first", 3000)
            return
        if not self._jump_names:
            self._jump_names = {f"{name}  f@{fi}": fi for fi, name in self._func_list.entries()}
        dialog = _JumpDialog(self, list(self._jump_names), self._resolve_jump)
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.findex is not None:
            self.navigate_to(dialog.findex)

    def _resolve_jump(self, text: str) -> "int | str":
        """findex for a Jump dialog entry, or an error message."""
        assert self._code is not None
        if not text:
            return "Enter a function index or name."
        match = re.fullmatch(r"(?:.*\s)?f@(\d+)|(\d+)", text)
        if match:
            findex = int(match.group(1) or match.group(2))
            if findex in self._code.get_findex_map():
                return findex
            return f"No function f@{findex}."
        lowered = text.lower()
        exact = [fi for name, fi in self._jump_names.items() if name.rsplit("  f@", 1)[0].lower() == lowered]
        if exact:
            return exact[0]
        partial = [fi for name, fi in self._jump_names.items() if lowered in name.lower()]
        if len(partial) == 1:
            return partial[0]
        return f"{len(partial)} functions match. Pick one from the list." if partial else "No such function."

    def _sync_view_for(self, findex: int) -> Optional[SyncView]:
        """The open tab showing the class `findex` belongs to."""
        class_key, _, _ = self._class_key_for(findex)
        idx = self._open_tabs.get(class_key)
        view = self._tabs.widget(idx) if idx is not None else None
        return view if isinstance(view, SyncView) else None

    def _on_symbol_focused(self, span: Optional[SymbolSpan]) -> None:
        """Say what the caret is on, so what a double-click or `X` would act on is never a guess."""
        if self._code is None:
            return
        if span is None:
            if self._symbol_status_shown:
                self._symbol_status_shown = False
                self._status_bar.clearMessage()
            return
        self._symbol_status_shown = True
        self._status_bar.showMessage(describe_symbol(self._code, span.ref))

    def _on_follow_requested(self, findex: int, span: Optional[SymbolSpan]) -> None:
        """Double-click / Enter in a code pane: go to the definition of the symbol under
        the caret. Already on the definition, list what uses it instead."""
        if self._code is None:
            return
        if span is None:
            self._status_bar.showMessage("No symbol here to follow", 3000)
            return
        ref = span.ref
        if ref.kind == SymbolKind.FUNCTION:
            if span.is_def:
                self._show_symbol_xrefs(findex, ref)
            else:
                self.navigate_to(ref.index)
        elif ref.kind in (SymbolKind.TYPE, SymbolKind.FIELD, SymbolKind.ENUM_CONSTRUCT):
            # A field or constructor is declared by its type, whose page lists it.
            self._open_types_tab(select=ref.index)
        elif ref.kind == SymbolKind.GLOBAL:
            handler = self._follow_handlers.get("g@")
            if handler is not None:
                handler(ref.index)
            else:
                self._show_symbol_xrefs(findex, ref)
        elif ref.kind == SymbolKind.LOCAL:
            view = self._sync_view_for(ref.scope)
            if span.is_def or view is None or not view.class_view.goto_definition(ref):
                self._show_symbol_xrefs(findex, ref)
        else:
            self._status_bar.showMessage(f"Nothing to follow for {describe_symbol(self._code, ref)}", 3000)

    def _navigate_to_xref(self, findex: int, op_idx: int, body_line: int) -> None:
        """Xref popup activation: a navigation, so it's recorded for Back."""
        if self._code is None:
            return
        self._push_history()
        self._forward_stack.clear()
        self._show_location(findex, op_idx, body_line)
        self._update_history_actions()

    def _show_location(self, findex: int, op_idx: int, body_line: int) -> None:
        """Open/focus `findex`'s class tab and scroll both panes to the op or line."""
        if self._code is None:
            return
        self._on_function_selected(findex)
        sync = self._current_sync_view()
        if sync is None:
            return
        view = sync.class_view
        if op_idx >= 0:
            sync.disasm_view.scroll_to_op(findex, op_idx)
        # Focus whichever pane is showing so keys (Esc, X, N, ...) act on it.
        (sync.disasm_view if self._view_mode == DISASM else view).setFocus()
        self._on_function_focused(findex)

        # Local site: body line is known directly.
        if body_line >= 0:
            view.scroll_to_op_line(findex, body_line)
            return

        if op_idx < 0:
            view.scroll_to_findex(findex)
            return

        opmap = self._opline_cache.get(findex)
        if opmap is None:
            # Map not cached yet (still decompiling) — defer to _on_decompile_finished.
            self._pending_op_scroll = (findex, op_idx)
            return

        line = opmap.get(op_idx)
        if line is None:
            # Nearest preceding mapped op.
            preceding = [v for k, v in opmap.items() if k <= op_idx]
            line = max(preceding) if preceding else None
        if line is None:
            view.scroll_to_findex(findex)
        else:
            view.scroll_to_op_line(findex, line)
