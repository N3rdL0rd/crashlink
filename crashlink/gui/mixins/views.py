"""View mode, focus tracking (CFG/REPL), the find bar and theme application for `MainWindow`."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from PySide6.QtGui import QColor
from PySide6.QtWidgets import QPlainTextEdit

from crashlink.core import Native
from crashlink.decomp.function import IRFunction

from ..themes import Theme, generate_qss
from ..widgets.class_view import ClassView
from ..widgets.sync_view import DISASM, PSEUDO, SPLIT, SyncView

if TYPE_CHECKING:
    from ._host import MainWindowHost as _Base
else:
    _Base = object


# View mode cycling: Tab steps through split → disassembly → decompiled → ...
_VIEW_MODE_CYCLE = [SPLIT, DISASM, PSEUDO]
_VIEW_MODE_NAMES = {SPLIT: "Split", DISASM: "Disassembly", PSEUDO: "Decompiled"}
_VIEW_MODE_GLYPHS = {SPLIT: "◧", DISASM: "≡", PSEUDO: "{ }"}


class ViewsMixin(_Base):
    """View mode, focus tracking (CFG/REPL), the find bar and theme application for `MainWindow`.

    State is set up by ``MainWindow.__init__``/``_build_ui`` (see ``._host`` for
    the typed surface); this area relies on:

    ``_cfg_findex``, ``_cfg_dock``, ``_cfg_view``, ``_code``, ``_ir_cache``, ``_log_panel``,
    ``_tabs``, ``_view_mode``, ``_view_mode_buttons``, ``_find_bar``, ``_status_bar``,
    ``_theme``, ``_tab_bar``, ``_func_list``, ``_xref_popup``, ``function_focused``,
    ``theme_changed``
    plus sibling-area methods resolved through ``MainWindow``.
    """

    def _on_function_focused(self, findex: int) -> None:
        if findex == self._cfg_findex:
            return
        self._cfg_findex = findex
        self._update_cfg_view(findex)
        self._update_repl_focus(findex)
        self.function_focused.emit(findex)

    def _on_op_focused(self, findex: int, op_idx: int) -> None:
        """Disasm cursor moved onto an opcode: outline its block in the CFG."""
        if self._cfg_dock.isVisible():
            self._cfg_view.highlight_op(findex, op_idx)

    def _update_repl_focus(self, findex: int) -> None:
        """Keep the REPL's `findex`/`func`/`irf` pointed at the focused function."""
        func = self._code.get_findex_map().get(findex) if self._code is not None else None
        self._log_panel.set_context(findex=findex, func=func, irf=self._ir_cache.get(findex))

    def _on_cfg_dock_visibility(self, visible: bool) -> None:
        if visible and self._cfg_findex is not None:
            self._update_cfg_view(self._cfg_findex)

    def _update_cfg_view(self, findex: int) -> None:
        if self._code is None or not self._cfg_dock.isVisible():
            return
        if self._code.inspection_only:
            self._cfg_view.show_native()
            return
        func = self._code.get_findex_map().get(findex)
        if isinstance(func, Native):
            self._cfg_view.show_native()
            return

        ir = self._ir_cache.get(findex)
        if not isinstance(ir, IRFunction):
            self._cfg_view.show_pending()
            return
        # Graphviz layout can take seconds on big functions; CfgView runs it off-thread.
        self._cfg_view.request(findex, ir)

    def _find_target_view(self) -> Optional[QPlainTextEdit]:
        sv = self._current_sync_view()
        if sv is None:
            return None
        if self._view_mode == DISASM:
            return sv.disasm_view
        if self._view_mode == PSEUDO:
            return sv.class_view
        # SPLIT: search whichever pane currently has focus, default to pseudo.
        return sv.disasm_view if sv.disasm_view.hasFocus() else sv.class_view

    def _open_find(self) -> None:
        target = self._find_target_view()
        if target is None:
            self._status_bar.showMessage("Open a class tab to search its code", 3000)
            return
        self._find_bar.open_on(target)

    def _current_class_view(self) -> Optional[ClassView]:
        w = self._tabs.currentWidget()
        if isinstance(w, SyncView):
            return w.class_view
        return None

    def _current_sync_view(self) -> Optional[SyncView]:
        w = self._tabs.currentWidget()
        return w if isinstance(w, SyncView) else None

    def _cycle_view_mode(self) -> None:
        next_idx = (_VIEW_MODE_CYCLE.index(self._view_mode) + 1) % len(_VIEW_MODE_CYCLE)
        self._set_view_mode(_VIEW_MODE_CYCLE[next_idx])

    def _set_view_mode(self, mode: int) -> None:
        self._view_mode = mode
        for i in range(self._tabs.count()):
            view = self._tabs.widget(i)
            if isinstance(view, SyncView):
                view.set_mode(mode)
        self._update_view_mode_label()

    def _update_view_mode_label(self) -> None:
        btn = self._view_mode_buttons.get(self._view_mode)
        if btn is not None:
            btn.setChecked(True)

    def _apply_theme(self, theme: Theme) -> None:
        self._theme = theme
        self.setStyleSheet(generate_qss(theme))
        self._tab_bar._fill = QColor(theme.mantle)
        self._tab_bar.update()
        self._func_list.set_theme(theme)
        self._log_panel.set_theme(theme)
        self._xref_popup.set_theme(theme)
        self._cfg_view.set_theme(theme)
        for i in range(self._tabs.count()):
            view = self._tabs.widget(i)
            set_theme = getattr(view, "set_theme", None)
            if callable(set_theme):
                set_theme(theme)
        self.theme_changed.emit(theme)
