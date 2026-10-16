"""Rename/comment/setstring edits and the undo stack plumbing for `MainWindow`."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from PySide6.QtWidgets import QInputDialog

from crashlink.decomp.function import IRFunction
from crashlink.pseudo.symbols import SymbolKind, SymbolRef

from ..undo import CommentCommand, RenameCommand, ReplaceFunctionCommand, SetStringCommand

if TYPE_CHECKING:
    from crashlink.asm import FunctionEdit

if TYPE_CHECKING:
    from ._host import MainWindowHost as _Base
else:
    _Base = object


class AnnotateMixin(_Base):
    """Rename/comment/setstring edits and the undo stack plumbing for `MainWindow`.

    State is set up by ``MainWindow.__init__``/``_build_ui`` (see ``._host`` for
    the typed surface); this area relies on:

    ``_code``, ``_ir_cache``, ``_opline_cache``, ``_spans_cache``, ``_status_bar``,
    ``_undo_stack``, ``_log_panel``, ``_worker``, ``_cfg_findex``, ``_cfg_view``,
    ``_class_findices``, ``_class_results``
    plus sibling-area methods resolved through ``MainWindow``.
    """

    def _on_rename_hotkey(self, findex: int, ref: "SymbolRef | None") -> None:
        """`N`: rename the local variable under the caret, everywhere it appears. One name
        can stand for several (register, definition) pairs of the bytecode (a register
        reused for the same variable), and all of them are renamed in one undo step."""
        if self._code is None:
            return
        if ref is None or ref.kind != SymbolKind.LOCAL:
            self._status_bar.showMessage("Place the cursor on a local variable to rename it", 3000)
            return
        findex, word = ref.scope, ref.name
        ir = self._ir_cache.get(findex)
        if not isinstance(ir, IRFunction):
            self._status_bar.showMessage("Still decompiling, try again in a moment", 3000)
            return

        targets = sorted(
            {
                (loc.reg_idx, loc.defining_op_idx)
                for loc in ir.all_locals
                if loc.name == word and loc.reg_idx is not None
            },
            key=lambda t: (t[0], -1 if t[1] is None else t[1]),
        )
        if not targets:
            self._status_bar.showMessage(f"'{word}' isn't a local variable of this function", 3000)
            return

        new_name, ok = QInputDialog.getText(self, "Rename", f"Rename '{word}' to:", text=word)
        if not ok or not new_name or new_name == word:
            return

        self._undo_stack.beginMacro(f"Rename '{word}' to '{new_name}'")
        for reg_idx, def_op in targets:
            self.apply_rename(findex, reg_idx, def_op, new_name)
        self._undo_stack.endMacro()
        self._log_panel.success(f"Renamed '{word}' → '{new_name}' in f@{findex}")

    def apply_rename(self, findex: int, reg_idx: int, def_op: Optional[int], new_name: Optional[str]) -> None:
        """new_name=None clears the rename (used by the CLI bridge's `unrename`)."""
        if self._code is None:
            return
        old_name = self._code.annotations.get_rename(findex, reg_idx, def_op)
        cmd = RenameCommand(
            self._code, findex, reg_idx, def_op, old_name, new_name, self._on_annotation_applied
        )
        self._undo_stack.push(cmd)

    def apply_comment(self, findex: int, op_idx: int, text: Optional[str]) -> None:
        """text=None clears the comment (used by the CLI bridge's `rmcomment`)."""
        if self._code is None:
            return
        old_text = self._code.annotations.get_comment(findex, op_idx)
        cmd = CommentCommand(self._code, findex, op_idx, old_text, text, self._on_annotation_applied)
        self._undo_stack.push(cmd)

    def apply_setstring(self, index: int, new_value: str) -> None:
        if self._code is None:
            return
        old_value = self._code.strings.value[index]
        cmd = SetStringCommand(self._code, index, old_value, new_value, self._on_annotation_applied)
        self._undo_stack.push(cmd)

    def apply_function_edit(self, edit: "FunctionEdit") -> None:
        """Swap in an edited function (from crashlink.asm.edit_function), undoably."""
        if self._code is None:
            return
        self._undo_stack.push(ReplaceFunctionCommand(self._code, edit, self._on_annotation_applied))

    def _on_annotation_applied(self, findex: Optional[int]) -> None:
        """Shared undo/redo callback for rename and comment commands."""
        if findex is None:
            return
        class_key, _, _ = self._class_key_for(findex)
        self._refresh_disasm_view(class_key)
        self._invalidate_and_redecompile(findex)

    def _invalidate_and_redecompile(self, findex: int) -> None:
        """After an annotation (rename/comment) changes, drop every cache that was
        derived from the old IR for this function and kick off a fresh decompile."""
        if self._code is None:
            return
        if self._code.inspection_only:
            self._update_cfg_view(findex)
            return
        self._worker.invalidate(findex)
        self._ir_cache.pop(findex, None)
        self._opline_cache.pop(findex, None)
        self._spans_cache.pop(findex, None)
        if findex == self._cfg_findex:
            self._cfg_view.show_pending()
            self._log_panel.set_context(irf=None)

        for class_key, fi_list in self._class_findices.items():
            if findex in fi_list:
                if class_key in self._class_results:
                    self._class_results[class_key][findex] = None
                self._start_decompile(class_key, findex)
                break

    def _on_comment_hotkey(self, findex: int, op_idx: int) -> None:
        if self._code is None:
            return
        existing = self._code.annotations.get_comment(findex, op_idx)
        text, ok = QInputDialog.getText(
            self, "Comment", f"Comment on op {op_idx} in f@{findex}:", text=existing or ""
        )
        if not ok:
            return
        text = text.strip()
        new_text = text or None
        self.apply_comment(findex, op_idx, new_text)
        if new_text:
            self._log_panel.success(f"Commented op {op_idx} in f@{findex}")
        else:
            self._log_panel.info(f"Cleared comment on op {op_idx} in f@{findex}")
