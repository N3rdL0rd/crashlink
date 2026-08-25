"""QUndoCommands for every mutation the GUI (and its !<cmd> CLI bridge) can make to a
Bytecode's AnnotationStore or string pool — the edit buffer is just a QUndoStack of these."""

from __future__ import annotations

from typing import Callable, Optional

from PySide6.QtGui import QUndoCommand

from ..core import Bytecode

# Called after any command's redo/undo applies, with the findex that needs
# re-decompiling (None if the edit isn't function-scoped, e.g. a string edit).
ApplyCallback = Callable[[Optional[int]], None]


class RenameCommand(QUndoCommand):
    def __init__(
        self,
        code: Bytecode,
        findex: int,
        reg_idx: int,
        def_op: Optional[int],
        old_name: Optional[str],
        new_name: Optional[str],
        on_applied: ApplyCallback,
        text: Optional[str] = None,
    ) -> None:
        super().__init__(text or (f"Rename to {new_name!r}" if new_name else "Clear rename"))
        self._code = code
        self._findex = findex
        self._reg_idx = reg_idx
        self._def_op = def_op
        self._old_name = old_name
        self._new_name = new_name
        self._on_applied = on_applied

    def _set(self, name: Optional[str]) -> None:
        if name is None:
            self._code.annotations.clear_rename(self._findex, self._reg_idx, self._def_op)
        else:
            self._code.annotations.rename(self._findex, self._reg_idx, self._def_op, name)
        self._on_applied(self._findex)

    def redo(self) -> None:
        self._set(self._new_name)

    def undo(self) -> None:
        self._set(self._old_name)


class CommentCommand(QUndoCommand):
    def __init__(
        self,
        code: Bytecode,
        findex: int,
        op_idx: int,
        old_text: Optional[str],
        new_text: Optional[str],
        on_applied: ApplyCallback,
        text: Optional[str] = None,
    ) -> None:
        super().__init__(text or (f"Comment op#{op_idx}" if new_text else f"Clear comment op#{op_idx}"))
        self._code = code
        self._findex = findex
        self._op_idx = op_idx
        self._old_text = old_text
        self._new_text = new_text
        self._on_applied = on_applied

    def _set(self, comment: Optional[str]) -> None:
        if comment is None:
            self._code.annotations.clear_comment(self._findex, self._op_idx)
        else:
            self._code.annotations.set_comment(self._findex, self._op_idx, comment)
        self._on_applied(self._findex)

    def redo(self) -> None:
        self._set(self._new_text)

    def undo(self) -> None:
        self._set(self._old_text)


class SetStringCommand(QUndoCommand):
    def __init__(
        self,
        code: Bytecode,
        index: int,
        old_value: str,
        new_value: str,
        on_applied: ApplyCallback,
    ) -> None:
        super().__init__(f"Set string @{index}")
        self._code = code
        self._index = index
        self._old_value = old_value
        self._new_value = new_value
        self._on_applied = on_applied

    def redo(self) -> None:
        self._code.strings.value[self._index] = self._new_value
        self._on_applied(None)

    def undo(self) -> None:
        self._code.strings.value[self._index] = self._old_value
        self._on_applied(None)
