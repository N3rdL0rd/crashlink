"""Log panel — timestamped, coloured output for GUI events, plus a Python REPL."""

from __future__ import annotations

import code as _pyconsole
import sys
import traceback
from datetime import datetime
from io import StringIO
from typing import Any, Dict, List, Optional, cast

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont, QKeyEvent, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import QHBoxLayout, QLabel, QLineEdit, QTextEdit, QVBoxLayout, QWidget

from ... import disasm, pseudo
from ...core import Bytecode, Function, Native, Opcode
from ...decomp import IRClass, IRFunction
from ..themes import Theme

# name -> description, shown by the `.help` REPL command. Kept in sync with the
# initial namespace below and whatever MainWindow.set_context() updates live.
_REPL_VAR_HELP: Dict[str, str] = {
    "code": "the loaded Bytecode, or None if nothing is open",
    "mw": "the MainWindow instance",
    "findex": "currently focused function index (int), or None",
    "func": "currently focused Function/Native (raw bytecode), or None",
    "irf": "currently focused IRFunction (decompiled IR), or None if not decompiled yet",
    "disasm": "crashlink.disasm module",
    "pseudo": "crashlink.pseudo module",
    "IRFunction": "crashlink.decomp.IRFunction class",
    "IRClass": "crashlink.decomp.IRClass class",
    "Bytecode": "crashlink.core.Bytecode class",
    "Function": "crashlink.core.Function class",
    "Native": "crashlink.core.Native class",
    "Opcode": "crashlink.core.Opcode class",
}


class _ReplLineEdit(QLineEdit):
    """A QLineEdit that emits history_prev/history_next on Up/Down instead of
    the default (no-op, since single-line edits have no built-in history)."""

    history_prev = Signal()
    history_next = Signal()

    def keyPressEvent(self, event: object) -> None:
        if isinstance(event, QKeyEvent):
            if event.key() == Qt.Key.Key_Up:
                self.history_prev.emit()
                return
            if event.key() == Qt.Key.Key_Down:
                self.history_next.emit()
                return
        super().keyPressEvent(cast(QKeyEvent, event))


class LogPanel(QWidget):
    # Internal: marshals appends onto the GUI thread. dbg_print may fire from
    # worker threads (e.g. the load thread), and QTextEdit is not thread-safe.
    _append_requested = Signal(str, str, str)  # level, msg, color

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._theme: Optional[Theme] = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._output = QTextEdit()
        self._output.setReadOnly(True)
        self._output.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self._output.document().setMaximumBlockCount(2000)
        font = QFont("JetBrains Mono", 11)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self._output.setFont(font)
        layout.addWidget(self._output)

        # ── REPL input row ──────────────────────────────────────
        repl_row = QHBoxLayout()
        repl_row.setContentsMargins(4, 2, 4, 2)
        repl_row.setSpacing(4)

        self._prompt_label = QLabel(">>>")
        self._prompt_label.setFont(font)
        repl_row.addWidget(self._prompt_label)

        self._repl_input = _ReplLineEdit()
        self._repl_input.setFont(font)
        self._repl_input.setPlaceholderText("Python REPL (.help for help)")
        self._repl_input.returnPressed.connect(self._on_repl_submit)
        self._repl_input.history_prev.connect(self._on_history_prev)
        self._repl_input.history_next.connect(self._on_history_next)
        repl_row.addWidget(self._repl_input, 1)

        layout.addLayout(repl_row)

        self._append_requested.connect(self._do_append, Qt.ConnectionType.QueuedConnection)

        # ── REPL state ──────────────────────────────────────────
        self._repl_namespace: Dict[str, Any] = {
            "code": None,
            "mw": None,
            "findex": None,
            "func": None,
            "irf": None,
            "disasm": disasm,
            "pseudo": pseudo,
            "IRFunction": IRFunction,
            "IRClass": IRClass,
            "Bytecode": Bytecode,
            "Function": Function,
            "Native": Native,
            "Opcode": Opcode,
        }
        self._interpreter = _pyconsole.InteractiveInterpreter(self._repl_namespace)
        self._continuation_lines: List[str] = []
        self._history: List[str] = []
        self._history_idx = 0
        self._history_pending = ""

    def set_theme(self, theme: Theme) -> None:
        self._theme = theme

    # ── REPL context ─────────────────────────────────────────────────────────

    def set_context(self, **kwargs: Any) -> None:
        """Update variables visible to the REPL, e.g. set_context(code=bytecode)."""
        self._repl_namespace.update(kwargs)

    # ── Public log methods ────────────────────────────────────────────────────

    def info(self, msg: str) -> None:
        self._append("INFO", msg, self._col("subtext"))

    def success(self, msg: str) -> None:
        self._append("OK  ", msg, self._col("green"))

    def warn(self, msg: str) -> None:
        self._append("WARN", msg, self._col("yellow"))

    def error(self, msg: str) -> None:
        self._append("ERR ", msg, self._col("red"))

    def result(self, msg: str) -> None:
        """Used for xref / rename results — stands out without being an error."""
        self._append(">>  ", msg, self._col("accent"))

    def clear(self) -> None:
        self._output.clear()

    # ── REPL execution ───────────────────────────────────────────────────────

    def _on_repl_submit(self) -> None:
        line = self._repl_input.text()
        self._repl_input.clear()

        if line.strip():
            self._history.append(line)
        self._history_idx = len(self._history)
        self._history_pending = ""

        prompt = "..." if self._continuation_lines else ">>>"
        self._append_raw(f"{prompt} {line}", self._col("text"))

        # Meta-commands (never valid Python, so no ambiguity) are only
        # recognized outside of a continuation block.
        if not self._continuation_lines and line.strip().startswith("."):
            self._run_repl_command(line.strip())
            return

        self._continuation_lines.append(line)
        # A blank line always ends a continuation, even if runsource would
        # otherwise keep waiting (e.g. a trailing comment-only block).
        force_finish = not line.strip() and len(self._continuation_lines) > 1
        source = "\n".join(self._continuation_lines)

        out_buf, err_buf = StringIO(), StringIO()
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out_buf, err_buf
        try:
            needs_more = self._interpreter.runsource(source, "<repl>") and not force_finish
        except Exception:
            err_buf.write(traceback.format_exc())
            needs_more = False
        finally:
            sys.stdout, sys.stderr = old_out, old_err

        for out_line in out_buf.getvalue().splitlines():
            self._append_raw(out_line, self._col("text"))
        for err_line in err_buf.getvalue().splitlines():
            self._append_raw(err_line, self._col("red"))

        if needs_more:
            self._prompt_label.setText("...")
        else:
            self._continuation_lines = []
            self._prompt_label.setText(">>>")

    def _run_repl_command(self, cmd_line: str) -> None:
        cmd, *args = cmd_line.split()
        if cmd in (".help", ".h"):
            self._print_help()
        elif cmd == ".clear":
            self.clear()
        elif cmd == ".vars":
            self._print_vars()
        elif cmd == ".goto":
            self._cmd_goto(args)
        elif cmd == ".disasm":
            self._cmd_disasm(args)
        elif cmd == ".pseudo":
            self._cmd_pseudo(args)
        elif cmd == ".save":
            self._cmd_save()
        else:
            self._append_raw(f"Unknown command: {cmd} (try .help)", self._col("yellow"))

    def _print_help(self) -> None:
        self._append_raw("Built-in variables:", self._col("accent"))
        for name, desc in _REPL_VAR_HELP.items():
            val = self._repl_namespace.get(name)
            type_name = type(val).__name__ if val is not None else "None"
            self._append_raw(f"  {name:<10} ({type_name}) - {desc}", self._col("text"))
        self._print_vars(header="Your variables:", empty_msg=None)
        self._append_raw(
            "Commands: .help  .clear  .vars  .goto <findex>  .disasm [findex]  .pseudo [findex]  .save",
            self._col("subtext"),
        )

    def _print_vars(self, header: str = "Your variables:", empty_msg: Optional[str] = "(none)") -> None:
        extra = sorted(
            k
            for k in self._repl_namespace
            if k not in _REPL_VAR_HELP and k != "__builtins__" and not k.startswith("__")
        )
        if not extra:
            if empty_msg is not None:
                self._append_raw(empty_msg, self._col("subtext"))
            return
        self._append_raw(header, self._col("accent"))
        for name in extra:
            try:
                val_repr = repr(self._repl_namespace[name])
            except Exception as e:
                val_repr = f"<repr failed: {e}>"
            if len(val_repr) > 100:
                val_repr = val_repr[:100] + "…"
            self._append_raw(f"  {name} = {val_repr}", self._col("text"))

    def _resolve_findex(self, args: List[str]) -> Optional[int]:
        if args:
            try:
                return int(args[0])
            except ValueError:
                self._append_raw(f"Invalid findex: {args[0]!r}", self._col("red"))
                return None
        fi = self._repl_namespace.get("findex")
        if fi is None:
            self._append_raw("No function focused, and no findex given.", self._col("yellow"))
        return fi

    def _cmd_goto(self, args: List[str]) -> None:
        fi = self._resolve_findex(args)
        if fi is None:
            return
        mw = self._repl_namespace.get("mw")
        if mw is None:
            self._append_raw("`mw` is not available.", self._col("red"))
            return
        try:
            mw._on_function_selected(fi)
        except Exception:
            self._append_raw(traceback.format_exc(), self._col("red"))

    def _cmd_disasm(self, args: List[str]) -> None:
        fi = self._resolve_findex(args)
        if fi is None:
            return
        bc = self._repl_namespace.get("code")
        if bc is None:
            self._append_raw("No bytecode loaded.", self._col("yellow"))
            return
        target = bc.get_findex_map().get(fi)
        if target is None:
            self._append_raw(f"f@{fi} not found.", self._col("red"))
            return
        try:
            text = disasm.func(bc, target)
        except Exception:
            self._append_raw(traceback.format_exc(), self._col("red"))
            return
        for line in text.splitlines():
            self._append_raw(line, self._col("text"))

    def _cmd_pseudo(self, args: List[str]) -> None:
        fi = self._resolve_findex(args)
        if fi is None:
            return
        bc = self._repl_namespace.get("code")
        if bc is None:
            self._append_raw("No bytecode loaded.", self._col("yellow"))
            return
        # Reuse the already-decompiled IR for the focused function; otherwise
        # decompile a throwaway copy just for this printout.
        ir = self._repl_namespace.get("irf") if self._repl_namespace.get("findex") == fi else None
        if ir is None:
            target = bc.get_findex_map().get(fi)
            if target is None:
                self._append_raw(f"f@{fi} not found.", self._col("red"))
                return
            try:
                ir = IRFunction(bc, target)
            except Exception:
                self._append_raw(traceback.format_exc(), self._col("red"))
                return
        try:
            text = pseudo.pseudo(ir)
        except Exception:
            self._append_raw(traceback.format_exc(), self._col("red"))
            return
        for line in text.splitlines():
            self._append_raw(line, self._col("text"))

    def _cmd_save(self) -> None:
        mw = self._repl_namespace.get("mw")
        if mw is None:
            self._append_raw("`mw` is not available.", self._col("red"))
            return
        try:
            mw._save_database()
        except Exception:
            self._append_raw(traceback.format_exc(), self._col("red"))

    def _on_history_prev(self) -> None:
        if not self._history:
            return
        if self._history_idx == len(self._history):
            self._history_pending = self._repl_input.text()
        if self._history_idx > 0:
            self._history_idx -= 1
            self._repl_input.setText(self._history[self._history_idx])

    def _on_history_next(self) -> None:
        if self._history_idx >= len(self._history):
            return
        self._history_idx += 1
        if self._history_idx == len(self._history):
            self._repl_input.setText(self._history_pending)
        else:
            self._repl_input.setText(self._history[self._history_idx])

    # ── Internal ──────────────────────────────────────────────────────────────

    def _col(self, attr: str) -> str:
        if self._theme:
            return getattr(self._theme, attr, self._theme.text)
        _fallbacks = {
            "subtext": "#a6adc8",
            "green": "#a6e3a1",
            "yellow": "#f9e2af",
            "red": "#f38ba8",
            "accent": "#b4befe",
            "text": "#cdd6f4",
        }
        return _fallbacks.get(attr, "#cdd6f4")

    def _append(self, level: str, msg: str, color: str) -> None:
        # Always hop to the GUI thread; callers may be on worker threads.
        self._append_requested.emit(level, msg, color)

    def _do_append(self, level: str, msg: str, color: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        cursor = self._output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        ts_fmt = QTextCharFormat()
        ts_fmt.setForeground(QColor(self._col("overlay") if self._theme else "#6c7086"))

        level_fmt = QTextCharFormat()
        level_fmt.setForeground(QColor(color))
        level_fmt.setFontWeight(QFont.Weight.Bold)

        msg_fmt = QTextCharFormat()
        msg_fmt.setForeground(QColor(self._col("text")))

        cursor.insertText(f"{ts} ", ts_fmt)
        cursor.insertText(f"[{level}]", level_fmt)
        cursor.insertText(f"  {msg}\n", msg_fmt)

        self._output.setTextCursor(cursor)
        self._output.ensureCursorVisible()

    def _append_raw(self, text: str, color: str) -> None:
        """Append a line with no timestamp/level prefix — used for REPL echo/output."""
        cursor = self._output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        cursor.insertText(text + "\n", fmt)
        self._output.setTextCursor(cursor)
        self._output.ensureCursorVisible()
