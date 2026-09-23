"""Log panel — timestamped, coloured output for GUI events, plus a Python REPL."""

from __future__ import annotations

import code as _pyconsole
import sys
import threading
import traceback
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Deque, Dict, List, Optional, TextIO, Tuple, cast

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont, QKeyEvent, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ... import disasm, pseudo
from ...core import Bytecode, Function, Native, Opcode
from ...decomp import IRClass, IRFunction
from ..ansi import split_ansi
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

# Log history kept for re-rendering on theme change; older entries are dropped.
_MAX_ENTRIES = 10_000

# CLI commands `!` refuses, by the command function's name: interactive ones
# would wait on the terminal's stdin, and `exit` would end the GUI.
_REFUSED_CLI = {
    "repl": "it needs an interactive terminal; use the Python REPL here instead",
    "exit": "close the window to quit",
    "patch": "it edits opcodes interactively in a terminal",
    "cfg": "it opens an external image viewer; use the CFG dock (Space) instead",
}

_FALLBACK_COLOURS = {
    "subtext": "#a6adc8",
    "overlay": "#6c7086",
    "green": "#a6e3a1",
    "yellow": "#f9e2af",
    "red": "#f38ba8",
    "accent": "#b4befe",
    "text": "#cdd6f4",
    "mauve": "#cba6f7",
    "teal": "#94e2d5",
}


@dataclass
class _Entry:
    """One log line. Colours are theme roles (Theme attribute names), resolved at render time."""

    timestamp: Optional[str]
    level: Optional[str]
    level_role: str
    runs: List[Tuple[str, str, bool]]  # (text, role, bold)


class _ThreadRoutedStream:
    """Stand-in for sys.stdout/sys.stderr that sends writes from threads with a
    registered sink there, and everything else to the original stream. This
    captures one command's output without swapping the process-wide stream,
    which would also swallow prints from unrelated worker threads."""

    def __init__(self, original: TextIO) -> None:
        self._original = original
        self._sinks: Dict[int, Callable[[str], None]] = {}
        self._lock = threading.Lock()

    def register(self, sink: Callable[[str], None]) -> None:
        with self._lock:
            self._sinks[threading.get_ident()] = sink

    def unregister(self) -> None:
        with self._lock:
            self._sinks.pop(threading.get_ident(), None)

    def write(self, text: str) -> int:
        sink = self._sinks.get(threading.get_ident())
        if sink is None:
            return self._original.write(text)
        sink(text)
        return len(text)

    def flush(self) -> None:
        if threading.get_ident() not in self._sinks:
            self._original.flush()

    def isatty(self) -> bool:
        return False

    def __getattr__(self, name: str) -> Any:
        return getattr(self._original, name)


def _routed_streams() -> Tuple[_ThreadRoutedStream, _ThreadRoutedStream]:
    """Install the routing streams once for the process and return them."""
    if not isinstance(sys.stdout, _ThreadRoutedStream):
        sys.stdout = _ThreadRoutedStream(sys.stdout)
    if not isinstance(sys.stderr, _ThreadRoutedStream):
        sys.stderr = _ThreadRoutedStream(sys.stderr)
    return sys.stdout, sys.stderr


class _LineSink:
    """Collects written text and hands out complete lines."""

    def __init__(self, emit: Callable[[str], None]) -> None:
        self._emit = emit
        self._pending = ""

    def __call__(self, text: str) -> None:
        self._pending += text
        *lines, self._pending = self._pending.split("\n")
        for line in lines:
            self._emit(line)

    def flush(self) -> None:
        if self._pending:
            self._emit(self._pending)
            self._pending = ""


def capture_output(fn: Callable[[], Any]) -> Tuple[Any, List[str]]:
    """Run `fn` on this thread; return its result and the lines it printed to
    stdout/stderr (only this thread's output is captured)."""
    captured: List[str] = []
    sink = _LineSink(captured.append)
    stdout, stderr = _routed_streams()
    stdout.register(sink)
    stderr.register(sink)
    try:
        result = fn()
    finally:
        stdout.unregister()
        stderr.unregister()
        sink.flush()
    return result, captured


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
    # Internal: marshal appends and CLI output onto the GUI thread. dbg_print and
    # CLI commands run on worker threads, and QTextEdit is not thread-safe.
    _append_requested = Signal(str, str, str)  # level, msg, level role
    _cli_line = Signal(str, str)  # text, default role
    _cli_finished = Signal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._theme: Optional[Theme] = None
        self._entries: Deque[_Entry] = deque(maxlen=_MAX_ENTRIES)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._output = QTextEdit()
        self._output.setReadOnly(True)
        self._output.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self._output.document().setMaximumBlockCount(_MAX_ENTRIES)
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
        self._repl_input.setPlaceholderText("REPL (.help for help, !<cmd> for the crashlink CLI)")
        self._repl_input.returnPressed.connect(self._on_repl_submit)
        self._repl_input.history_prev.connect(self._on_history_prev)
        self._repl_input.history_next.connect(self._on_history_next)
        repl_row.addWidget(self._repl_input, 1)

        layout.addLayout(repl_row)

        self._append_requested.connect(self._do_append, Qt.ConnectionType.QueuedConnection)
        self._cli_line.connect(self._on_cli_line, Qt.ConnectionType.QueuedConnection)
        self._cli_finished.connect(self._on_cli_finished, Qt.ConnectionType.QueuedConnection)

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
        # CLI commands run one at a time on a worker thread; later ones wait here.
        self._cli_running = False
        self._cli_queue: Deque[str] = deque()

    def set_theme(self, theme: Theme) -> None:
        """Apply `theme` and re-render every existing line in its colours."""
        self._theme = theme
        bar = self._output.verticalScrollBar()
        at_bottom = bar.value() >= bar.maximum() - 2
        old_value = bar.value()
        self._output.setUpdatesEnabled(False)
        self._output.clear()
        cursor = self._output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        for entry in self._entries:
            self._render(cursor, entry)
        self._output.setUpdatesEnabled(True)
        bar.setValue(bar.maximum() if at_bottom else old_value)

    # ── REPL context ─────────────────────────────────────────────────────────

    def set_context(self, **kwargs: Any) -> None:
        """Update variables visible to the REPL, e.g. set_context(code=bytecode)."""
        self._repl_namespace.update(kwargs)

    # ── Public log methods (thread-safe) ──────────────────────────────────────

    def info(self, msg: str) -> None:
        self._append("INFO", msg, "subtext")

    def success(self, msg: str) -> None:
        self._append("OK  ", msg, "green")

    def warn(self, msg: str) -> None:
        self._append("WARN", msg, "yellow")

    def error(self, msg: str) -> None:
        self._append("ERR ", msg, "red")

    def result(self, msg: str) -> None:
        """Used for xref / rename results — stands out without being an error."""
        self._append(">>  ", msg, "accent")

    def debug(self, msg: str) -> None:
        """Decompiler debug output; dimmed so it doesn't compete with real messages."""
        self._append("DBG ", msg, "overlay")

    def clear(self) -> None:
        self._entries.clear()
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
        self._append_raw(f"{prompt} {line}", "text")

        # Meta-commands (never valid Python, so no ambiguity) are only
        # recognized outside of a continuation block.
        if not self._continuation_lines and line.strip().startswith("."):
            self._run_repl_command(line.strip())
            return

        # `!<cmd>` dispatches to the crashlink CLI's own command set (same
        # dispatch as the `crashlink` shell's `handle_cmd`).
        if not self._continuation_lines and line.strip().startswith("!"):
            self._run_cli_command(line.strip()[1:].strip())
            return

        self._continuation_lines.append(line)
        # A blank line always ends a continuation, even if runsource would
        # otherwise keep waiting (e.g. a trailing comment-only block).
        force_finish = not line.strip() and len(self._continuation_lines) > 1
        source = "\n".join(self._continuation_lines)

        # Python runs synchronously on the UI thread (user code may touch Qt);
        # output is captured for this thread only.
        out_lines: List[Tuple[str, str]] = []
        out_sink = _LineSink(lambda text: out_lines.append((text, "text")))
        err_sink = _LineSink(lambda text: out_lines.append((text, "red")))
        stdout, stderr = _routed_streams()
        stdout.register(out_sink)
        stderr.register(err_sink)
        try:
            needs_more = self._interpreter.runsource(source, "<repl>") and not force_finish
        except Exception:
            err_sink(traceback.format_exc())
            needs_more = False
        finally:
            stdout.unregister()
            stderr.unregister()
            out_sink.flush()
            err_sink.flush()

        for text, role in out_lines:
            self._append_raw(text, role)

        if needs_more:
            self._prompt_label.setText("...")
        else:
            self._continuation_lines = []
            self._prompt_label.setText(">>>")

    def _run_cli_command(self, cmd_line: str) -> None:
        bc = self._repl_namespace.get("code")
        if bc is None:
            self._append_raw("No bytecode loaded.", "yellow")
            return
        if not cmd_line:
            return
        if self._try_undoable_cli_command(cmd_line):
            return
        verb = cmd_line.split(" ")[0]
        from ...__main__ import Commands  # deferred: avoids CLI import cost at GUI startup

        func = Commands(bc)._get_commands().get(verb)
        name = getattr(func, "__name__", verb)
        if name == "clear":
            self.clear()
            return
        if name in _REFUSED_CLI:
            self._append_raw(f"!{verb} isn't available here: {_REFUSED_CLI[name]}.", "yellow")
            return
        if self._cli_running:
            self._cli_queue.append(cmd_line)
            self._append_raw(f"(queued behind the running command: {cmd_line})", "subtext")
            return
        self._start_cli(bc, cmd_line)

    def _start_cli(self, bc: Bytecode, cmd_line: str) -> None:
        """Run a CLI command on a worker thread, streaming its output into the log."""
        from ...__main__ import handle_cmd

        self._cli_running = True
        self._prompt_label.setText("…")
        self._prompt_label.setToolTip(f"Running: !{cmd_line}")

        def work() -> None:
            out_sink = _LineSink(lambda text: self._cli_line.emit(text, "text"))
            err_sink = _LineSink(lambda text: self._cli_line.emit(text, "red"))
            stdout, stderr = _routed_streams()
            stdout.register(out_sink)
            stderr.register(err_sink)
            try:
                handle_cmd(bc, cmd_line)
            except SystemExit:
                pass
            except Exception:
                err_sink(traceback.format_exc())
            finally:
                stdout.unregister()
                stderr.unregister()
                out_sink.flush()
                err_sink.flush()
                self._cli_finished.emit()

        threading.Thread(target=work, name=f"crashlink-cli: {cmd_line}", daemon=True).start()

    def _on_cli_line(self, text: str, role: str) -> None:
        self._add(_Entry(None, None, role, split_ansi(text, role)))

    def _on_cli_finished(self) -> None:
        self._cli_running = False
        self._prompt_label.setText("..." if self._continuation_lines else ">>>")
        self._prompt_label.setToolTip("")
        bc = self._repl_namespace.get("code")
        if self._cli_queue and bc is not None:
            self._start_cli(bc, self._cli_queue.popleft())
        else:
            self._cli_queue.clear()

    # CLI verbs that mutate the bytecode and have an undo-aware equivalent on
    # MainWindow, routed there instead of straight to handle_cmd so they land
    # on the undo stack / edit history instead of bypassing it.
    def _try_undoable_cli_command(self, cmd_line: str) -> bool:
        """Handles `rename`/`unrename`/`addcomment`/`rmcomment`/`setstring` by delegating to
        MainWindow's undo-aware methods. Returns False (unhandled) for every other command,
        including their aliases — those fall through to the plain CLI dispatch."""
        parts = cmd_line.split(" ")
        verb, args = parts[0], parts[1:]
        mw = self._repl_namespace.get("mw")
        if mw is None:
            return False

        def _def_op(s: str) -> Optional[int]:
            return None if s == "_" else int(s)

        try:
            if verb == "rename" and len(args) >= 4:
                mw.apply_rename(int(args[0]), int(args[1]), _def_op(args[2]), args[3])
                self._append_raw(f"Renamed reg{args[1]} in f@{args[0]} -> {args[3]!r}.", "text")
                return True
            if verb == "unrename" and len(args) >= 3:
                mw.apply_rename(int(args[0]), int(args[1]), _def_op(args[2]), None)
                self._append_raw("Rename cleared.", "text")
                return True
            if verb == "addcomment" and len(args) >= 3:
                mw.apply_comment(int(args[0]), int(args[1]), " ".join(args[2:]))
                self._append_raw(f"Comment set on f@{args[0]} op#{args[1]}.", "text")
                return True
            if verb == "rmcomment" and len(args) >= 2:
                mw.apply_comment(int(args[0]), int(args[1]), None)
                self._append_raw("Comment cleared.", "text")
                return True
            if verb == "setstring" and len(args) >= 2:
                mw.apply_setstring(int(args[0]), " ".join(args[1:]))
                self._append_raw("String set.", "text")
                return True
        except (ValueError, IndexError) as e:
            self._append_raw(f"Bad arguments for {verb}: {e}", "red")
            return True
        return False

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
            self._append_raw(f"Unknown command: {cmd} (try .help)", "yellow")

    def _print_help(self) -> None:
        self._append_raw("Built-in variables:", "accent")
        for name, desc in _REPL_VAR_HELP.items():
            val = self._repl_namespace.get(name)
            type_name = type(val).__name__ if val is not None else "None"
            self._append_raw(f"  {name:<10} ({type_name}) - {desc}", "text")
        self._print_vars(header="Your variables:", empty_msg=None)
        self._append_raw(
            "Commands: .help  .clear  .vars  .goto <findex>  .disasm [findex]  .pseudo [findex]  .save",
            "subtext",
        )
        self._append_raw(
            "!<cmd> runs a crashlink CLI command (e.g. !findfunc Foo, !obj 12; !help lists them) in the "
            "background. Output streams in, and later commands queue behind it.",
            "subtext",
        )
        refused = ", ".join(f"!{name}" for name in _REFUSED_CLI)
        self._append_raw(f"Not available via !: {refused}. !clear clears this log.", "subtext")

    def _print_vars(self, header: str = "Your variables:", empty_msg: Optional[str] = "(none)") -> None:
        extra = sorted(
            k
            for k in self._repl_namespace
            if k not in _REPL_VAR_HELP and k != "__builtins__" and not k.startswith("__")
        )
        if not extra:
            if empty_msg is not None:
                self._append_raw(empty_msg, "subtext")
            return
        self._append_raw(header, "accent")
        for name in extra:
            try:
                val_repr = repr(self._repl_namespace[name])
            except Exception as e:
                val_repr = f"<repr failed: {e}>"
            if len(val_repr) > 100:
                val_repr = val_repr[:100] + "…"
            self._append_raw(f"  {name} = {val_repr}", "text")

    def _resolve_findex(self, args: List[str]) -> Optional[int]:
        if args:
            try:
                return int(args[0].removeprefix("f@"))
            except ValueError:
                self._append_raw(f"Invalid findex: {args[0]!r}", "red")
                return None
        fi = self._repl_namespace.get("findex")
        if fi is None:
            self._append_raw("No function focused, and no findex given.", "yellow")
        return fi

    def _cmd_goto(self, args: List[str]) -> None:
        fi = self._resolve_findex(args)
        if fi is None:
            return
        mw = self._repl_namespace.get("mw")
        if mw is None:
            self._append_raw("`mw` is not available.", "red")
            return
        try:
            mw.navigate_to(fi)
        except Exception:
            self._append_raw(traceback.format_exc(), "red")

    def _cmd_disasm(self, args: List[str]) -> None:
        fi = self._resolve_findex(args)
        if fi is None:
            return
        bc = self._repl_namespace.get("code")
        if bc is None:
            self._append_raw("No bytecode loaded.", "yellow")
            return
        target = bc.get_findex_map().get(fi)
        if target is None:
            self._append_raw(f"f@{fi} not found.", "red")
            return
        try:
            text = disasm.func(bc, target)
        except Exception:
            self._append_raw(traceback.format_exc(), "red")
            return
        for line in text.splitlines():
            self._append_raw(line, "text")

    def _cmd_pseudo(self, args: List[str]) -> None:
        fi = self._resolve_findex(args)
        if fi is None:
            return
        bc = self._repl_namespace.get("code")
        if bc is None:
            self._append_raw("No bytecode loaded.", "yellow")
            return
        # Reuse the already-decompiled IR for the focused function; otherwise
        # decompile a throwaway copy just for this printout.
        ir = self._repl_namespace.get("irf") if self._repl_namespace.get("findex") == fi else None
        if ir is None:
            target = bc.get_findex_map().get(fi)
            if target is None:
                self._append_raw(f"f@{fi} not found.", "red")
                return
            try:
                ir = IRFunction(bc, target)
            except Exception:
                self._append_raw(traceback.format_exc(), "red")
                return
        try:
            text = pseudo.pseudo(ir)
        except Exception:
            self._append_raw(traceback.format_exc(), "red")
            return
        for line in text.splitlines():
            self._append_raw(line, "text")

    def _cmd_save(self) -> None:
        mw = self._repl_namespace.get("mw")
        if mw is None:
            self._append_raw("`mw` is not available.", "red")
            return
        try:
            mw._save_database()
        except Exception:
            self._append_raw(traceback.format_exc(), "red")

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

    def _colour(self, role: str) -> QColor:
        if self._theme:
            return QColor(getattr(self._theme, role, self._theme.text))
        return QColor(_FALLBACK_COLOURS.get(role, _FALLBACK_COLOURS["text"]))

    def _append(self, level: str, msg: str, level_role: str) -> None:
        # Always hop to the GUI thread; callers may be on worker threads.
        self._append_requested.emit(level, msg, level_role)

    def _do_append(self, level: str, msg: str, level_role: str) -> None:
        # Debug lines are dimmed entirely; everything else has plain message text.
        msg_role = "overlay" if level_role == "overlay" else "text"
        ts = datetime.now().strftime("%H:%M:%S")
        self._add(_Entry(ts, level, level_role, [(msg, msg_role, False)]))

    def _append_raw(self, text: str, role: str) -> None:
        """Append lines with no timestamp/level prefix, for REPL echo/output."""
        for line in text.split("\n"):
            self._add(_Entry(None, None, role, split_ansi(line, role)))

    def _add(self, entry: _Entry) -> None:
        self._entries.append(entry)
        bar = self._output.verticalScrollBar()
        at_bottom = bar.value() >= bar.maximum() - 2
        cursor = QTextCursor(self._output.document())
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self._render(cursor, entry)
        if at_bottom:
            bar.setValue(bar.maximum())

    def _render(self, cursor: QTextCursor, entry: _Entry) -> None:
        if not cursor.atStart():
            cursor.insertBlock()
        if entry.timestamp is not None:
            ts_fmt = QTextCharFormat()
            ts_fmt.setForeground(self._colour("overlay"))
            cursor.insertText(f"{entry.timestamp} ", ts_fmt)
        if entry.level is not None:
            level_fmt = QTextCharFormat()
            level_fmt.setForeground(self._colour(entry.level_role))
            level_fmt.setFontWeight(QFont.Weight.Bold)
            cursor.insertText(f"[{entry.level}]  ", level_fmt)
        for text, role, bold in entry.runs:
            fmt = QTextCharFormat()
            fmt.setForeground(self._colour(role))
            if bold:
                fmt.setFontWeight(QFont.Weight.Bold)
            cursor.insertText(text, fmt)
