"""File Info (Ctrl+I): size, hash, table counts, native libraries and entry point
of the loaded image, plus the bytecode sanity checks (CLI `verify`)."""

from __future__ import annotations

import html
import os
from typing import TYPE_CHECKING, List, Optional, Tuple

from PySide6.QtCore import QUrl
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import QHBoxLayout, QPushButton, QTextBrowser, QVBoxLayout, QWidget

from ... import disasm
from ...core import Bytecode, Function
from ..widgets.log_panel import capture_output

if TYPE_CHECKING:
    from ..main_window import MainWindow

_TAB_KEY = "__file_info__"


def _rows(code: Bytecode, path: Optional[str]) -> List[Tuple[str, str]]:
    rows: List[Tuple[str, str]] = []
    if path:
        rows.append(("Path", path))
        try:
            rows.append(("Size", f"{os.path.getsize(path):,} bytes"))
        except OSError:
            pass
    rows.append(("SHA-256", code.sha256 or "unknown"))
    rows.append(("Bytecode version", str(code.version)))
    rows.append(("Debug info", "yes" if code.has_debug_info else "no"))
    if code.inspection_only:
        rows.append(("Recovery", "inspection-only native recovery (de-HL/C)"))
        rows.append(("Capabilities", ", ".join(sorted(code.recovery_capabilities))))
    counts = [
        ("Types", len(code.types)),
        ("Functions", len(code.functions)),
        ("Natives", len(code.natives)),
        ("Globals", len(code.global_types)),
        ("Strings", len(code.strings.value)),
        ("Ints", len(code.ints)),
        ("Floats", len(code.floats)),
        (
            "Debug files",
            len(code.debugfiles.value) if code.debugfiles is not None and code.has_debug_info else 0,
        ),
    ]
    rows.extend((name, f"{count:,}") for name, count in counts)
    return rows


def _entry(code: Bytecode) -> Tuple[Optional[int], str]:
    try:
        entry = code.entrypoint.resolve(code)
    except Exception as e:
        return None, f"unresolved ({e})"
    if isinstance(entry, Function):
        return entry.findex.value, disasm.func_header(code, entry)
    return None, f"native {entry.name.resolve(code)}"


def _native_libs(code: Bytecode) -> List[Tuple[str, int]]:
    counts: dict[str, int] = {}
    for native in code.natives:
        lib = native.lib.resolve(code) if native.lib.value else "(none)"
        counts[lib] = counts.get(lib, 0) + 1
    return sorted(counts.items())


class FileInfoView(QWidget):
    def __init__(self, mw: "MainWindow", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._mw = mw
        self._checks: Optional[str] = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        buttons = QHBoxLayout()
        self._verify = QPushButton("Run sanity checks")
        self._verify.setToolTip("Structural checks on counts, indices and references (CLI `verify`)")
        self._verify.clicked.connect(self._run_checks)
        buttons.addWidget(self._verify)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        self._browser = QTextBrowser()
        self._browser.setOpenLinks(False)
        self._browser.anchorClicked.connect(self._on_link)
        layout.addWidget(self._browser, 1)
        mw.theme_changed.connect(self._on_theme_changed)
        self.refresh()

    def _on_theme_changed(self, _theme: object) -> None:
        self.refresh()

    def refresh(self) -> None:
        code = self._mw.code
        if code is None:
            self._browser.setHtml("<p>No file loaded.</p>")
            return
        theme = self._mw.theme
        muted = f"color:{theme.subtext}"
        parts = ["<table cellspacing='0' cellpadding='4'>"]
        for name, value in _rows(code, self._mw.source_path):
            parts.append(
                f"<tr><td style='{muted}'>{html.escape(name)}</td><td>{html.escape(value)}</td></tr>"
            )
        entry_findex, entry_label = _entry(code)
        entry_html = html.escape(entry_label)
        if entry_findex is not None:
            entry_html = f"<a style='color:{theme.accent}' href='entry:{entry_findex}'>{entry_html}</a>"
        parts.append(f"<tr><td style='{muted}'>Entry point</td><td>{entry_html}</td></tr></table>")

        libs = _native_libs(code)
        parts.append(f"<h3 style='color:{theme.text}'>Native libraries</h3>")
        if libs:
            parts.append("<table cellspacing='0' cellpadding='3'>")
            for lib, count in libs:
                parts.append(f"<tr><td>{html.escape(lib)}</td><td style='{muted}'>{count} natives</td></tr>")
            parts.append("</table>")
        else:
            parts.append(f"<p style='{muted}'>None.</p>")

        parts.append(f"<h3 style='color:{theme.text}'>Sanity checks</h3>")
        parts.append(self._checks or f"<p style='{muted}'>Not run yet.</p>")
        self._browser.setHtml("".join(parts))

    def _on_link(self, url: QUrl) -> None:
        text = url.toString()
        if text.startswith("entry:"):
            self._mw.navigate_to(int(text.split(":", 1)[1]))

    def _run_checks(self) -> None:
        code = self._mw.code
        if code is None:
            return
        if code.inspection_only:
            self._checks = "<p>Not available for inspection-only native recovery.</p>"
            self.refresh()
            return
        self._verify.setEnabled(False)
        self._mw.run_background(
            "Running sanity checks…",
            lambda: capture_output(code.is_ok),
            self._checks_done,
            self._checks_failed,
        )

    def _checks_done(self, result: Tuple[bool, List[str]]) -> None:
        ok, lines = result
        theme = self._mw.theme
        colour = theme.green if ok else theme.red
        verdict = "All checks passed." if ok else "Verification failed."
        details = "<br>".join(html.escape(line) for line in lines if line.strip())
        self._checks = f"<p style='color:{colour}'><b>{verdict}</b></p>" + (
            f"<pre>{details}</pre>" if details else ""
        )
        self._verify.setEnabled(True)
        self.refresh()

    def _checks_failed(self, message: str) -> None:
        self._checks = f"<p style='color:{self._mw.theme.red}'>Checks crashed: {html.escape(message)}</p>"
        self._verify.setEnabled(True)
        self.refresh()


def open_file_info(mw: "MainWindow") -> None:
    if mw.code is None:
        mw.statusBar().showMessage("Open a file first", 3000)
        return
    mw.open_tab(_TAB_KEY, "File Info", lambda: FileInfoView(mw))


def install(mw: "MainWindow") -> None:
    action = QAction("File Info…", mw)
    action.setShortcut(QKeySequence("Ctrl+I"))
    action.triggered.connect(lambda: open_file_info(mw))
    mw.menu("File").addAction(action)
