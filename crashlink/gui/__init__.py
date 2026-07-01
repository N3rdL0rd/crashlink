"""crashlink GUI — PySide6-based bytecode inspector."""

from __future__ import annotations


def _install_excepthook(win: object) -> None:
    """Route uncaught exceptions to the log panel instead of letting PySide6
    abort the process — the decompiler in particular is still EXPERIMENTAL,
    so an unexpected exception from a panel that isn't already try/excepted
    (CFG rendering, xref resolution, a REPL command, ...) shouldn't take the
    whole window down with it."""
    import sys
    import traceback

    def _hook(exc_type: type, exc_value: BaseException, exc_tb: object) -> None:
        tb_text = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        print(tb_text, file=sys.stderr)  # keep it visible in the terminal too
        log_panel = getattr(win, "_log_panel", None)
        if log_panel is None:
            return
        try:
            log_panel.error(f"Unhandled exception ({exc_type.__name__}): {exc_value}")
            for line in tb_text.rstrip("\n").splitlines():
                log_panel.info(line)
        except Exception:
            pass  # the log panel itself is broken — nothing left to do but have printed above

    sys.excepthook = _hook


def main() -> None:
    """Launch the crashlink GUI application."""
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        print("PySide6 is required for the GUI. Install it with: pip install crashlink[gui]")
        return

    import sys
    from .main_window import MainWindow

    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    assert isinstance(app, QApplication)
    app.setApplicationName("crashlink")
    app.setOrganizationName("N3rdL0rd")
    app.setCursorFlashTime(0)  # static cursor, no blinking

    win = MainWindow()
    _install_excepthook(win)
    win.show()

    # Open a file from the command line if provided
    if len(sys.argv) > 1:
        import os

        path = sys.argv[1]
        if os.path.isfile(path):
            win._load_file(path)

    sys.exit(app.exec())
