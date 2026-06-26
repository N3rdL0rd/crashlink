"""crashlink GUI — PySide6-based bytecode inspector."""

from __future__ import annotations


def main() -> None:
    """Launch the crashlink GUI application."""
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        print("PySide6 is required for the GUI. Install it with: pip install crashlink[gui]")
        return

    import sys
    from .main_window import MainWindow

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("crashlink")
    app.setOrganizationName("N3rdL0rd")
    app.setCursorFlashTime(0)  # static cursor, no blinking

    win = MainWindow()
    win.show()

    # Open a file from the command line if provided
    if len(sys.argv) > 1:
        import os
        path = sys.argv[1]
        if os.path.isfile(path):
            win._load_file(path)

    sys.exit(app.exec())
