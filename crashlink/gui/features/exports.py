"""File > Export: write the (possibly edited) bytecode back out (as bytecode or .hlasm), and run the CLI's
generators (HL/C, stubs, API docs, MkDocs, shaders, self-contained classes).
Each export runs in the background and logs the output path when done."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Callable, Dict, List, Optional

from PySide6.QtCore import QObject, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QFileDialog, QInputDialog, QMessageBox

from ... import disasm
from ...core import Bytecode, Obj, destaticify

if TYPE_CHECKING:
    from ..main_window import MainWindow


def _write_files(root: str, files: Dict[str, str]) -> int:
    for rel_path, content in files.items():
        dest = os.path.join(root, rel_path)
        os.makedirs(os.path.dirname(dest) or root, exist_ok=True)
        with open(dest, "w", encoding="utf-8") as f:
            f.write(content)
    return len(files)


def _write_text(path: str, text: str) -> str:
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


class _Exporter(QObject):
    """Shared plumbing: dialogs, background run, completion message. Parented to the
    window: the menu actions only hold its bound methods, which don't keep it alive."""

    def __init__(self, mw: "MainWindow") -> None:
        super().__init__(mw)
        self.mw = mw

    def _code(self, needs_bytecode: bool = True) -> Optional[Bytecode]:
        code = self.mw.code
        if code is None:
            self.mw.statusBar().showMessage("Open a file first", 3000)
            return None
        if needs_bytecode and code.inspection_only:
            QMessageBox.information(
                self.mw,
                "Not available",
                "This needs recovered bytecode; inspection-only native images can't be exported.",
            )
            return None
        return code

    def _base(self) -> str:
        path = self.mw.source_path
        return os.path.splitext(os.path.basename(path))[0] if path else "export"

    def _run(self, label: str, work: Callable[[], str], what: str) -> None:
        def done(target: str) -> None:
            self.mw.log.success(f"{what}: {target}")
            box = QMessageBox(
                QMessageBox.Icon.Information, "Export finished", f"{what}:\n{target}", parent=self.mw
            )
            open_btn = box.addButton("Open Folder", QMessageBox.ButtonRole.ActionRole)
            box.addButton(QMessageBox.StandardButton.Close)
            folder = target if os.path.isdir(target) else os.path.dirname(target)
            open_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(folder)))
            box.open()

        def failed(message: str) -> None:
            self.mw.log.error(f"{what} failed: {message}")
            QMessageBox.warning(self.mw, "Export failed", message)

        self.mw.run_background(label, work, done, failed)

    # ── Actions ──────────────────────────────────────────────────────────────

    def save_bytecode(self) -> None:
        code = self._code()
        if code is None:
            return
        path, _ = QFileDialog.getSaveFileName(
            self.mw, "Save Bytecode As", f"{self._base()}.hl", "HashLink bytecode (*.hl *.dat);;All files (*)"
        )
        if not path:
            return

        def work() -> str:
            data = code.serialise()
            with open(path, "wb") as f:
                f.write(data)
            return path

        self._run("Serialising bytecode…", work, "Bytecode saved")

    def save_hlasm(self) -> None:
        code = self._code()
        if code is None:
            return
        path, _ = QFileDialog.getSaveFileName(
            self.mw, "Save as .hlasm", f"{self._base()}.hlasm", "crashlink assembly (*.hlasm);;All files (*)"
        )
        if not path:
            return
        from ...asm import to_hlasm

        self._run("Writing .hlasm…", lambda: _write_text(path, to_hlasm(code)), ".hlasm written")

    def transpile_c(self) -> None:
        code = self._code()
        if code is None:
            return
        path, _ = QFileDialog.getSaveFileName(
            self.mw, "Transpile to C", f"{self._base()}.c", "C source (*.c)"
        )
        if not path:
            return
        from ...hlc import code_to_c

        self._run("Transpiling to HL/C…", lambda: _write_text(path, code_to_c(code)), "HL/C written")

    def stub_file(self) -> None:
        code = self._code()
        if code is None:
            return
        files = sorted(code.debugfiles.value) if code.debugfiles is not None and code.has_debug_info else []
        if not files:
            QMessageBox.information(
                self.mw, "No debug info", "Stubbing needs debug info (source file names)."
            )
            return
        name, ok = QInputDialog.getItem(self.mw, "Stub Source File", "Debug file:", files, 0, True)
        if not ok or not name:
            return
        path, _ = QFileDialog.getSaveFileName(
            self.mw, "Save Stub", os.path.basename(name), "Haxe source (*.hx)"
        )
        if not path:
            return
        from ...pseudo import stub_file

        def work() -> str:
            text = stub_file(code, name)
            if text is None:
                raise ValueError(f"No debug file matching {name!r}")
            return _write_text(path, text + "\n")

        self._run("Writing stub…", work, "Stub written")

    def stub_all(self) -> None:
        code = self._code()
        if code is None:
            return
        if not code.has_debug_info:
            QMessageBox.information(
                self.mw, "No debug info", "Stubbing needs debug info (source file names)."
            )
            return
        folder = QFileDialog.getExistingDirectory(self.mw, "Stub All Files Into")
        if not folder:
            return
        from ...pseudo import stub_all

        def work() -> str:
            _write_files(folder, {rel: text + "\n" for rel, text in stub_all(code)})
            return folder

        self._run("Stubbing every source file…", work, "Stubs written")

    def api_docs(self) -> None:
        code = self._code()
        if code is None:
            return
        folder = QFileDialog.getExistingDirectory(self.mw, "Write API Docs Into")
        if not folder:
            return

        def work() -> str:
            _write_files(folder, disasm.gen_docs(code))
            return folder

        self._run("Generating API docs…", work, "API docs written")

    def mkdocs(self) -> None:
        code = self._code()
        if code is None:
            return
        folder = QFileDialog.getExistingDirectory(self.mw, "Create MkDocs Project In")
        if not folder:
            return
        site_name, ok = QInputDialog.getText(self.mw, "MkDocs Site", "Site name:", text="API Reference")
        if not ok:
            return

        def work() -> str:
            _write_files(folder, disasm.gen_mkdocs(code, site_name=site_name or "API Reference"))
            return folder

        self._run("Generating MkDocs site…", work, "MkDocs project written (run `mkdocs serve` there)")

    def shaders(self) -> None:
        code = self._code(needs_bytecode=False)
        if code is None:
            return
        folder = QFileDialog.getExistingDirectory(self.mw, "Write Recovered Shaders Into")
        if not folder:
            return
        from ... import hxsl

        def work() -> str:
            shaders = hxsl.find_shaders(code)
            if not shaders:
                raise ValueError("No hxsl shaders found in this image.")
            files = {
                f"{shader.name.replace('.', '/')}.hx": hxsl.render_shader(shader) + "\n" for shader in shaders
            }
            _write_files(folder, files)
            return folder

        self._run("Recovering shaders…", work, "Shaders written")

    def class_with_deps(self) -> None:
        code = self._code()
        if code is None:
            return
        classes: Dict[str, Obj] = {}
        for typ in code.types:
            if isinstance(typ.definition, Obj):
                name = destaticify(typ.definition.name.resolve(code))
                classes.setdefault(name, typ.definition)
        names: List[str] = sorted(classes)
        name, ok = QInputDialog.getItem(self.mw, "Class With Dependencies", "Class:", names, 0, True)
        if not ok or name not in classes:
            return
        path, _ = QFileDialog.getSaveFileName(
            self.mw, "Save Class", f"{name.rsplit('.', 1)[-1]}.hx", "Haxe source (*.hx)"
        )
        if not path:
            return
        from ...decomp import IRClass

        obj = classes[name]
        self._run(
            f"Decompiling {name} and every class it references…",
            lambda: _write_text(path, IRClass(code, obj).pseudo(max_classes=None)),
            "Class written",
        )


def install(mw: "MainWindow") -> None:
    exporter = _Exporter(mw)
    menu = mw.menu("File/Export")
    menu.addAction("Save Bytecode As…", exporter.save_bytecode)
    menu.addAction("Save as .hlasm…", exporter.save_hlasm)
    menu.addAction("Transpile to C (HL/C)…", exporter.transpile_c)
    menu.addSeparator()
    menu.addAction("Class With Dependencies…", exporter.class_with_deps)
    menu.addAction("Stub Source File…", exporter.stub_file)
    menu.addAction("Stub All Files…", exporter.stub_all)
    menu.addSeparator()
    menu.addAction("API Docs…", exporter.api_docs)
    menu.addAction("MkDocs Site…", exporter.mkdocs)
    menu.addAction("Recover Shaders…", exporter.shaders)
