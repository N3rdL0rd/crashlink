"""File open/load (bytecode and de-HL/C images), recent files, export, and shutdown for `MainWindow`."""

from __future__ import annotations

import gc
import os
from typing import TYPE_CHECKING, Optional, cast

from PySide6.QtCore import QSettings, QThread, Slot
from PySide6.QtGui import QCloseEvent, QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import QFileDialog, QMessageBox

from crashlink.core import AnnotationStore, Bytecode
from crashlink.database import DatabaseLoadResult
from crashlink.globals import set_dbg_callback

from ..themes import THEMES
from ..widgets.function_list import NavigatorData
from ..workers import _DehlcLoadThread, _IndexBuildThread, _LoadThread, _looks_like_native_image
from .views import _VIEW_MODE_NAMES

if TYPE_CHECKING:
    from ._host import MainWindowHost as _Base
else:
    _Base = object


class FileIoMixin(_Base):
    """File open/load (bytecode and de-HL/C images), recent files, export, and shutdown for `MainWindow`.

    The `.cldb` load thread and `_save_database`/`_load_database_from` stay in
    `main_window` because tests monkeypatch `load_database`/`save_database` there.

    State is set up by ``MainWindow.__init__``/``_build_ui`` (see ``._host`` for
    the typed surface); this area relies on:

    ``_code``, ``_source_path``, ``_dirty``, ``_generation``, ``_threads``,
    ``_active_decompiles``, ``_decomp_tokens``, ``_decomp_jobs``, ``_tabs``, ``_open_tabs``,
    ``_generic_tabs``, ``_back_stack``, ``_forward_stack``, ``_jump_names``, ``_find_bar``,
    ``_class_findices``, ``_class_results``, ``_class_names``, ``_ir_cache``,
    ``_opline_cache``, ``_spans_cache``, ``_pending_op_scroll``, ``_cfg_findex``,
    ``_cfg_view``, ``_db_cache``, ``_log_panel``, ``_undo_stack``, ``_loaded_via_dehlc``,
    ``_native_asm_cache``, ``_plt_map``, ``_disasm_source``, ``_emit_ctx``, ``_lifter``,
    ``_fidx_addr``, ``_arm_lift_warned``, ``_progress_bar``, ``_status_label``, ``_busy``,
    ``_load_thread``, ``_index_build_thread``, ``_recent_files``, ``_recent_menu``,
    ``_welcome``, ``_func_list``, ``_xref_popup``, ``_worker``, ``_db_request``, ``_closing``,
    ``_bg_pool``, ``_bg_jobs``, ``_render_pool``, ``code_loaded``
    plus sibling-area methods resolved through ``MainWindow``.
    """

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        urls = event.mimeData().urls() if event.mimeData().hasUrls() else []
        if len(urls) == 1 and urls[0].isLocalFile():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        urls = event.mimeData().urls()
        if not urls:
            return
        path = urls[0].toLocalFile()
        if os.path.isfile(path) and self._confirm_discard_changes():
            event.acceptProposedAction()
            self._load_file(path)

    def _open_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open HashLink bytecode or HL/C-compiled binary",
            "",
            "HashLink files (*.hl *.dat);;Executables (*.exe *.elf);;All files (*)",
        )
        if path and self._confirm_discard_changes():
            self._load_file(path)

    def _open_recent(self, path: str) -> None:
        if not os.path.isfile(path):
            self._log_panel.warn(f"No longer exists: {path}")
            self._recent_files = [p for p in self._recent_files if p != path]
            self._rebuild_recent_menu()
            return
        if self._confirm_discard_changes():
            self._load_file(path)

    def _add_recent_file(self, path: str) -> None:
        path = os.path.abspath(path)
        self._recent_files = [path] + [p for p in self._recent_files if p != path]
        del self._recent_files[10:]
        self._rebuild_recent_menu()
        QSettings("N3rdL0rd", "crashlink").setValue("recent_files", self._recent_files)

    def _rebuild_recent_menu(self) -> None:
        self._recent_menu.clear()
        self._welcome.set_recent(self._recent_files)
        if not self._recent_files:
            action = self._recent_menu.addAction("(none yet)")
            action.setEnabled(False)
            return
        for path in self._recent_files:
            self._recent_menu.addAction(path, lambda p=path: self._open_recent(p))
        self._recent_menu.addSeparator()
        self._recent_menu.addAction("Clear Recent Files", self._clear_recent_files)

    def _clear_recent_files(self) -> None:
        self._recent_files = []
        self._rebuild_recent_menu()
        QSettings("N3rdL0rd", "crashlink").setValue("recent_files", self._recent_files)

    def _confirm_discard_changes(self) -> bool:
        """Ask to save unsaved renames/comments before discarding them (opening a
        different file or closing the app). Returns True if it's OK to proceed."""
        if not self._dirty:
            return True
        box = QMessageBox(self)
        box.setWindowTitle("Unsaved changes")
        box.setText("You have unsaved renames/comments. Save the analysis database before continuing?")
        box.setStandardButtons(
            QMessageBox.StandardButton.Save
            | QMessageBox.StandardButton.Discard
            | QMessageBox.StandardButton.Cancel
        )
        box.setDefaultButton(QMessageBox.StandardButton.Save)
        choice = box.exec()
        if choice == QMessageBox.StandardButton.Cancel:
            return False
        if choice == QMessageBox.StandardButton.Save:
            return self._save_database()
        return choice == QMessageBox.StandardButton.Discard

    def _load_file(self, path: str) -> None:
        self._generation += 1
        for old_thread in self._threads:
            old_thread.requestInterruption()
        self._active_decompiles = 0
        self._decomp_tokens.clear()
        self._busy.stop_all()
        self._decomp_jobs.clear()
        self._tabs.clear()
        self._open_tabs.clear()
        self._generic_tabs.clear()
        self._back_stack.clear()
        self._forward_stack.clear()
        self._update_history_actions()
        self._jump_names.clear()
        self._find_bar.hide()
        self._class_findices.clear()
        self._class_results.clear()
        self._class_names.clear()
        self._ir_cache.clear()
        self._opline_cache.clear()
        self._spans_cache.clear()
        self._pending_op_scroll = None
        self._cfg_findex = None
        self._cfg_view.clear_view()
        self._db_cache.clear()
        self._log_panel.clear()
        self._undo_stack.clear()
        self._dirty = False
        self._code = None
        self._loaded_via_dehlc = _looks_like_native_image(path)
        self._native_asm_cache.clear()
        self._plt_map = None
        self._disasm_source = "asm"
        self._emit_ctx = None
        self._lifter = None
        self._fidx_addr.clear()
        self._arm_lift_warned = False
        self._set_disasm_toggle_visible(self._loaded_via_dehlc)
        self._log_panel.set_context(code=None, findex=None, func=None, irf=None)
        self._source_path = path
        self._update_window_title()
        self._worker.invalidate()
        self._xref_popup.set_code(None)
        self.code_loaded.emit(None)
        self._update_central_page()
        # The previous document was frozen out of cyclic GC as it loaded (see
        # _bulk_build); unfreeze so its reference cycles become collectable.
        gc.unfreeze()
        gc.collect()

        self._progress_bar.setVisible(True)
        self._progress_bar.setValue(0)
        self._status_label.setText(f"Loading {path}...")
        self._busy.start(
            "Reading bytecode..." if not self._loaded_via_dehlc else "Reading binary...", key="load"
        )

        if self._loaded_via_dehlc:
            thread: QThread = _DehlcLoadThread(path, self._generation)
            self._log_panel.info("De-HL/C: Loading binary...")
        else:
            thread = _LoadThread(path, self._generation)
        self._load_thread = thread
        thread.signals.progress.connect(self._on_load_progress)
        thread.signals.finished.connect(self._on_load_finished)
        thread.signals.error.connect(self._on_load_error)
        self._start_thread(thread)

    def _is_current(self, generation: int) -> bool:
        return not self._closing and generation == self._generation

    @Slot(int, float, str)
    def _on_load_progress(self, generation: int, frac: float, status: str) -> None:
        if not self._is_current(generation):
            return
        if frac < 0:
            # Indeterminate progress (de-HL/C passes): hide the bar, show phase text.
            self._progress_bar.setVisible(False)
            self._status_label.setText(status)
            return
        self._progress_bar.setValue(int(frac * 100))
        self._status_label.setText(status)

    @Slot(int, object, object)
    def _on_load_finished(self, generation: int, code: Bytecode, nav_data: object = None) -> None:
        if not self._is_current(generation):
            return
        self._code = code
        self._progress_bar.setVisible(False)
        self._busy.stop(key="load")
        assert self._source_path is not None
        self._add_recent_file(self._source_path)
        n = len(code.functions)
        label = "Loaded (inspection-only native recovery)" if code.inspection_only else "Loaded"
        self._status_label.setText(f"{label}, {n} functions")
        self._log_panel.info(f"{label} {os.path.basename(self._source_path)}: {n} functions")
        if code.inspection_only:
            for diagnostic in code.recovery_diagnostics:
                self._log_panel.warn(diagnostic)
        self._log_panel.set_context(code=code)
        self._func_list.load(code, cast(Optional[NavigatorData], nav_data))
        self._xref_popup.set_code(code)
        self.code_loaded.emit(code)

        assert self._source_path is not None
        cldb_path = self._source_path + ".cldb"
        if os.path.exists(cldb_path):
            self._load_database_from(cldb_path)

        # Pre-warm the xref/search/source-map indices in the background so the
        # first 'X' lookup doesn't stall the UI thread building them on demand.
        self._busy.start("Building xref table...", key="index")
        self._index_build_thread = _IndexBuildThread(self._worker, code, generation)
        self._index_build_thread.signals.finished.connect(self._on_index_finished)
        self._index_build_thread.signals.error.connect(self._on_index_error)
        self._start_thread(self._index_build_thread)

    @Slot(int)
    def _on_index_finished(self, generation: int) -> None:
        if self._is_current(generation):
            self._busy.stop(key="index")

    @Slot(int, str)
    def _on_index_error(self, generation: int, msg: str) -> None:
        if self._is_current(generation):
            self._on_index_finished(generation)
            self._log_panel.error(f"Failed to build indices: {msg}")

    @Slot(int, str)
    def _on_load_error(self, generation: int, msg: str) -> None:
        if not self._is_current(generation):
            return
        self._progress_bar.setVisible(False)
        self._busy.stop(key="load")
        self._status_label.setText(f"Error: {msg}")
        path = self._source_path or "file"
        self._log_panel.error(f"Couldn't open {path}: {msg}")
        box = QMessageBox(
            QMessageBox.Icon.Warning, "Couldn't open file", f"Couldn't open {path}", parent=self
        )
        box.setInformativeText(msg)
        box.open()  # non-blocking: the load threads' queued signals keep flowing

    def _open_database_file(self) -> None:
        if self._code is None or self._source_path is None:
            self._log_panel.warn("Open a bytecode file first.")
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "Load analysis database", "", "crashlink database (*.cldb)"
        )
        if path and self._confirm_discard_changes():
            self._load_database_from(path)

    def _export_disasm(self) -> None:
        view = self._current_sync_view()
        if view is None:
            self._log_panel.warn("No class tab open to export.")
            return
        self._export_text(view.disasm_view.toPlainText(), "Export Disassembly", "disasm.txt")

    def _export_pseudo(self) -> None:
        view = self._current_sync_view()
        if view is None:
            self._log_panel.warn("No class tab open to export.")
            return
        self._export_text(view.class_view.toPlainText(), "Export Pseudocode", "pseudo.hx")

    def _export_text(self, text: str, title: str, default_name: str) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, title, default_name, "Text files (*.txt *.hx);;All files (*)"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        except OSError as e:
            self._log_panel.error(f"Failed to export: {e}")
            return
        self._log_panel.success(f"Exported to {path}")

    def _accept_db_token(self, token: tuple) -> bool:
        return self._is_current(token[0]) and token[1] == self._db_request

    @Slot(object, str)
    def _on_db_load_error(self, token: tuple, msg: str) -> None:
        if self._accept_db_token(token):
            self._log_panel.error(f"Failed to load database: {msg}")

    @Slot(object, object, object)
    def _on_db_load_finished(
        self, token: tuple, result: DatabaseLoadResult, annotations: AnnotationStore
    ) -> None:
        if not self._accept_db_token(token) or self._code is None:
            return
        for w in result.warnings:
            self._log_panel.warn(w)
        if not result.matched:
            return
        self._code.annotations = annotations
        self._worker.invalidate()
        self._ir_cache.clear()
        self._opline_cache.clear()
        self._spans_cache.clear()
        self._undo_stack.clear()
        self._dirty = False
        self._update_window_title()
        for class_key, findices in self._class_findices.items():
            for findex in findices:
                self._start_decompile(class_key, findex)

        self._db_cache = dict(result.cache)
        self._log_panel.success(
            f"Loaded database: {result.renames_applied} renames, "
            f"{result.comments_applied} comments, {len(result.cache)} cached functions"
        )

        session = result.session
        if session is None:
            return

        theme = THEMES.get(session.theme_name)
        if theme is not None:
            self._apply_theme(theme)
        if session.view_mode in _VIEW_MODE_NAMES:
            self._set_view_mode(session.view_mode)
        for findex in session.open_findices:
            self._on_function_selected(findex)
        if session.current_tab_index is not None and 0 <= session.current_tab_index < self._tabs.count():
            self._tabs.setCurrentIndex(session.current_tab_index)

    def closeEvent(self, event: QCloseEvent) -> None:
        if not self._confirm_discard_changes():
            event.ignore()
            return
        self._save_settings()
        set_dbg_callback(None)
        self._closing = True
        self._generation += 1
        self._busy.stop_all()
        self._decomp_jobs.clear()
        self._bg_pool.clear()
        self._bg_jobs.clear()
        self._worker.invalidate()
        for thread in self._threads:
            thread.requestInterruption()
        for thread in self._threads:
            thread.wait()
        self._bg_pool.waitForDone()
        self._worker.shutdown(wait=True)
        self._render_pool.shutdown(wait=True, cancel_futures=True)
        self._threads.clear()
        # Hand the document back to the cyclic GC (frozen since it loaded).
        gc.unfreeze()
        super().closeEvent(event)
