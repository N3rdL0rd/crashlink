"""Type-checking host interface for the `MainWindow` mixins.

The mixins in this package are composed into `MainWindow`
(`crashlink.gui.main_window`) and rely on the state its `__init__`/`_build_ui`
set up, plus each other's methods. To keep `ty` clean without runtime coupling,
each mixin inherits `MainWindowHost` under `TYPE_CHECKING` and plain `object` at
runtime; this class declares — but never implements — the shared surface.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from concurrent.futures import ThreadPoolExecutor
    from typing import Any, Callable, Dict, List, Optional, Set, Tuple

    from PySide6.QtCore import QThread, QThreadPool, SignalInstance
    from PySide6.QtGui import QAction, QUndoStack
    from PySide6.QtWidgets import (
        QButtonGroup,
        QDockWidget,
        QFrame,
        QLabel,
        QMainWindow,
        QMenu,
        QPlainTextEdit,
        QProgressBar,
        QPushButton,
        QStackedWidget,
        QStatusBar,
        QTabWidget,
        QUndoView,
        QWidget,
    )

    from crashlink.core import AnalysisWorker, Bytecode
    from crashlink.dehlc.emit import EmitContext
    from crashlink.dehlc.lift import FunctionLifter
    from crashlink.pseudo.doc import RenderedSource
    from crashlink.pseudo.symbols import SymbolRef, SymbolSpan

    from ..chrome import _BusyIndicator, _FindBar, _TabBar, _WelcomePage
    from ..themes import Theme
    from ..widgets.cfg_view import CfgView
    from ..widgets.function_list import FunctionList
    from ..widgets.log_panel import LogPanel
    from ..widgets.sync_view import SyncView
    from ..widgets.xref_panel import XrefPopup
    from ..workers import _DecompJob, _IndexBuildThread

    class MainWindowHost(QMainWindow):
        """The `MainWindow` surface the mixins rely on (state + cross-area methods)."""

        # ── Signals (MainWindow class body; `SignalInstance` is what instance access yields) ──
        code_loaded: SignalInstance
        theme_changed: SignalInstance
        function_focused: SignalInstance

        # ── State (MainWindow.__init__) ──────────────────────────────────────
        _code: Optional[Bytecode]
        _worker: AnalysisWorker
        _render_pool: ThreadPoolExecutor
        _decomp_jobs: Dict[tuple, _DecompJob]
        _generation: int
        _closing: bool
        _threads: Set[QThread]
        _db_request: int
        _decomp_request: int
        _decomp_tokens: Dict[Tuple[str, int], tuple]
        _load_thread: Optional[QThread]
        _theme: Theme
        _loaded_via_dehlc: bool
        _native_asm_cache: Dict[int, Optional[Tuple[str, List[str]]]]
        _plt_map: Optional[Dict[int, str]]
        _disasm_source: str
        _emit_ctx: Optional[EmitContext]
        _lifter: Optional[FunctionLifter]
        _fidx_addr: Dict[int, int]
        _arm_lift_warned: bool
        _open_tabs: Dict[str, int]
        _class_findices: Dict[str, List[int]]
        _class_results: Dict[str, Dict[int, Optional[str]]]
        _class_names: Dict[str, str]
        _class_fields: Dict[str, List[str]]
        _ir_cache: Dict[int, object]
        _opline_cache: Dict[int, Dict[int, int]]
        _spans_cache: Dict[int, RenderedSource]
        _pending_op_scroll: Optional[Tuple[int, int]]
        _view_mode: int
        _cfg_findex: Optional[int]
        _source_path: Optional[str]
        _db_cache: Dict[int, RenderedSource]
        _db_load_thread: Optional[QThread]
        _index_build_thread: Optional[_IndexBuildThread]
        _active_decompiles: int
        _dirty: bool
        _recent_files: List[str]
        _undo_stack: QUndoStack
        _back_stack: List[Tuple[int, Optional[int]]]
        _forward_stack: List[Tuple[int, Optional[int]]]
        _jump_names: Dict[str, int]
        _generic_tabs: Dict[str, QWidget]
        _menus: Dict[str, QMenu]
        _bg_request: int
        _bg_jobs: Dict[int, Tuple[int, Callable[[Any], None], Optional[Callable[[str], None]]]]
        _bg_pool: QThreadPool
        _follow_handlers: Dict[str, Callable[[int], None]]
        _symbol_status_shown: bool
        _busy: _BusyIndicator

        # ── Widgets (MainWindow._build_ui) ───────────────────────────────────
        _view_mode_bar: QFrame
        _view_mode_group: QButtonGroup
        _view_mode_buttons: Dict[int, QPushButton]
        _disasm_source_bar: QFrame
        _disasm_source_group: QButtonGroup
        _view_mode_corner: QWidget
        _tab_bar: _TabBar
        _tabs: QTabWidget
        _welcome: _WelcomePage
        _central_stack: QStackedWidget
        _find_bar: _FindBar
        _func_list: FunctionList
        _nav_dock: QDockWidget
        _log_panel: LogPanel
        _log_dock: QDockWidget
        _history_view: QUndoView
        _history_dock: QDockWidget
        _cfg_view: CfgView
        _cfg_dock: QDockWidget
        _xref_popup: XrefPopup
        _status_bar: QStatusBar
        _status_label: QLabel
        _progress_bar: QProgressBar
        _busy_label: QLabel
        _busy_bar: QProgressBar

        # ── Actions (MenusMixin._build_menu) ─────────────────────────────────
        _recent_menu: QMenu
        _quit_action: QAction
        _debug_output_action: QAction
        _back_action: QAction
        _forward_action: QAction
        _jump_action: QAction
        _cfg_space_action: QAction

        # ── Navigation (navigation.py) ───────────────────────────────────────
        def navigate_back(self) -> None: ...
        def navigate_forward(self) -> None: ...
        def _open_jump_dialog(self) -> None: ...
        def _update_history_actions(self) -> None: ...
        def _show_location(self, findex: int, op_idx: int, body_line: int) -> None: ...
        def _on_follow_requested(self, findex: int, span: Optional[SymbolSpan]) -> None: ...
        def _on_symbol_focused(self, span: Optional[SymbolSpan]) -> None: ...

        # ── Xrefs (xrefs.py) ─────────────────────────────────────────────────
        def _on_native_xref_requested(self, findex: int) -> None: ...
        def _show_xrefs_for(self, word: str) -> None: ...
        def _on_xref_hotkey(self, findex: int, target: "SymbolRef | str | None") -> None: ...
        def _show_symbol_xrefs(self, findex: int, ref: SymbolRef) -> None: ...

        # ── Rename/comment (annotate.py) ─────────────────────────────────────
        def _on_rename_hotkey(self, findex: int, ref: "SymbolRef | None") -> None: ...
        def _on_comment_hotkey(self, findex: int, op_idx: int) -> None: ...

        # ── File load/save (fileio.py) ───────────────────────────────────────
        def _is_current(self, generation: int) -> bool: ...
        def _open_file(self) -> None: ...
        def _open_recent(self, path: str) -> None: ...
        def _rebuild_recent_menu(self) -> None: ...
        def _open_database_file(self) -> None: ...
        def _export_disasm(self) -> None: ...
        def _export_pseudo(self) -> None: ...

        # ── Class tabs / decompile (tabs.py) ─────────────────────────────────
        def _on_function_selected(self, findex: int) -> None: ...
        def _class_key_for(self, findex: int) -> Tuple[str, str, List[int]]: ...
        def _refresh_disasm_view(self, class_key: str) -> None: ...
        def _set_disasm_toggle_visible(self, visible: bool) -> None: ...
        def _update_central_page(self) -> None: ...
        def _open_natives_tab(self) -> None: ...
        def _open_types_tab(self, select: Optional[int] = None) -> None: ...

        # ── Views / focus (views.py) ─────────────────────────────────────────
        def _current_sync_view(self) -> Optional[SyncView]: ...
        def _on_function_focused(self, findex: int) -> None: ...
        def _on_op_focused(self, findex: int, op_idx: int) -> None: ...
        def _update_cfg_view(self, findex: int) -> None: ...
        def _update_repl_focus(self, findex: int) -> None: ...
        def _apply_theme(self, theme: Theme) -> None: ...
        def _set_view_mode(self, mode: int) -> None: ...
        def _cycle_view_mode(self) -> None: ...
        def _open_find(self) -> None: ...
        def _find_target_view(self) -> Optional[QPlainTextEdit]: ...

        # ── MainWindow (main_window.py) ──────────────────────────────────────
        def _start_thread(self, thread: QThread) -> None: ...
        def open_tab(self, key: str, title: str, factory: Callable[[], QWidget]) -> QWidget: ...
        def run_background(
            self,
            label: str,
            fn: Callable[[], Any],
            on_done: Callable[[Any], None],
            on_error: Optional[Callable[[str], None]] = None,
        ) -> None: ...
        def _start_decompile(self, class_key: str, findex: int) -> None: ...
        def _load_database_from(self, cldb_path: str) -> None: ...
        def _save_database(self) -> bool: ...
        def _update_window_title(self) -> None: ...
        def _save_settings(self) -> None: ...
