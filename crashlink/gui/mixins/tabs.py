"""Class-tab lifecycle and decompile-result management for `MainWindow`."""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional, Tuple, cast

from PySide6.QtCore import QChildEvent, QEvent, QSize, Qt, QTimer, Slot
from PySide6.QtWidgets import QDockWidget, QTabBar, QToolButton, QWidget

from crashlink.core import Function, Native, destaticify
from crashlink.decomp.function import IRFunction
from crashlink.pseudo import _method_registry, class_field_lines
from crashlink.pseudo.doc import RenderedSource

from ..chrome import _DockMiddleClose, _tab_label
from ..widgets.natives_view import NativesView
from ..widgets.sync_view import SyncView
from ..widgets.types_view import TypesView

if TYPE_CHECKING:
    from ._host import MainWindowHost as _Base
else:
    _Base = object


class TabsMixin(_Base):
    """Class-tab lifecycle and decompile-result management for `MainWindow`.

    State is set up by ``MainWindow.__init__``/``_build_ui`` (see ``._host`` for
    the typed surface); this area relies on:

    ``_code``, ``_open_tabs``, ``_class_findices``, ``_class_names``, ``_class_results``,
    ``_class_fields``, ``_db_cache``, ``_opline_cache``, ``_spans_cache``, ``_ir_cache``,
    ``_theme``, ``_view_mode``, ``_tabs``, ``_status_label``, ``_status_bar``, ``_busy``,
    ``_active_decompiles``, ``_decomp_tokens``, ``_decomp_jobs``, ``_pending_op_scroll``,
    ``_cfg_findex``, ``_central_stack``, ``_welcome``, ``_find_bar``, ``_log_panel``,
    ``_disasm_source``, ``_disasm_source_bar``, ``_view_mode_corner``, ``_native_asm_cache``,
    ``_plt_map``, ``_emit_ctx``, ``_lifter``, ``_fidx_addr``, ``_arm_lift_warned``,
    ``_generic_tabs``
    plus sibling-area methods resolved through ``MainWindow``.
    """

    def _class_key_for(self, findex: int) -> Tuple[str, str, List[int]]:
        """
        Returns (class_key, display_name, all_findices_for_class).
        Uses destaticify to unify static $Foo and instance Foo into one class.
        Falls back to a standalone key for unregistered functions.
        """
        assert self._code is not None
        reg = _method_registry(self._code)
        if findex not in reg:
            return f"func:{findex}", f"f@{findex}", [findex]

        obj, _, _ = reg[findex]
        raw_name = obj.name.resolve(self._code)
        canonical = destaticify(raw_name)
        class_key = f"class:{canonical}"

        # Gather all findices that belong to this canonical class (static + instance)
        all_fi = sorted(
            fi for fi, (o, _, _) in reg.items() if destaticify(o.name.resolve(self._code)) == canonical
        )
        # Constructor first (as in `decompile --class`), then declaration (findex) order.
        ctors = [fi for fi in all_fi if reg[fi][1] == "__constructor__"]
        return class_key, canonical, ctors + [fi for fi in all_fi if fi not in ctors]

    def _open_natives_tab(self) -> None:
        code = self._code
        if code is None:
            self._status_bar.showMessage("Open a file first", 3000)
            return

        def build() -> QWidget:
            view = NativesView()
            view.set_theme(self._theme)
            view.load(code)
            view.xref_requested.connect(self._on_native_xref_requested)
            return view

        self.open_tab("__natives__", "Natives", build)

    def _open_types_tab(self, select: Optional[int] = None) -> None:
        code = self._code
        if code is None:
            self._status_bar.showMessage("Open a file first", 3000)
            return

        def build() -> QWidget:
            view = TypesView()
            view.set_theme(self._theme)
            view.load(code)
            view.xref_requested.connect(self._show_xrefs_for)
            return view

        view = self.open_tab("__types__", "Types", build)
        if select is not None and isinstance(view, TypesView):
            view.select_type(select)

    def _native_asm_blocks(self, findices: List[int]) -> List[Tuple[int, str, List[str]]]:
        """(findex, header, rows) machine-code blocks for a tab's disassembly pane.
        Cached per findex; slots without code (natives) are skipped."""
        bin_view = self._code.hlc_binary if self._code is not None else None
        if bin_view is None:
            return []
        from crashlink.dehlc.asmview import function_asm_block
        from crashlink.dehlc.binary import _resolve_plt_targets

        if self._plt_map is None:
            self._plt_map = _resolve_plt_targets(bin_view)
        blocks: List[Tuple[int, str, List[str]]] = []
        for fi in findices:
            if fi not in self._native_asm_cache:
                self._native_asm_cache[fi] = function_asm_block(bin_view, fi, plt_map=self._plt_map)
            block = self._native_asm_cache[fi]
            if block is not None:
                blocks.append((fi, block[0], block[1]))
        return blocks

    def _recovery_text(self, findex: int) -> str:
        """Approximate native operations, never invented executable dataflow."""
        assert self._code is not None
        from crashlink.dehlc.emit import format_recovered_ops

        ops = self._code.recovery_opcodes.get(findex, [])
        text = format_recovered_ops(ops)
        if not ops:
            text += "\nNo HL-shaped operations recovered; see original machine-code disassembly."
        events = self._code.recovery_lifts.get(findex, [])
        if events:
            text += "\nNative lift events (including unmapped events):\n"
            text += "\n".join(f"{event.src_addr:#x} {event!r}" for event in events)
        return text

    def _load_disasm_pane(self, view: SyncView, all_fi: List[int]) -> None:
        """Fills a SyncView's disassembly pane: for de-HL/C images either the
        original machine code or inspection-only approximate operations,
        HL opcodes for ordinary bytecode."""
        assert self._code is not None
        if self._code.hlc_binary is None:
            findex_map = self._code.get_findex_map()
            view.load_disasm(self._code, [(fi, findex_map[fi]) for fi in all_fi if fi in findex_map])
            return
        if self._disasm_source == "ops":
            self._ensure_lifted(all_fi)
            view.disasm_view.load_native(
                [(fi, f"f@{fi} approximate lift", self._recovery_text(fi).splitlines()) for fi in all_fi]
            )
        else:
            view.disasm_view.load_native(self._native_asm_blocks(all_fi))

    def _ensure_lifted(self, findices: List[int]) -> None:
        """
        Recover inspection records without changing Function.ops or register types.
        Unsupported architectures remain browsable as original machine code.
        """
        assert self._code is not None
        bin_view = self._code.hlc_binary
        assert bin_view is not None
        findex_map = self._code.get_findex_map()
        todo = []
        for fi in findices:
            fn = findex_map.get(fi)
            if isinstance(fn, Function) and fi not in self._code.recovery_opcodes:
                todo.append(fi)
        if not todo:
            return
        if bin_view.arch not in ("x86_64", "x86", "aarch64"):
            if not self._arm_lift_warned:
                self._arm_lift_warned = True
                self._log_panel.warn(
                    f"Opcode lifting supports x86 and aarch64 - {bin_view.arch} bodies stay empty."
                )
            return
        from crashlink.dehlc.binary import _resolve_plt_targets
        from crashlink.dehlc.emit import EmitContext, emit_function
        from crashlink.dehlc.lift import FunctionLifter

        if self._emit_ctx is None or self._lifter is None:
            if self._plt_map is None:
                self._plt_map = _resolve_plt_targets(bin_view)
            self._emit_ctx = EmitContext(self._code, bin_view)
            self._fidx_addr = {v: k for k, v in self._emit_ctx.addr2findex.items()}
            self._lifter = FunctionLifter.for_binary(bin_view, self._plt_map)
        ctx = self._emit_ctx
        lifter = self._lifter
        lifted = 0
        for fi in todo:
            addr = self._fidx_addr.get(fi)
            if not addr:
                continue  # native slot / padding entry
            try:
                stream = lifter.lift(addr)
                ops = emit_function(ctx, stream)
            except Exception as e:
                self._log_panel.warn(f"lifting failed for f@{fi}: {e}")
                continue
            self._code.recovery_lifts[fi] = stream
            self._code.recovery_opcodes[fi] = ops
            lifted += 1
        if lifted:
            self._log_panel.info(f"Recovered inspection-only approximations for {lifted} function(s).")

    def _set_disasm_source(self, source: str) -> None:
        """Toolbar toggle: original assembly vs inspection-only approximate operations."""
        if source == self._disasm_source:
            return
        self._disasm_source = source
        for class_key in list(self._open_tabs):
            self._refresh_disasm_view(class_key)

    def _set_disasm_toggle_visible(self, visible: bool) -> None:
        """Shows/hides the Asm/Ops toggle. QMenuBar sizes AND positions its corner
        widget from a cached size hint, so merely toggling an inner bar's visibility
        leaves the corner clipped/overflowing - re-registering the corner forces the
        menubar to re-measure it."""
        self._disasm_source_bar.setVisible(visible)
        mb = self.menuBar()
        corner = self._view_mode_corner
        if mb.cornerWidget(Qt.Corner.TopRightCorner) is corner:
            # Qt's C++ API takes nullptr here to release the widget; the PySide6
            # stubs only type the non-null overload.
            mb.setCornerWidget(cast("QWidget", None), Qt.Corner.TopRightCorner)
        mb.setCornerWidget(corner, Qt.Corner.TopRightCorner)

    def _open_class_tab(self, class_key: str, display_name: str, all_fi: List[int], jump_to: int) -> None:
        assert self._code is not None

        self._class_findices[class_key] = all_fi
        self._class_names[class_key] = display_name
        self._class_results[class_key] = {fi: None for fi in all_fi}
        self._class_fields[class_key] = self._class_field_lines(all_fi)

        # Seed from a loaded .cldb where available, so cached functions render
        # immediately instead of flashing "decompiling..." — a real decompile still
        # runs below to warm _ir_cache for rename/xref support.
        if not self._code.inspection_only:
            for fi in all_fi:
                cached = self._db_cache.get(fi)
                if cached is not None:
                    self._class_results[class_key][fi] = cached.text
                    self._opline_cache[fi] = cached.oplines
                    self._spans_cache[fi] = cached

        view = SyncView(self._opline_cache)
        view.setProperty("class_key", class_key)
        view.set_theme(self._theme)
        view.set_mode(self._view_mode)
        view.cycle_requested.connect(self._cycle_view_mode)
        view.class_view.function_focused.connect(self._on_function_focused)
        view.class_view.rename_requested.connect(self._on_rename_hotkey)
        view.class_view.xref_requested.connect(self._on_xref_hotkey)
        view.disasm_view.function_focused.connect(self._on_function_focused)
        view.disasm_view.xref_requested.connect(self._on_xref_hotkey)
        view.comment_requested.connect(self._on_comment_hotkey)
        view.follow_requested.connect(self._on_follow_requested)
        view.symbol_focused.connect(self._on_symbol_focused)
        view.disasm_view.op_focused.connect(self._on_op_focused)

        # Native bodies remain separate from bytecode and never enter the IR pipeline.
        if self._code.hlc_binary is not None:
            self._ensure_lifted(all_fi)

        findex_map = self._code.get_findex_map()
        methods: List[Tuple[int, str]] = []
        to_decompile: List[int] = []
        for fi in all_fi:
            if self._code.inspection_only:
                self._ir_cache.pop(fi, None)
                self._opline_cache.pop(fi, None)
                self._spans_cache.pop(fi, None)
                text = self._recovery_text(fi)
                self._class_results[class_key][fi] = text
                methods.append((fi, text))
                continue
            cached = self._db_cache.get(fi)
            if cached is not None:
                # Seed from a loaded .cldb so cached functions render immediately
                # instead of flashing "decompiling..." — a real decompile still runs
                # below to warm _ir_cache for rename/xref support. The stored spans
                # make symbols resolvable from the first frame; the class view only
                # uses them for exactly this text.
                self._class_results[class_key][fi] = cached.text
                self._opline_cache[fi] = cached.oplines
                self._spans_cache[fi] = cached
                to_decompile.append(fi)
                methods.append((fi, cached.text))
                continue
            fn = findex_map.get(fi)
            if isinstance(fn, Native):
                methods.append(
                    (fi, f"// f@{fi}  native primitive (implemented in an hdll)\n// signature only")
                )
            elif isinstance(fn, Function) and not fn.ops:
                methods.append((fi, f"f@{fi}() {{\n  // body not recovered\n}}"))
            else:
                to_decompile.append(fi)
                methods.append(
                    (
                        fi,
                        f"class {display_name} {{\n    // f@{fi}  decompiling...\n}}",
                    )
                )

        view.load_pseudo(
            display_name,
            methods,
            fields=self._class_fields[class_key],
            spans={fi: self._spans_cache[fi] for fi in all_fi if fi in self._spans_cache},
        )
        self._load_disasm_pane(view, all_fi)

        tab_label = _tab_label(display_name)
        idx = self._tabs.addTab(view, tab_label)
        self._tabs.setTabToolTip(idx, display_name)
        self._open_tabs[class_key] = idx
        self._add_close_btn(idx, class_key)
        self._tabs.setCurrentIndex(idx)
        if jump_to in all_fi:
            view.scroll_to_findex(jump_to)

        # Kick off decompile for every method that actually has opcodes.
        for fi in to_decompile:
            self._start_decompile(class_key, fi)

        pending = len(to_decompile)
        if pending:
            self._status_label.setText(f"Decompiling {display_name} ({pending}/{len(all_fi)} methods)...")
        else:
            self._status_label.setText(f"{display_name}, {len(all_fi)} methods")

    def _class_field_lines(self, all_fi: List[int]) -> List[str]:
        """Field declarations for a class tab, from the class's Obj (no decompile needed)."""
        assert self._code is not None
        if self._code.inspection_only or not all_fi:
            return []
        info = _method_registry(self._code).get(all_fi[0])
        if info is None:
            return []
        try:
            return class_field_lines(self._code, info[0])
        except Exception as e:
            return [f"// fields unavailable: {e}"]

    def _decompile_batch_done(self) -> None:
        self._active_decompiles = max(0, self._active_decompiles - 1)
        if self._active_decompiles == 0:
            self._busy.stop(key="decompile")

    def _add_close_btn(self, tab_idx: int, class_key: str) -> None:
        btn = QToolButton()
        btn.setObjectName("tabCloseBtn")
        btn.setText("×")
        btn.setFixedSize(QSize(18, 18))
        btn.setToolTip("Close tab")
        btn.clicked.connect(lambda: QTimer.singleShot(0, lambda: self._close_tab_by_key(class_key)))
        self._tabs.tabBar().setTabButton(tab_idx, QTabBar.ButtonPosition.RightSide, btn)

    def _close_tab_at(self, index: int) -> None:
        widget = self._tabs.widget(index)
        key = widget.property("class_key") if widget is not None else None
        if key:
            self._close_tab_by_key(key)

    def childEvent(self, event: QChildEvent) -> None:
        super().childEvent(event)
        # Docks, and the tab bars Qt creates when docks are tabbed together, are
        # children of the window; watch them for middle-click closes once they
        # are fully constructed (polished).
        if event.type() == QEvent.Type.ChildPolished:
            child = event.child()
            if isinstance(child, (QDockWidget, QTabBar)):
                closer = self.__dict__.get("_dock_middle_close")
                if closer is None:
                    closer = self._dock_middle_close = _DockMiddleClose(self)
                closer.watch(child)

    def _close_tab_by_key(self, class_key: str) -> None:
        idx = self._open_tabs.pop(class_key, None)
        if idx is None:
            return
        self._class_findices.pop(class_key, None)
        self._class_results.pop(class_key, None)
        self._class_names.pop(class_key, None)
        self._class_fields.pop(class_key, None)
        self._generic_tabs.pop(class_key, None)
        self._tabs.removeTab(idx)
        self._rebuild_tab_map()

    def _rebuild_tab_map(self) -> None:
        self._open_tabs = {}
        for i in range(self._tabs.count()):
            w = self._tabs.widget(i)
            if w is not None:
                key = w.property("class_key")
                if key:
                    self._open_tabs[key] = i
        self._update_central_page()

    def _on_tab_changed(self, _idx: int) -> None:
        self._update_central_page()

    def _update_central_page(self) -> None:
        """Welcome page when no tabs are open, the tab widget otherwise."""
        self._central_stack.setCurrentWidget(self._tabs if self._tabs.count() else self._welcome)
        if not self._tabs.count():
            self._find_bar.hide()

    def _on_function_selected(self, findex: int) -> None:
        if self._code is None:
            return
        class_key, display_name, all_fi = self._class_key_for(findex)

        if class_key in self._open_tabs:
            idx = self._open_tabs[class_key]
            self._tabs.setCurrentIndex(idx)
            view = self._tabs.widget(idx)
            if isinstance(view, SyncView):
                view.scroll_to_findex(findex)
        else:
            self._open_class_tab(class_key, display_name, all_fi, jump_to=findex)

    def _accept_decompile(self, token: tuple, class_key: str, findex: int) -> bool:
        self._decomp_jobs.pop(token, None)
        if not self._is_current(token[0]):
            return False
        self._decompile_batch_done()
        return self._decomp_tokens.get((class_key, findex)) == token

    @Slot(object, str, int, object, object)
    def _on_decompile_finished(
        self, token: tuple, class_key: str, findex: int, ir: object, rendered: RenderedSource
    ) -> None:
        if not self._accept_decompile(token, class_key, findex):
            return
        if not isinstance(ir, IRFunction):
            return

        self._ir_cache[findex] = ir

        if class_key not in self._class_results:
            return

        text, opmap = rendered.text, rendered.oplines
        self._opline_cache[findex] = opmap
        self._spans_cache[findex] = rendered
        self._class_results[class_key][findex] = text
        self._show_method_text(class_key, findex, text, rendered)

        if findex == self._cfg_findex:
            self._update_cfg_view(findex)
            self._update_repl_focus(findex)

        if self._pending_op_scroll is not None and self._pending_op_scroll[0] == findex:
            pf, pop = self._pending_op_scroll
            self._pending_op_scroll = None
            self._show_location(pf, pop, -1)

        # Update status when all done
        results = self._class_results.get(class_key, {})
        pending = sum(1 for v in results.values() if v is None)
        if pending == 0:
            name = self._class_names.get(class_key, class_key)
            self._status_label.setText(f"{name}, {len(results)} methods")

    @Slot(object, str, int, str)
    def _on_decompile_error(self, token: tuple, class_key: str, findex: int, msg: str) -> None:
        if not self._accept_decompile(token, class_key, findex):
            return
        if class_key not in self._class_results:
            return
        err_text = f"class ? {{\n    // f@{findex} error: {msg}\n}}"
        self._class_results[class_key][findex] = err_text
        self._show_method_text(class_key, findex, err_text)

    def _show_method_text(
        self, class_key: str, findex: int, text: str, rendered: Optional[RenderedSource] = None
    ) -> None:
        """Put one method's new pseudocode into its open class tab, in place."""
        idx = self._open_tabs.get(class_key)
        view = self._tabs.widget(idx) if idx is not None else None
        if isinstance(view, SyncView):
            view.update_method(findex, text, rendered)

    def _refresh_class_view(self, class_key: str) -> None:
        idx = self._open_tabs.get(class_key)
        if idx is None:
            return
        view = self._tabs.widget(idx)
        if not isinstance(view, SyncView):
            return

        display_name = self._class_names.get(class_key, "?")
        all_fi = self._class_findices.get(class_key, [])
        results = self._class_results.get(class_key, {})

        methods = []
        for fi in all_fi:
            text = results.get(fi)
            if text is None:
                text = f"class {display_name} {{\n    // f@{fi}  decompiling...\n}}"
            methods.append((fi, text))

        view.load_pseudo(
            display_name,
            methods,
            fields=self._class_fields.get(class_key),
            spans={fi: self._spans_cache[fi] for fi in all_fi if fi in self._spans_cache},
        )

    def _refresh_disasm_view(self, class_key: str) -> None:
        """Disasm rendering needs no decompile — re-render straight from opcodes (or
        cached machine code) so an annotation change (e.g. a comment) shows up
        immediately, no waiting on the background redecompile that updates the
        pseudocode pane."""
        if self._code is None:
            return
        idx = self._open_tabs.get(class_key)
        if idx is None:
            return
        view = self._tabs.widget(idx)
        if not isinstance(view, SyncView):
            return
        all_fi = self._class_findices.get(class_key, [])
        self._load_disasm_pane(view, all_fi)
