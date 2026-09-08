"""Native recovery remains visibly approximate and outside the bytecode IR path."""

import os
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")
pytest.importorskip("capstone")
pytest.importorskip("lief")

from PySide6.QtWidgets import QApplication

from crashlink.core import Bytecode, Function, fIndex
from crashlink.dehlc import asmview, binary
from crashlink.dehlc.binary import HLCBinary, _SymView
from crashlink.dehlc.lift import FunctionLifter, LiftedOp
from crashlink.gui import main_window as gui
from crashlink.gui.widgets.sync_view import SyncView


class NativeImage(HLCBinary):
    def __init__(self):
        self.PTR = 8
        self.arch = "x86_64"
        table = _SymView("hl_functions_ptrs", 0x100, 8, "PROGBITS")
        self.symbols_by_name = {table.name: table}
        self.symbols_by_addr = {table.value: [table]}

    def read_ptr(self, address: int) -> int:
        return 0x200 if address == 0x100 else 0


@pytest.fixture
def native_window(monkeypatch):
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(gui.MainWindow, "_restore_settings", lambda self: None)
    monkeypatch.setattr(gui.MainWindow, "_save_settings", lambda self: None)
    window = gui.MainWindow()
    code = Bytecode.create_empty()
    fn = Function()
    fn.findex = fIndex(0)
    code.functions = [fn]
    code.natives = []
    code.inspection_only = True
    code.hlc_binary = NativeImage()
    code.recovery_opcodes = {}
    code.recovery_lifts = {}
    window._code = code
    window._loaded_via_dehlc = True
    monkeypatch.setattr(binary, "_resolve_plt_targets", lambda image: {})
    monkeypatch.setattr(
        FunctionLifter,
        "for_binary",
        lambda *args: SimpleNamespace(
            lift=lambda addr: [LiftedOp("Int", {"value": 9}, addr), LiftedOp("Ret", {}, addr + 4)]
        ),
    )
    monkeypatch.setattr(
        asmview,
        "function_asm_block",
        lambda *args, **kwargs: ("f@0 native assembly", ["0x200 mov eax, 9", "0x204 ret"]),
    )
    yield window, code, fn
    window._dirty = False
    window.close()
    app.processEvents()


def test_native_tab_ignores_cached_pseudocode_and_never_attaches_bytecode(native_window):
    window, code, fn = native_window
    original_regs = list(fn.regs)
    window._db_cache[0] = ("STALE_FAITHFUL_PSEUDOCODE", {0: 1})
    window._open_class_tab("recovered", "Recovered", [0], 0)
    view = window._tabs.widget(window._open_tabs["recovered"])
    assert isinstance(view, SyncView)
    text = view.class_view.toPlainText()
    assert "Inspection-only" in text
    assert "dst=?" in text
    assert "ret=?" in text
    assert "0x200" in text
    assert "STALE_FAITHFUL_PSEUDOCODE" not in text
    assert "mov eax, 9" in view.disasm_view.toPlainText()
    assert view.disasm_view.op_at_cursor() is None
    assert fn.ops == []
    assert fn.regs == original_regs
    assert code.recovery_lifts[0][0].src_addr == 0x200
    assert window._active_decompiles == 0

    window._set_disasm_source("ops")
    assert "dst=?" in view.disasm_view.toPlainText()
    assert view.disasm_view.op_at_cursor() is None
    window._set_disasm_source("asm")
    assert "mov eax, 9" in view.disasm_view.toPlainText()


def test_native_decompile_and_cfg_do_not_claim_faithful_analysis(native_window, monkeypatch):
    window, _, _ = native_window

    def reject_job(*args, **kwargs):
        pytest.fail("Native recovery must not enter the bytecode decompiler")

    monkeypatch.setattr(gui, "_DecompRunnable", reject_job)
    window._start_decompile("recovered", 0)
    assert window._active_decompiles == 0
    window.show()
    window._cfg_dock.show()
    QApplication.processEvents()
    window._update_cfg_view(0)
    assert "Native" in window._cfg_view._message.text()
    assert window._cfg_view._message.isVisible()
