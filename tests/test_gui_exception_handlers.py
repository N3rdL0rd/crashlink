"""Regression tests for the narrowed exception handlers in crashlink/gui:
a corrupt-bytecode table index (IndexError/KeyError) degrades one display cell,
while anything unexpected now propagates instead of being silently swallowed.

Runnable with offscreen Qt; the bytecode fixture is compiled from the committed
.hx source, so the tests skip when haxe is not installed."""

import os
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication

from crashlink.core import Bytecode
from crashlink.decomp.function import IRFunction
from crashtest.behavior import compile_haxe


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


@pytest.fixture(scope="module")
def code(tmp_path_factory):
    if not shutil.which("haxe"):
        pytest.skip("haxe is not installed")
    source = Path("tests/haxe/Arithmetic.hx").read_text(encoding="utf-8")
    target, error = compile_haxe(source, "Arithmetic", tmp_path_factory.mktemp("hl"))
    if error:
        pytest.skip(error)
    return Bytecode.from_path(str(target))


def _raising(exc):
    def inner(*args, **kwargs):
        raise exc

    return inner


# ── function_list._func_name ──────────────────────────────────────────────────


def test_func_name_falls_back_on_corrupt_name_index(code, monkeypatch):
    from crashlink.gui.widgets.function_list import _func_name

    func = code.functions[0]
    monkeypatch.setattr(Bytecode, "full_func_name", _raising(IndexError("bad strRef")))
    assert _func_name(code, func) == f"f@{func.findex.value}"


def test_func_name_propagates_unexpected_errors(code, monkeypatch):
    from crashlink.gui.widgets.function_list import _func_name

    monkeypatch.setattr(Bytecode, "full_func_name", _raising(RuntimeError("bug")))
    with pytest.raises(RuntimeError):
        _func_name(code, code.functions[0])


# ── types_view summary column ─────────────────────────────────────────────────


def test_types_view_blank_summary_on_corrupt_index(qapp, code, monkeypatch):
    from crashlink.gui.widgets import types_view

    monkeypatch.setattr(types_view, "type_summary", _raising(IndexError("bad strRef")))
    view = types_view.TypesView()
    view.load(code)
    summary = view._table.item(0, 2)
    kind = view._table.item(0, 1)
    assert summary is not None and kind is not None
    assert summary.text() == ""
    # The index/kind columns are still populated; only the summary degraded.
    assert kind.text()


def test_types_view_propagates_unexpected_errors(qapp, code, monkeypatch):
    from crashlink.gui.widgets import types_view

    monkeypatch.setattr(types_view, "type_summary", _raising(RuntimeError("bug")))
    with pytest.raises(RuntimeError):
        types_view.TypesView().load(code)


# ── globals_window ────────────────────────────────────────────────────────────


def test_global_rows_question_mark_on_corrupt_type_index(code, monkeypatch):
    import crashlink.disasm as disasm
    from crashlink.gui.features.globals_window import _global_rows

    if not code.global_types:
        pytest.skip("fixture has no globals")
    monkeypatch.setattr(disasm, "type_name", _raising(IndexError("bad strRef")))
    rows = _global_rows(code)
    assert all(row[1] == "?" for row in rows)


def test_initial_value_falls_back_when_not_a_constant_string(code, monkeypatch):
    from crashlink.gui.features.globals_window import _initial_value

    if not code.global_types:
        pytest.skip("fixture has no globals")
    monkeypatch.setattr(Bytecode, "const_str", _raising(ValueError("no constant value")))
    monkeypatch.setattr(code, "initialized_globals", {})
    assert _initial_value(code, 0) == ""


# ── locals_panel type column ──────────────────────────────────────────────────


def _fake_ir():
    local = SimpleNamespace(reg_idx=0, defining_op_idx=0, name="x", get_type=lambda: object())
    return SimpleNamespace(func=SimpleNamespace(findex=SimpleNamespace(value=0)), all_locals=[local])


def test_locals_panel_question_mark_on_corrupt_type(qapp, monkeypatch):
    import crashlink.disasm as disasm
    from crashlink.gui.widgets.locals_panel import LocalsPanel

    monkeypatch.setattr(disasm, "type_name", _raising(IndexError("bad strRef")))
    panel = LocalsPanel()
    panel.load(cast(IRFunction, _fake_ir()), cast(Bytecode, SimpleNamespace()))
    cell = panel._table.item(0, 2)
    assert cell is not None
    assert cell.text() == "?"


def test_locals_panel_propagates_unexpected_errors(qapp, monkeypatch):
    import crashlink.disasm as disasm
    from crashlink.gui.widgets.locals_panel import LocalsPanel

    monkeypatch.setattr(disasm, "type_name", _raising(RuntimeError("bug")))
    with pytest.raises(RuntimeError):
        LocalsPanel().load(cast(IRFunction, _fake_ir()), cast(Bytecode, SimpleNamespace()))


# ── cfg_view DOT labels ───────────────────────────────────────────────────────


def _fake_cfg_ir():
    op = SimpleNamespace(op="Int")
    node = SimpleNamespace(base_offset=0, ops=[op], branches=[])
    cfg = SimpleNamespace(nodes=[node], entry=node)
    return SimpleNamespace(cfg=cfg, code=SimpleNamespace(), func=SimpleNamespace(regs=[]))


def test_cfg_dot_degrades_single_op_label(qapp, monkeypatch):
    import crashlink.disasm as disasm
    from crashlink.gui.widgets.cfg_view import _build_dot
    from crashlink.gui.themes import DEFAULT_THEME

    monkeypatch.setattr(disasm, "pseudo_from_op", _raising(KeyError("dst")))
    dot, _ = _build_dot(_fake_cfg_ir(), DEFAULT_THEME)
    assert "Int" in dot  # the opcode name stands in for the unreadable operand text


def test_cfg_dot_propagates_unexpected_errors(qapp, monkeypatch):
    import crashlink.disasm as disasm
    from crashlink.gui.widgets.cfg_view import _build_dot
    from crashlink.gui.themes import DEFAULT_THEME

    monkeypatch.setattr(disasm, "pseudo_from_op", _raising(RuntimeError("bug")))
    with pytest.raises(RuntimeError):
        _build_dot(_fake_cfg_ir(), DEFAULT_THEME)


# ── hlasm_edit dialog title ───────────────────────────────────────────────────


@pytest.fixture
def window(qapp, monkeypatch):
    from crashlink.gui import main_window as gui

    monkeypatch.setattr(gui.MainWindow, "_restore_settings", lambda self: None)
    monkeypatch.setattr(gui.MainWindow, "_save_settings", lambda self: None)
    win = gui.MainWindow()
    yield win
    win._dirty = False
    win.close()
    qapp.processEvents()


def test_hlasm_edit_title_falls_back_on_corrupt_name(window, code, monkeypatch):
    from crashlink.gui.features.hlasm_edit import HlasmEditDialog

    window._code = code
    func = code.functions[0]
    monkeypatch.setattr(Bytecode, "full_func_name", _raising(IndexError("bad strRef")))
    dialog = HlasmEditDialog(window, func)
    assert dialog.windowTitle() == f"Edit f@{func.findex.value} as .hlasm"
    dialog.close()


def test_hlasm_edit_propagates_unexpected_errors(window, code, monkeypatch):
    from crashlink.gui.features.hlasm_edit import HlasmEditDialog

    window._code = code
    monkeypatch.setattr(Bytecode, "full_func_name", _raising(RuntimeError("bug")))
    with pytest.raises(RuntimeError):
        HlasmEditDialog(window, code.functions[0])


# ── file_info optional size row ───────────────────────────────────────────────


def test_file_info_omits_size_when_stat_fails(code, monkeypatch):
    from crashlink.gui.features.file_info import _rows

    monkeypatch.setattr(os.path, "getsize", _raising(OSError("gone")))
    rows = _rows(code, "/nonexistent/program.hl")
    assert ("Path", "/nonexistent/program.hl") in rows
    assert all(name != "Size" for name, _ in rows)


# ── xref_panel resolvers ──────────────────────────────────────────────────────


def test_func_label_falls_back_for_unknown_findex(code):
    from crashlink.gui.widgets.xref_panel import _func_label

    assert _func_label(code, 999999) == "f@999999"


def test_func_label_falls_back_on_corrupt_header(code, monkeypatch):
    import crashlink.disasm as disasm
    from crashlink.gui.widgets.xref_panel import _func_label

    findex = code.functions[0].findex.value
    monkeypatch.setattr(disasm, "func_header", _raising(IndexError("bad strRef")))
    assert _func_label(code, findex) == f"f@{findex}"


def test_func_label_propagates_unexpected_errors(code, monkeypatch):
    import crashlink.disasm as disasm
    from crashlink.gui.widgets.xref_panel import _func_label

    monkeypatch.setattr(disasm, "func_header", _raising(RuntimeError("bug")))
    with pytest.raises(RuntimeError):
        _func_label(code, code.functions[0].findex.value)


def test_describe_symbol_fallbacks(code):
    from crashlink.core import Obj
    from crashlink.gui.widgets.xref_panel import describe_symbol
    from crashlink.pseudo.symbols import SymbolKind, SymbolRef

    # Out-of-range global index → IndexError → generic fallback.
    bad = len(code.global_types) + 100
    assert describe_symbol(code, SymbolRef.global_(bad)) == f"global {bad}"
    # Field ref whose type index doesn't point at a class → isinstance guard → fallback.
    non_obj = next(i for i, t in enumerate(code.types) if not isinstance(t.definition, Obj))
    assert describe_symbol(code, SymbolRef(SymbolKind.FIELD, index=non_obj, slot=0)) == f"field {non_obj}"
    # Out-of-range string index → fallback.
    bad_str = len(code.strings.value) + 100
    assert describe_symbol(code, SymbolRef(SymbolKind.STRING, index=bad_str)) == f"string {bad_str}"
    # A valid function still describes fully.
    findex = code.functions[0].findex.value
    assert describe_symbol(code, SymbolRef.function(findex)).startswith(f"function f@{findex}")


def test_describe_symbol_propagates_unexpected_errors(code, monkeypatch):
    import crashlink.disasm as disasm
    from crashlink.gui.widgets.xref_panel import describe_symbol
    from crashlink.pseudo.symbols import SymbolRef

    monkeypatch.setattr(disasm, "type_name", _raising(RuntimeError("bug")))
    with pytest.raises(RuntimeError):
        describe_symbol(code, SymbolRef.global_(0))


def test_resolve_targets_global_label_fallback(code, monkeypatch):
    import crashlink.disasm as disasm
    from crashlink.gui.widgets.xref_panel import resolve_targets

    monkeypatch.setattr(disasm, "type_name", _raising(IndexError("bad strRef")))
    groups = resolve_targets(code, "g@0")
    assert groups and groups[0].label == "global g@0 (?)"


# ── ref_info lookups ──────────────────────────────────────────────────────────


def _some_function_findex(code):
    from crashlink.core import Function

    return next(fi for fi, f in code.get_findex_map().items() if isinstance(f, Function))


def test_ref_info_function_name_falls_back_on_corrupt_index(code, monkeypatch):
    from crashlink.gui.widgets.ref_info import RefInfo

    monkeypatch.setattr(Bytecode, "full_func_name", _raising(IndexError("bad strRef")))
    assert RefInfo(code).function_name(_some_function_findex(code)) is None


def test_ref_info_function_name_propagates_unexpected_errors(code, monkeypatch):
    from crashlink.gui.widgets.ref_info import RefInfo

    monkeypatch.setattr(Bytecode, "full_func_name", _raising(RuntimeError("bug")))
    with pytest.raises(RuntimeError):
        RefInfo(code).function_name(_some_function_findex(code))


def test_ref_info_global_string_falls_back_when_not_constant(code, monkeypatch):
    from crashlink.gui.widgets.ref_info import RefInfo

    monkeypatch.setattr(Bytecode, "const_str", _raising(ValueError("no constant value")))
    refs = RefInfo(code)
    assert refs.global_string(0) is None
    assert refs.global_inline(0) is None


def test_ref_info_global_string_propagates_unexpected_errors(code, monkeypatch):
    from crashlink.gui.widgets.ref_info import RefInfo

    monkeypatch.setattr(Bytecode, "const_str", _raising(RuntimeError("bug")))
    with pytest.raises(RuntimeError):
        RefInfo(code).global_string(0)


def test_ref_info_function_tooltip_falls_back_on_corrupt_header(code, monkeypatch):
    import crashlink.disasm as disasm
    from crashlink.gui.widgets.ref_info import RefInfo

    findex = code.functions[0].findex.value
    monkeypatch.setattr(disasm, "func_header", _raising(IndexError("bad strRef")))
    tip = RefInfo(code).function_tooltip(findex)
    assert tip is not None and f"f@{findex}" in tip


def test_ref_info_type_tooltip_fallbacks(code, monkeypatch):
    import crashlink.disasm as disasm
    from crashlink.core import Obj
    from crashlink.gui.widgets.ref_info import RefInfo

    tindex = next(i for i, t in enumerate(code.types) if isinstance(t.definition, Obj))
    monkeypatch.setattr(disasm, "type_name", _raising(IndexError("bad strRef")))
    tip = RefInfo(code).type_tooltip(tindex)
    assert tip is not None and f"t@{tindex}" in tip
    # Cyclic/invalid hierarchy (resolve_fields' ValueError) just omits the field list.
    monkeypatch.setattr(disasm, "type_name", lambda *args: "Foo")
    monkeypatch.setattr(Obj, "resolve_fields", _raising(ValueError("cyclic")))
    tip2 = RefInfo(code).type_tooltip(tindex)
    assert tip2 is not None and "fields:" not in tip2


# ── xref popup site labels/snippets ───────────────────────────────────────────


def _site(code, opcode_index=None):
    from crashlink.gui.widgets.xref_panel import XrefSite

    return XrefSite(
        source_findex=_some_function_findex(code),
        source_label="original",
        opcode_index=opcode_index,
        body_line=None,
        ref_kind="call",
    )


def test_xref_popup_site_label_falls_back_on_corrupt_name(qapp, code, monkeypatch):
    from crashlink.gui.widgets.xref_panel import XrefPopup

    popup = XrefPopup()
    popup.set_code(code)
    monkeypatch.setattr(Bytecode, "full_func_name", _raising(IndexError("bad strRef")))
    assert popup._site_label(_site(code)) == "original"
    popup.deleteLater()


def test_xref_popup_site_snippet_falls_back_on_corrupt_op(qapp, code, monkeypatch):
    import crashlink.disasm as disasm
    from crashlink.gui.widgets.xref_panel import XrefPopup

    popup = XrefPopup()
    popup.set_code(code)
    monkeypatch.setattr(disasm, "fmt_op_compact", _raising(IndexError("bad index")))
    assert popup._site_snippet(_site(code, opcode_index=0)) is None
    popup.deleteLater()


def test_xref_popup_site_snippet_propagates_unexpected_errors(qapp, code, monkeypatch):
    import crashlink.disasm as disasm
    from crashlink.gui.widgets.xref_panel import XrefPopup

    popup = XrefPopup()
    popup.set_code(code)
    monkeypatch.setattr(disasm, "fmt_op_compact", _raising(RuntimeError("bug")))
    with pytest.raises(RuntimeError):
        popup._site_snippet(_site(code, opcode_index=0))
    popup.deleteLater()


# ── disasm_view rows ──────────────────────────────────────────────────────────


def test_disasm_view_header_and_row_fallbacks(qapp, code, monkeypatch):
    import crashlink.disasm as disasm
    from crashlink.gui.widgets.disasm_view import DisasmView

    findex = code.functions[0].findex.value
    monkeypatch.setattr(disasm, "func_header", _raising(IndexError("bad strRef")))
    monkeypatch.setattr(disasm, "fmt_op_compact", _raising(IndexError("bad index")))
    view = DisasmView()
    view.load(code, [(findex, code.functions[0])])
    text = view.toPlainText()
    assert f"f@{findex}:" in text
    assert "<fmt error:" in text
    view.deleteLater()


def test_disasm_view_propagates_unexpected_errors(qapp, code, monkeypatch):
    import crashlink.disasm as disasm
    from crashlink.gui.widgets.disasm_view import DisasmView

    findex = code.functions[0].findex.value
    monkeypatch.setattr(disasm, "fmt_op_compact", _raising(RuntimeError("bug")))
    with pytest.raises(RuntimeError):
        DisasmView().load(code, [(findex, code.functions[0])])
