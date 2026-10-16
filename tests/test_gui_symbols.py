"""The code panes know which symbol they are on: double-click, X and highlights act on it."""

import os
import shutil

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QTextCursor
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from crashlink import pseudo
from crashlink.core import Bytecode, Function
from crashlink.decomp import IRFunction
from crashlink.gui import main_window as gui
from crashlink.gui.widgets.class_view import ClassView
from crashlink.gui.widgets.ref_info import RefInfo
from crashlink.pseudo.doc import RenderedSource
from crashlink.pseudo.symbols import SymbolKind, SymbolRef, SymbolSpan

SOURCE = """class Shadow {
    var n:Int;
    public function new() { n = 1; }
    function f(n:Int):Int { return n + this.n; }
    static function main() { var s = new Shadow(); Sys.println(s.f(2)); }
}"""


@pytest.fixture(scope="module")
def code(tmp_path_factory):
    if shutil.which("haxe") is None:
        pytest.skip("haxe not installed")
    from crashtest.behavior import compile_haxe

    artifact, error = compile_haxe(SOURCE, "Shadow", tmp_path_factory.mktemp("shadow"))
    assert error is None, error
    return Bytecode.from_path(str(artifact))


def _function(code: Bytecode, full_name: str) -> Function:
    return next(f for f in code.functions if code.full_func_name(f) == full_name)


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


def _view_of(code: Bytecode, f: Function, types: bool = False) -> tuple[ClassView, RenderedSource]:
    rendered = pseudo.pseudo_spans(IRFunction(code, f), types=types)
    view = ClassView()
    view.resize(900, 500)
    view.load_methods("Shadow", [(f.findex.value, rendered.text)], spans={f.findex.value: rendered})
    view.show()
    QApplication.processEvents()
    return view, rendered


def _place(view: ClassView, rendered, span) -> QPoint:
    """Put the caret inside `span` and return the middle of that token on screen."""
    start = view._line_ranges[0][0]
    block = view.document().findBlockByNumber(start + span.line - rendered.body_start)
    left = QTextCursor(view.document())
    left.setPosition(block.position() + span.start)
    right = QTextCursor(view.document())
    right.setPosition(block.position() + span.end)
    inside = QTextCursor(view.document())
    inside.setPosition(block.position() + span.start + max(1, (span.end - span.start) // 2))
    view.setTextCursor(inside)
    a, b = view.cursorRect(left).center(), view.cursorRect(right).center()
    return QPoint((a.x() + b.x()) // 2, a.y())


def test_a_local_and_a_field_of_the_same_name_are_different_symbols(app, code):
    f = _function(code, "Shadow.f")
    view, rendered = _view_of(code, f)

    by_kind = {}
    for token, span in (
        (rendered.text.split("\n")[s.line][s.start : s.end], s) for s in rendered.spans if not s.is_def
    ):
        if token == "n":
            by_kind[span.ref.kind] = span
    assert set(by_kind) == {SymbolKind.LOCAL, SymbolKind.FIELD}

    _place(view, rendered, by_kind[SymbolKind.LOCAL])
    at = view.symbol_at_cursor()
    assert at is not None and at.ref.kind == SymbolKind.LOCAL
    _place(view, rendered, by_kind[SymbolKind.FIELD])
    at = view.symbol_at_cursor()
    assert at is not None and at.ref.kind == SymbolKind.FIELD
    view.close()


def test_focus_signal_reports_the_symbol_under_the_caret(app, code):
    f = _function(code, "Shadow.f")
    view, rendered = _view_of(code, f)
    seen = []
    view.symbol_focused.connect(seen.append)

    local = next(s for s in rendered.spans if s.ref.kind == SymbolKind.LOCAL and not s.is_def)
    _place(view, rendered, local)

    assert seen and seen[-1].ref == local.ref
    view.close()


def test_double_click_follows_the_symbol_it_lands_on(app, code):
    main = _function(code, "$Shadow.main")
    f = _function(code, "Shadow.f")
    view, rendered = _view_of(code, main)
    followed = []
    view.follow_requested.connect(lambda findex, span: followed.append((findex, span)))

    call = next(s for s in rendered.spans if s.ref == SymbolRef.function(f.findex.value) and not s.is_def)
    pos = _place(view, rendered, call)
    QTest.mouseDClick(view.viewport(), Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, pos)

    assert followed
    findex, span = followed[-1]
    assert findex == main.findex.value
    assert span.ref == SymbolRef.function(f.findex.value)
    view.close()


def test_double_click_on_punctuation_follows_nothing(app, code):
    f = _function(code, "Shadow.f")
    view, rendered = _view_of(code, f)
    followed = []
    view.follow_requested.connect(lambda findex, span: followed.append(span))

    start = view._line_ranges[0][0]
    cursor = QTextCursor(view.document().findBlockByNumber(start))
    cursor.setPosition(view.document().findBlockByNumber(start).position() + 1)
    view.setTextCursor(cursor)
    view._emit_follow()

    assert followed == [None]
    view.close()


def test_the_local_definition_is_reachable_from_a_use(app, code):
    f = _function(code, "Shadow.f")
    view, rendered = _view_of(code, f)
    ref = SymbolRef.local(f.findex.value, "n")
    definition = rendered.definition_of(ref)
    assert definition is not None

    assert view.goto_definition(ref)
    at = view.symbol_at_cursor()
    assert at is not None and at.is_def and at.ref == ref
    view.close()


def test_highlights_cover_the_entity_not_the_spelling(app, code):
    f = _function(code, "Shadow.f")
    view, rendered = _view_of(code, f)
    local = next(s for s in rendered.spans if s.ref.kind == SymbolKind.LOCAL and not s.is_def)
    field = next(s for s in rendered.spans if s.ref.kind == SymbolKind.FIELD)

    first, last = 0, view.document().blockCount()
    local_ranges = view.symbol_ranges(local.ref, first, last)
    field_ranges = view.symbol_ranges(field.ref, first, last)

    assert local_ranges and field_ranges
    assert not set(local_ranges) & set(field_ranges)
    view.close()


def test_stale_symbols_are_dropped_with_the_text_they_describe(app, code):
    f = _function(code, "Shadow.f")
    view, rendered = _view_of(code, f)

    view.replace_method(f.findex.value, "class ? {\n    // f@1 error: boom\n}")

    assert view.rendered_for(f.findex.value) is None
    assert view.symbol_span_at(1, 5) is None
    view.close()


# ── Dispatch in the main window ───────────────────────────────────────────────


@pytest.fixture
def window(app, monkeypatch, code):
    monkeypatch.setattr(gui.MainWindow, "_restore_settings", lambda self: None)
    monkeypatch.setattr(gui.MainWindow, "_save_settings", lambda self: None)
    monkeypatch.setattr(gui.MainWindow, "_add_recent_file", lambda self, path: None)
    window = gui.MainWindow()
    window._code = code
    yield window
    window._dirty = False
    window.close()
    app.processEvents()


def test_following_a_call_goes_to_that_function(window, monkeypatch):
    jumps = []
    monkeypatch.setattr(window, "navigate_to", lambda findex, op_idx=None: jumps.append(findex))

    window._on_follow_requested(1, SymbolSpan(0, 0, 1, SymbolRef.function(7)))

    assert jumps == [7]


def test_following_a_definition_lists_its_uses_instead(window, monkeypatch):
    jumps, listed = [], []
    monkeypatch.setattr(window, "navigate_to", lambda findex, op_idx=None: jumps.append(findex))
    monkeypatch.setattr(window, "_show_symbol_xrefs", lambda findex, ref: listed.append(ref))

    window._on_follow_requested(7, SymbolSpan(0, 0, 1, SymbolRef.function(7), is_def=True))

    assert jumps == [] and listed == [SymbolRef.function(7)]


def test_following_a_type_opens_it_in_the_types_table(window, monkeypatch):
    opened = []
    monkeypatch.setattr(window, "_open_types_tab", lambda select=None: opened.append(select))

    window._on_follow_requested(1, SymbolSpan(0, 0, 1, SymbolRef.type_(3)))
    window._on_follow_requested(1, SymbolSpan(0, 0, 1, SymbolRef.field(4, 0)))

    assert opened == [3, 4]


def test_following_nothing_says_so(window, monkeypatch):
    shown = []
    monkeypatch.setattr(window._status_bar, "showMessage", lambda text, timeout=0: shown.append(text))

    window._on_follow_requested(1, None)

    assert shown and "No symbol" in shown[-1]


def test_hovering_a_token_with_the_pointer_shows_its_tooltip(app, code):
    f = _function(code, "Shadow.f")
    view, rendered = _view_of(code, f, types=True)
    view.set_ref_info(RefInfo(code))
    local = next(s for s in rendered.spans if s.ref.kind == SymbolKind.LOCAL and not s.is_def)
    pos = _place(view, rendered, local)

    html = view.tooltip_at_point(view.cursorForPosition(pos), pos)

    assert html is not None and "local" in html and "Int" in html
    view.close()


def test_hovering_blank_space_shows_nothing(app, code):
    f = _function(code, "Shadow.f")
    view, rendered = _view_of(code, f, types=True)
    view.set_ref_info(RefInfo(code))
    line_end = view.cursorRect(view.cursorForPosition(QPoint(2000, 5))).center()
    pos = QPoint(line_end.x() + 300, line_end.y())

    assert view.tooltip_at_point(view.cursorForPosition(pos), pos) is None
    view.close()
