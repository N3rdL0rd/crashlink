"""Hover text: what a symbol is and what an expression produces, from recorded spans."""

import os
import shutil

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from crashlink import pseudo
from crashlink.core import Bytecode, Function
from crashlink.decomp import IRFunction
from crashlink.gui.widgets.hover import hover_html
from crashlink.gui.widgets.ref_info import RefInfo
from crashlink.pseudo.doc import RenderedSource
from crashlink.pseudo.symbols import SymbolKind

SOURCE = """class HoverFixture {
    var scale:Float;
    public function new() { scale = 1.5; }
    function area(w:Int, h:Int):Float { return (w + h) * scale; }
    static function main() { var f = new HoverFixture(); Sys.println(f.area(2, 3)); }
}"""


@pytest.fixture(scope="module")
def code(tmp_path_factory):
    if shutil.which("haxe") is None:
        pytest.skip("haxe not installed")
    from crashtest.behavior import compile_haxe

    artifact, error = compile_haxe(SOURCE, "HoverFixture", tmp_path_factory.mktemp("hover"))
    assert error is None, error
    return Bytecode.from_path(str(artifact))


def _function(code: Bytecode, full_name: str) -> Function:
    return next(f for f in code.functions if code.full_func_name(f) == full_name)


def _find(rendered: RenderedSource, needle: str) -> tuple[int, int]:
    """(line, column) of the first occurrence of `needle` in the rendered text."""
    for number, line in enumerate(rendered.text.split("\n")):
        col = line.find(needle)
        if col >= 0:
            return number, col
    raise AssertionError(needle)


def test_type_spans_never_change_the_text(code):
    for f in code.functions:
        if "HoverFixture" not in (code.full_func_name(f) or ""):
            continue
        plain = pseudo.pseudo(IRFunction(code, f))
        assert pseudo.pseudo_spans(IRFunction(code, f), types=True).text == plain


def test_a_parenthesis_shows_what_the_group_produces(code):
    area = _function(code, "HoverFixture.area")
    rendered = pseudo.pseudo_spans(IRFunction(code, area), types=True)
    line, col = _find(rendered, "(w + h)")

    for at in (col, col + len("(w + h)") - 1):  # the opening and the closing parenthesis
        html = hover_html(RefInfo(code), rendered, line, at)
        assert html is not None
        assert "Group" in html and "(w + h)" in html and "Float" in html


def test_an_operator_shows_the_expression_it_belongs_to(code):
    area = _function(code, "HoverFixture.area")
    rendered = pseudo.pseudo_spans(IRFunction(code, area), types=True)
    line, col = _find(rendered, "(w + h) * this.scale")
    star = col + len("(w + h) ")

    html = hover_html(RefInfo(code), rendered, line, star)

    assert html is not None and "Expression" in html and "(w + h) * this.scale" in html


def test_a_local_shows_its_type(code):
    area = _function(code, "HoverFixture.area")
    rendered = pseudo.pseudo_spans(IRFunction(code, area), types=True)
    local = next(
        s for s in rendered.spans if s.ref.kind == SymbolKind.LOCAL and not s.is_def and s.ref.name == "w"
    )

    html = hover_html(RefInfo(code), rendered, local.line, local.start)

    assert html is not None
    assert "local" in html and "Type:" in html and "Int" in html


def test_a_field_shows_its_owner_and_declared_type(code):
    area = _function(code, "HoverFixture.area")
    rendered = pseudo.pseudo_spans(IRFunction(code, area), types=True)
    field = next(s for s in rendered.spans if s.ref.kind == SymbolKind.FIELD)

    html = hover_html(RefInfo(code), rendered, field.line, field.start)

    assert html is not None
    assert "HoverFixture.scale" in html and "Float" in html


def test_a_call_shows_the_signature_not_the_expression_type(code):
    main = _function(code, "$HoverFixture.main")
    area = _function(code, "HoverFixture.area")
    rendered = pseudo.pseudo_spans(IRFunction(code, main), types=True)
    call = next(
        s for s in rendered.spans if s.ref.kind == SymbolKind.FUNCTION and s.ref.index == area.findex.value
    )

    html = hover_html(RefInfo(code), rendered, call.line, call.start)

    assert html is not None
    assert f"f@{area.findex.value}" in html


def test_punctuation_outside_any_expression_has_no_tooltip(code):
    area = _function(code, "HoverFixture.area")
    rendered = pseudo.pseudo_spans(IRFunction(code, area), types=True)

    assert hover_html(RefInfo(code), rendered, 0, 0) is None
