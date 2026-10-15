"""Symbol spans: what each token of the rendered pseudocode names."""

import inspect
import shutil

import pytest

from crashlink import pseudo
from crashlink.core import Bytecode, Function
from crashlink.decomp import IRFunction
from crashlink.pseudo import doc
from crashlink.pseudo.symbols import SymbolKind, SymbolRef

# ── Doc model ─────────────────────────────────────────────────────────────────


def test_marks_are_inert_outside_marked_mode():
    assert doc.mark("name", SymbolRef.local(1, "name")) == "name"
    assert not doc.marking()


def test_marked_text_renders_to_plain_text_with_spans():
    a, b = SymbolRef.local(7, "a"), SymbolRef.field(3, 1)
    with doc.marked() as table:
        text = f"var {doc.mark('a', a, True)} = {doc.mark('obj', a)}.{doc.mark('f', b)};\nreturn {doc.mark('a', a)};"
    rendered = doc.render_marked(text, table)

    assert rendered.text == "var a = obj.f;\nreturn a;"
    assert doc.strip(text) == rendered.text
    assert rendered.symbol_at(0, 4) == a
    assert rendered.symbol_at(0, 12) == b
    assert rendered.symbol_at(0, 0) is None  # `var` names nothing
    assert rendered.symbol_at(1, 7) == a
    definition = rendered.definition_of(a)
    assert definition is not None and (definition.line, definition.start) == (0, 4)


def test_equal_symbols_render_equal_strings():
    ref = SymbolRef.function(5)
    with doc.marked():
        assert doc.mark("f", ref) == doc.mark("f", ref)
        assert doc.mark("f", ref) != doc.mark("f", ref, True)


def test_nested_symbols_resolve_to_the_innermost():
    outer, inner = SymbolRef.function(1), SymbolRef.local(1, "x")
    with doc.marked() as table:
        text = doc.mark(f"call({doc.mark('x', inner)})", outer)
    rendered = doc.render_marked(text, table)
    assert rendered.text == "call(x)"
    assert rendered.symbol_at(0, 0) == outer
    assert rendered.symbol_at(0, 5) == inner


def test_utf16_columns_count_astral_characters_twice():
    assert doc.utf16_col("a\U0001f600b", 2) == 3


# ── API surface the rest of crashlink imports from `crashlink.pseudo` ─────────

_PUBLIC = [
    "pseudo",
    "pseudo_oplines",
    "class_pseudo",
    "decompile_file",
    "stub_file",
    "class_field_lines",
    "rebuilt_inline_declarations",
    "global_name",
    "_method_registry",
    "_stub_class",
    "_enum_pseudo",
    "_class_body",
    "_call_args",
    "_hoist_closure_contexts",
    "_expression_to_haxe",
    "_generate_statements",
    "_is_definitely_assigned_before_use",
    "_collect_locals",
    "_is_std_class_obj",
]


@pytest.mark.parametrize("name", _PUBLIC)
def test_existing_names_stay_importable(name):
    assert callable(getattr(pseudo, name))


def test_str_returning_signatures_are_unchanged():
    hints = {name: inspect.signature(getattr(pseudo, name)).return_annotation for name in _PUBLIC}
    assert hints["pseudo"] in (str, "str")
    assert hints["_expression_to_haxe"] in (str, "str")
    assert "Tuple" in str(hints["pseudo_oplines"])


# ── Spans from a real decompile ───────────────────────────────────────────────

SOURCE = """class SpanFixture {
    var count:Int;
    public function new() { this.count = 3; }
    function bump(by:Int):Int { count += by; return count; }
    static function main() {
        var box = new SpanFixture();
        var n = box.bump(2);
        Sys.println(n + box.count);
    }
}"""


@pytest.fixture(scope="module")
def fixture_code(tmp_path_factory):
    if shutil.which("haxe") is None:
        pytest.skip("haxe not installed")
    from crashtest.behavior import compile_haxe

    artifact, error = compile_haxe(SOURCE, "SpanFixture", tmp_path_factory.mktemp("spans"))
    assert error is None, error
    return Bytecode.from_path(str(artifact))


def _function(code: Bytecode, full_name: str) -> Function:
    for f in code.functions:
        if code.full_func_name(f) == full_name:
            return f
    raise AssertionError(full_name)


def test_spans_never_change_the_text(fixture_code):
    for f in fixture_code.functions:
        name = fixture_code.full_func_name(f) or ""
        if "SpanFixture" not in name:
            continue
        assert pseudo.pseudo_spans(IRFunction(fixture_code, f)).text == pseudo.pseudo(
            IRFunction(fixture_code, f)
        )


def _spans_of(rendered, kind):
    lines = rendered.text.split("\n")
    return [(lines[s.line][s.start : s.end], s) for s in rendered.spans if s.ref.kind == kind]


def test_a_call_names_the_method_not_a_word(fixture_code):
    code = fixture_code
    main = _function(code, "$SpanFixture.main")
    bump = _function(code, "SpanFixture.bump")
    rendered = pseudo.pseudo_spans(IRFunction(code, main))

    calls = [s for token, s in _spans_of(rendered, SymbolKind.FUNCTION) if token == "bump"]
    assert [s.ref for s in calls] == [SymbolRef.function(bump.findex.value)]


def test_a_field_names_its_declaring_slot(fixture_code):
    code = fixture_code
    main = _function(code, "$SpanFixture.main")
    rendered = pseudo.pseudo_spans(IRFunction(code, main))

    fields = [s for token, s in _spans_of(rendered, SymbolKind.FIELD) if token == "count"]
    assert len(fields) == 1
    owner = code.types[fields[0].ref.index].definition
    assert owner.fields[fields[0].ref.slot].name.resolve(code) == "count"


def test_a_local_use_resolves_to_its_declaration(fixture_code):
    code = fixture_code
    main = _function(code, "$SpanFixture.main")
    rendered = pseudo.pseudo_spans(IRFunction(code, main))

    box = [s for token, s in _spans_of(rendered, SymbolKind.LOCAL) if token == "box"]
    definitions = [s for s in box if s.is_def]
    uses = [s for s in box if not s.is_def]
    assert len(definitions) == 1 and uses
    assert all(u.ref == definitions[0].ref for u in uses)
    assert rendered.definition_of(definitions[0].ref) == definitions[0]


def test_a_constructor_call_names_the_type(fixture_code):
    code = fixture_code
    main = _function(code, "$SpanFixture.main")
    rendered = pseudo.pseudo_spans(IRFunction(code, main))

    types = [s for token, s in _spans_of(rendered, SymbolKind.TYPE) if token == "SpanFixture"]
    assert types
    assert code.types[types[0].ref.index].definition.name.resolve(code) == "SpanFixture"


def test_a_method_header_is_its_own_definition(fixture_code):
    code = fixture_code
    bump = _function(code, "SpanFixture.bump")
    rendered = pseudo.pseudo_spans(IRFunction(code, bump))

    definition = rendered.definition_of(SymbolRef.function(bump.findex.value))
    assert definition is not None
    line = rendered.text.split("\n")[definition.line]
    assert line[definition.start : definition.end] == "bump"
