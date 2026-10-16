"""Regression tests for the narrowed exception handlers in crashlink/pseudo:
a corrupt-bytecode table index (IndexError/MalformedBytecode/ValueError) degrades
to the documented fallback, while anything unexpected now propagates instead of
being silently swallowed.

Fixtures are compiled from the committed .hx sources, so the tests skip when
haxe is not installed."""

import shutil
from pathlib import Path

import pytest

from crashlink import disasm
from crashlink.core import Bytecode, Enum, Function, Obj, fIndex, strRef, tIndex
from crashtest.behavior import compile_haxe


def _compile(tmp_path_factory, name: str) -> Bytecode:
    if not shutil.which("haxe"):
        pytest.skip("haxe is not installed")
    source = Path(f"tests/haxe/{name}.hx").read_text(encoding="utf-8")
    target, error = compile_haxe(source, name, tmp_path_factory.mktemp("hl"))
    if error:
        pytest.skip(error)
    return Bytecode.from_path(str(target))


@pytest.fixture(scope="module")
def clazz(tmp_path_factory):
    return _compile(tmp_path_factory, "Clazz")


@pytest.fixture(scope="module")
def enums(tmp_path_factory):
    return _compile(tmp_path_factory, "Enums")


def _raising(exc):
    def inner(*args, **kwargs):
        raise exc

    return inner


def _obj_named(code: Bytecode, name: str) -> Obj:
    for t in code.types:
        if isinstance(t.definition, Obj) and t.definition.name.resolve(code) == name:
            return t.definition
    raise AssertionError(f"no Obj named {name}")


# ── typetext.type_text ────────────────────────────────────────────────────────


def test_type_text_kind_fallback_on_corrupt_name_index(clazz):
    from crashlink.pseudo import typetext

    typ = next(t for t in clazz.types if isinstance(t.definition, Obj))
    obj = typ.definition
    original = obj.name.value
    obj.name.value = 10**9
    try:
        assert typetext.type_text(clazz, typ) == "Obj"
    finally:
        obj.name.value = original


def test_type_text_propagates_unexpected_errors(clazz, monkeypatch):
    from crashlink.pseudo import typetext

    typ = next(t for t in clazz.types if isinstance(t.definition, Obj))
    monkeypatch.setattr(disasm, "type_to_haxe", _raising(RuntimeError("bug")))
    with pytest.raises(RuntimeError):
        typetext.type_text(clazz, typ)


# ── annotate.annotate_with_type ───────────────────────────────────────────────


def test_annotate_with_type_drops_tag_on_corrupt_type(clazz):
    from crashlink.pseudo.annotate import annotate_with_type

    assert annotate_with_type(_raising(IndexError("bad tIndex")), "x + 1", clazz) == "x + 1"


def test_annotate_with_type_propagates_unexpected_errors(clazz):
    from crashlink.pseudo.annotate import annotate_with_type

    with pytest.raises(RuntimeError):
        annotate_with_type(_raising(RuntimeError("bug")), "x + 1", clazz)


# ── annotate.member_ref ───────────────────────────────────────────────────────


def test_member_ref_skips_corrupt_proto_name(clazz):
    from crashlink.pseudo.annotate import member_ref

    obj = _obj_named(clazz, "Clazz")
    assert obj.protos
    original = obj.protos[0].name.value
    obj.protos[0].name.value = 10**9
    try:
        assert member_ref(clazz, obj, "missing") is None
    finally:
        obj.protos[0].name.value = original


def test_member_ref_propagates_unexpected_errors(clazz, monkeypatch):
    from crashlink.pseudo.annotate import member_ref

    obj = _obj_named(clazz, "Clazz")
    monkeypatch.setattr(strRef, "resolve", _raising(RuntimeError("bug")))
    with pytest.raises(RuntimeError):
        member_ref(clazz, obj, "method")


# ── annotate.annotate_expression (enum construct names) ──────────────────────


def _enum_fixture(enums):
    from crashlink.decomp.ir import IREnumConstruct

    enum_ti = next(
        ti for ti, t in enumerate(enums.types) if isinstance(t.definition, Enum) and t.definition.constructs
    )
    enum = enums.types[enum_ti].definition
    construct_name = enum.constructs[0].name.resolve(enums)
    expr = IREnumConstruct(enums, construct_name, [], tIndex(enum_ti))
    return enum, construct_name, expr


def test_annotate_expression_skips_corrupt_construct_name(enums):
    from crashlink.pseudo.annotate import annotate_expression
    from crashlink.pseudo.doc import marked

    enum, construct_name, expr = _enum_fixture(enums)
    original = enum.constructs[0].name.value
    enum.constructs[0].name.value = 10**9
    try:
        with marked():
            assert annotate_expression(expr, f"{construct_name}()", enums, None) == f"{construct_name}()"
    finally:
        enum.constructs[0].name.value = original


def test_annotate_expression_propagates_unexpected_errors(enums, monkeypatch):
    from crashlink.pseudo.annotate import annotate_expression
    from crashlink.pseudo.doc import marked

    _, construct_name, expr = _enum_fixture(enums)
    monkeypatch.setattr(strRef, "resolve", _raising(RuntimeError("bug")))
    with marked():
        with pytest.raises(RuntimeError):
            annotate_expression(expr, f"{construct_name}()", enums, None)


# ── _is_std_function (resolve_file) ───────────────────────────────────────────


def test_is_std_function_resolve_failure_means_not_std(clazz):
    from crashlink.pseudo import _is_std_function

    # The fixture is compiled without -debug (resolve_file raises ValueError);
    # even with debug info the file is not under /std/. Either way: False.
    assert _is_std_function(clazz.functions[0], clazz) is False


def test_is_std_function_propagates_unexpected_errors(clazz, monkeypatch):
    from crashlink.pseudo import _is_std_function

    monkeypatch.setattr(Function, "resolve_file", _raising(RuntimeError("bug")))
    with pytest.raises(RuntimeError):
        _is_std_function(clazz.functions[0], clazz)


# ── _ancestors (superclass type index) ────────────────────────────────────────


def test_ancestors_stops_on_corrupt_super_index(clazz):
    from crashlink.pseudo import _ancestors

    obj = _obj_named(clazz, "Clazz")
    assert len(list(_ancestors(clazz, obj))) == 1  # Parent
    original = obj.super.value
    obj.super.value = 10**9
    try:
        assert list(_ancestors(clazz, obj)) == []
    finally:
        obj.super.value = original


def test_ancestors_propagates_unexpected_errors(clazz, monkeypatch):
    from crashlink.pseudo import _ancestors

    obj = _obj_named(clazz, "Clazz")
    monkeypatch.setattr(tIndex, "resolve", _raising(RuntimeError("bug")))
    with pytest.raises(RuntimeError):
        list(_ancestors(clazz, obj))


# ── _find_constructor / _obj_functions (member findex) ───────────────────────


def test_find_constructor_skips_unmapped_findex(clazz):
    from crashlink.pseudo import _find_constructor

    obj = _obj_named(clazz, "Clazz")
    before = _find_constructor(clazz, obj)
    assert before is not None
    original = obj.protos[0].findex.value
    obj.protos[0].findex.value = 10**9
    try:
        # The corrupt entry is skipped; the constructor is still found.
        assert _find_constructor(clazz, obj) is before
    finally:
        obj.protos[0].findex.value = original


def test_find_constructor_propagates_unexpected_errors(clazz, monkeypatch):
    from crashlink.pseudo import _find_constructor

    obj = _obj_named(clazz, "Clazz")
    monkeypatch.setattr(fIndex, "resolve", _raising(RuntimeError("bug")))
    with pytest.raises(RuntimeError):
        _find_constructor(clazz, obj)


def test_obj_functions_skips_unmapped_findex(clazz):
    from crashlink.pseudo import _obj_functions

    obj = _obj_named(clazz, "Clazz")
    before = _obj_functions(clazz, obj)
    assert before
    original = obj.protos[0].findex.value
    obj.protos[0].findex.value = 10**9
    try:
        assert len(_obj_functions(clazz, obj)) == len(before) - 1
    finally:
        obj.protos[0].findex.value = original


# ── _is_std_class_obj (member findex) ─────────────────────────────────────────


def test_is_std_class_obj_skips_unmapped_member_findex(clazz):
    from crashlink.pseudo import _is_std_class_obj

    obj = _obj_named(clazz, "Clazz")
    original = obj.protos[0].findex.value
    obj.protos[0].findex.value = 10**9
    try:
        # The corrupt member is skipped; the class is user code either way.
        assert _is_std_class_obj(clazz, obj) is False
    finally:
        obj.protos[0].findex.value = original


# ── _obj_fields (field name index) ────────────────────────────────────────────


def test_obj_fields_skips_corrupt_field_name(clazz):
    from crashlink.pseudo import _obj_fields

    obj = _obj_named(clazz, "Clazz")
    assert "b" in [name for name, _ in _obj_fields(clazz, obj)]
    original = obj.fields[0].name.value
    obj.fields[0].name.value = 10**9
    try:
        assert "b" not in [name for name, _ in _obj_fields(clazz, obj)]
    finally:
        obj.fields[0].name.value = original


def test_obj_fields_propagates_unexpected_errors(clazz, monkeypatch):
    from crashlink.pseudo import _obj_fields

    obj = _obj_named(clazz, "Clazz")
    monkeypatch.setattr(strRef, "resolve", _raising(RuntimeError("bug")))
    with pytest.raises(RuntimeError):
        _obj_fields(clazz, obj)


# ── _base_class_for_virtual_method (superclass chain) ─────────────────────────


def test_base_class_for_virtual_method_tolerates_corrupt_super_index(clazz):
    from crashlink.pseudo import _base_class_for_virtual_method

    obj = _obj_named(clazz, "Parent")
    assert obj.super.value < 0
    fn = next(
        entry.findex.resolve(clazz)
        for entry in _obj_named(clazz, "Clazz").protos
        if entry.name.resolve(clazz) == "method"
    )
    assert isinstance(fn, Function)
    original = obj.super.value
    obj.super.value = 10**9
    try:
        assert _base_class_for_virtual_method(fn, clazz) is None
    finally:
        obj.super.value = original
