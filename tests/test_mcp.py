import re

import pytest

import crashlink.mcp as mcp


def _extract_index(pattern: str, text: str) -> int:
    match = re.search(pattern, text, re.M)
    assert match is not None, f"pattern {pattern!r} not found in: {text!r}"
    return int(match.group(1))


@pytest.fixture()
def clazz_loaded():
    mcp.load_bytecode("tests/haxe/Clazz.hl")
    yield
    mcp._code = None


def test_find_type_by_name_substring(clazz_loaded):
    result = mcp.find_type_by_name("clazz")
    assert "Obj Clazz" in result
    assert "Obj $Clazz" in result


def test_find_type_by_name_exact(clazz_loaded):
    result = mcp.find_type_by_name("Clazz", exact=True)
    lines = [line for line in result.splitlines() if ": Obj" in line]
    assert len(lines) == 1
    assert lines[0].endswith("Obj Clazz")


def test_find_type_by_name_no_match(clazz_loaded):
    assert mcp.find_type_by_name("NoSuchTypeXYZ") == "No types matching 'NoSuchTypeXYZ'."


def test_get_type_xrefs_reports_allocation_site(clazz_loaded):
    tindex = _extract_index(r"t@(\d+): Obj Clazz$", mcp.find_type_by_name("Clazz", exact=True))
    result = mcp.get_type_xrefs(tindex)
    assert "[alloc]" in result
    assert "Clazz.main" in result


def test_get_type_xrefs_unknown_type(clazz_loaded):
    with pytest.raises(RuntimeError, match="not found"):
        mcp.get_type_xrefs(999999)


def test_get_field_xrefs_reads_and_writes(clazz_loaded):
    tindex = _extract_index(r"t@(\d+): Obj Clazz$", mcp.find_type_by_name("Clazz", exact=True))
    result = mcp.get_field_xrefs(tindex, 0)
    assert "1 read(s), 3 write(s)" in result
    assert "[reads]" in result
    assert "[writes]" in result


def test_get_field_xrefs_rejects_non_obj_type(clazz_loaded):
    with pytest.raises(RuntimeError, match="not a class"):
        mcp.get_field_xrefs(0, 0)


def test_get_string_xrefs_finds_use_site(clazz_loaded):
    idx = _extract_index(r"s@(\d+): Clazz$", mcp.search_strings("Clazz"))
    result = mcp.get_string_xrefs(idx)
    assert "[use]" in result
    assert "1 total" in result


def test_get_string_xrefs_unknown_index(clazz_loaded):
    with pytest.raises(RuntimeError, match="not found"):
        mcp.get_string_xrefs(999999)
