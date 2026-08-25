"""Tests for de-HL/C type-table recovery contracts that don't need a binary.

HGUID (kind 23) is the newest no-data kind: these lock the wiring that lets the
de-HL/C engine parse it wherever it appears (type table, signature encoding,
C re-emission), as exercised end-to-end against real game images.
"""

import pytest

capstone = pytest.importorskip("capstone")  # noqa: F841  (dehlc imports pull it in)

from crashlink.core import GUID, Type  # noqa: E402
from crashlink.dehlc.binary import SIMPLE_KINDS, HLCBinary  # noqa: E402
from crashlink.dehlc.types import HL_TYPE_STR  # noqa: E402


def test_hguid_is_a_simple_no_data_kind():
    # The de-HL/C parser must treat GUID like VOID/I32/... : definition straight
    # from TYPEDEFS, never "Unsupported (for now...) type kind".
    assert Type.Kind.GUID.value == 23
    assert Type.TYPEDEFS[23] is GUID
    assert Type.Kind.GUID in SIMPLE_KINDS


def test_hguid_signature_char():
    # hashlink's TYPE_STR ("vcsilfdbBDPOATR??X?N?S?g") maps HGUID to 'g'; the
    # de-HL/C signature encoder uses this for native-name matching.
    assert len(HL_TYPE_STR) == 24
    assert HL_TYPE_STR[Type.Kind.GUID.value] == "g"


def test_hguid_c_emission_matches_runtime_i64():
    # HGUID is a 64-bit value at runtime (hl_guid_str takes an int64); the C
    # emitter must render it as a by-value int64 and never as a pointer kind.
    from crashlink.core import Bytecode

    code = Bytecode.create_empty(no_extra_types=True)
    t = Type()
    t.kind.value = 23
    t.definition = GUID()
    code.types.append(t)

    from crashlink.hlc import ctype, is_ptr

    assert ctype(code, t, 0) == "int64"
    assert not is_ptr(Type.Kind.GUID.value)


def test_findex_code_addrs_reads_function_table(tmp_path):
    # Smoke-check the assembly-view helper's contract on a non-HL image: with no
    # hl_functions_ptrs symbol it must return an empty map rather than raise.
    bin_view = HLCBinary(data=b"\x7fELF" + b"\x00" * 64)
    from crashlink.dehlc.asmview import findex_code_addrs, format_function_asm

    assert findex_code_addrs(bin_view) == {}
    assert format_function_asm(bin_view, 0) is None
