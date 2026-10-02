"""Every entrypoint that loads an image must record its hash and path: hash-gated plugins key on them."""

import hashlib
from pathlib import Path

import crashlink.mcp as mcp
from crashlink.__main__ import _load_code_from_cli_path
from crashlink.core import Bytecode

CLAZZ = str(Path(__file__).parent / "haxe" / "Clazz.hl")


def _expected_sha() -> str:
    return hashlib.sha256(Path(CLAZZ).read_bytes()).hexdigest()


def test_cli_loader_records_sha_and_path():
    code = _load_code_from_cli_path(CLAZZ, no_constants=False)
    assert code.sha256 == _expected_sha()
    assert code.source_path == CLAZZ


def test_mcp_load_records_sha_and_path():
    try:
        mcp.load_bytecode(CLAZZ)
        assert mcp._code is not None
        assert mcp._code.sha256 == _expected_sha()
        assert mcp._code.source_path == CLAZZ
    finally:
        mcp._code = None


def test_init_globals_flag_is_honoured_by_from_path():
    resolved = Bytecode.from_path(CLAZZ)
    raw = Bytecode.from_path(CLAZZ, init_globals=False)
    assert resolved.virtuals_built
    assert not raw.virtuals_built
    assert raw.sha256 == resolved.sha256
