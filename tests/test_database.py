"""Round-trip tests for the .cldb analysis-database format (crashlink.database)."""

import os
import shutil
import struct
import zlib
from io import BytesIO
from typing import Dict, Optional

import pytest

from crashlink import database as db
from crashlink.core import Bytecode, Function

SAMPLE = "tests/haxe/Arithmetic.hl"


def _fresh_code() -> Bytecode:
    return Bytecode.from_path(SAMPLE)


def test_round_trip_renames_and_comments(tmp_path):
    code = _fresh_code()
    findex = code.functions[0].findex.value
    code.annotations.rename(findex, 0, None, "myVar")
    code.annotations.set_comment(findex, 2, "a helpful note")

    cldb_path = str(tmp_path / "test.cldb")
    db.save_database(cldb_path, code=code, source_path=SAMPLE, class_results={}, opline_cache={})

    fresh = _fresh_code()
    result = db.load_database(cldb_path, code=fresh, source_path=SAMPLE)

    assert result.matched
    assert result.renames_applied == 1
    assert result.comments_applied == 1
    assert fresh.annotations.get_rename(findex, 0, None) == "myVar"
    assert fresh.annotations.get_comment(findex, 2) == "a helpful note"


def test_round_trip_decompile_cache(tmp_path):
    code = _fresh_code()
    findex = code.functions[0].findex.value
    class_results: Dict[str, Dict[int, Optional[str]]] = {
        "class:Foo": {findex: "class Foo { function main() {} }"}
    }
    opline_cache = {findex: {0: 0, 1: 1, 2: 1}}

    cldb_path = str(tmp_path / "test.cldb")
    db.save_database(
        cldb_path,
        code=code,
        source_path=SAMPLE,
        class_results=class_results,
        opline_cache=opline_cache,
    )

    fresh = _fresh_code()
    result = db.load_database(cldb_path, code=fresh, source_path=SAMPLE)

    assert result.matched
    assert findex in result.cache
    rendered = result.cache[findex]
    assert rendered.text == "class Foo { function main() {} }"
    assert rendered.oplines == {0: 0, 1: 1, 2: 1}
    assert rendered.spans == []  # saved without a spans cache
    assert rendered.types == []


def test_pending_results_are_not_cached(tmp_path):
    """None entries (still-decompiling placeholders) must never be persisted."""
    code = _fresh_code()
    findex = code.functions[0].findex.value
    class_results: Dict[str, Dict[int, Optional[str]]] = {"class:Foo": {findex: None}}

    cldb_path = str(tmp_path / "test.cldb")
    db.save_database(
        cldb_path,
        code=code,
        source_path=SAMPLE,
        class_results=class_results,
        opline_cache={},
    )

    fresh = _fresh_code()
    result = db.load_database(cldb_path, code=fresh, source_path=SAMPLE)
    assert findex not in result.cache


def test_cache_entry_invalidated_by_rename_after_save(tmp_path):
    """A cache entry must not be trusted if that specific function's annotations
    have changed since the entry was cached, even though the overall file still
    matches (SRCI passes)."""
    code = _fresh_code()
    findex = code.functions[0].findex.value
    class_results: Dict[str, Dict[int, Optional[str]]] = {"class:Foo": {findex: "stale cached text"}}

    cldb_path = str(tmp_path / "test.cldb")
    db.save_database(
        cldb_path,
        code=code,
        source_path=SAMPLE,
        class_results=class_results,
        opline_cache={},
    )

    fresh = _fresh_code()
    fresh.annotations.rename(findex, 0, None, "somethingNew")
    result = db.load_database(cldb_path, code=fresh, source_path=SAMPLE)

    assert result.matched  # SRCI still matches — same file
    assert findex not in result.cache  # but this function's own entry is stale


def test_session_round_trip(tmp_path):
    code = _fresh_code()
    findex = code.functions[0].findex.value
    session = db.SessionState(view_mode=2, theme_name="Mocha", open_findices=[findex], current_tab_index=0)

    cldb_path = str(tmp_path / "test.cldb")
    db.save_database(
        cldb_path,
        code=code,
        source_path=SAMPLE,
        class_results={},
        opline_cache={},
        session=session,
    )

    fresh = _fresh_code()
    result = db.load_database(cldb_path, code=fresh, source_path=SAMPLE)

    assert result.session is not None
    assert result.session.view_mode == 2
    assert result.session.theme_name == "Mocha"
    assert result.session.open_findices == [findex]
    assert result.session.current_tab_index == 0


def test_missing_session_chunk_still_loads(tmp_path):
    """A .cldb saved without session=... (e.g. from a future CLI tool) must still
    load its renames/cache fine — SESS is optional."""
    code = _fresh_code()
    findex = code.functions[0].findex.value
    code.annotations.rename(findex, 0, None, "x")

    cldb_path = str(tmp_path / "test.cldb")
    db.save_database(cldb_path, code=code, source_path=SAMPLE, class_results={}, opline_cache={})

    fresh = _fresh_code()
    result = db.load_database(cldb_path, code=fresh, source_path=SAMPLE)
    assert result.matched
    assert result.session is None
    assert fresh.annotations.get_rename(findex, 0, None) == "x"


def test_hash_mismatch_rejects_everything(tmp_path):
    code = _fresh_code()
    findex = code.functions[0].findex.value
    code.annotations.rename(findex, 0, None, "shouldNotApply")
    class_results: Dict[str, Dict[int, Optional[str]]] = {"class:Foo": {findex: "shouldNotApply either"}}

    cldb_path = str(tmp_path / "test.cldb")
    db.save_database(
        cldb_path,
        code=code,
        source_path=SAMPLE,
        class_results=class_results,
        opline_cache={},
    )

    other_sample = "tests/haxe/Enums.hl"
    fresh = Bytecode.from_path(other_sample)
    result = db.load_database(cldb_path, code=fresh, source_path=other_sample)

    assert not result.matched
    assert result.warnings
    assert result.renames_applied == 0
    assert result.comments_applied == 0
    assert result.cache == {}
    assert fresh.annotations.get_rename(findex, 0, None) is None


def test_bad_magic_rejected_cleanly(tmp_path):
    bogus_path = tmp_path / "bogus.cldb"
    bogus_path.write_bytes(b"NOTCLDB!!!!")

    fresh = _fresh_code()
    result = db.load_database(str(bogus_path), code=fresh, source_path=SAMPLE)
    assert not result.matched
    assert result.warnings


def test_save_writes_next_to_source_path_convention(tmp_path):
    """Not enforced by save_database itself (caller picks the path), but confirm
    the documented `<source>.cldb` convention round-trips end to end."""
    code = _fresh_code()
    src_copy = tmp_path / "Arithmetic.hl"
    src_copy.write_bytes(open(SAMPLE, "rb").read())
    cldb_path = str(src_copy) + ".cldb"

    db.save_database(
        cldb_path,
        code=code,
        source_path=str(src_copy),
        class_results={},
        opline_cache={},
    )
    assert os.path.exists(cldb_path)

    fresh = Bytecode.from_path(str(src_copy))
    result = db.load_database(cldb_path, code=fresh, source_path=str(src_copy))
    assert result.matched


SPANS_SOURCE = """
class DbSpans {
    static var total:Int;
    static function bump(x:Int):Int {
        return x + 1;
    }
    static function main() {
        var local = bump(41);
        total = local;
        Sys.println(total);
    }
}
"""


def test_cached_spans_round_trip(tmp_path):
    """A function's rendered symbol/type spans must survive a save→load so the GUI
    can resolve symbols from a cached database before the redecompile lands."""
    if not shutil.which("haxe"):
        pytest.skip("haxe not installed")
    from crashtest.behavior import compile_haxe

    from crashlink import pseudo
    from crashlink.decomp.function import IRFunction

    artifact, error = compile_haxe(SPANS_SOURCE, "DbSpans", tmp_path / "build")
    assert error is None, error
    source_path = str(artifact)
    code = Bytecode.from_path(source_path)
    func = next(
        f
        for f in code.functions
        if isinstance(f, Function) and f.ops and code.full_func_name(f).endswith("DbSpans.main")
    )
    findex = func.findex.value

    # types=True exercises the type-span codec too; the loader restores whatever
    # the renderer produced, so this round-trips either way.
    rendered = pseudo.pseudo_spans(IRFunction(code, func), types=True)
    assert rendered.spans, "fixture must produce symbol spans"
    assert rendered.types, "fixture must produce expression type spans"

    cldb_path = str(tmp_path / "test.cldb")
    db.save_database(
        cldb_path,
        code=code,
        source_path=source_path,
        class_results={"class:DbSpans": {findex: rendered.text}},
        opline_cache={findex: rendered.oplines},
        spans_cache={findex: rendered},
    )

    fresh = Bytecode.from_path(source_path)
    result = db.load_database(cldb_path, code=fresh, source_path=source_path)

    assert result.matched
    restored = result.cache[findex]
    assert restored.text == rendered.text
    assert restored.spans == rendered.spans
    assert restored.types == rendered.types
    assert restored.oplines == rendered.oplines
    assert restored.body_start == rendered.body_start
    # The restored spans actually resolve: the definition of a local is findable.
    name = next(s.ref for s in rendered.spans if s.ref.kind.name == "LOCAL" and s.is_def)
    assert restored.definition_of(name) == rendered.definition_of(name)


def test_v1_database_without_spans_still_loads(tmp_path):
    """Format v1 wrote DCAC entries as findex/hash/text/opmap only. Such databases
    must still load; their entries simply carry no spans (the behaviour cached
    functions had until the redecompile landed)."""
    code = _fresh_code()
    findex = code.functions[0].findex.value
    text = "class Foo { function main() {} }"
    opmap = {0: 0, 1: 1}
    content_hash = db._function_content_hash(code, findex)
    assert content_hash is not None

    # A v1 DCAC entry, exactly the way the previous version encoded it.
    dcac = BytesIO()
    db._write_varint(dcac, 1)  # one entry
    db._write_varint(dcac, findex)
    dcac.write(content_hash)
    db._write_str(dcac, text)
    db._write_varint(dcac, len(opmap))
    for op_idx, body_line in opmap.items():
        db._write_varint(dcac, op_idx)
        db._write_varint(dcac, body_line)

    body = BytesIO()
    source_hash, source_size = db.hash_file(SAMPLE)
    for tag, payload in (
        (db.TAG_SRCI, db._encode_srci(code, SAMPLE, source_hash, source_size)),
        (db.TAG_DCAC, dcac.getvalue()),
    ):
        body.write(tag)
        body.write(struct.pack("<I", len(payload)))
        body.write(payload)
    raw = zlib.compress(body.getvalue(), level=9)
    cldb_path = tmp_path / "old.cldb"
    cldb_path.write_bytes(db.MAGIC + struct.pack("<HB", 1, db.FLAG_COMPRESSED) + raw)

    fresh = _fresh_code()
    result = db.load_database(str(cldb_path), code=fresh, source_path=SAMPLE)

    assert result.matched
    rendered = result.cache[findex]
    assert rendered.text == text
    assert rendered.oplines == opmap
    assert rendered.spans == []
    assert rendered.types == []
