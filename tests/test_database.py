"""Round-trip tests for the .cldb analysis-database format (crashlink.database)."""

import os

from crashlink import database as db
from crashlink.core import Bytecode

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
    class_results = {"class:Foo": {findex: "class Foo { function main() {} }"}}
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
    text, opmap = result.cache[findex]
    assert text == "class Foo { function main() {} }"
    assert opmap == {0: 0, 1: 1, 2: 1}


def test_pending_results_are_not_cached(tmp_path):
    """None entries (still-decompiling placeholders) must never be persisted."""
    code = _fresh_code()
    findex = code.functions[0].findex.value
    class_results = {"class:Foo": {findex: None}}

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
    class_results = {"class:Foo": {findex: "stale cached text"}}

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
    class_results = {"class:Foo": {findex: "shouldNotApply either"}}

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
