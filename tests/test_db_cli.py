"""Tests for the `crashlink db` CLI subcommand."""

import pytest

from crashlink import database as db
from crashlink.__main__ import db_main
from crashlink.core import Bytecode

SAMPLE = "tests/haxe/Arithmetic.hl"


def _make_cldb(tmp_path) -> str:
    code = Bytecode.from_path(SAMPLE)
    findex = code.functions[0].findex.value
    code.annotations.rename(findex, 0, None, "myVar")
    code.annotations.set_comment(findex, 2, "a note")
    session = db.SessionState(view_mode=1, theme_name="Mocha", open_findices=[findex], current_tab_index=0)
    cldb_path = str(tmp_path / "test.cldb")
    db.save_database(
        cldb_path,
        code=code,
        source_path=SAMPLE,
        class_results={"k": {findex: "cached text"}},
        opline_cache={findex: {0: 0}},
        session=session,
    )
    return cldb_path


def test_db_info(tmp_path, capsys):
    cldb_path = _make_cldb(tmp_path)
    db_main(["info", cldb_path])
    out = capsys.readouterr().out
    assert "Arithmetic.hl" in out
    assert "Renames: 1" in out
    assert "Comments: 1" in out
    assert "Cached functions: 1" in out
    assert "Mocha" in out


def test_db_renames(tmp_path, capsys):
    cldb_path = _make_cldb(tmp_path)
    db_main(["renames", cldb_path])
    out = capsys.readouterr().out
    assert "myVar" in out


def test_db_comments(tmp_path, capsys):
    cldb_path = _make_cldb(tmp_path)
    db_main(["comments", cldb_path])
    out = capsys.readouterr().out
    assert "a note" in out


def test_db_check_match(tmp_path, capsys):
    cldb_path = _make_cldb(tmp_path)
    db_main(["check", cldb_path, SAMPLE])
    out = capsys.readouterr().out
    assert "OK" in out


def test_db_check_mismatch_exits_nonzero(tmp_path, capsys):
    cldb_path = _make_cldb(tmp_path)
    with pytest.raises(SystemExit) as exc:
        db_main(["check", cldb_path, "tests/haxe/Enums.hl"])
    assert exc.value.code != 0
    out = capsys.readouterr().out
    assert "MISMATCH" in out


def test_db_info_bad_file_exits_nonzero(tmp_path, capsys):
    bogus = tmp_path / "bogus.cldb"
    bogus.write_bytes(b"NOTCLDB!!!!")
    with pytest.raises(SystemExit) as exc:
        db_main(["info", str(bogus)])
    assert exc.value.code != 0
