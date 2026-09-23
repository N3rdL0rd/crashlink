"""Document ownership and unsaved-edit regressions, runnable with offscreen Qt."""

import os
from threading import Event
from time import monotonic

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import QApplication, QMessageBox

from crashlink.core import Bytecode
from crashlink.database import DatabaseLoadResult
from crashlink.gui import main_window as gui


@pytest.fixture
def window(monkeypatch):
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(gui.MainWindow, "_restore_settings", lambda self: None)
    monkeypatch.setattr(gui.MainWindow, "_save_settings", lambda self: None)
    monkeypatch.setattr(gui.MainWindow, "_add_recent_file", lambda self, path: None)
    window = gui.MainWindow()
    yield window
    window._dirty = False
    window.close()
    app.processEvents()


def _pump_until(predicate):
    deadline = monotonic() + 5
    while not predicate():
        QApplication.processEvents()
        if monotonic() >= deadline:
            pytest.fail("Timed out waiting for GUI job")
    QApplication.processEvents()


@pytest.mark.parametrize("action", ["open", "recent", "close"])
def test_failed_save_preserves_dirty_document(window, monkeypatch, tmp_path, action):
    source = tmp_path / "original.hl"
    source.write_bytes(b"HLB")
    code = Bytecode.from_path("tests/haxe/Arithmetic.hl")
    window._code = code
    window._source_path = str(source)
    window._dirty = True
    code.annotations.rename(0, 0, None, "unsaved")
    monkeypatch.setattr(QMessageBox, "exec", lambda self: QMessageBox.StandardButton.Save)

    def fail_save(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(gui, "save_database", fail_save)
    monkeypatch.setattr(gui.QFileDialog, "getOpenFileName", lambda *args: (str(source), ""))
    if action == "open":
        window._open_file()
    elif action == "recent":
        window._open_recent(str(source))
    else:
        event = QCloseEvent()
        window.closeEvent(event)
        assert not event.isAccepted()
    assert window._code is code
    assert window._source_path == str(source)
    assert window._dirty
    assert code.annotations.get_rename(0, 0, None) == "unsaved"
    assert not window._closing


def test_switched_load_keeps_old_thread_alive_and_rejects_its_result(window, monkeypatch, tmp_path):
    first = Bytecode.from_path("tests/haxe/Arithmetic.hl")
    second = Bytecode.from_path("tests/haxe/Arithmetic.hl")
    entered, release = Event(), Event()
    path_a, path_b = tmp_path / "a.hl", tmp_path / "b.hl"
    path_a.write_bytes(b"HLB")
    path_b.write_bytes(b"HLB")

    def load(path, **kwargs):
        if path == str(path_a):
            entered.set()
            assert release.wait(5)
            return first
        return second

    monkeypatch.setattr(gui.Bytecode, "from_path", load)
    try:
        window._load_file(str(path_a))
        assert entered.wait(5)
        old_thread = window._load_thread
        window._load_file(str(path_b))
        _pump_until(lambda: window._code is second)
        assert old_thread in window._threads
        assert old_thread.isRunning()
        release.set()
        _pump_until(lambda: old_thread not in window._threads)
        assert window._code is second
        assert window._source_path == str(path_b)
        assert "Error:" not in window._status_label.text()
    finally:
        release.set()


def test_stale_progress_index_and_decompile_signals_do_not_touch_new_document(window, monkeypatch):
    window._generation = 2
    window._status_label.setText("Current document")
    window._class_results = {"same-class": {0: "current pseudocode"}}
    window._decomp_tokens[("same-class", 0)] = (2, 2)
    window._active_decompiles = 1
    window._busy.start("Current decompile")
    monkeypatch.setattr(window, "_refresh_class_view", lambda key: pytest.fail("Stale result rendered"))
    stop = window._busy.stop
    monkeypatch.setattr(window._busy, "stop", lambda: pytest.fail("Stale result stopped current work"))
    window._on_load_progress(1, 0.8, "Old document")
    window._on_load_error(1, "Old failure")
    window._on_index_finished(1)
    window._on_index_error(1, "Old index failure")
    window._on_decompile_error((1, 1), "same-class", 0, "Old failure")
    window._on_decompile_finished((1, 1), "same-class", 0, object(), ("", {}))
    assert window._status_label.text() == "Current document"
    assert window._class_results["same-class"][0] == "current pseudocode"
    assert window._active_decompiles == 1
    monkeypatch.setattr(window._busy, "stop", stop)


def test_database_load_does_not_mutate_live_annotations_before_acceptance(window, monkeypatch):
    code = Bytecode.from_path("tests/haxe/Arithmetic.hl")
    window._code = code
    window._source_path = "tests/haxe/Arithmetic.hl"
    entered, release = Event(), Event()

    def load_database(path, *, code, source_path):
        entered.set()
        assert release.wait(5)
        code.annotations.rename(0, 0, None, "database name")
        return DatabaseLoadResult(renames_applied=1)

    monkeypatch.setattr(gui, "load_database", load_database)
    try:
        window._load_database_from("old.cldb")
        assert entered.wait(5)
        old_thread = window._db_load_thread
        # Editing while the database is loading supersedes its annotation snapshot.
        window.apply_rename(0, 0, None, "user edit")
        release.set()
        _pump_until(lambda: old_thread not in window._threads)
        assert code.annotations.get_rename(0, 0, None) == "user edit"
        assert window._dirty
    finally:
        release.set()


def test_stale_database_result_cannot_replace_new_document_annotations(window):
    code = Bytecode.from_path("tests/haxe/Arithmetic.hl")
    window._code = code
    window._generation = 2
    code.annotations.rename(0, 0, None, "current")
    old = Bytecode.from_path("tests/haxe/Arithmetic.hl")
    old.annotations.rename(0, 0, None, "old")
    window._on_db_load_finished((1, 0), DatabaseLoadResult(), old.annotations)
    assert code.annotations.get_rename(0, 0, None) == "current"


def test_close_waits_for_owned_loader_and_ignores_queued_completion(window, monkeypatch, tmp_path):
    code = Bytecode.from_path("tests/haxe/Arithmetic.hl")
    entered, release, exited = Event(), Event(), Event()
    source = tmp_path / "closing.hl"
    source.write_bytes(b"HLB")

    def load(path, **kwargs):
        entered.set()
        assert release.wait(5)
        exited.set()
        return code

    monkeypatch.setattr(gui.Bytecode, "from_path", load)
    window._load_file(str(source))
    assert entered.wait(5)
    thread = window._load_thread
    interrupt = thread.requestInterruption

    def cancel():
        interrupt()
        release.set()

    monkeypatch.setattr(thread, "requestInterruption", cancel)
    try:
        event = QCloseEvent()
        window.closeEvent(event)
        assert event.isAccepted()
        assert exited.is_set()
        assert not thread.isRunning()
        QApplication.processEvents()
        assert window._code is None
    finally:
        release.set()


def test_newer_database_request_wins_when_old_load_finishes_last(window, monkeypatch):
    window._code = Bytecode.from_path("tests/haxe/Arithmetic.hl")
    window._source_path = "tests/haxe/Arithmetic.hl"
    entered, release = Event(), Event()

    def load_database(path, *, code, source_path):
        if path == "old.cldb":
            entered.set()
            assert release.wait(5)
        code.annotations.rename(0, 0, None, path)
        return DatabaseLoadResult(renames_applied=1)

    monkeypatch.setattr(gui, "load_database", load_database)
    try:
        window._load_database_from("old.cldb")
        assert entered.wait(5)
        old_thread = window._db_load_thread
        window._load_database_from("new.cldb")
        _pump_until(lambda: window._code.annotations.get_rename(0, 0, None) == "new.cldb")
        release.set()
        _pump_until(lambda: old_thread not in window._threads)
        assert window._code.annotations.get_rename(0, 0, None) == "new.cldb"
    finally:
        release.set()
