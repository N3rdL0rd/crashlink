"""Background workers for the GUI: document load threads, decompile jobs, index builds.

Everything here runs off the UI thread and reports back through Qt signals; the
window-side slots live in `main_window` and `mixins/`.
"""

from __future__ import annotations

import gc
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager
from typing import Any, Callable, Iterator

from PySide6.QtCore import QObject, QRunnable, QThread, Signal

from crashlink.core import AnalysisWorker, Bytecode
from crashlink.decomp.function import _cached_enum_global_map
from crashlink.decomp.inline_calls import inline_index
from crashlink.pseudo import pseudo_oplines, pseudo_spans
from crashlink.pseudo.doc import RenderedSource

from .widgets.function_list import FunctionList


def _looks_like_native_image(path: str) -> bool:
    """True when the file is an ELF image or PE executable (HL/C-compiled binary)
    rather than serialised HashLink bytecode."""
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except OSError:
        return False
    return head[:4] == b"\x7fELF" or head[:2] == b"MZ"


@contextmanager
def _bulk_build() -> Iterator[None]:
    """Pause the cyclic GC while building a large, long-lived structure (the loaded
    document, its indices), then freeze the result. Otherwise the GC walks those
    millions of new objects once per generation as they age, each pass holding the
    GIL for up to a second and freezing the UI; frozen, later passes skip them.
    `_load_file` unfreezes before the next document loads."""
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        yield
    finally:
        gc.freeze()
        if was_enabled:
            gc.enable()


class _LoadSignals(QObject):
    progress = Signal(int, float, str)
    finished = Signal(int, object, object)  # generation, Bytecode, NavigatorData
    error = Signal(int, str)


class _LoadThread(QThread):
    def __init__(self, path: str, generation: int) -> None:
        super().__init__()
        self.path = path
        self.generation = generation
        self.signals = _LoadSignals()

    def run(self) -> None:
        try:

            def _cb(frac: float, status: str) -> None:
                if self.isInterruptionRequested():
                    raise InterruptedError("Document load cancelled")
                self.signals.progress.emit(self.generation, frac, status)

            with _bulk_build():
                code = Bytecode.from_path(self.path, progress_cb=_cb)
                # Navigator data is pure Python work over every function. Build it
                # here so the UI thread only creates the tree items.
                nav_data = FunctionList.prepare(code)
            self.signals.finished.emit(self.generation, code, nav_data)
        except Exception as e:
            self.signals.error.emit(self.generation, str(e))


class _DehlcLoadThread(_LoadThread):
    """Loads a native image off the UI thread, with cancellation between phases."""

    def run(self) -> None:
        try:
            from crashlink.dehlc import code_from_bin

            def _cb(status: str) -> None:
                if self.isInterruptionRequested():
                    raise InterruptedError("Document load cancelled")
                self.signals.progress.emit(self.generation, -1.0, f"de-HL/C: {status}")

            with _bulk_build():
                code = code_from_bin(path=self.path, verbose=False, progress_cb=_cb)
                nav_data = FunctionList.prepare(code)
            self.signals.finished.emit(self.generation, code, nav_data)
        except ImportError:
            self.signals.error.emit(
                self.generation,
                "de-HL/C needs crashlink[extras] (`pip install lief capstone`) to open compiled binaries.",
            )
        except Exception as e:
            self.signals.error.emit(self.generation, str(e))


class _DecompJob(QObject):
    """One decompile request. The IR comes from the shared AnalysisWorker; its
    pseudocode is rendered on `render_pool` too, so the UI thread only inserts text.
    No thread sits blocked waiting on the future."""

    # token, class_key, findex, IRFunction, RenderedSource (text, symbol spans, {op index: body line})
    finished = Signal(object, str, int, object, object)
    error = Signal(object, str, int, str)

    def __init__(self, class_key: str, findex: int, token: tuple) -> None:
        super().__init__()
        self.class_key = class_key
        self.findex = findex
        self.token = token

    def start(self, worker: AnalysisWorker, code: Bytecode, render_pool: ThreadPoolExecutor) -> None:
        future = worker.decompile(code, self.findex)
        # The callback may run on the decompile thread or, for a cached result,
        # right here; either way the rendering itself goes to render_pool.
        future.add_done_callback(lambda done: self._queue_render(render_pool, done))

    def _queue_render(self, render_pool: ThreadPoolExecutor, future: "Future[Any]") -> None:
        try:
            render_pool.submit(self._render, future)
        except RuntimeError:
            pass  # window closing: the render pool is shut down and nobody wants the result

    def _render(self, future: "Future[Any]") -> None:
        try:
            ir = future.result()
        except BaseException as e:  # includes CancelledError
            self.error.emit(self.token, self.class_key, self.findex, str(e) or type(e).__name__)
            return
        try:
            rendered = pseudo_spans(ir, types=True)
        except Exception:
            # A failure particular to symbol tagging must not cost the text itself.
            try:
                text, oplines = pseudo_oplines(ir)
                rendered = RenderedSource(text, [], oplines)
            except Exception as e:
                rendered = RenderedSource(f"class ? {{\n    // f@{self.findex} error: {e}\n}}")
        self.finished.emit(self.token, self.class_key, self.findex, ir, rendered)


class _IndexBuildSignals(QObject):
    finished = Signal(int)
    error = Signal(int, str)


class _IndexBuildThread(QThread):
    """Pre-warm document indices without blocking the UI."""

    def __init__(self, worker: AnalysisWorker, code: Bytecode, generation: int) -> None:
        super().__init__()
        self.generation = generation
        self.signals = _IndexBuildSignals()
        self._code = code
        self._future = worker.build_indices(code, self._progress)

    def _progress(self, _frac: float, _status: str) -> None:
        if self.isInterruptionRequested():
            raise InterruptedError("Index build cancelled")

    def run(self) -> None:
        try:
            with _bulk_build():
                self._future.result()
                if not self._code.inspection_only and not self.isInterruptionRequested():
                    # The first decompile would otherwise pay these whole-image scans
                    # (~1 s and ~15 s on large games) while the user waits for the tab.
                    _cached_enum_global_map(self._code)
                    if not self.isInterruptionRequested():
                        inline_index(self._code)
            self.signals.finished.emit(self.generation)
        except Exception as e:
            self.signals.error.emit(self.generation, str(e))

    def requestInterruption(self) -> None:
        self._future.cancel()
        super().requestInterruption()


class _BackgroundSignals(QObject):
    done = Signal(object, object)  # token, result
    failed = Signal(object, str)  # token, message


class _BackgroundRunnable(QRunnable):
    """Runs one `MainWindow.run_background` job on the shared thread pool."""

    def __init__(self, token: object, fn: Callable[[], Any]) -> None:
        super().__init__()
        self._token = token
        self._fn = fn
        self.signals = _BackgroundSignals()

    def run(self) -> None:
        try:
            result = self._fn()
        except Exception as e:
            self.signals.failed.emit(self._token, f"{type(e).__name__}: {e}")
            return
        self.signals.done.emit(self._token, result)
