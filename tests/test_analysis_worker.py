"""Thread-pool cache behavior under invalidation and concurrent requests."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event, Lock

import pytest

from crashlink.core import AnalysisWorker, Bytecode, Function
from crashlink.decomp import function as decomp_function


def _code():
    code = Bytecode()
    func = Function()
    func.findex.value = 0
    code.functions = [func]
    return code


@pytest.mark.parametrize("invalidate_one", [False, True])
def test_invalidation_during_construction_cannot_repopulate_cache(monkeypatch, invalidate_one):
    entered, release = Event(), Event()
    calls = []

    def make_ir(code, func):
        result = object()
        calls.append(result)
        if len(calls) == 1:
            entered.set()
            assert release.wait(5)
        return result

    monkeypatch.setattr(decomp_function, "IRFunction", make_ir)
    code = _code()
    with AnalysisWorker(max_workers=2) as worker:
        old = worker.decompile(code, 0)
        try:
            assert entered.wait(5)
            worker.invalidate(0 if invalidate_one else None)
            current = worker.decompile(code, 0).result(timeout=5)
        finally:
            release.set()
        assert old.result(timeout=5) is not current
        assert worker.decompile(code, 0).result(timeout=5) is current
        assert len(calls) == 2


def test_same_findex_in_different_documents_never_shares_ir(monkeypatch):
    first, second = _code(), _code()
    monkeypatch.setattr(decomp_function, "IRFunction", lambda code, func: code)
    with AnalysisWorker() as worker:
        assert worker.decompile(first, 0).result(timeout=5) is first
        assert worker.decompile(second, 0).result(timeout=5) is second
        assert worker.decompile(first, 0).result(timeout=5) is first


def test_concurrent_decompiles_share_one_inflight_analysis(monkeypatch):
    barrier, release = Barrier(8), Event()
    calls, lock = [], Lock()

    def make_ir(code, func):
        result = object()
        with lock:
            calls.append(result)
        assert release.wait(5)
        return result

    monkeypatch.setattr(decomp_function, "IRFunction", make_ir)
    code = _code()
    with AnalysisWorker(max_workers=8) as worker:

        def request():
            barrier.wait(timeout=5)
            return worker.decompile(code, 0)

        try:
            with ThreadPoolExecutor(max_workers=8) as clients:
                futures = list(clients.map(lambda _: request(), range(8)))
        finally:
            release.set()
        results = [future.result(timeout=5) for future in futures]
        assert all(result is results[0] for result in results)
        assert len(calls) == 1


def test_failed_analysis_can_be_retried(monkeypatch):
    calls = []
    result = object()

    def make_ir(code, func):
        calls.append(None)
        if len(calls) == 1:
            raise ValueError("analysis failed")
        return result

    monkeypatch.setattr(decomp_function, "IRFunction", make_ir)
    code = _code()
    with AnalysisWorker() as worker:
        with pytest.raises(ValueError, match="analysis failed"):
            worker.decompile(code, 0).result(timeout=5)
        assert worker.decompile(code, 0).result(timeout=5) is result
