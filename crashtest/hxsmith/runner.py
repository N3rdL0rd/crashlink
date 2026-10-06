"""Run many programs in parallel worker processes and summarise where they land on the ladder.

A run is a list of `Job`s from any source: the random generator (`fuzz`), a corpus
(`crashtest.hxcorpus`), or a file. `execute_jobs` is the one place that spawns workers,
enforces the time limit, keeps artifacts and aggregates a `Report`.
"""

from __future__ import annotations

import collections
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from .gen import Config
from .job import Job
from .pipeline import Result
from .program import generate
from .quality import Quality, Verdict, error_kinds

# Not under crashtest/runs: `crashtest build` loads every JSON file beneath that folder.
RUNS = Path(__file__).resolve().parent.parent / "hxsmith-runs"
WORKER_TIMEOUT_S = 180.0


def run_worker(workdir: Path, timeout: float = WORKER_TIMEOUT_S) -> Optional[str]:
    """Run the pipeline for the job in `workdir` in its own process group. Returns why it died, if it did."""
    command = [sys.executable, "-m", "crashtest.hxsmith.pipeline", str(workdir)]
    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=os.name == "posix",
        text=True,
    )
    try:
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill(proc)
        proc.communicate()
        return f"timed out after {timeout:g}s"
    if proc.returncode != 0:
        tail = (out or "").strip().splitlines()[-1:] or [""]
        return f"worker exited {proc.returncode}: {tail[0]}"
    return None


def _kill(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL) if os.name == "posix" else proc.kill()
    except ProcessLookupError:
        pass


def run_job(job: Job, out: Path, keep: Callable[[Result], bool], timeout: float = WORKER_TIMEOUT_S) -> Result:
    """Evaluate one job in a worker. The artifact folder survives only if `keep(result)`."""
    start = time.monotonic()
    folder = out / job.name
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "job.json").write_text(json.dumps(job.to_json()), encoding="utf-8")
    died = run_worker(folder, timeout)
    result_file = folder / "result.json"
    if died is None and result_file.exists():
        result = Result.from_json(json.loads(result_file.read_text(encoding="utf-8")))
    else:
        # The pipeline never got to report: the decompiler hung or blew its memory limit.
        why = died or "worker wrote no result"
        result = Result(
            job.name, job.class_name, verdict=Verdict(Quality.CRASH, "decompile", why, "worker: " + why)
        )
    result.features = job.features
    result.elapsed = time.monotonic() - start
    if keep(result):
        result.artifacts = str(folder)
    else:
        shutil.rmtree(folder, ignore_errors=True)
    return result


@dataclass
class Report:
    results: List[Result] = field(default_factory=list)

    @property
    def valid(self) -> List[Result]:
        return [r for r in self.results if r.verdict is not None]

    @property
    def invalid(self) -> List[Result]:
        return [r for r in self.results if r.verdict is None]

    def histogram(self) -> Dict[Quality, int]:
        counts = collections.Counter(r.verdict.quality for r in self.valid if r.verdict)
        return {q: counts.get(q, 0) for q in Quality}

    def clusters(self) -> List[Tuple[Quality, str, List[str]]]:
        """Failures (below BEHAVES) grouped by signature, biggest first: the fix queue."""
        groups: Dict[Tuple[Quality, str], List[str]] = collections.defaultdict(list)
        for r in self.valid:
            if r.verdict and r.verdict.quality < Quality.BEHAVES:
                groups[(r.verdict.quality, r.verdict.signature)].append(r.name)
        ranked = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0][0]))
        return [(q, sig, names) for (q, sig), names in ranked]

    def fix_order(self) -> List[Tuple[str, int, int]]:
        """Compile errors in the order to fix them: (kind, programs with it, programs it clears).

        Greedy: each step takes the kind that makes the most programs compile-clean given the
        kinds already chosen (ties and dead ends fall back to the most frequent), so the first
        entries are the fixes that unblock the most programs, not just the most common message."""
        programs = {
            r.name: error_kinds(r.verdict.detail)
            for r in self.valid
            if r.verdict and r.verdict.quality == Quality.NO_COMPILE
        }
        programs = {n: k for n, k in programs.items() if k}
        frequency = collections.Counter(kind for kinds in programs.values() for kind in kinds)
        chosen: set = set()
        order: List[Tuple[str, int, int]] = []
        remaining = dict(programs)
        while remaining:
            cleared = collections.Counter()
            for kinds in remaining.values():
                missing = kinds - chosen
                if len(missing) == 1:
                    cleared[next(iter(missing))] += 1
            if cleared:
                kind = max(cleared, key=lambda k: (cleared[k], frequency[k]))
            else:
                kind = max(
                    {k for kinds in remaining.values() for k in kinds - chosen}, key=lambda k: frequency[k]
                )
            chosen.add(kind)
            done = [n for n, kinds in remaining.items() if kinds <= chosen]
            order.append((kind, frequency[kind], len(done)))
            for n in done:
                del remaining[n]
        return order

    def by_feature(self) -> List[Tuple[str, int, float, float]]:
        """Per feature: programs using it, their mean rung, and the share below BEHAVES.
        A feature with a low share-good is where the decompiler is weakest."""
        stats: Dict[str, List[int]] = collections.defaultdict(list)
        for r in self.valid:
            assert r.verdict is not None
            for name in r.features:
                stats[name].append(int(r.verdict.quality))
        rows = [
            (name, len(v), sum(v) / len(v), sum(1 for q in v if q < Quality.BEHAVES) / len(v))
            for name, v in stats.items()
        ]
        return sorted(rows, key=lambda row: -row[3])

    def mean_quality(self) -> float:
        valid = self.valid
        return sum(int(r.verdict.quality) for r in valid if r.verdict) / len(valid) if valid else 0.0

    def render(self, top: int = 12) -> str:
        total, valid = len(self.results), len(self.valid)
        lines = [f"{total} programs, {valid} valid, {total - valid} invalid (not usable as tests)"]
        hist = self.histogram()
        width = max(hist.values(), default=0) or 1
        lines.append("")
        for q in reversed(list(Quality)):
            n = hist[q]
            pct = 100.0 * n / valid if valid else 0.0
            lines.append(f"  {q.value} {q.name:<10} {n:>5} {pct:5.1f}%  {'#' * round(30 * n / width)}")
        lines.append(f"\nmean rung {self.mean_quality():.2f} / {int(max(Quality))}")
        clusters = self.clusters()
        if clusters:
            lines.append("\nfailure clusters (rung, count, signature, examples):")
            for q, sig, names in clusters[:top]:
                lines.append(f"  {q.name:<10} {len(names):>4}  {sig}  {names[:4]}")
        order = self.fix_order()
        if order:
            lines.append(
                "\ncompile errors in fix order (kind, programs having it, programs it newly clears):"
            )
            for kind, have, cleared in order[:top]:
                lines.append(f"  {have:>5} {cleared:>5}  {kind}")
        rows = self.by_feature()
        if rows:
            lines.append("\nper feature (programs, mean rung, share below BEHAVES):")
            for name, n, mean, bad in rows:
                lines.append(f"  {name:<14} {n:>5}  {mean:4.2f}  {100 * bad:5.1f}%")
        problems = collections.Counter(r.invalid for r in self.invalid)
        if problems:
            lines.append("\ninvalid programs:")
            for why, n in problems.most_common(5):
                lines.append(f"  {n:>4}  {why}")
        return "\n".join(lines)

    @classmethod
    def from_json(cls, data: dict) -> "Report":
        return cls([Result.from_json(r) for r in data["results"]])

    def to_json(self) -> dict:
        return {
            "histogram": {q.name: n for q, n in self.histogram().items()},
            "mean_quality": self.mean_quality(),
            "clusters": [{"quality": q.name, "signature": s, "names": n} for q, s, n in self.clusters()],
            "fix_order": [{"kind": k, "programs": h, "clears": c} for k, h, c in self.fix_order()],
            "results": [r.to_json() for r in self.results],
        }


def execute_jobs(
    makers: Sequence[Callable[[], Result]],
    jobs: int,
    out: Path,
    progress: Optional[Callable[[int, int, Result], None]] = None,
) -> Report:
    """Run the callables in a thread pool (each drives a worker process) and write `report.json`."""
    out.mkdir(parents=True, exist_ok=True)
    report = Report()
    lock = threading.Lock()
    with ThreadPoolExecutor(jobs or max(1, (os.cpu_count() or 2) // 2)) as pool:
        futures = [pool.submit(m) for m in makers]
        try:
            for done, future in enumerate(as_completed(futures), 1):
                result = future.result()
                with lock:
                    report.results.append(result)
                if progress:
                    progress(done, len(futures), result)
        except KeyboardInterrupt:
            for future in futures:
                future.cancel()
            raise
    report.results.sort(key=lambda r: r.name)
    (out / "report.json").write_text(json.dumps(report.to_json(), indent=1), encoding="utf-8")
    return report


def keeper(keep_above: Quality) -> Callable[[Result], bool]:
    """Keep artifacts of every program that did not reach `keep_above`, and of every invalid one."""
    return lambda result: result.verdict is None or result.verdict.quality < keep_above


def run_jobs(
    items: Iterable[Job],
    jobs: int = 0,
    out: Optional[Path] = None,
    keep_above: Quality = Quality.BEHAVES,
    progress: Optional[Callable[[int, int, Result], None]] = None,
) -> Tuple[Report, Path]:
    out = out or RUNS / time.strftime("%Y%m%d%H%M%S")
    keep = keeper(keep_above)
    makers = [(lambda job=job: run_job(job, out, keep)) for job in items]
    return execute_jobs(makers, jobs, out, progress), out


def fuzz(
    seeds: Iterable[int],
    only: Optional[Iterable[str]] = None,
    exclude: Iterable[str] = (),
    jobs: int = 0,
    out: Optional[Path] = None,
    config: Optional[Config] = None,
    keep_above: Quality = Quality.BEHAVES,
    swarm: float = 0.0,
    progress: Optional[Callable[[int, int, Result], None]] = None,
) -> Tuple[Report, Path]:
    """Generate a program per seed and run each."""
    only = list(only) if only else None
    exclude = list(exclude)
    out = out or RUNS / time.strftime("%Y%m%d%H%M%S")
    keep = keeper(keep_above)

    def one(seed: int) -> Result:
        try:
            program = generate(seed, only, exclude, config, swarm)
        except Exception as exc:  # noqa: BLE001 - a generator bug is a finding, not a reason to stop the run
            return Result(
                f"seed{seed}", f"Fuzz{seed}", invalid=f"generator crash: {type(exc).__name__}: {exc}"
            )
        job = Job(
            f"seed{seed}", program.class_name, {program.filename: program.source}, features=program.features
        )
        return run_job(job, out, keep)

    return execute_jobs([(lambda s=s: one(s)) for s in seeds], jobs, out, progress), out


def lint(
    seeds: Iterable[int],
    only: Optional[Iterable[str]] = None,
    exclude: Iterable[str] = (),
    jobs: int = 0,
    config: Optional[Config] = None,
    swarm: float = 0.0,
) -> List[Tuple[int, str]]:
    """Check that the generator's programs are valid tests, without decompiling anything:
    each must compile, run, finish and repeat its own output. Returns (seed, problem) for
    the ones that do not. This is the loop for developing a feature."""
    import tempfile

    from .pipeline import build_original, check_original

    only = list(only) if only else None
    exclude = list(exclude)

    def one(seed: int) -> Optional[Tuple[int, str]]:
        try:
            program = generate(seed, only, exclude, config, swarm)
        except Exception as exc:  # noqa: BLE001
            return seed, f"generator crash: {type(exc).__name__}: {exc}"
        job = Job(f"seed{seed}", program.class_name, {program.filename: program.source})
        with tempfile.TemporaryDirectory(prefix="hxsmith-lint-") as tmp:
            target, error = build_original(job, Path(tmp))
            if error:
                return seed, "does not compile: " + "; ".join(
                    line.strip() for line in error.splitlines() if "Error" in line or ".hx:" in line
                )[:300]
            problem = check_original(target)
            return (seed, problem) if problem else None

    with ThreadPoolExecutor(jobs or max(1, (os.cpu_count() or 2) // 2)) as pool:
        return [r for r in pool.map(one, list(seeds)) if r is not None]


def lint_jobs(items: Iterable[Job], jobs: int = 0) -> List[Tuple[str, str]]:
    """`lint` for arbitrary jobs: (name, problem) for each that is not a valid test."""
    import tempfile

    from .pipeline import build_original, check_original
    from .quality import normalize

    def one(job: Job) -> Optional[Tuple[str, str]]:
        with tempfile.TemporaryDirectory(prefix="hxsmith-lint-") as tmp:
            target, error = build_original(job, Path(tmp))
            if error:
                return job.name, "does not build: " + normalize(error)
            problem = check_original(target)
            return (job.name, problem) if problem else None

    with ThreadPoolExecutor(jobs or max(1, (os.cpu_count() or 2) // 2)) as pool:
        return [r for r in pool.map(one, list(items)) if r is not None]
