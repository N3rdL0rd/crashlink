"""Evaluate one program: compile, run, decompile, recompile, run, compare.

Each stage is a small function returning data, so a stage can be replaced or
reused. `evaluate` strings them together and feeds `quality.classify`. It is
meant to run in a throwaway worker process (`python -m crashtest.hxsmith.pipeline
<workdir>`, which reads `<workdir>/job.json`): a decompiler hang or memory blowup
is then just a CRASH verdict.
"""

from __future__ import annotations

import json
import sys
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from crashlink import project
from crashlink.core import Bytecode

from ..behavior import compare_programs, execute, resolve_hl_runtime
from .compare import compare
from .job import Job
from .quality import Observation, Quality, Verdict, classify, normalize


@dataclass
class Result:
    """The outcome for one program: a verdict, or why the program was unusable as a test."""

    name: str
    class_name: str
    features: Tuple[str, ...] = ()
    verdict: Optional[Verdict] = None
    invalid: Optional[str] = None  # the program is not a valid test (does not build, nondeterministic, ...)
    elapsed: float = 0.0
    artifacts: Optional[str] = None

    def to_json(self) -> dict:
        return {
            "name": self.name,
            "class_name": self.class_name,
            "features": list(self.features),
            "verdict": self.verdict.to_json() if self.verdict else None,
            "invalid": self.invalid,
            "elapsed": self.elapsed,
            "artifacts": self.artifacts,
        }

    @classmethod
    def from_json(cls, data: dict) -> "Result":
        return cls(
            data["name"],
            data["class_name"],
            tuple(data["features"]),
            Verdict.from_json(data["verdict"]) if data["verdict"] else None,
            data["invalid"],
            data["elapsed"],
            data.get("artifacts"),
        )


# ---- stages ---------------------------------------------------------------------------------


def build_original(job: Job, directory: Path) -> Tuple[Path, Optional[str]]:
    """Write the job's sources into `directory` and compile them for HashLink."""
    directory.mkdir(parents=True, exist_ok=True)
    for rel, text in job.sources.items():
        path = directory / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    target = directory / "program.hl"
    command = ["haxe", "-hl", str(target), "-cp", str(directory)]
    for root in job.classpaths:
        command += ["-cp", root]
    result = execute(command + ["-main", job.class_name], str(directory), timeout=90)
    error = result.error
    if not error and result.returncode != 0:
        error = f"Haxe compilation failed:\n{result.stderr}"
    return target, error


def check_original(program: Path) -> Optional[str]:
    """Why the original cannot serve as an oracle: it must run, finish, and repeat itself."""
    runtime = resolve_hl_runtime()
    if not runtime:
        return "HashLink runtime unavailable; set HL_RUNTIME or install hl on PATH"
    runs = [execute([runtime, str(program)], str(program.parent), 5.0) for _ in range(2)]
    for run in runs:
        if run.error:
            return run.error
    if runs[0] != runs[1]:
        return "original is not deterministic"
    return None


def decompile(program: Path) -> Tuple[Dict[str, str], Optional[str]]:
    """Export the bytecode image as a Haxe project; the error is where the decompiler fell over."""
    try:
        return project.export(Bytecode.from_path(str(program))), None
    except BaseException as exc:  # noqa: BLE001 - any failure is a verdict, including MemoryError
        frames = traceback.extract_tb(exc.__traceback__)
        where = f"{frames[-1].name}" if frames else "?"
        return {}, f"{type(exc).__name__} in {where}: {exc}"


def recompile(files: Dict[str, str], directory: Path) -> Tuple[Path, Optional[str]]:
    project.write(str(directory), files)
    result = execute(["haxe", "build.hxml"], str(directory), timeout=90)
    error = result.error
    if not error and result.returncode != 0:
        error = f"Haxe compilation failed:\n{result.stderr}"
    return directory / "out.hl", error


# ---- driver ---------------------------------------------------------------------------------


def evaluate(job: Job, directory: Path) -> Result:
    """Run every stage in `directory` and return the verdict. Never raises for a bad program."""
    result = Result(job.name, job.class_name, job.features)
    if job.unreliable:
        result.invalid = "original is not a reliable oracle: " + job.unreliable
        return result
    original, error = build_original(job, directory / "original")
    if error:
        result.invalid = "original does not build: " + normalize(error)
        return result
    problem = check_original(original)
    if problem:
        result.invalid = normalize(problem)
        return result

    obs = Observation()
    files, obs.decompile_error = decompile(original)
    obs.decompiled = files
    if not obs.decompile_error:
        recompiled, obs.compile_error = recompile(files, directory / "decompiled")
        if not obs.compile_error and not any("decompilation failed" in t for t in files.values()):
            obs.behavior = compare_programs(original, recompiled, job.class_name, modules=tuple(job.modules))
            if obs.behavior.passed:
                try:
                    obs.similarity, obs.differing = compare(
                        Bytecode.from_path(str(original)),
                        Bytecode.from_path(str(recompiled)),
                        job.compared_modules(),
                    )
                except Exception as exc:  # noqa: BLE001 - similarity is diagnostic; behaviour already passed
                    obs.similarity, obs.differing = None, [("compare failed: " + str(exc), 0.0)]
    result.verdict = classify(obs)
    return result


def main(argv: List[str]) -> int:
    """Worker entry: evaluate `<workdir>/job.json`, write `<workdir>/result.json`."""
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_AS, (16 << 30, resource.RLIM_INFINITY))
    except (ImportError, ValueError):
        pass
    workdir = Path(argv[0])
    job = Job.from_json(json.loads((workdir / "job.json").read_text(encoding="utf-8")))
    result = evaluate(job, workdir)
    (workdir / "result.json").write_text(json.dumps(result.to_json()), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))


__all__ = ["Result", "evaluate", "Quality"]
