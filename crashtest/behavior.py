"""Differential execution on the real HashLink runtime, never an emulated fallback.

Fixtures must expose return values, mutations and caught exceptions through output.
Only terminating, repeatable observations can pass; unhandled errors, missing tools,
output floods and timeouts fail closed. This is a corpus oracle, not equivalence
proof for unexecuted branches or nondeterministic/interactive programs.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path


def resolve_hl_runtime() -> str | None:
    """Find the HashLink runtime to execute against.

    `HL_RUNTIME` (an absolute path) always wins when set, e.g. for CI or a
    non-standard install. Otherwise, `hl` on PATH is used directly - no env
    var required for the common case of a normal local HashLink install.
    """
    return os.environ.get("HL_RUNTIME") or shutil.which("hl")


@dataclass
class Execution:
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    error: str | None = None


@dataclass
class BehavioralComparison:
    passed: bool
    original: Execution
    recompiled: Execution
    error: str | None = None
    runtime: str = "HashLink"
    exemption_reason: str | None = None

    def to_json(self) -> dict:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict) -> BehavioralComparison:
        return cls(
            passed=data["passed"],
            original=Execution(**data["original"]),
            recompiled=Execution(**data["recompiled"]),
            error=data.get("error"),
            runtime=data.get("runtime", "HashLink"),
            exemption_reason=data.get("exemption_reason"),
        )


def execute(command: list[str], cwd: str, timeout: float = 5.0) -> Execution:
    """Run with no input, isolated cwd, bounded output, and a hard deadline."""
    env = dict(os.environ, LC_ALL="C", TZ="UTC")
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            proc = subprocess.Popen(
                command,
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                start_new_session=os.name == "posix",
            )
        except OSError as exc:
            return Execution(error=f"Execution unavailable: {exc}")
        deadline = time.monotonic() + timeout
        error = None
        while proc.poll() is None:
            if time.monotonic() >= deadline:
                error = f"Execution timed out after {timeout:g}s"
                break
            if os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size > 1024 * 1024:
                error = "Execution exceeded the 1 MiB output limit"
                break
            time.sleep(0.01)
        if error:
            if os.name == "posix":
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                proc.kill()
        proc.wait()
        if os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size > 1024 * 1024:
            error = "Execution exceeded the 1 MiB output limit"
        stdout.seek(0)
        stderr.seek(0)
        return Execution(
            stdout.read(1024 * 1024).decode("utf-8", errors="replace"),
            stderr.read(1024 * 1024).decode("utf-8", errors="replace"),
            proc.returncode,
            error,
        )


def compile_haxe(source: str, class_name: str, directory: Path) -> tuple[Path, str | None]:
    """Compile one self-contained Haxe module for HashLink, retaining its artifact."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{class_name}.hx").write_text(source, encoding="utf-8")
    target = directory / "program.hl"
    result = execute(
        ["haxe", "-hl", str(target), "-cp", str(directory), "-main", class_name],
        str(directory),
        timeout=30,
    )
    error = result.error
    if not error and result.returncode != 0:
        error = f"Haxe compilation failed:\n{result.stderr}"
    return target, error


def normalize_positions(text: str, class_name: str) -> str:
    """Strip source positions that only encode the module's own layout.

    The fixture is compiled from `tests/haxe/<Class>.hx` and the decompiled
    program from `<Class>.hx` in a sandbox, and the decompiled source has its
    own line numbering, so neither trace prefixes (`<Class>.hx:12: `) nor stack
    frames (`Called from $C.main(<Class>.hx:12)`) are comparable. Everything
    else — values, messages, frame order, function names — is.
    """
    module = re.escape(class_name)
    text = re.sub(rf"(?m)^[^\s:]*{module}\.hx:\d+: ", "", text)
    return re.sub(rf"[^\s()]*{module}\.hx:\d+", f"{class_name}.hx:?", text)


def compare_programs(
    original: Path, recompiled: Path, class_name: str, timeout: float = 5.0
) -> BehavioralComparison:
    runtime = resolve_hl_runtime()
    if not runtime:
        error = "HashLink runtime unavailable; set HL_RUNTIME or install hl on PATH"
        return BehavioralComparison(False, Execution(), Execution(), error)
    runtime = str(Path(runtime).resolve())
    observations = []
    # Repetition rejects random/time-dependent output instead of calling an
    # accidental match semantic success. Each execution gets a fresh sandbox.
    for program in (original, recompiled, original, recompiled):
        with tempfile.TemporaryDirectory(prefix="crashtest-exec-") as tmp:
            target = Path(tmp) / "program.hl"
            shutil.copyfile(program, target)
            result = execute([runtime, str(target)], tmp, timeout)
        result.stdout = normalize_positions(result.stdout, class_name)
        result.stderr = normalize_positions(result.stderr, class_name)
        observations.append(result)
        # A program that reports a failure is still an observation: fixtures
        # that end in an uncaught exception are precisely where decompiled
        # exception handling has to be checked. Only an unusable execution —
        # timeout, output flood, spawn failure — makes comparison impossible.
        if result.error:
            return BehavioralComparison(
                False,
                observations[0],
                observations[1] if len(observations) > 1 else Execution(),
                result.error,
            )
    before, after, before_again, after_again = observations
    if before != before_again or after != after_again:
        return BehavioralComparison(False, before, after, "Execution is not deterministic")
    if before != after:
        return BehavioralComparison(False, before, after, "Behavior differs (stdout, stderr, or exit status)")
    return BehavioralComparison(True, before, after)
