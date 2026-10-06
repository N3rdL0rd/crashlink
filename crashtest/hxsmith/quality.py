"""The decompilation-quality ladder.

Every decompiled program lands on exactly one rung, the highest it reaches.
Rungs are ordered so a regression is simply `new < old`.

`classify` is a pure function of what each pipeline stage observed, so the
rules live in one place and are testable without Haxe, HashLink or a bytecode
image. The stages themselves are in `pipeline.py`.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional

from ..behavior import BehavioralComparison


class Quality(IntEnum):
    """How far a decompilation got. Higher is better."""

    CRASH = 0  # the decompiler raised, hung, or emitted a "decompilation failed" stub
    UNLIFTED = 1  # output still contains raw opcodes the lifter could not express
    NO_COMPILE = 2  # output does not typecheck/compile with Haxe
    DIVERGES = 3  # compiles, but the program behaves differently on the real runtime
    BEHAVES = 4  # same observable behaviour as the original
    IDENTICAL = 5  # same behaviour and the same opcode sequence in every user function

    @property
    def meaning(self) -> str:
        return _MEANING[self]


_MEANING = {
    Quality.CRASH: "decompiler crashed, hung or gave up on a type",
    Quality.UNLIFTED: "output contains UNLIFTED OPCODE markers",
    Quality.NO_COMPILE: "decompiled source does not compile",
    Quality.DIVERGES: "compiles but behaves differently",
    Quality.BEHAVES: "behaves identically",
    Quality.IDENTICAL: "behaves identically and recompiles to the same opcodes",
}


@dataclass
class Observation:
    """What each pipeline stage saw. A stage that did not run is left at its default."""

    decompile_error: Optional[str] = None
    decompiled: Dict[str, str] = field(default_factory=dict)
    compile_error: Optional[str] = None
    behavior: Optional[BehavioralComparison] = None
    # Mean opcode-sequence similarity over the original's user functions, 1.0 = every one equal.
    similarity: Optional[float] = None
    # User functions whose opcode sequence differs, worst first: (name, similarity).
    differing: List[tuple] = field(default_factory=list)


@dataclass
class Verdict:
    quality: Quality
    stage: str  # decompile | lift | compile | run | compare
    detail: str = ""
    # A short stable string for grouping the same failure across programs.
    signature: str = ""
    similarity: Optional[float] = None
    differing: List[tuple] = field(default_factory=list)

    def to_json(self) -> dict:
        data = asdict(self)
        data["quality"] = self.quality.name
        return data

    @classmethod
    def from_json(cls, data: dict) -> "Verdict":
        data = dict(data)
        data["quality"] = Quality[data["quality"]]
        data["differing"] = [tuple(d) for d in data.get("differing", [])]
        return cls(**data)


_UNLIFTED = re.compile(r"UNLIFTED OPCODE: (\w+)")
_FAILED = re.compile(r"decompilation failed: (.*)")


def normalize(message: str) -> str:
    """Strip what varies between instances of one failure: numbers, positions, generated names."""
    lines = [line for line in message.splitlines() if line.strip()]
    # "Haxe compilation failed:" is a header; the error is on the next line.
    first = next((line for line in lines if not line.rstrip().endswith("failed:")), lines[0] if lines else "")
    first = re.sub(r"[^\s:]*Fuzz\d+\.hx:\d+:?( characters? \d+(-\d+)?)?", "<pos>", first)
    first = re.sub(r"\bFuzz\d+", "Fuzz", first)
    first = re.sub(r"\bf@\d+", "f@N", first)
    first = re.sub(r"\b[a-z]+_?\d+\b", "<id>", first)
    return re.sub(r"\d+", "N", first).strip()[:160]


_POSITION = re.compile(r"^\S*\.hx:\d+:\s*(?:characters \d+-\d+|lines \d+-\d+)?\s*:?\s*")


def error_kinds(detail: str) -> frozenset:
    """The distinct kinds of Haxe error in a compiler report. Haxe reports every error, so a
    program can have several unrelated ones; the first alone would hide the rest. Positions,
    numbers and the member named in `has no field X` are stripped so one bug is one kind."""
    kinds = set()
    for line in detail.splitlines():
        if not _POSITION.match(line) or "Warning" in line:
            continue
        message = _POSITION.sub("", line).strip()
        if message.startswith("..."):  # context for the error above it
            continue
        message = re.sub(r"has no field \w+", "has no field <name>", message)
        message = re.sub(r"Class<[^>]*>", "Class<T>", message)
        message = re.sub(r"\bf@\d+", "f@N", message)
        kinds.add(re.sub(r"\d+", "N", message)[:120])
    return frozenset(kinds)


def _diff_signature(behavior: BehavioralComparison) -> str:
    a, b = behavior.original, behavior.recompiled
    if (
        behavior.error
        and "not deterministic" not in behavior.error
        and behavior.error != "Behavior differs (stdout, stderr, or exit status)"
    ):
        return "run: " + normalize(behavior.error)
    parts = []
    if a.returncode != b.returncode:
        parts.append(f"exit {a.returncode}->{b.returncode}")
    if a.stdout != b.stdout:
        parts.append("stdout")
    if a.stderr != b.stderr:
        parts.append("stderr")
    return "differs: " + ",".join(parts or ["?"])


def first_difference(behavior: BehavioralComparison) -> str:
    """The first output line that differs, for a human looking at a DIVERGES verdict."""
    left = behavior.original.stdout.splitlines()
    right = behavior.recompiled.stdout.splitlines()
    for n, (x, y) in enumerate(zip(left, right), 1):
        if x != y:
            return f"stdout line {n}: original {x!r} vs recompiled {y!r}"
    if len(left) != len(right):
        return f"stdout length: original {len(left)} lines vs recompiled {len(right)}"
    return behavior.error or "stderr or exit status differs"


def classify(obs: Observation) -> Verdict:
    """Place an observation on the ladder, taking the first failing rung from the bottom."""
    if obs.decompile_error:
        return Verdict(
            Quality.CRASH, "decompile", obs.decompile_error, "crash: " + normalize(obs.decompile_error)
        )
    text = "\n".join(obs.decompiled.values())
    failed = _FAILED.search(text)
    if failed:
        return Verdict(Quality.CRASH, "decompile", failed.group(1), "gave up: " + normalize(failed.group(1)))
    unlifted = sorted(set(_UNLIFTED.findall(text)))
    if unlifted:
        return Verdict(Quality.UNLIFTED, "lift", ", ".join(unlifted), "unlifted: " + ",".join(unlifted))
    if obs.compile_error:
        return Verdict(
            Quality.NO_COMPILE, "compile", obs.compile_error, "compile: " + normalize(obs.compile_error)
        )
    behavior = obs.behavior
    if behavior is None or not behavior.passed:
        if behavior is None:
            return Verdict(Quality.DIVERGES, "run", "behaviour was not compared", "run: not compared")
        return Verdict(Quality.DIVERGES, "run", first_difference(behavior), _diff_signature(behavior))
    if obs.similarity is not None and obs.similarity >= 1.0 and not obs.differing:
        return Verdict(Quality.IDENTICAL, "compare", similarity=obs.similarity)
    detail = f"mean opcode similarity {obs.similarity:.3f}" if obs.similarity is not None else ""
    return Verdict(
        Quality.BEHAVES,
        "compare",
        detail,
        "behaves",
        similarity=obs.similarity,
        differing=list(obs.differing),
    )
