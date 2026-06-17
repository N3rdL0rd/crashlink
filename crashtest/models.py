"""
Dataclass models.
"""

import json
import os
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

SIMILARITY_THRESHOLD = 0.70


@dataclass
class TestFile:
    """
    Represents a file and its content.
    """

    name: str
    content: str

    def to_json(self) -> dict:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict) -> "TestFile":
        return cls(**data)


@dataclass
class MethodComparison:
    """Opcode-level comparison result for a single method."""

    name: str
    similarity: float
    original_count: int
    recompiled_count: int
    orig_disasm: str = ""
    recomp_disasm: str = ""
    error: Optional[str] = None

    def to_json(self) -> dict:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict) -> "MethodComparison":
        return cls(
            name=data["name"],
            similarity=data["similarity"],
            original_count=data["original_count"],
            recompiled_count=data["recompiled_count"],
            orig_disasm=data.get("orig_disasm", ""),
            recomp_disasm=data.get("recomp_disasm", ""),
            error=data.get("error"),
        )


@dataclass
class OpcodeComparison:
    """Opcode-level comparison between original and recompiled bytecode."""

    overall_similarity: float
    methods: List[MethodComparison] = field(default_factory=list)
    recompile_error: Optional[str] = None

    def to_json(self) -> dict:
        return {
            "overall_similarity": self.overall_similarity,
            "methods": [m.to_json() for m in self.methods],
            "recompile_error": self.recompile_error,
        }

    @classmethod
    def from_json(cls, data: dict) -> "OpcodeComparison":
        return cls(
            overall_similarity=data["overall_similarity"],
            methods=[MethodComparison.from_json(m) for m in data.get("methods", [])],
            recompile_error=data.get("recompile_error"),
        )


@dataclass
class TestCase:
    """
    Represents a test case.
    """

    original: TestFile
    decompiled: TestFile
    ir: TestFile
    test_id: int
    failed: bool
    test_name: Optional[str] = None
    error: Optional[str] = None
    opcode_comparison: Optional[OpcodeComparison] = None
    layers: Optional[Dict[str, Any]] = None

    def to_json(self) -> dict:
        return {
            "original": self.original.to_json(),
            "decompiled": self.decompiled.to_json(),
            "ir": self.ir.to_json(),
            "test_id": self.test_id,
            "test_name": self.test_name,
            "failed": self.failed,
            "error": self.error,
            "opcode_comparison": self.opcode_comparison.to_json() if self.opcode_comparison else None,
            "layers": self.layers,
        }

    @classmethod
    def from_json(cls, data: dict) -> "TestCase":
        oc_data = data.get("opcode_comparison")
        return cls(
            original=TestFile.from_json(data["original"]),
            decompiled=TestFile.from_json(data["decompiled"]),
            ir=TestFile.from_json(data["ir"]),
            test_id=data["test_id"],
            test_name=data["test_name"],
            failed=data["failed"],
            error=data["error"] if data.get("error") else None,
            opcode_comparison=OpcodeComparison.from_json(oc_data) if oc_data else None,
            layers=data.get("layers"),
        )


@dataclass
class TestContext:
    """
    Represents the context for a complete test suite run.
    """

    version: str

    def to_json(self) -> dict:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict) -> "TestContext":
        return cls(**data)


@dataclass
class GitInfo:
    """
    Represents information about the git branch and commit, or lack thereof.
    """

    is_release: bool
    dirty: bool
    branch: Optional[str] = None
    commit: Optional[str] = None
    github: Optional[str] = None

    def to_json(self) -> dict:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict) -> "GitInfo":
        return cls(**data)


@dataclass
class Run:
    """
    Represents a complete test run with git+version info and multiple test cases.
    """

    git: GitInfo
    context: TestContext
    cases: List[TestCase]
    id: str
    timestamp: str
    status: str
    status_color: str = "#a6e3a1"

    def avg_similarity(self) -> Optional[float]:
        scores = [
            c.opcode_comparison.overall_similarity
            for c in self.cases
            if c.opcode_comparison and c.opcode_comparison.overall_similarity >= 0
        ]
        if not scores:
            return None
        return sum(scores) / len(scores)

    def to_json(self) -> dict:
        return {
            "git": self.git.to_json(),
            "context": self.context.to_json(),
            "cases": [case.to_json() for case in self.cases],
            "id": self.id,
            "timestamp": self.timestamp,
            "status": self.status,
            "status_color": self.status_color,
        }

    @classmethod
    def from_json(cls, data: dict) -> "Run":
        return cls(
            git=GitInfo.from_json(data["git"]),
            context=TestContext.from_json(data["context"]),
            cases=[TestCase.from_json(case) for case in data["cases"]],
            id=data["id"],
            timestamp=data["timestamp"],
            status=data["status"],
            status_color=data["status_color"],
        )


def save_run(run: Run, path: str) -> None:
    """Save run to JSON file."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(run.to_json(), f, indent=4)


def load_runs(path: str) -> List[Run]:
    """Load test runs from a folder."""
    runs = []
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(".json"):
                with open(os.path.join(root, file), "r") as f:
                    runs.append(Run.from_json(json.load(f)))
    return runs
