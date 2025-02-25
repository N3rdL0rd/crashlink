"""
Dataclass models.
"""

import json
import os
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple


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

    def to_json(self) -> dict:
        return {
            "original": self.original.to_json(),
            "decompiled": self.decompiled.to_json(),
            "ir": self.ir.to_json(),
            "test_id": self.test_id,
            "test_name": self.test_name,
            "failed": self.failed,
            "error": self.error,
        }

    @classmethod
    def from_json(cls, data: dict) -> "TestCase":
        return cls(
            original=TestFile.from_json(data["original"]),
            decompiled=TestFile.from_json(data["decompiled"]),
            ir=TestFile.from_json(data["ir"]),
            test_id=data["test_id"],
            test_name=data["test_name"],
            failed=data["failed"],
            error=data["error"] if data["error"] else None,
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
