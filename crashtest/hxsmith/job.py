"""One program to evaluate, independent of where it came from (generator, corpus, a file)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List, Tuple


@dataclass
class Job:
    name: str  # unique label; also the artifact folder name
    class_name: str  # the main class: `haxe -main`, and the name positions are normalised against
    sources: Dict[str, str]  # relative path -> text, written into the original's build folder
    classpaths: List[str] = field(default_factory=list)  # extra -cp roots (absolute)
    # Stems of the source files whose functions are compared opcode by opcode; the rest
    # (std, shims, harness) would only add noise. Empty means just `class_name`.
    modules: List[str] = field(default_factory=list)
    features: Tuple[str, ...] = ()
    origin: str = ""  # where the program came from, for the report

    def compared_modules(self) -> List[str]:
        return self.modules or [self.class_name]

    def to_json(self) -> dict:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict) -> "Job":
        data = dict(data)
        data["features"] = tuple(data.get("features", ()))
        return cls(**data)
