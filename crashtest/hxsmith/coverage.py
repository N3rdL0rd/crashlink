"""Which constructs of the Haxe parser's AST does some feature generate?

The vocabulary is read from `src/core/ast.ml` of a Haxe checkout, so it follows
the language as it evolves; `Feature.covers` claims constructors from it. This
reports claimed, unclaimed and deliberately excluded constructors, and is how
you find the next feature to write.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

from .feature import REGISTRY, resolve

DEFAULT_HAXE = Path.home() / "code" / "haxe"

# ast.ml types whose constructors are language constructs worth generating.
SECTIONS = (
    "constant",
    "binop",
    "unop",
    "expr_def",
    "function_kind",
    "efield_kind",
    "while_flag",
    "access",
    "class_flag",
    "class_field_kind",
    "type_def",
)

# Constructs hxsmith does not generate, and why. Anything else unclaimed is a gap.
EXCLUDED = {
    "EDisplay": "IDE completion marker; never in compiled code",
    "AMacro": "macros run at compile time and leave no trace in bytecode",
    "HExtern": "extern classes have no bytecode",
    "EStatic": "module-level statics are produced by the same code path as class statics",
}

_SECTION = r"^(?:type|and) %s =\n((?:\s*\|.*\n|\s*\(\*.*\n)+)"


@dataclass
class Coverage:
    claimed: Dict[str, List[str]]  # constructor -> features claiming it
    unclaimed: List[str]
    excluded: Dict[str, str]
    unknown: Dict[str, List[str]]  # claimed by a feature but absent from ast.ml (typos, renames)

    def render(self) -> str:
        total = len(self.claimed) + len(self.unclaimed)
        lines = [f"AST coverage: {len(self.claimed)}/{total} constructors claimed"]
        if self.unclaimed:
            lines.append("\nnot generated yet:\n  " + ", ".join(self.unclaimed))
        if self.excluded:
            lines.append("\nexcluded on purpose:")
            lines += [f"  {name}: {why}" for name, why in sorted(self.excluded.items())]
        if self.unknown:
            lines.append("\nclaimed but not in ast.ml:")
            lines += [f"  {name} (by {', '.join(by)})" for name, by in sorted(self.unknown.items())]
        return "\n".join(lines)


def vocabulary(haxe: Path = DEFAULT_HAXE) -> List[str]:
    """Every constructor of the `SECTIONS` types in `ast.ml`."""
    text = (haxe / "src" / "core" / "ast.ml").read_text(encoding="utf-8")
    names: List[str] = []
    for section in SECTIONS:
        match = re.search(_SECTION % re.escape(section), text, re.M)
        if match is None:
            raise ValueError(f"type {section!r} not found in ast.ml; update coverage.SECTIONS")
        names += re.findall(r"^\s*\|\s*(\w+)", match.group(1), re.M)
    return list(dict.fromkeys(names))


def measure(haxe: Path = DEFAULT_HAXE) -> Coverage:
    resolve()  # load every feature module
    known = vocabulary(haxe)
    claimed: Dict[str, List[str]] = {}
    for feature in REGISTRY.values():
        for name in feature.covers:
            claimed.setdefault(name, []).append(feature.name)
    unknown = {n: by for n, by in claimed.items() if n not in known and not n.startswith(("decl:", "std:"))}
    claimed = {n: by for n, by in claimed.items() if n in known}
    excluded = {n: why for n, why in EXCLUDED.items() if n in known and n not in claimed}
    unclaimed = [n for n in known if n not in claimed and n not in excluded]
    return Coverage(claimed, unclaimed, excluded, unknown)
