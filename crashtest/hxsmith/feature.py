"""The plug-in contract: one `Feature` per slice of the Haxe language.

A feature contributes any of:

- `declare`  top-level types and helper members, once per program
- `types`    value types the generator may pick for variables and parameters
- `exprs`    ways to build an expression of a requested type
- `stmts`    ways to emit a statement
- `show`     how to turn a value of one of its types into a deterministic String

A feature never calls another feature directly; it asks the `Gen` (`g.expr(ty)`,
`g.stmt()`, `g.fns`, ...), so features can be added, removed or restricted with
`--features`/`--exclude` without touching one another. Register one with
`@register`; modules under `features/` are imported automatically.

`covers` names what the feature exercises: constructors of `expr_def` in
`haxe/src/core/ast.ml`, or `decl:<kind>` / `std:<name>` tags for things the AST
does not list. `crashtest hxsmith coverage` checks this table against the
Haxe source so a language construct nobody generates is visible.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Dict, Iterable, List, Optional, Sequence, Union

if TYPE_CHECKING:
    from .gen import Gen
    from .types import Ty


@dataclass
class Choice:
    """One way to build something. `build` returns None to decline, having emitted nothing.

    leaf     usable when the expression budget is spent (must not recurse into `g.expr`
             for a type that can recurse unboundedly)
    nested   a statement that opens blocks; unavailable at the statement-depth limit
    Statement builders return True on success; expression builders return the source text.
    """

    weight: float
    build: Callable[[], Union[str, bool, None]]
    leaf: bool = False
    nested: bool = False
    feature: str = ""


class Feature:
    name: str = ""
    summary: str = ""
    covers: Sequence[str] = ()
    requires: Sequence[str] = ()
    order: int = 50  # `declare` runs in ascending order

    def declare(self, g: "Gen") -> None:
        pass

    def types(self, g: "Gen", depth: int) -> Iterable[tuple]:
        """(weight, Ty) pairs. `depth` is how deeply a composite type is nested."""
        return ()

    def exprs(self, g: "Gen", ty: "Ty") -> Iterable[Choice]:
        return ()

    def stmts(self, g: "Gen") -> Iterable[Choice]:
        return ()

    def show(self, g: "Gen", ty: "Ty", expr: str) -> Optional[str]:
        """A String-typed expression printing `expr`, or None to defer to the next feature."""
        return None


REGISTRY: Dict[str, Feature] = {}


def register(cls: type) -> type:
    feature = cls()
    if not feature.name:
        raise ValueError(f"{cls.__name__} has no name")
    if feature.name in REGISTRY:
        raise ValueError(f"duplicate feature {feature.name!r}")
    REGISTRY[feature.name] = feature
    return cls


def resolve(only: Optional[Iterable[str]] = None, exclude: Iterable[str] = ()) -> List[Feature]:
    """The enabled features in `declare` order, with their `requires` pulled in."""
    from . import features  # noqa: F401  (imports every feature module)

    unknown = [n for n in list(only or []) + list(exclude) if n not in REGISTRY]
    if unknown:
        raise KeyError(f"unknown feature(s) {', '.join(unknown)}; known: {', '.join(sorted(REGISTRY))}")
    wanted = set(only) if only else set(REGISTRY)
    wanted -= set(exclude)
    wanted.add("literals")
    pending = list(wanted)
    while pending:
        for need in REGISTRY[pending.pop()].requires:
            if need not in wanted:
                wanted.add(need)
                pending.append(need)
    return sorted((REGISTRY[n] for n in wanted), key=lambda f: (f.order, f.name))
