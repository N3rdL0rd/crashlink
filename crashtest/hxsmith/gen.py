"""The generator core: random choices, scopes, emission, and the typed expression/statement drivers.

`Gen` knows nothing about particular language constructs; features plug in
through `Feature` (see `feature.py`). Everything random flows through
`Gen.rng`, so a seed plus a feature set reproduces a program exactly.
"""

from __future__ import annotations

import random
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional, Sequence, Set, Tuple

from .feature import Choice, Feature
from .types import BOOL, FLOAT, INT, STRING, VOID, Ty


class GenError(Exception):
    """No way to build what was asked in the current context; the caller backs out."""


@dataclass
class Config:
    max_expr_depth: int = 2
    max_stmt_depth: int = 2
    block_size: Tuple[int, int] = (1, 4)
    main_statements: Tuple[int, int] = (6, 14)
    helper_functions: Tuple[int, int] = (2, 5)


@dataclass
class Var:
    name: str
    ty: Ty
    mutable: bool = True


@dataclass
class Fn:
    """Something callable. With a `receiver` it is a method: `<receiver expr>.name(args)`."""

    name: str
    params: Tuple[Ty, ...]
    ret: Ty
    receiver: Optional[Ty] = None


class Gen:
    def __init__(self, seed: int, features: Sequence[Feature], config: Optional[Config] = None) -> None:
        self.seed = seed
        self.rng = random.Random(seed)
        self.features = list(features)
        self.cfg = config or Config()
        self.class_name = f"Fuzz{seed}"

        self.lines: List[str] = []
        self.level = 0
        self.scopes: List[List[Var]] = [[]]
        self.expr_depth = 0
        self.effects = 0  # increment/decrement values built in the current statement
        self.stmt_depth = 0
        self.loop_depth = 0
        self.ret_ty: Optional[Ty] = None
        self._names: Dict[str, int] = {}

        self.decls: List[str] = []  # top-level declarations, in order
        self.members: List[str] = []  # members of the main class, besides main
        self.fns: List[Fn] = []  # everything callable, in definition order (so calls form a DAG)
        self.subtypes: Dict[Ty, List[Ty]] = {}  # a user type -> types assignable to it
        self.state: Dict[str, Any] = {}  # per-feature scratch space, keyed by feature name
        self.used: Set[str] = set()  # features that contributed to the output
        # Features whose `declare` has started. While declarations are generated, a feature of a
        # higher `order` has not set up its state yet, so it contributes nothing.
        self.ready: Set[str] = {f.name for f in features}

    @property
    def active(self) -> List[Feature]:
        return [f for f in self.features if f.name in self.ready]

    # ---- randomness -------------------------------------------------------------------

    def chance(self, p: float) -> bool:
        return self.rng.random() < p

    def between(self, lo: int, hi: int) -> int:
        return self.rng.randint(lo, hi)

    def pick(self, items: Sequence[Any]) -> Any:
        return items[self.rng.randrange(len(items))]

    def weighted(self, items: Sequence[Any], weights: Sequence[float]) -> Any:
        return self.rng.choices(items, weights=weights)[0]

    def fresh(self, prefix: str) -> str:
        n = self._names.get(prefix, 0)
        self._names[prefix] = n + 1
        return f"{prefix}{n}"

    # ---- emission ---------------------------------------------------------------------

    def emit(self, line: str = "") -> None:
        self.lines.append("\t" * self.level + line if line else "")

    @contextmanager
    def capture(self, level: int = 0) -> Iterator[List[str]]:
        """Redirect `emit` into a fresh buffer; the buffer outlives the context."""
        saved = (self.lines, self.level)
        self.lines, self.level = [], level
        try:
            yield self.lines
        finally:
            self.lines, self.level = saved

    @contextmanager
    def block(self, header: str, footer: str = "}") -> Iterator[None]:
        """`header`, an indented scope, `footer`. Emits nothing for the footer if it is empty."""
        self.emit(header)
        self.level += 1
        self.stmt_depth += 1
        self.scopes.append([])
        try:
            yield
        finally:
            self.scopes.pop()
            self.stmt_depth -= 1
            self.level -= 1
            if footer:
                self.emit(footer)

    @contextmanager
    def function(
        self, params: Sequence[Tuple[str, Ty]], ret: Optional[Ty], inherit: bool = False
    ) -> Iterator[None]:
        """The context of a function body: its parameters in scope, `return` typed, loops reset.
        A closure passes `inherit` to keep seeing the enclosing function's variables."""
        saved = (self.scopes, self.ret_ty, self.loop_depth, self.expr_depth)
        scope = [Var(n, t, True) for n, t in params]
        self.scopes = (self.scopes + [scope]) if inherit else [scope]
        self.ret_ty, self.loop_depth = ret, 0
        try:
            yield
        finally:
            self.scopes, self.ret_ty, self.loop_depth, self.expr_depth = saved

    # ---- scopes -----------------------------------------------------------------------

    def declare_var(self, name: str, ty: Ty, mutable: bool = True) -> Var:
        var = Var(name, ty, mutable)
        self.scopes[-1].append(var)
        return var

    def visible(self, ty: Optional[Ty] = None, mutable: bool = False) -> List[Var]:
        found: Dict[str, Var] = {}
        for scope in self.scopes:
            for var in scope:
                found[var.name] = var  # an inner declaration shadows an outer one
        return [v for v in found.values() if (ty is None or v.ty == ty) and (v.mutable or not mutable)]

    # ---- types ------------------------------------------------------------------------

    def subtype_choices(self, ty: Ty) -> List[Ty]:
        return [ty, *self.subtypes.get(ty, [])]

    def pick_type(self, depth: int = 0) -> Ty:
        options = [t for f in self.active for t in f.types(self, depth)]
        if not options:
            return INT
        return self.weighted([t for _, t in options], [w for w, _ in options])

    def show(self, expr: str, ty: Ty) -> str:
        """A String expression printing `expr` deterministically."""
        for feature in self.active:
            shown = feature.show(self, ty, expr)
            if shown is not None:
                self.used.add(feature.name)
                return shown
        return f"Std.string({expr})"

    # ---- expressions ------------------------------------------------------------------

    def _candidates(self, ty: Ty, leaf_only: bool) -> List[Choice]:
        found = []
        for feature in self.active:
            for choice in feature.exprs(self, ty):
                if leaf_only and not choice.leaf:
                    continue
                choice.feature = feature.name
                found.append(choice)
        return found

    def expr(self, ty: Ty) -> str:
        """An expression of exactly type `ty` (or a subtype)."""
        cands = self._candidates(ty, self.expr_depth >= self.cfg.max_expr_depth)
        while cands:
            choice = self.weighted(cands, [c.weight for c in cands])
            cands.remove(choice)
            self.expr_depth += 1
            try:
                built = choice.build()
            finally:
                self.expr_depth -= 1
            if built is not None:
                self.used.add(choice.feature)
                return built
        raise GenError(f"no way to build a {ty}")

    def exprs(self, *tys: Ty) -> List[str]:
        return [self.expr(t) for t in tys]

    # ---- statements -------------------------------------------------------------------

    def stmt(self) -> bool:
        """Emit one statement. Returns False if nothing could be built (nothing is left behind)."""
        self.effects = 0
        cands: List[Choice] = []
        for feature in self.active:
            for choice in feature.stmts(self):
                if choice.nested and self.stmt_depth >= self.cfg.max_stmt_depth:
                    continue
                choice.feature = feature.name
                cands.append(choice)
        while cands:
            choice = self.weighted(cands, [c.weight for c in cands])
            cands.remove(choice)
            mark = self._mark()
            try:
                built = choice.build()
            except GenError:
                self._reset(mark)
                continue
            if built:
                self.used.add(choice.feature)
                return True
            self._reset(mark)
        return False

    def _mark(self) -> tuple:
        return (
            len(self.lines),
            self.level,
            len(self.scopes),
            self.stmt_depth,
            self.loop_depth,
            self.expr_depth,
            len(self.scopes[-1]),
        )

    def _reset(self, mark: tuple) -> None:
        n, self.level, scopes, self.stmt_depth, self.loop_depth, self.expr_depth, inner = mark
        del self.lines[n:]
        del self.scopes[scopes:]
        del self.scopes[-1][inner:]

    def statements(self, count: Optional[int] = None) -> None:
        lo, hi = self.cfg.block_size
        for _ in range(count if count is not None else self.between(lo, hi)):
            self.stmt()

    def observe(self) -> None:
        """Print every mutable scalar in scope: the function's final state becomes observable."""
        for var in self.visible():
            if var.mutable and var.ty in (INT, FLOAT, BOOL, STRING):
                self.emit(f"Sys.println({self.show(var.name, var.ty)});")

    def body(self, ret: Optional[Ty], count: Optional[int] = None) -> None:
        """A function body: some statements, then the return value if there is one."""
        self.statements(count)
        self.observe()
        if ret is not None and ret != VOID:
            self.emit(f"return {self.expr(ret)};")
