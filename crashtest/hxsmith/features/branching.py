"""if/else, early return, switch on scalars, and switch/if as values."""

from __future__ import annotations

from ..feature import Choice, Feature, register
from ..gen import Gen
from ..types import BOOL, INT, STRING, VOID, Ty


@register
class Branching(Feature):
    name = "branching"
    summary = "if/else chains, early return, scalar switch (statement and expression)"
    covers = ("EIf", "ESwitch", "EReturn", "EBlock")
    order = 30

    def stmts(self, g: Gen):
        out = [
            Choice(4, lambda: self._if(g), nested=True),
            Choice(2, lambda: self._chain(g), nested=True),
            Choice(2, lambda: self._switch(g), nested=True),
            Choice(1, lambda: self._block(g), nested=True),
        ]
        if g.ret_ty is not None and g.ret_ty != VOID:
            out.append(Choice(1.5, lambda: self._early_return(g)))
        return out

    def exprs(self, g: Gen, ty: Ty):
        return [Choice(1, lambda: self._switch_value(g, ty)), Choice(1, lambda: self._if_value(g, ty))]

    # ---- statements -------------------------------------------------------------------

    def _if(self, g: Gen) -> bool:
        has_else = g.chance(0.5)
        with g.block(f"if ({g.expr(BOOL)}) {{", "" if has_else else "}"):
            g.statements()
        if has_else:
            with g.block("} else {"):
                g.statements()
        return True

    def _chain(self, g: Gen) -> bool:
        with g.block(f"if ({g.expr(BOOL)}) {{", ""):
            g.statements()
        for _ in range(g.between(1, 2)):
            with g.block(f"}} else if ({g.expr(BOOL)}) {{", ""):
                g.statements()
        with g.block("} else {"):
            g.statements()
        return True

    def _block(self, g: Gen) -> bool:
        with g.block("{"):
            g.statements()
        return True

    def _early_return(self, g: Gen) -> bool:
        assert g.ret_ty is not None
        g.emit(f"if ({g.expr(BOOL)}) return {g.expr(g.ret_ty)};")
        return True

    def _switch(self, g: Gen) -> bool:
        ty = g.pick([INT, STRING])
        subject = g.expr(ty)
        cases = self._patterns(g, ty)
        g.emit(f"switch ({subject}) {{")
        g.level += 1
        for pattern in cases:
            with g.block(f"case {pattern}:", ""):
                g.statements(g.between(1, 2))
        if g.chance(0.7):
            with g.block("default:", ""):
                g.statements(g.between(1, 2))
        g.level -= 1
        g.emit("}")
        return True

    # ---- expressions ------------------------------------------------------------------

    def _switch_value(self, g: Gen, ty: Ty) -> str:
        subject_ty = g.pick([INT, STRING])
        subject = g.expr(subject_ty)
        arms = [f"case {p}: {g.expr(ty)};" for p in self._patterns(g, subject_ty)]
        return f"(switch ({subject}) {{ {' '.join(arms)} default: {g.expr(ty)}; }})"

    def _if_value(self, g: Gen, ty: Ty) -> str:
        return f"(if ({g.expr(BOOL)}) {g.expr(ty)} else {g.expr(ty)})"

    # ---- helpers ----------------------------------------------------------------------

    def _patterns(self, g: Gen, ty: Ty) -> list:
        """Distinct constant patterns, some grouped (`case 1, 2:`)."""
        pool = ["0", "1", "2", "3", "5", "8", "13"] if ty == INT else ['"a"', '"b"', '"hello"', '""', '"x y"']
        g.rng.shuffle(pool)
        patterns = []
        for _ in range(g.between(1, 3)):
            width = g.between(1, 2)
            group, pool = pool[:width], pool[width:]
            if group:
                patterns.append(", ".join(group))
        return patterns
