"""Bounded loops: for-range, for-in over arrays, while, do-while, break, continue."""

from __future__ import annotations

from ..feature import Choice, Feature, register
from ..gen import Gen
from ..types import BOOL, INT


@register
class Loops(Feature):
    name = "loops"
    summary = "for (range / array), while, do-while, break, continue"
    covers = ("EFor", "EWhile", "EBreak", "EContinue", "OpIn", "OpInterval", "NormalWhile", "DoWhile")
    order = 35

    def stmts(self, g: Gen):
        out = [
            Choice(4, lambda: self._range(g), nested=True),
            Choice(2, lambda: self._while(g, do_while=False), nested=True),
            Choice(1.5, lambda: self._while(g, do_while=True), nested=True),
            Choice(2, lambda: self._each(g), nested=True),
        ]
        if g.loop_depth:
            out.append(Choice(2, lambda: self._jump(g)))
        return out

    def _range(self, g: Gen) -> bool:
        i = g.fresh("i")
        low = g.pick(["0", "0", "1", "2"])
        high = g.pick(["3", "4", "5", "(1 + (" + g.expr(INT) + " & 3))"])
        with g.block(f"for ({i} in {low}...{high}) {{"):
            g.loop_depth += 1
            g.declare_var(i, INT, mutable=False)
            g.statements()
            g.loop_depth -= 1
        return True

    def _each(self, g: Gen) -> bool:
        arrays = [v for v in g.visible() if v.ty.name == "Array"]
        if not arrays:
            return False
        source = g.pick(arrays)
        item = g.fresh("it")
        with g.block(f"for ({item} in {source.name}) {{"):
            g.loop_depth += 1
            g.declare_var(item, source.ty.args[0], mutable=False)
            g.statements()
            g.loop_depth -= 1
        return True

    def _while(self, g: Gen, do_while: bool) -> bool:
        # The counter is bumped first thing, so `continue` cannot skip it and the loop ends.
        n = g.fresh("n")
        limit = g.between(2, 5)
        g.emit(f"var {n} = 0;")
        g.declare_var(n, INT, mutable=False)
        if do_while:
            header, footer = "do {", f"}} while ({n} < {limit});"
        else:
            header, footer = f"while ({n} < {limit}) {{", "}"
        with g.block(header, footer):
            g.emit(f"{n}++;")
            g.loop_depth += 1
            g.statements()
            g.loop_depth -= 1
        return True

    def _jump(self, g: Gen) -> bool:
        g.emit(f"if ({g.expr(BOOL)}) {g.pick(['break', 'continue'])};")
        return True
