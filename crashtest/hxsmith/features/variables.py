"""Locals: declaration, assignment (plain, compound, increment) and printing."""

from __future__ import annotations

import re
from typing import Optional

from ..feature import Choice, Feature, register
from ..gen import Gen, Var
from ..types import FLOAT, INT, STRING, Ty

_COMPOUND_INT = ["+=", "-=", "*=", "&=", "|=", "^="]


@register
class Variables(Feature):
    name = "variables"
    summary = "var/final declarations, assignment, compound assignment, ++/--, printing"
    covers = ("EVars", "EBinop", "EUnop", "OpAssign", "Increment", "Decrement")
    order = 15

    def stmts(self, g: Gen):
        return [
            Choice(5, lambda: self._declare(g)),
            Choice(4, lambda: self._assign(g)),
            Choice(2, lambda: self._compound(g)),
            Choice(1.5, lambda: self._step(g)),
            Choice(5, lambda: self._print(g)),
        ]

    def exprs(self, g: Gen, ty: Ty):
        if ty != INT:
            return []
        mutable = g.visible(INT, mutable=True)
        if not mutable:
            return []
        # Increment/decrement used as a value: the result depends on pre- vs post-form. At most one
        # per statement: two in one expression crash Haxe 4.3's HashLink generator
        # (`v = ((--v | 0) ^ (~++v))`).
        return [Choice(1, lambda: self._value_step(g, mutable), leaf=True)]

    def _value_step(self, g: Gen, mutable: list) -> Optional[str]:
        if g.effects:
            return None
        g.effects += 1
        return self._step_value(g, g.pick(mutable).name)

    def _declare(self, g: Gen) -> bool:
        ty = g.pick_type()
        value = g.expr(ty)
        name = g.fresh("v")
        final = g.chance(0.15)
        # Only these three are inferred exactly; anything else needs the annotation
        # (`var f = 1` is an Int, `var b = new Derived()` is not its base type).
        annotate = ty not in (INT, STRING) or g.chance(0.4)
        head = "final" if final else "var"
        g.emit(f"{head} {name}{f':{ty}' if annotate else ''} = {value};")
        g.declare_var(name, ty, mutable=not final)
        return True

    def _assign(self, g: Gen) -> bool:
        targets = g.visible(mutable=True)
        if not targets:
            return False
        var = g.pick(targets)
        value = g.expr(var.ty)
        # Haxe rejects assigning a variable to itself, also through inlined identity wrappers.
        if re.sub(r"[\w.]+\(", "", value).strip("()+-") == var.name:
            return False
        g.emit(f"{var.name} = {self._capped(var, value)};")
        return True

    def _compound(self, g: Gen) -> bool:
        targets = [v for v in g.visible(mutable=True) if v.ty in (INT, FLOAT, STRING)]
        if not targets:
            return False
        var = g.pick(targets)
        if var.ty == INT:
            op = g.pick(_COMPOUND_INT + ["<<=", ">>=", ">>>="])
            value = str(g.between(0, 31)) if "<" in op or ">" in op else g.expr(INT)
        elif var.ty == FLOAT:
            op, value = g.pick(["+=", "-=", "*="]), g.expr(FLOAT)
        else:
            op, value = "+=", self._capped(var, g.expr(g.pick([STRING, INT])), 8)
        g.emit(f"{var.name} {op} {value};")
        return True

    def _capped(self, var: Var, value: str, limit: int = 40) -> str:
        """A string that mentions itself would double in a loop; keep it bounded."""
        if var.ty == STRING and re.search(rf"\b{var.name}\b", value):
            return f"Std.string({value}).substr(0, {limit})"
        return value

    def _step(self, g: Gen) -> bool:
        targets = g.visible(INT, mutable=True)
        if not targets:
            return False
        g.emit(self._step_value(g, g.pick(targets).name) + ";")
        return True

    def _step_value(self, g: Gen, name: str) -> str:
        return g.pick([f"{name}++", f"++{name}", f"{name}--", f"--{name}"])

    def _print(self, g: Gen) -> bool:
        ty = g.pick_type()
        g.emit(f"Sys.println({g.show(g.expr(ty), ty)});")
        return True
