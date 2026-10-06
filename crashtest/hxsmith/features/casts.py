"""Dynamic, casts, type checks, `untyped`, `Null<T>` and `??`."""

from __future__ import annotations

from typing import List

from ..feature import Choice, Feature, register
from ..gen import Gen
from ..types import BOOL, DYNAMIC, FLOAT, INT, SCALARS, STRING, Ty, null_of

_NULLABLE = (INT, STRING)
_NUMERIC_OPS = ["+", "-", "*"]


@register
class Casts(Feature):
    name = "casts"
    summary = "Dynamic values and arithmetic, cast, (e : T), is/isOfType, untyped, Null<T>, ??"
    covers = (
        "ECast",
        "EIs",
        "ECheckType",
        "EUntyped",
        "EBinop",
        "EIf",
        "OpNullCoal",
        "OpAssignOp",
        "OpAdd",
        "OpSub",
        "OpMult",
        "OpEq",
        "OpNotEq",
        "OpLt",
        "std:Std.isOfType",
        "std:Dynamic",
        "std:Null",
    )
    order = 47

    # ---- types ------------------------------------------------------------------------
    def declare(self, g: Gen) -> None:
        name = g.fresh("dyn")
        g.members.append(f"\tstatic function {name}(v:Dynamic):Dynamic {{\n\t\treturn v;\n\t}}")
        g.state[self.name] = name

    def types(self, g: Gen, depth: int):
        if depth:
            return []
        return [(1.5, DYNAMIC), (1, null_of(INT)), (1, null_of(STRING))]

    def show(self, g: Gen, ty: Ty, expr: str):
        if ty == DYNAMIC or ty.name == "Null":
            return f"Std.string({expr})"
        return None

    # ---- expressions ------------------------------------------------------------------

    def exprs(self, g: Gen, ty: Ty):
        if ty == DYNAMIC:
            return [
                Choice(3, lambda: self._dyn(g, g.pick(SCALARS)), leaf=True),
                Choice(2, lambda: self._dyn_arith(g)),
                Choice(1, lambda: f"(cast {self._dyn(g, g.pick(SCALARS))} : Dynamic)"),
            ]
        if ty.name == "Null" and ty.args[0] in _NULLABLE:
            inner = ty.args[0]
            return [
                Choice(2, lambda: f"(null : {ty})", leaf=True),
                Choice(2, lambda: g.expr(inner), leaf=True),
                Choice(1, lambda: f"(if ({g.expr(BOOL)}) (null : {ty}) else {g.expr(inner)})"),
                Choice(1, lambda: f"({g.expr(ty)} ?? {g.expr(ty)})"),
            ]
        out: List[Choice] = []
        if ty in _NULLABLE:
            out.append(Choice(2, lambda: f"({g.expr(null_of(ty))} ?? {g.expr(ty)})"))
        if ty in SCALARS:
            out += [
                Choice(2, lambda: f"cast({self._dyn(g, ty)}, {ty})"),
                Choice(2, lambda: f"(cast {self._dyn(g, ty)} : {ty})"),
                Choice(1.5, lambda: f"({g.expr(ty)} : {ty})"),
                Choice(1, lambda: self._untyped(g, ty)),
            ]
        if ty != BOOL and ty in SCALARS:
            out.append(Choice(2, lambda: self._dyn_result(g, ty)))
        if ty == BOOL:
            out += [
                Choice(2, lambda: self._is(g)),
                Choice(1.5, lambda: self._dyn_compare(g)),
            ]
        return out

    def _dyn(self, g: Gen, ty: Ty) -> str:
        """A `ty`-valued expression whose static type is really Dynamic.

        `(e : Dynamic)` would not do: haxe keeps the operand's own type, so `c ? ("a" : Dynamic) : (false : Dynamic)`
        fails in the HashLink generator and `(1 : Dynamic) + 2` is plain Int arithmetic."""
        value = g.expr(ty)
        if g.chance(0.3):
            t = g.fresh("t")
            return f"({{ var {t}:Dynamic = {value}; {t}; }})"
        return f"{g.state[self.name]}({value})"

    def _is(self, g: Gen) -> str:
        subject, target = g.expr(DYNAMIC), g.pick([INT, FLOAT, STRING, BOOL])
        if g.chance(0.5):
            return f"Std.isOfType({subject}, {target})"
        return f"({subject} is {target})"

    def _operands(self, g: Gen, ty: Ty) -> tuple:
        """Operand types whose Dynamic sum is defined on HashLink and whose result is `ty` at runtime."""
        if ty == INT:
            return INT, INT
        if ty == FLOAT:
            return g.pick([(FLOAT, FLOAT), (FLOAT, INT), (INT, FLOAT)])
        return STRING, g.pick([STRING, INT, FLOAT])

    def _dyn_result(self, g: Gen, ty: Ty) -> str:
        left, right = self._operands(g, ty)
        op = "+" if ty == STRING else g.pick(_NUMERIC_OPS)
        return f"(cast ({self._dyn(g, left)} {op} {g.expr(right)}) : {ty})"

    def _dyn_arith(self, g: Gen) -> str:
        ty = g.pick([INT, FLOAT, STRING])
        left, right = self._operands(g, ty)
        op = "+" if ty == STRING else g.pick(_NUMERIC_OPS)
        return f"({self._dyn(g, left)} {op} {g.expr(right)})"

    def _dyn_compare(self, g: Gen) -> str:
        ty = g.pick(SCALARS)
        ops = ["==", "!="] if ty in (STRING, BOOL) else ["==", "!=", "<"]
        return f"({self._dyn(g, ty)} {g.pick(ops)} {g.expr(ty)})"

    def _untyped(self, g: Gen, ty: Ty) -> str:
        op = "&&" if ty == BOOL else "+" if ty == STRING else g.pick(_NUMERIC_OPS)
        return f"((untyped ({g.expr(ty)} {op} {g.expr(ty)})) : {ty})"

    # ---- statements -------------------------------------------------------------------

    def stmts(self, g: Gen):
        return [
            Choice(2, lambda: self._dispatch(g), nested=True),
            Choice(2, lambda: self._dyn_update(g)),
            Choice(2, lambda: self._null_check(g), nested=True),
        ]

    def _dispatch(self, g: Gen) -> bool:
        """Test a Dynamic's runtime type, then read it back as that type through different casts."""
        d = g.fresh("d")
        g.emit(f"var {d}:Dynamic = {g.expr(DYNAMIC)};")
        g.declare_var(d, DYNAMIC)
        order = g.rng.sample([INT, FLOAT, STRING, BOOL], g.between(2, 4))
        for i, ty in enumerate(order):
            test = g.pick([f"Std.isOfType({d}, {ty})", f"{d} is {ty}"])
            head = f"if ({test}) {{" if i == 0 else f"}} else if ({test}) {{"
            with g.block(head, ""):
                v = g.fresh("c")
                form = g.pick(
                    [f"var {v}:{ty} = {d};", f"var {v} = cast({d}, {ty});", f"var {v} = ({d} : {ty});"]
                )
                g.emit(form)
                g.declare_var(v, ty, mutable=False)
                g.emit(f"Sys.println({g.show(self._use(g, v, ty), ty)});")
        with g.block("} else {", ""):
            g.emit(f"Sys.println({g.show(d, DYNAMIC)});")
        g.emit("}")
        return True

    def _use(self, g: Gen, v: str, ty: Ty) -> str:
        if ty == INT:
            return f"({v} + 1)"
        if ty == FLOAT:
            return f"({v} * 2)"
        if ty == STRING:
            return f'({v} + "!")'
        return f"(!{v})"

    def _dyn_update(self, g: Gen) -> bool:
        """A Dynamic local updated in place with compound assignment or ++."""
        ty = g.pick([INT, FLOAT, STRING])
        left, right = self._operands(g, ty)
        d = g.fresh("d")
        g.emit(f"var {d}:Dynamic = {g.expr(left)};")
        g.declare_var(d, DYNAMIC)
        if ty != STRING and g.chance(0.3) and left == INT:
            g.emit(f"{d}{g.pick(['++', '--'])};")
        else:
            op = "+" if ty == STRING else g.pick(_NUMERIC_OPS)
            g.emit(f"{d} {op}= {g.expr(right)};")
        g.emit(f"Sys.println({g.show(d, DYNAMIC)});")
        return True

    def _null_check(self, g: Gen) -> bool:
        nullable = [v for v in g.visible() if v.ty.name == "Null" and v.ty.args[0] in _NULLABLE]
        if nullable and g.chance(0.6):
            var = g.pick(nullable)
            name, inner = var.name, var.ty.args[0]
        else:
            inner = g.pick(_NULLABLE)
            name = g.fresh("nv")
            g.emit(f"var {name}:Null<{inner}> = {g.expr(null_of(inner))};")
            var = g.declare_var(name, null_of(inner))
        use = f"({name} + 1)" if inner == INT else f'({name} + "!")'
        if var.mutable and g.chance(0.3):
            g.emit(f"{name} ??= {g.expr(inner)};")
        with g.block(f"if ({name} != null) {{", ""):
            g.emit(f"Sys.println({g.show(use, inner)});")
        with g.block("} else {", ""):
            g.emit(f'Sys.println("{name} is null");')
        g.emit("}")
        return True
