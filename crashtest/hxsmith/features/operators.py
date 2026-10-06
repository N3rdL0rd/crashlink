"""Arithmetic, bitwise, comparison, logical and string operators, ternaries, std math."""

from __future__ import annotations

from ..feature import Choice, Feature, register
from ..gen import Gen
from ..types import BOOL, FLOAT, INT, STRING, Ty

_INT_BIN = ["+", "-", "*", "&", "|", "^"]
_SHIFT = ["<<", ">>", ">>>"]
_CMP = ["<", "<=", ">", ">=", "==", "!="]
_MATH = ["Math.abs", "Math.floor", "Math.ceil", "Math.round"]


@register
class Operators(Feature):
    name = "operators"
    summary = "binary/unary operators, ternary, parentheses, Math"
    covers = (
        "EBinop",
        "EUnop",
        "EParenthesis",
        "ETernary",
        "OpDiv",
        "OpMod",
        "OpShl",
        "OpShr",
        "OpUShr",
        "OpAnd",
        "OpOr",
        "OpXor",
        "OpGt",
        "OpGte",
        "OpLte",
        "OpBoolAnd",
        "OpBoolOr",
        "Not",
        "Neg",
        "NegBits",
    )
    order = 20

    def exprs(self, g: Gen, ty: Ty):
        out = [Choice(1, lambda: self._ternary(g, ty))]
        if ty == INT:
            out += [
                Choice(4, lambda: self._bin(g, INT, g.pick(_INT_BIN))),
                Choice(1.5, lambda: f"({g.expr(INT)} {g.pick(_SHIFT)} {g.between(0, 31)})"),
                Choice(1.5, lambda: f"({g.expr(INT)} % {self._nonzero(g)})"),
                Choice(1, lambda: f"(- {g.expr(INT)})"),
                Choice(1, lambda: f"(~{g.expr(INT)})"),
                Choice(1, lambda: f"Std.int({g.expr(FLOAT)})"),
                Choice(1, lambda: f"Std.int({g.expr(INT)} / {self._nonzero(g)})"),
                Choice(0.7, lambda: f"{g.pick(['Math.floor', 'Math.ceil', 'Math.round'])}({g.expr(FLOAT)})"),
            ]
        elif ty == FLOAT:
            out += [
                Choice(3, lambda: self._bin(g, FLOAT, g.pick(["+", "-", "*"]))),
                Choice(1.5, lambda: f"({g.expr(FLOAT)} / {self._nonzero_float(g)})"),
                Choice(1.5, lambda: f"({g.expr(INT)} / {self._nonzero(g)})"),  # Int / Int is a Float
                Choice(1, lambda: f"({g.expr(INT)} + {g.expr(FLOAT)})"),  # Int promoted to Float
                Choice(1, lambda: f"(- {g.expr(FLOAT)})"),
                Choice(1, lambda: f"Math.sqrt(Math.abs({g.expr(FLOAT)}))"),
                Choice(0.7, lambda: f"{g.pick(['Math.sin', 'Math.cos', 'Math.abs'])}({g.expr(FLOAT)})"),
            ]
        elif ty == BOOL:
            out += [
                Choice(3, lambda: self._compare(g, g.pick([INT, FLOAT, STRING]))),
                Choice(2, lambda: f"({g.expr(BOOL)} {g.pick(['&&', '||'])} {g.expr(BOOL)})"),
                Choice(1, lambda: f"(!{g.expr(BOOL)})"),
                Choice(0.5, lambda: f"({g.expr(BOOL)} {g.pick(['==', '!='])} {g.expr(BOOL)})"),
            ]
        elif ty == STRING:
            out += [
                Choice(3, lambda: f"({g.expr(STRING)} + {g.expr(STRING)})"),
                Choice(2, lambda: f"({g.expr(STRING)} + {g.expr(g.pick([INT, FLOAT, BOOL]))})"),
                Choice(1, lambda: f"({g.expr(INT)} + {g.expr(STRING)})"),
            ]
        return out

    def _bin(self, g: Gen, ty: Ty, op: str) -> str:
        return f"({g.expr(ty)} {op} {g.expr(ty)})"

    def _compare(self, g: Gen, ty: Ty) -> str:
        op = g.pick(_CMP)
        return f"({g.expr(ty)} {op} {g.expr(ty)})"

    def _nonzero(self, g: Gen) -> str:
        """A divisor that cannot be zero, so the program never depends on division by zero."""
        return g.pick(["3", "7", "(1 + (" + g.expr(INT) + " & 15))"])

    def _nonzero_float(self, g: Gen) -> str:
        return g.pick(["2.0", "0.5", "(1.0 + Math.abs(" + g.expr(FLOAT) + "))"])

    def _ternary(self, g: Gen, ty: Ty) -> str:
        return f"({g.expr(BOOL)} ? {g.expr(ty)} : {g.expr(ty)})"
