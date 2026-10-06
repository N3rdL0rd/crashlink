"""Constants, and reads of variables already in scope."""

from __future__ import annotations

from ..feature import Choice, Feature, register
from ..gen import Gen
from ..types import BOOL, FLOAT, INT, STRING, Ty

_INTS = [
    "0",
    "1",
    "2",
    "3",
    "7",
    "10",
    "42",
    "100",
    "255",
    "1000",
    "65535",
    "0x7fffffff",
    "0xff",
    "0x10",
    "123456",
]
_FLOATS = ["0.0", "0.5", "1.0", "1.5", "2.25", "3.14159", "100.0", "0.001", "1e3", "2.5e-2"]
_STRINGS = ["", "a", "hello", "x y", "line\\n", "tab\\t", 'q\\"uote', "\\\\", "123", "Zed", "caf\\u00e9"]


@register
class Literals(Feature):
    name = "literals"
    summary = "constants and variable reads"
    covers = ("EConst", "Int", "Float", "String", "Ident")
    order = 10

    def types(self, g: Gen, depth: int):
        return [(4, INT), (2, FLOAT), (2, BOOL), (3, STRING)]

    def exprs(self, g: Gen, ty: Ty):
        out = [Choice(2, lambda ty=ty: self._variable(g, ty), leaf=True)] if g.visible(ty) else []
        if ty == INT:
            out.append(Choice(2, lambda: self._int(g), leaf=True))
        elif ty == FLOAT:
            out.append(Choice(2, lambda: self._wrap(g.pick(_FLOATS), g), leaf=True))
        elif ty == BOOL:
            out.append(Choice(1, lambda: g.pick(["true", "false"]), leaf=True))
        elif ty == STRING:
            out.append(Choice(2, lambda: '"' + g.pick(_STRINGS) + '"', leaf=True))
        return out

    def _variable(self, g: Gen, ty: Ty) -> str:
        return g.pick(g.visible(ty)).name

    def _int(self, g: Gen) -> str:
        text = g.pick(_INTS)
        return f"(-{text})" if g.chance(0.15) else text

    def _wrap(self, text: str, g: Gen) -> str:
        return f"(-{text})" if g.chance(0.15) else text
