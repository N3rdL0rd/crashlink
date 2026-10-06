"""Strings: interpolation, String methods, StringTools, StringBuf, comparison, iteration, parsing literals."""

from __future__ import annotations

import re

from ..feature import Choice, Feature, register
from ..gen import Gen
from ..types import BOOL, FLOAT, INT, SCALARS, STRING, Ty

_PREFIXES = ["", "a=", "v: ", "(", "#", "x"]
_TAILS = [" ", ", ", ")", ": ", "|", "-", " and ", "; "]  # each starts with a non-identifier char
_NEEDLES = ['"a"', '"l"', '"o"', '"he"', '" "', '"zz"', '""']
_PADS = ['"0"', '" "', '"*"', '"ab"']
_NO_NEST = re.compile(r"\\[^tnru]|\$\$")  # escapes the lexer re-reads inside `${}`
_GOOD_INTS = ['"12"', '"-7"', '"0x1F"', '"0"', '"2147483647"', '"007"']
_GOOD_FLOATS = ['"1.5"', '"42"', '"0.25"', '"-3.75"', '"1e2"', '".5"']


@register
class Strings(Feature):
    name = "strings"
    summary = "interpolation, String/StringTools/StringBuf, parsing, char iteration"
    covers = ("EConst", "EBinop", "std:String", "std:StringTools", "std:StringBuf")
    requires = ("literals",)
    order = 22

    def declare(self, g: Gen) -> None:
        g.state[self.name] = g.chance(0.5)  # `using StringTools` (method syntax) vs qualified calls
        if g.state[self.name]:
            g.decls.append("using StringTools;")

    def exprs(self, g: Gen, ty: Ty):
        if ty == STRING:
            return [
                Choice(4, lambda: self._interp(g)),
                Choice(1, lambda: self._single_quoted(g), leaf=True),
                Choice(1.5, lambda: f"{self._s(g)}.{g.pick(['toUpperCase', 'toLowerCase'])}()"),
                Choice(1.5, lambda: f"{self._s(g)}.charAt({self._idx(g)})"),
                Choice(
                    2,
                    lambda: f"{self._s(g)}.{g.pick(['substr', 'substring'])}({self._idx(g)}, {self._idx(g)})",
                ),
                Choice(1.5, lambda: f"{self._s(g)}.substr({g.pick(['0', '1', '-1', '-2'])})"),
                Choice(1.5, lambda: self._split_join(g)),
                Choice(2, lambda: self._tools_string(g)),
                Choice(1, lambda: f"String.fromCharCode(65 + {self._idx(g, 15)})"),
                Choice(1.5, lambda: f"Std.string({g.expr(g.pick([INT, FLOAT, BOOL]))})"),
                Choice(1, lambda: self._buf_expr(g)),
            ]
        if ty == INT:
            return [
                Choice(3, lambda: f"{self._s(g)}.length"),
                Choice(2, lambda: self._char_code(g)),
                Choice(2, lambda: f"{self._s(g)}.{g.pick(['indexOf', 'lastIndexOf'])}({self._needle(g)})"),
                Choice(1, lambda: f"{self._s(g)}.indexOf({self._needle(g)}, {self._idx(g)})"),
                Choice(1, lambda: f"Reflect.compare({self._s(g)}, {self._s(g)})"),
                Choice(1, lambda: f"({self._s(g)}.split({self._needle(g)}).length + 0)"),
                Choice(1, lambda: f"(Std.parseInt({g.pick(_GOOD_INTS)}) ?? 0)", leaf=True),
                Choice(1, lambda: f"(Std.parseInt(Std.string({g.expr(INT)})) ?? 0)"),
            ]
        if ty == FLOAT:
            return [Choice(1, lambda: f"Std.parseFloat({g.pick(_GOOD_FLOATS)})", leaf=True)]
        if ty == BOOL:
            return [
                Choice(2, lambda: self._tools_bool(g)),
                Choice(
                    2,
                    lambda: (
                        f"({self._s(g)}.indexOf({self._needle(g)}) {g.pick(['>=', '<', '=='])} {g.pick(['0', '-1'])})"
                    ),
                ),
                Choice(
                    2, lambda: f"({self._s(g)} {g.pick(['<', '<=', '>', '>=', '==', '!='])} {self._s(g)})"
                ),
                Choice(1, lambda: f"({self._s(g)}.length {g.pick(['==', '>', '<='])} {g.between(0, 6)})"),
            ]
        return []

    def stmts(self, g: Gen):
        return [
            Choice(2, lambda: self._buf_stmt(g)),
            Choice(2, lambda: self._scan(g), nested=True),
            Choice(1.5, lambda: self._append(g)),
        ]

    # ---- expression helpers -----------------------------------------------------------

    def _s(self, g: Gen) -> str:
        return g.expr(STRING)

    def _idx(self, g: Gen, mask: int = 7) -> str:
        """An Int in `0..mask`; String methods tolerate any index, so this is for variety."""
        return g.pick([str(g.between(0, mask)), f"({g.expr(INT)} & {mask})"])

    def _needle(self, g: Gen) -> str:
        return g.pick([g.pick(_NEEDLES), g.expr(STRING)])

    def _single_quoted(self, g: Gen) -> str:
        return "'" + g.pick(["", "it's", "a b", "$$5", 'q"d', "x\\ty", "{}"]).replace("'", "\\'") + "'"

    def _hole(self, g: Gen, ty: Ty, last: bool) -> str:
        """`$name`, `${expr}` or, when the lexer cannot nest `expr`, a concatenation break."""
        names = g.visible(ty)
        if names and g.chance(0.5):
            return f"${g.pick(names).name}{g.pick(_TAILS)}"
        expr = g.expr(ty)
        tail = "" if last and g.chance(0.5) else g.pick(_TAILS)
        if _NO_NEST.search(expr):
            return f"' + ({expr}) + '{tail}"
        return "${" + expr + "}" + tail

    def _interp(self, g: Gen) -> str:
        count = g.between(1, 3)
        text = ""
        for k in range(count):
            text += g.pick(_PREFIXES) + self._hole(g, g.pick(SCALARS), k == count - 1)
        return f"('{text}')" if "' + (" in text else f"'{text}'"

    def _split_join(self, g: Gen) -> str:
        return f"{self._s(g)}.split({g.pick(_NEEDLES)}).join({g.pick(_NEEDLES)})"

    def _char_code(self, g: Gen) -> str:
        """charCodeAt is Null<Int> (null outside the string), so it is guarded and defaulted with `??`."""
        names = g.visible(STRING)
        if names and g.chance(0.6):
            s = g.pick(names).name
            return f"({s}.length == 0 ? 0 : ({s}.charCodeAt(({g.expr(INT)} & 0xff) % {s}.length) ?? 0))"
        return f'(({self._s(g)} + "!").charCodeAt(0) ?? 0)'

    def _tools_string(self, g: Gen) -> str:
        s = self._s(g)
        kind = g.pick(["trim", "ltrim", "rtrim", "replace", "lpad", "rpad", "hex", "escape"])
        if kind == "hex":
            return f"StringTools.hex({g.expr(INT)}, {g.between(0, 8)})"
        if kind == "escape":
            return f"StringTools.{g.pick(['urlEncode', 'htmlEscape'])}({s})"
        extra = {
            "replace": [g.pick(_NEEDLES[:-1]), g.pick(_NEEDLES + _PADS)],
            "lpad": [g.pick(_PADS), self._idx(g, 15)],
            "rpad": [g.pick(_PADS), self._idx(g, 15)],
        }.get(kind, [])
        if g.state[self.name] and g.chance(0.6):
            return f"{s}.{kind}({', '.join(extra)})"
        return f"StringTools.{kind}({', '.join([s, *extra])})"

    def _tools_bool(self, g: Gen) -> str:
        s, needle = self._s(g), self._needle(g)
        kind = g.pick(["startsWith", "endsWith", "contains"])
        if g.state[self.name] and g.chance(0.5):
            return f"{s}.{kind}({needle})"
        return f"StringTools.{kind}({s}, {needle})"

    def _buf_adds(self, g: Gen, sb: str) -> str:
        return " ".join(
            g.pick(
                [
                    lambda: f"{sb}.add({self._s(g)});",
                    lambda: f"{sb}.add({g.expr(g.pick([INT, FLOAT, BOOL]))});",
                    lambda: f"{sb}.addChar(65 + {self._idx(g, 15)});",
                    lambda: f"{sb}.addSub({self._s(g)}, {g.between(0, 2)}, {g.between(0, 3)});",
                ]
            )()
            for _ in range(g.between(1, 3))
        )

    def _buf_expr(self, g: Gen) -> str:
        sb = g.fresh("sb")
        return f"(function():String {{ var {sb} = new StringBuf(); {self._buf_adds(g, sb)} return {sb}.toString(); }})()"

    # ---- statements -------------------------------------------------------------------

    def _buf_stmt(self, g: Gen) -> bool:
        sb, out = g.fresh("sb"), g.fresh("sbs")
        g.emit(f"var {sb} = new StringBuf();")
        for _ in range(g.between(1, 3)):
            g.emit(self._buf_adds(g, sb))
        if g.chance(0.4):
            i = g.fresh("i")
            g.emit(f"for ({i} in 0...{g.between(1, 4)}) {sb}.add({i} * {g.between(1, 9)});")
        g.emit(f"var {out} = {sb}.toString();")
        g.declare_var(out, STRING)
        if g.chance(0.3):
            n = g.fresh("sbn")
            g.emit(f"var {n} = {sb}.length;")
            g.declare_var(n, INT)
        return True

    def _scan(self, g: Gen) -> bool:
        """Walk a string by index, folding charCodeAt / charAt into an accumulator."""
        names = g.visible(STRING)
        if names and g.chance(0.6):
            s = g.pick(names).name
        else:
            s = g.fresh("sc")
            g.emit(f"var {s} = {self._s(g)};")
            g.declare_var(s, STRING, mutable=False)
        acc, i = g.fresh("acc"), g.fresh("i")
        g.emit(f"var {acc} = {g.pick(['0', '17', '1'])};")
        header = f"for ({i} in 0...{s}.length) {{"
        with g.block(header):
            g.declare_var(i, INT, mutable=False)
            if g.chance(0.7):
                g.emit(f"{acc} = (({acc} * 31) + ({s}.charCodeAt({i}) ?? 0)) & 0xffff;")
            else:
                g.emit(f"if ({s}.charAt({i}) == {g.pick(_NEEDLES[:-1])}) {acc}++;")
        g.declare_var(acc, INT)
        return True

    def _append(self, g: Gen) -> bool:
        """`s += ...`, capped at 8 characters so loops that feed a string into itself stay linear."""
        targets = g.visible(STRING, mutable=True)
        if not targets:
            return False
        part = g.expr(g.pick([STRING, INT, BOOL]))
        g.emit(f"{g.pick(targets).name} += Std.string({part}).substr(0, 8);")
        return True
