"""Standard library: Math, Std, haxe.Int64, haxe.io.Bytes, EReg, Lambda."""

from __future__ import annotations

from ..feature import Choice, Feature, register
from ..gen import Gen, Var
from ..types import BOOL, FLOAT, INT, STRING, Ty, array_of

_I64 = "haxe.Int64"
_BYTES = "haxe.io.Bytes"
_PATTERNS = ["[aeiou]", "l+", "^h", "o$", "[a-c]+", "(l+)(o)", "a|e", "."]
_LITERALS = ["~/[aeiou]/g", "~/\\s+/g", "~/\\d+/", "~/(\\w)(\\w)/", "~/l+/i", "~/^[a-z]/", "~/[^a-z ]/g"]
_WORDS = ['"a"', '"hello"', '""']
_GROUPLESS = ["_", "-", "", "<$0>"]
_I64_LITERALS = ['"0"', '"1234567890123"', '"-42"', '"9007199254740993"']


@register
class Stdlib(Feature):
    name = "stdlib"
    summary = "Math, Std, Int64, Bytes, EReg, Lambda"
    covers = ("EConst", "Regexp", "std:Math", "std:Std", "std:Int64", "std:Bytes", "std:EReg", "std:Lambda")
    requires = ("literals",)
    order = 23

    def declare(self, g: Gen) -> None:
        # Int64.make/ofInt are inline: an Int expression typed Null<Int> (optional fields, `??`) breaks the HL
        # generator there, so the constructors are reached through plain functions that coerce at the call.
        g.members += [
            f"\tpublic static function hxsInt64(v:Int):{_I64} return {_I64}.ofInt(v);",
            f"\tpublic static function hxsMake64(h:Int, l:Int):{_I64} return {_I64}.make(h, l);",
        ]

    def exprs(self, g: Gen, ty: Ty):
        out = []
        arrays = [v for v in g.visible() if v.ty in (array_of(INT), array_of(STRING))]
        if ty == INT:
            out += [
                Choice(2, lambda: f"Std.int(Math.{g.pick(['min', 'max'])}({g.expr(INT)}, {g.expr(INT)}))"),
                Choice(1.5, lambda: f"Std.int(Math.pow({g.between(2, 5)}, {g.expr(INT)} & 7))"),
                Choice(
                    1.5,
                    lambda: f"Math.{g.pick(['floor', 'ceil', 'round'])}(Math.sqrt(Math.abs({g.expr(FLOAT)})))",
                ),
                Choice(1, lambda: f"Std.int(Math.abs({g.expr(INT)}) % 1000)"),
                Choice(2, lambda: f"{self._i64(g)}.{g.pick(['low', 'high'])}"),
                Choice(1, lambda: f"{_I64}.compare({self._i64(g)}, {self._i64(g)})"),
                Choice(1, lambda: f"{_I64}.toInt({g.class_name}.hxsInt64({g.expr(INT)}))"),
                Choice(2, lambda: self._bytes_int(g)),
                Choice(1, lambda: self._ereg_pos(g)),
            ]
            out += [Choice(2, lambda v=v: self._lambda_int(g, v)) for v in arrays]
        elif ty == FLOAT:
            out += [
                Choice(
                    2, lambda: f"Math.{g.pick(['min', 'max', 'atan2'])}({g.expr(FLOAT)}, {g.expr(FLOAT)})"
                ),
                Choice(1, lambda: "Math.PI"),
                Choice(
                    1.5,
                    lambda: f"Math.{g.pick(['sin', 'cos', 'atan', 'ffloor', 'fceil', 'fround'])}({g.expr(FLOAT)})",
                ),
                Choice(1, lambda: f"Math.pow({g.between(1, 4)}, {g.expr(INT)} & 7)"),
                Choice(1, lambda: f"Math.log(Math.abs({g.expr(FLOAT)}) + 1)"),
                Choice(1, lambda: f"Math.exp({g.expr(INT)} & 3)"),
            ]
        elif ty == BOOL:
            out += [
                Choice(1.5, lambda: f"Math.{g.pick(['isNaN', 'isFinite'])}({g.expr(FLOAT)})"),
                Choice(1, lambda: f"Math.isNaN(Math.sqrt({g.expr(FLOAT)}))"),
                Choice(
                    1,
                    lambda: f"({g.expr(FLOAT)} {g.pick(['<', '>'])} Math.{g.pick(['POSITIVE', 'NEGATIVE'])}_INFINITY)",
                ),
                Choice(
                    1.5,
                    lambda: (
                        f"Std.isOfType({g.expr(g.pick([INT, FLOAT, STRING, BOOL]))}, {g.pick(['Int', 'Float', 'String', 'Bool'])})"
                    ),
                ),
                Choice(2, lambda: self._i64_bool(g)),
                Choice(2, lambda: self._ereg_bool(g)),
            ]
            out += [Choice(2, lambda v=v: self._lambda_bool(g, v)) for v in arrays]
        elif ty == STRING:
            out += [
                Choice(2, lambda: f"{_I64}.toStr({self._i64(g)})"),
                Choice(1, lambda: self._bytes_string(g)),
                Choice(2, lambda: self._ereg_replace(g)),
                Choice(1, lambda: self._ereg_matched(g)),
                Choice(1, lambda: f"{_BYTES}.ofString({g.expr(STRING)}).toString()"),
            ]
        elif ty == array_of(INT):
            out += [Choice(2, lambda v=v: self._lambda_array(g, v)) for v in g.visible(array_of(INT))]
        return out

    # ---- haxe.Int64 -------------------------------------------------------------------

    def _i64(self, g: Gen, depth: int = 0) -> str:
        """An Int64 expression; nesting is bounded here so it cannot grow with the expression budget."""

        def sub() -> str:
            return self._i64(g, depth + 1)

        options = [
            lambda: f"{g.class_name}.hxsInt64({g.expr(INT)})",
            lambda: f"{g.class_name}.hxsMake64({g.expr(INT)}, {g.expr(INT)})",
            lambda: f"{_I64}.parseString({g.pick(_I64_LITERALS)})",
        ]
        if depth < 2:
            options += [
                lambda: f"{_I64}.{g.pick(['add', 'sub', 'mul', 'and', 'or', 'xor'])}({sub()}, {sub()})",
                lambda: f"({sub()} {g.pick(['+', '-', '*', '&', '|', '^'])} {sub()})",
                lambda: f"({sub()} {g.pick(['+', '-', '*'])} {g.between(1, 99)})",
                lambda: f"({sub()} {g.pick(['<<', '>>', '>>>'])} {g.between(0, 40)})",
                lambda: f"({sub()} {g.pick(['/', '%'])} {_I64}.ofInt({g.between(1, 9)}))",
                lambda: f"{g.pick([_I64 + '.neg', '-', '~'])}({sub()})",
            ]
        return g.pick(options)()

    def _i64_bool(self, g: Gen) -> str:
        a, b = self._i64(g), self._i64(g)
        return g.pick(
            [
                f"({a} {g.pick(['<', '<=', '>', '>=', '==', '!='])} {b})",
                f"({_I64}.compare({a}, {b}) {g.pick(['<', '==', '>'])} 0)",
                f"{_I64}.{g.pick(['isNeg', 'isZero'])}({a})",
            ]
        )

    # ---- haxe.io.Bytes ----------------------------------------------------------------

    def _bytes_ops(self, g: Gen, b: str, size: int) -> str:
        def op() -> str:
            return g.pick(
                [
                    lambda: f"{b}.set({g.between(0, size - 1)}, {g.expr(INT)});",
                    lambda: f"{b}.setInt32({g.between(0, size - 4)}, {g.expr(INT)});",
                    lambda: f"{b}.setUInt16({g.between(0, size - 2)}, {g.expr(INT)});",
                    lambda: f"{b}.fill({g.between(0, 3)}, {g.between(0, size - 3)}, {g.expr(INT)});",
                    lambda: f'{b}.blit({g.between(0, size - 8)}, {_BYTES}.ofString("abcdefgh"), 0, {g.between(1, 8)});',
                    lambda: f"{b}.setDouble({g.between(0, size - 8)}, {g.expr(FLOAT)});",
                ]
            )()

        return " ".join(op() for _ in range(g.between(1, 4)))

    def _bytes_int(self, g: Gen) -> str:
        b, size = g.fresh("by"), g.pick([8, 16])
        ops = self._bytes_ops(g, b, size)
        result = g.pick(
            [
                f"{b}.get({g.between(0, size - 1)})",
                f"{b}.getInt32({g.between(0, size - 4)})",
                f"{b}.getUInt16({g.between(0, size - 2)})",
                f"({b}.length + {b}.get({g.between(0, size - 1)}))",
                f"{b}.sub({g.between(0, 3)}, {g.between(1, 4)}).length",
            ]
        )
        return f"(function():Int {{ var {b} = {_BYTES}.alloc({size}); {ops} return {result}; }})()"

    def _bytes_string(self, g: Gen) -> str:
        b, size, i = g.fresh("by"), g.pick([8, 16]), g.fresh("i")
        ops = self._bytes_ops(g, b, size)
        if g.chance(0.5):  # fill with printable ASCII so getString/toString round-trip
            tail = f"for ({i} in 0...{size}) {b}.set({i}, 65 + (({g.expr(INT)} + {i}) & 15)); return {b}.{g.pick(['toString()', f'getString(0, {size})'])};"
        else:
            tail = f"return {b}.{g.pick(['toHex()', 'sub(1, 3).toHex()'])};"
        return f"(function():String {{ var {b} = {_BYTES}.alloc({size}); {ops} {tail} }})()"

    # ---- EReg -------------------------------------------------------------------------

    def _ereg(self, g: Gen) -> str:
        if g.chance(0.5):
            return g.pick(_LITERALS)
        return f'new EReg("{g.pick(_PATTERNS)}", "{g.pick(["", "g", "i", "ig"])}")'

    def _ereg_bool(self, g: Gen) -> str:
        return f"({self._ereg(g)}).match({g.expr(STRING)})"

    def _ereg_replace(self, g: Gen) -> str:
        if g.chance(0.25):
            return f'({self._ereg(g)}).split({g.expr(STRING)}).join("{g.pick(["|", ","])}")'
        return f'({self._ereg(g)}).replace({g.expr(STRING)}, "{g.pick(_GROUPLESS)}")'

    def _ereg_pos(self, g: Gen) -> str:
        r = g.fresh("re")
        return f"(function():Int {{ var {r} = {self._ereg(g)}; return {r}.match({g.expr(STRING)}) ? {r}.matchedPos().pos : -1; }})()"

    def _ereg_matched(self, g: Gen) -> str:
        r = g.fresh("re")
        part = g.pick(["matched(0)", "matchedLeft()", "matchedRight()"])
        return f'(function():String {{ var {r} = {self._ereg(g)}; return {r}.match({g.expr(STRING)}) ? {r}.{part} : ""; }})()'

    # ---- Lambda -----------------------------------------------------------------------

    def _pred(self, g: Gen, elem: Ty) -> str:
        if elem == INT:
            body = g.pick(
                [
                    f"(x {g.pick(['>', '<', '!='])} {g.expr(INT)})",
                    "((x & 1) == 0)",
                    f"(x == {g.between(0, 9)})",
                ]
            )
            return g.pick([f"function(x:Int):Bool return {body}", f"(x:Int) -> {body}"])
        body = g.pick(["(x.length > 1)", f"(x == {g.pick(_WORDS)})", '(x.indexOf("a") >= 0)'])
        return g.pick([f"function(x:String):Bool return {body}", f"(x:String) -> {body}"])

    def _lambda_int(self, g: Gen, arr: Var) -> str:
        a, elem = arr.name, arr.ty.args[0]
        weight = "x" if elem == INT else "x.length"
        options = [
            f"Lambda.count({a})",
            f"Lambda.count({a}, {self._pred(g, elem)})",
            f"Lambda.fold({a}, function(x:{elem}, acc:Int):Int return (acc + {weight}), {g.expr(INT)})",
            f"Lambda.fold({a}, (x:{elem}, acc:Int) -> (acc * 3) ^ {weight}, 1)",
            f"Lambda.indexOf({a}, {g.expr(elem)})",
        ]
        return g.pick(options)

    def _lambda_bool(self, g: Gen, arr: Var) -> str:
        a, elem = arr.name, arr.ty.args[0]
        pred = self._pred(g, elem)
        return g.pick([f"Lambda.exists({a}, {pred})", f"Lambda.foreach({a}, {pred})", f"Lambda.empty({a})"])

    def _lambda_array(self, g: Gen, arr: Var) -> str:
        a = arr.name
        fn = g.pick(
            [
                f"function(x:Int):Int return (x * {g.between(2, 5)})",
                f"(x:Int) -> x + {g.expr(INT)}",
            ]
        )
        if g.chance(0.4):
            return f"Lambda.filter({a}, {self._pred(g, INT)})"
        return f"Lambda.map({a}, {fn})"
