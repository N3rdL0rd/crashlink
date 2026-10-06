"""Array<T>: literals, comprehensions, higher-order methods, indexed reads and read-modify-write.

Every array this feature builds is non-empty, so a masked index (`(i & 0x7fffffff) % a.length`) is always valid.
Growth is capped (`length < 6` before push/insert, `.slice(0, 8)` after concat) so that loops which feed an array
back into itself stay finite and fast.
"""

from __future__ import annotations

import re
from contextlib import contextmanager
from typing import Callable, Iterator, Tuple

from ..feature import Choice, Feature, register
from ..gen import Gen, Var
from ..types import BOOL, FLOAT, INT, SCALARS, STRING, Ty, array_of

_IDENT = re.compile(r"^\w+$")


def supported(ty: Ty) -> bool:
    """Array<scalar>, or an Array of those."""
    if ty.name != "Array":
        return False
    elem = ty.args[0]
    return elem in SCALARS or (elem.name == "Array" and elem.args[0] in SCALARS)


def _hoist(g: Gen, index: str, value: str) -> str:
    """Haxe 4.3.7's HashLink backend crashes on `a[--i] = ~--j`: a value with side effects goes into a local first."""
    if re.search(r"\+\+|--", index) and re.search(r"\+\+|--", value):
        tmp = g.fresh("h")
        g.emit(f"var {tmp} = {value};")
        return tmp
    return value


@contextmanager
def _scope(g: Gen, *bound: Tuple[str, Ty]) -> Iterator[None]:
    g.scopes.append([Var(n, t, False) for n, t in bound])
    try:
        yield
    finally:
        g.scopes.pop()


def _with(g: Gen, source: str, ty: Ty, body: Callable[[str], str]) -> str:
    """`body(name)` where `name` holds `source`: the source itself if it is a plain variable."""
    if _IDENT.match(source):
        return body(source)
    tmp = g.fresh("t")
    return f"({{ var {tmp}:{ty} = {source}; {body(tmp)}; }})"


def _typed(g: Gen, text: str, ty: Ty) -> str:
    """Pin the type of a literal (`[1, 2]` is an Array<Int> unless told otherwise)."""
    return f"({text} : {ty})" if "Float" in str(ty) or g.chance(0.15) else text


def _index(g: Gen, arr: str) -> str:
    return f"((({g.expr(INT)}) & 0x7fffffff) % {arr}.length)"


def _lambda(g: Gen, param: Ty, ret: Ty, body: Callable[[str], str]) -> str:
    x = g.fresh("x")
    with _scope(g, (x, param)):
        value = body(x)
    forms = [
        f"function({x}:{param}):{ret} return {value}",
        f"function({x}:{param}):{ret} {{ return {value}; }}",
    ]
    if ret != FLOAT:
        forms += [f"{x} -> {value}", f"({x}) -> {value}"]
    return g.pick(forms)


def _comparator(g: Gen, elem: Ty) -> str:
    if elem == BOOL:
        return g.pick(
            [
                "(a, b) -> (a == b) ? 0 : (a ? 1 : -1)",
                "function(a:Bool, b:Bool):Int return (a == b) ? 0 : (b ? 1 : -1)",
            ]
        )
    if elem.name == "Array":
        return g.pick(["(a, b) -> a.length - b.length", "(a, b) -> b.length - a.length"])
    return g.pick(
        [
            "(a, b) -> Reflect.compare(a, b)",
            "(a, b) -> Reflect.compare(b, a)",
            "function(a, b) return (a < b) ? -1 : ((a > b) ? 1 : 0)",
        ]
    )


@register
class Arrays(Feature):
    name = "arrays"
    summary = "Array<T>: literals, comprehensions, map/filter/sort, indexed read/write, push/insert"
    covers = ("EArrayDecl", "EArray", "EFor", "EFunction", "ECheckType", "std:Array")
    order = 25

    def types(self, g: Gen, depth: int):
        out = [(1.5, array_of(t)) for t in SCALARS]
        if depth == 0:
            out += [(0.4, array_of(array_of(t))) for t in (INT, STRING)]
        return out

    # ---- expressions ------------------------------------------------------------------

    def exprs(self, g: Gen, ty: Ty):
        out = []
        if supported(ty):
            out += [
                Choice(3, lambda: self._literal(g, ty), leaf=True),
                Choice(2, lambda: self._comprehension(g, ty)),
                Choice(2, lambda: self._map(g, ty)),
                Choice(1.5, lambda: self._filter(g, ty)),
                Choice(1, lambda: self._slice(g, ty)),
                Choice(1, lambda: self._concat(g, ty)),
                Choice(1, lambda: self._copy(g, ty)),
                Choice(1, lambda: self._sorted(g, ty)),
                Choice(1, lambda: self._from_iterator(g, ty)),
            ]
        if ty in SCALARS or supported(array_of(ty)):
            arrays = g.visible(array_of(ty))
            if arrays:
                out.append(Choice(2, lambda: self._read_var(g, ty), leaf=True))
            out.append(Choice(2, lambda: self._read(g, ty)))
        if ty == INT:
            out += [Choice(1.5, lambda: self._length(g)), Choice(1, lambda: self._index_of(g))]
        elif ty == BOOL:
            out.append(Choice(1, lambda: self._contains(g)))
        elif ty == STRING:
            out.append(Choice(1.5, lambda: self._join(g)))
        return out

    def _scalar(self, g: Gen) -> Ty:
        return g.pick(SCALARS)

    def _literal(self, g: Gen, ty: Ty) -> str:
        items = ", ".join(g.expr(ty.args[0]) for _ in range(g.between(1, 4)))
        return _typed(g, f"[{items}]", ty)

    def _comprehension(self, g: Gen, ty: Ty) -> str:
        elem = ty.args[0]
        i, j = g.fresh("i"), g.fresh("j")
        shape = g.pick(["flat", "flat", "nested", "filtered"])
        cond = ""
        with _scope(g, *[(i, INT), (j, INT)][: 2 if shape == "nested" else 1]):
            if shape == "filtered":
                cond = f"if ({g.expr(BOOL)}) "
            body = g.expr(elem)
        high = g.between(1, 5)
        if shape == "nested":
            loops = (
                f"for ({i} in 0...{g.between(1, 3)}) for ({j} in {g.pick(['0', '1'])}...{g.between(2, 4)}) "
            )
        else:
            loops = f"for ({i} in 0...{high}) "
        text = f"([{loops}{cond}{body}] : {ty})"
        # A filter may drop every element; the appended fallback keeps the array non-empty.
        return f"{text}.concat([{g.expr(elem)}])" if shape == "filtered" else text

    def _map(self, g: Gen, ty: Ty) -> str:
        src_elem = self._scalar(g) if ty.args[0] in SCALARS else ty.args[0]
        src = array_of(src_elem)
        fn = _lambda(g, src_elem, ty.args[0], lambda _x: g.expr(ty.args[0]))
        return _with(g, g.expr(src), src, lambda a: f"{a}.map({fn})")

    def _filter(self, g: Gen, ty: Ty) -> str:
        fn = _lambda(g, ty.args[0], BOOL, lambda _x: g.expr(BOOL))
        fallback = f"[{g.expr(ty.args[0])}]"
        return _with(g, g.expr(ty), ty, lambda a: f"{a}.filter({fn}).concat({fallback}).slice(0, 8)")

    def _slice(self, g: Gen, ty: Ty) -> str:
        def body(a: str) -> str:
            if g.chance(0.5):
                return f"{a}.slice({_index(g, a)})"
            return f"{a}.slice(0, 1 + ({g.expr(INT)} & 3))"

        return _with(g, g.expr(ty), ty, body)

    def _concat(self, g: Gen, ty: Ty) -> str:
        # The tail is sliced so that `a = a.concat(a)` in a loop cannot double its size each time.
        tail = _with(g, g.expr(ty), ty, lambda b: f"{b}.slice(0, {g.between(1, 3)})")
        return _with(g, g.expr(ty), ty, lambda a: f"{a}.concat({tail}).slice(0, 8)")

    def _copy(self, g: Gen, ty: Ty) -> str:
        def body(a: str) -> str:
            if g.chance(0.5):
                return f"{a}.copy()"
            r = g.fresh("r")
            return f"({{ var {r}:{ty} = {a}.copy(); {r}.reverse(); {r}; }})"

        return _with(g, g.expr(ty), ty, body)

    def _sorted(self, g: Gen, ty: Ty) -> str:
        def body(a: str) -> str:
            r = g.fresh("r")
            return f"({{ var {r}:{ty} = {a}.copy(); {r}.sort({_comparator(g, ty.args[0])}); {r}; }})"

        return _with(g, g.expr(ty), ty, body)

    def _from_iterator(self, g: Gen, ty: Ty) -> str:
        src_elem = self._scalar(g) if ty.args[0] in SCALARS else ty.args[0]
        x = g.fresh("it")
        with _scope(g, (x, src_elem)):
            body = g.expr(ty.args[0])
        source = _with(
            g,
            g.expr(array_of(src_elem)),
            array_of(src_elem),
            lambda a: f"[for ({x} in {a}.iterator()) {body}]",
        )
        return f"({source} : {ty})"

    def _read(self, g: Gen, ty: Ty) -> str:
        src = array_of(ty)
        return _with(g, g.expr(src), src, lambda a: f"{a}[{_index(g, a)}]")

    def _read_var(self, g: Gen, ty: Ty) -> str:
        name = g.pick(g.visible(array_of(ty))).name
        return f"{name}[{_index(g, name)}]"

    def _length(self, g: Gen) -> str:
        return f"{self._bound(g, array_of(self._scalar(g)))}.length"

    def _bound(self, g: Gen, ty: Ty) -> str:
        return f"({g.expr(ty)} : {ty})"

    def _index_of(self, g: Gen) -> str:
        elem = self._scalar(g)
        method = g.pick(["indexOf", "lastIndexOf"])
        return f"({self._bound(g, array_of(elem))}.{method}({g.expr(elem)}))"

    def _contains(self, g: Gen) -> str:
        elem = self._scalar(g)
        return f"{self._bound(g, array_of(elem))}.contains({g.expr(elem)})"

    def _join(self, g: Gen) -> str:
        sep = g.pick(['","', '""', '"-"', '" "'])
        return f"{self._bound(g, array_of(self._scalar(g)))}.join({sep}).substr(0, 24)"

    # ---- statements -------------------------------------------------------------------

    def stmts(self, g: Gen):
        arrays = [v for v in g.visible() if supported(v.ty)]
        if not arrays:
            return []
        return [
            Choice(3, lambda: self._write(g, arrays)),
            Choice(3, lambda: self._compound(g, arrays)),
            Choice(2, lambda: self._grow(g, arrays)),
            Choice(1, lambda: self._reorder(g, arrays)),
        ]

    def _write(self, g: Gen, arrays: list) -> bool:
        var = g.pick(arrays)
        index, value = _index(g, var.name), g.expr(var.ty.args[0])
        if var.ty.args[0] == STRING:
            value = f"({value}).substr(0, 32)"
        g.emit(f"{var.name}[{index}] = {_hoist(g, index, value)};")
        return True

    def _compound(self, g: Gen, arrays: list) -> bool:
        targets = [v for v in arrays if v.ty.args[0] in (INT, FLOAT, STRING)]
        if not targets:
            return False
        var = g.pick(targets)
        elem = var.ty.args[0]
        slot = f"{var.name}[{_index(g, var.name)}]" if elem != STRING else ""
        if elem == INT and g.chance(0.3):
            g.emit(g.pick([f"{slot}++;", f"{slot}--;", f"++{slot};", f"--{slot};"]))
        elif elem == INT:
            op = g.pick(["+=", "-=", "*=", "&=", "|=", "^="])
            g.emit(f"{slot} {op} {g.expr(INT)};")
        elif elem == FLOAT:
            g.emit(f"{slot} {g.pick(['+=', '-=', '*='])} {g.expr(FLOAT)};")
        else:
            # Strings read from the array can be appended back into it, so each one is capped.
            h = g.fresh("h")
            g.emit(f"var {h} = {_index(g, var.name)};")
            g.emit(f"{var.name}[{h}] += {g.expr(g.pick([STRING, INT]))};")
            g.emit(f"if ({var.name}[{h}].length > 32) {var.name}[{h}] = {var.name}[{h}].substr(0, 32);")
        return True

    def _grow(self, g: Gen, arrays: list) -> bool:
        var = g.pick(arrays)
        value = g.expr(var.ty.args[0])
        name = var.name
        call = g.pick(
            [
                f"{name}.push({value})",
                f"{name}.unshift({value})",
                f"{name}.insert(({g.expr(INT)} & 7) % ({name}.length + 1), {value})",
            ]
        )
        g.emit(f"if ({name}.length < 6) {call};")
        return True

    def _reorder(self, g: Gen, arrays: list) -> bool:
        var = g.pick(arrays)
        if g.chance(0.4):
            g.emit(f"{var.name}.reverse();")
        else:
            g.emit(f"{var.name}.sort({_comparator(g, var.ty.args[0])});")
        return True

    # ---- printing ---------------------------------------------------------------------

    def show(self, g: Gen, ty: Ty, expr: str):
        if not supported(ty):
            return None
        x = g.fresh("e")
        item = g.show(x, ty.args[0])
        return f'("[" + ({expr} : {ty}).map({x} -> {item}).join(",") + "]")'
