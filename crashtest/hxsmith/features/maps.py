"""Map<Int, T> and Map<String, T>: literals, get/set/exists/remove, `??` defaults, sorted-key iteration.

Iteration order of a Map is unspecified, so output never depends on it: keys are collected and sorted first,
and the one unsorted `for (k => v in m)` loop only folds into an Int with a commutative operator.
"""

from __future__ import annotations

import re
from contextlib import contextmanager
from typing import Callable, Iterator, Optional, Tuple

from ..feature import Choice, Feature, register
from ..gen import Gen, Var
from ..types import BOOL, FLOAT, INT, SCALARS, STRING, Ty, array_of, map_of

_IDENT = re.compile(r"^\w+$")
_KEYS = (INT, STRING)


def supported(ty: Ty) -> bool:
    return ty.name == "Map" and ty.args[0] in _KEYS


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
    tmp = g.fresh("m")
    return f"({{ var {tmp}:{ty} = {source}; {body(tmp)}; }})"


def _key(g: Gen, key: Ty) -> str:
    """A key from a small pool, so that gets and removes often hit what was set."""
    if key == INT:
        return g.pick([str(g.between(0, 5)), f"({g.expr(INT)} & 7)", f"({g.expr(INT)} % 4)"])
    return g.pick(
        [f'"{g.pick(["a", "b", "c", "dd"])}"', f'("k" + ({g.expr(INT)} & 3))', f'"k{g.between(0, 3)}"']
    )


def _sorted_keys(g: Gen, name: str, key: Ty) -> Tuple[str, str]:
    """The statements that collect and sort the keys, and the array they end up in."""
    ks = g.fresh("ks")
    cmp = "(a, b) -> a - b" if key == INT and g.chance(0.5) else "(a, b) -> Reflect.compare(a, b)"
    return f"var {ks}:Array<{key}> = [for (k in {name}.keys()) k]; {ks}.sort({cmp});", ks


def _term(ty: Ty, name: str) -> Optional[str]:
    """An Int derived from a key or value, or None."""
    return {INT: name, STRING: f"{name}.length", BOOL: f"({name} ? 1 : 0)"}.get(ty)


@register
class Maps(Feature):
    name = "maps"
    summary = "Map<Int|String, T>: literal, set/get/exists/remove, ??, sorted-key iteration"
    covers = ("EArrayDecl", "EArray", "EFor", "EBinop", "ENew", "std:Map")
    order = 26

    def types(self, g: Gen, depth: int):
        if depth > 0:
            return []
        out: list = [(1, map_of(k, v)) for k in _KEYS for v in SCALARS]
        if any(f.name == "arrays" for f in g.features):
            out += [(0.4, map_of(k, array_of(INT))) for k in _KEYS]
        return out

    # ---- expressions ------------------------------------------------------------------

    def exprs(self, g: Gen, ty: Ty):
        out = []
        if supported(ty):
            out += [
                Choice(2, lambda: self._new(g, ty), leaf=True),
                Choice(3, lambda: self._literal(g, ty), leaf=True),
                Choice(1, lambda: self._copy(g, ty)),
            ]
        if ty == INT:
            out.append(Choice(1, lambda: self._count(g)))
        if ty == BOOL:
            out.append(Choice(1.5, lambda: self._exists(g)))
        if ty in SCALARS or ty == array_of(INT):
            out.append(Choice(3, lambda: self._get(g, ty)))
        return out

    def _new(self, g: Gen, ty: Ty) -> str:
        key, value = ty.args
        if g.chance(0.3):
            return f"(new haxe.ds.{'IntMap' if key == INT else 'StringMap'}<{value}>() : {ty})"
        return f"new Map<{key}, {value}>()"

    def _literal(self, g: Gen, ty: Ty) -> str:
        key, value = ty.args
        count = g.between(1, 4)
        if key == INT:  # distinct constants only: a repeated key is a compile error
            keys = [str(n) for n in sorted(g.rng.sample(range(10), count))]
        else:
            keys = [f'"{n}"' for n in sorted(g.rng.sample(["a", "b", "c", "dd", "e"], count))]
        items = ", ".join(f"{k} => {g.expr(value)}" for k in keys)
        return f"([{items}] : {ty})"

    def _copy(self, g: Gen, ty: Ty) -> str:
        return _with(g, g.expr(ty), ty, lambda m: f"{m}.copy()")

    def _count(self, g: Gen) -> str:
        ty = map_of(g.pick(_KEYS), g.pick(SCALARS))
        return _with(g, g.expr(ty), ty, lambda m: f"[for (k in {m}.keys()) k].length")

    def _exists(self, g: Gen) -> str:
        ty = map_of(g.pick(_KEYS), g.pick(SCALARS))
        return _with(g, g.expr(ty), ty, lambda m: f"{m}.exists({_key(g, ty.args[0])})")

    def _get(self, g: Gen, ty: Ty) -> str:
        src = map_of(g.pick(_KEYS), ty)
        form = g.between(0, 2)

        def body(m: str) -> str:
            k = _key(g, src.args[0])
            if form == 0:
                return f"({m}.get({k}) ?? {g.expr(ty)})"
            if form == 1:
                return f"({m}.exists({k}) ? {m}[{k}] : {g.expr(ty)})"
            return f"({m}.get({k}) != null ? {m}.get({k}) : {g.expr(ty)})"

        return _with(g, g.expr(src), src, body)

    # ---- statements -------------------------------------------------------------------

    def stmts(self, g: Gen):
        maps = [v for v in g.visible() if supported(v.ty)]
        if not maps:
            return []
        out = [
            Choice(4, lambda: self._set(g, maps)),
            Choice(1.5, lambda: self._remove(g, maps)),
            Choice(2, lambda: self._compound(g, maps)),
            Choice(1.5, lambda: self._fold(g, maps)),
            Choice(2, lambda: self._sorted_loop(g, maps), nested=True),
        ]
        return out

    def _set(self, g: Gen, maps: list) -> bool:
        var = g.pick(maps)
        key, value = var.ty.args
        k, v = _key(g, key), g.expr(value)
        if value == STRING:
            v = f"({v}).substr(0, 32)"
        v = _hoist(g, k, v)
        g.emit(g.pick([f"{var.name}[{k}] = {v};", f"{var.name}.set({k}, {v});"]))
        return True

    def _remove(self, g: Gen, maps: list) -> bool:
        var = g.pick(maps)
        g.emit(f"{var.name}.remove({_key(g, var.ty.args[0])});")
        return True

    def _compound(self, g: Gen, maps: list) -> bool:
        targets = [v for v in maps if v.ty.args[1] in (INT, FLOAT, STRING)]
        if not targets:
            return False
        var = g.pick(targets)
        key, value = var.ty.args
        k = _key(g, key)
        if value == INT:
            op, rhs = g.pick(["+=", "-=", "*=", "^=", "|="]), g.expr(INT)
        elif value == FLOAT:
            op, rhs = g.pick(["+=", "-=", "*="]), g.expr(FLOAT)
        else:
            # Strings read from the map can be appended back into it, so each one is capped.
            h, name = g.fresh("h"), var.name
            g.emit(f"var {h} = {k};")
            rhs = g.expr(g.pick([STRING, INT]))
            g.emit(
                f"if ({name}.exists({h})) {{ {name}[{h}] += {rhs}; if ({name}[{h}].length > 32) {name}[{h}] = {name}[{h}].substr(0, 32); }}"
            )
            return True
        g.emit(f"if ({var.name}.exists({k})) {var.name}[{k}] {op} {rhs};")
        return True

    def _fold(self, g: Gen, maps: list) -> bool:
        """`for (k => v in m)` in raw iteration order, folding into an Int with `+`, which commutes."""
        accs = g.visible(INT, mutable=True)
        if not accs:
            return False
        var = g.pick(maps)
        key, value = var.ty.args
        acc = g.pick(accs).name
        k, v = g.fresh("k"), g.fresh("v")
        term = f"({_term(key, k)} * 3 + {_term(value, v) or '1'})"
        g.emit(f"for ({k} => {v} in {var.name}) {acc} += {term};")
        return True

    def _sorted_loop(self, g: Gen, maps: list) -> bool:
        var = g.pick(maps)
        key, value = var.ty.args
        k, v = g.fresh("k"), g.fresh("v")
        collect, keys = _sorted_keys(g, var.name, key)
        g.emit(collect)
        with g.block(f"for ({k} in {keys}) {{"):
            g.loop_depth += 1
            g.declare_var(k, key, mutable=False)
            g.emit(f"var {v}:{value} = {var.name}[{k}];")
            g.declare_var(v, value)
            g.statements()
            g.loop_depth -= 1
        return True

    # ---- printing ---------------------------------------------------------------------

    def show(self, g: Gen, ty: Ty, expr: str):
        if not supported(ty):
            return None
        m, k = g.fresh("m"), g.fresh("k")
        item = g.show(f"{m}[{k}]", ty.args[1])
        collect, keys = _sorted_keys(g, m, ty.args[0])
        return f'({{ var {m}:{ty} = {expr}; {collect} "{{" + {keys}.map({k} -> Std.string({k}) + "=" + {item}).join(",") + "}}"; }})'
