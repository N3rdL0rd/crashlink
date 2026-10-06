"""Static helper functions (default, optional and rest arguments, bounded recursion) and every call site.

This feature is the one place that turns `g.fns` into calls. A feature that generates bodies under
restrictions (see `classes`) publishes `g.state["calls"] = {"allow": Fn -> bool, "note": Fn -> None}`.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Iterator, List, Optional, Tuple

from ..feature import Choice, Feature, register
from ..gen import Fn, Gen, GenError
from ..types import BOOL, FLOAT, INT, STRING, VOID, Ty

_SCALARS = [INT, INT, STRING, FLOAT, BOOL]


@dataclass
class _Sig:
    """What a call needs to know beyond `Fn.params`."""

    optional: int = 0  # trailing parameters that may be omitted
    rest: Optional[Ty] = None  # element type of a `...rest` parameter
    bounded: bool = False  # the first argument is a recursion depth: pass a small literal


_MAX_COST = 5  # a function whose body (transitively) makes more calls than this is not called again


def _key(fn: Fn) -> Tuple[str, str]:
    return (fn.name, fn.receiver.name if fn.receiver else "")


@contextmanager
def _costed(g: Gen, key: Tuple[str, str]) -> Iterator[None]:
    """Record the calls a body makes: its cost is one plus the cost of everything it calls."""
    frames = g.state.setdefault("frames", [])
    frames.append(set())
    try:
        yield
    finally:
        cost = g.state.setdefault("cost", {})
        cost[key] = 1 + sum(cost.get(k, 1) for k in frames.pop())


@register
class Functions(Feature):
    name = "functions"
    summary = "static helpers with default/optional/rest args and bounded recursion; all call sites"
    covers = ("ECall", "ETernary", "APublic", "AStatic", "AInline")
    order = 60

    # ---- definitions ------------------------------------------------------------------

    def declare(self, g: Gen) -> None:
        sigs = g.state.setdefault(self.name, {})
        lo, hi = g.cfg.helper_functions
        made = 0
        target = g.between(lo, hi)
        while made < target:
            kind = g.weighted(
                [
                    self._plain,
                    self._short,
                    self._defaults,
                    self._rest,
                    self._counting,
                    self._fib,
                    self._mutual,
                ],
                [5, 1.5, 3, 2, 2, 1, 1],
            )
            made += kind(g, sigs)

    def _ty(self, g: Gen) -> Ty:
        return g.pick(_SCALARS) if g.chance(0.8) else g.pick_type()

    def _ret(self, g: Gen) -> Ty:
        return VOID if g.chance(0.2) else self._ty(g)

    def _const(self, g: Gen, ty: Ty) -> str:
        if ty == INT:
            return str(g.between(-5, 50))
        if ty == FLOAT:
            return g.pick(["0.5", "2.0", "1.25", "-3.5"])
        return g.pick(["true", "false"]) if ty == BOOL else g.pick(['"d"', '""', '"abc"'])

    def _define(
        self,
        g: Gen,
        sigs: dict,
        name: str,
        params: List[Tuple[str, Ty]],
        decl: str,
        ret: Ty,
        sig: _Sig,
        body: Callable[[], None],
        inline: bool = False,
    ) -> None:
        with _costed(g, (name, "")), g.capture(level=2) as lines:
            with g.function(params, None if inline else ret):
                for var in g.scopes[-1]:
                    if var.ty.is_fn:
                        var.mutable = (
                            False  # a reassignable function parameter could be pointed back at its caller
                        )
                body()
        mods = "public static inline" if inline else "public static"
        g.members.append("\n".join([f"\t{mods} function {name}({decl}):{ret} {{", *lines, "\t}"]))
        g.fns.append(Fn(name, tuple(t for _, t in params), ret))
        sigs[name] = sig

    @staticmethod
    def _decl(params: List[Tuple[str, Ty]]) -> str:
        return ", ".join(f"{n}:{t}" for n, t in params)

    def _params(self, g: Gen, lo: int, hi: int) -> List[Tuple[str, Ty]]:
        return [(g.fresh("a"), self._ty(g)) for _ in range(g.between(lo, hi))]

    def _plain(self, g: Gen, sigs: dict) -> int:
        params, ret = self._params(g, 0, 3), self._ret(g)
        inline = g.chance(0.1)
        self._define(
            g, sigs, g.fresh("fn"), params, self._decl(params), ret, _Sig(), lambda: g.body(ret), inline
        )
        return 1

    def _short(self, g: Gen, sigs: dict) -> int:
        params, ret = self._params(g, 1, 2), g.pick(_SCALARS)
        name = g.fresh("fn")
        with _costed(g, (name, "")), g.function(params, ret):
            value = g.expr(ret)
        g.members.append(f"\tpublic static function {name}({self._decl(params)}):{ret} return {value};")
        g.fns.append(Fn(name, tuple(t for _, t in params), ret))
        sigs[name] = _Sig()
        return 1

    def _defaults(self, g: Gen, sigs: dict) -> int:
        params = self._params(g, 0, 2)
        decl = [f"{n}:{t}" for n, t in params]
        tail: List[Tuple[str, Ty]] = []
        normalise: List[Tuple[str, Ty, str]] = []
        for _ in range(g.between(1, 2)):
            n, t = g.fresh("d"), g.pick(_SCALARS)
            tail.append((n, t))
            if g.chance(0.5):
                decl.append(f"{n}:{t} = {self._const(g, t)}")
            else:
                decl.append(f"?{n}:{t}")
                normalise.append((n, t, self._const(g, t)))
        ret = self._ret(g)

        def body() -> None:
            for n, t, dflt in normalise:
                g.scopes[-1][:] = [v for v in g.scopes[-1] if v.name != n]  # `Null<T>` stays out of reach
                g.emit(f"final {n}n:{t} = ({n} == null) ? {dflt} : {n};")
                g.declare_var(f"{n}n", t, mutable=False)
            g.body(ret)

        name = g.fresh("fn")
        self._define(g, sigs, name, params + tail, ", ".join(decl), ret, _Sig(optional=len(tail)), body)
        return 1

    def _rest(self, g: Gen, sigs: dict) -> int:
        params, elem, ret = self._params(g, 0, 2), g.pick([INT, INT, STRING]), self._ret(g)

        def body() -> None:
            total = g.fresh("tot")
            g.emit(f"var {total}:{elem} = {'0' if elem == INT else chr(34) * 2};")
            g.declare_var(total, elem)
            if g.chance(0.5):
                x = g.fresh("x")
                g.emit(f"for ({x} in r) {total} += {x};")
            else:
                i = g.fresh("i")
                g.emit(f"for ({i} in 0...r.length) {total} += r[{i}];")
            count = g.fresh("cnt")
            g.emit(f"final {count} = r.length;")
            g.declare_var(count, INT, mutable=False)
            g.body(ret)

        decl = ", ".join([*(f"{n}:{t}" for n, t in params), f"...r:{elem}"])
        self._define(g, sigs, g.fresh("fn"), params, decl, ret, _Sig(rest=elem), body)
        return 1

    def _counting(self, g: Gen, sigs: dict) -> int:
        n, acc = g.fresh("n"), g.fresh("acc")
        name = g.fresh("rec")
        params = [(n, INT), (acc, INT)]

        def body() -> None:
            g.scopes[-1][0].mutable = False
            g.emit(f"if ({n} <= 0) return {acc};")
            g.statements(g.between(1, 2))
            g.emit(
                f"return {name}({n} - 1, {g.pick([f'{acc} + ', f'{acc} * 2 - ', f'{acc} ^ '])}{g.expr(INT)});"
            )

        self._define(g, sigs, name, params, self._decl(params), INT, _Sig(bounded=True), body)
        return 1

    def _fib(self, g: Gen, sigs: dict) -> int:
        n, name = g.fresh("n"), g.fresh("fib")

        def body() -> None:
            g.emit(f"if ({n} < 2) return {n};")
            g.emit(f"return {name}({n} - 1) + {name}({n} - 2);")

        self._define(g, sigs, name, [(n, INT)], f"{n}:Int", INT, _Sig(bounded=True), body)
        return 1

    def _mutual(self, g: Gen, sigs: dict) -> int:
        even, odd, n = g.fresh("even"), g.fresh("odd"), g.fresh("n")
        for name, other, base in ((even, odd, "true"), (odd, even, "false")):
            g.members.append(
                f"\tpublic static function {name}({n}:Int):Bool return ({n} <= 0) ? {base} : {other}({n} - 1);"
            )
            g.fns.append(Fn(name, (INT,), BOOL))
            sigs[name] = _Sig(bounded=True)
        return 2

    # ---- call sites -------------------------------------------------------------------

    def _allowed(self, g: Gen, fn: Fn) -> bool:
        policy = g.state.get("calls")
        return policy is None or policy["allow"](fn)

    def _candidates(self, g: Gen, accept: Callable[[Fn], bool]) -> List[Fn]:
        cost = g.state.get("cost", {})
        return [
            fn for fn in g.fns if accept(fn) and cost.get(_key(fn), 1) <= _MAX_COST and self._allowed(g, fn)
        ]

    def _call(self, g: Gen, fn: Fn) -> Optional[str]:
        sigs = g.state.get(self.name, {})
        sig = sigs.get(fn.name, _Sig())
        try:
            receiver = f"({g.expr(fn.receiver)})." if fn.receiver is not None else ""
            args = [
                str(g.between(0, 6)) if sig.bounded and i == 0 else g.expr(t) for i, t in enumerate(fn.params)
            ]
            if sig.optional:
                del args[len(args) - g.between(0, sig.optional) :]
            if sig.rest:
                args += [g.expr(sig.rest) for _ in range(g.between(0, 3))]
        except GenError:
            return None
        policy = g.state.get("calls")
        if policy is not None:
            policy["note"](fn)
        if g.state.get("frames"):
            g.state["frames"][-1].add(_key(fn))
        # Helpers of the main class are qualified so that any generated class can reach them.
        owner = f"{g.class_name}." if fn.receiver is None and "." not in fn.name else ""
        return f"{receiver}{owner}{fn.name}({', '.join(args)})"

    def exprs(self, g: Gen, ty: Ty):
        fns = self._candidates(g, lambda fn: fn.ret != VOID and fn.ret in g.subtype_choices(ty))
        return [Choice(2, lambda: self._call(g, g.pick(fns)))] if fns else []

    def stmts(self, g: Gen):
        return [
            Choice(3, lambda: self._statement(g, lambda fn: fn.ret == VOID)),
            Choice(1, lambda: self._statement(g, lambda fn: fn.ret != VOID)),
        ]

    def _statement(self, g: Gen, accept: Callable[[Fn], bool]) -> bool:
        fns = self._candidates(g, accept)
        if not fns:
            return False
        call = self._call(g, g.pick(fns))
        if call is None:
            return False
        g.emit(call + ";")
        return True
