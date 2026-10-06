"""Function values: local functions, lambdas, captured and mutated variables, higher-order helpers, bind.

Function-typed values can never refer to themselves: a lambda body does not see mutable function
variables (a later assignment could point one back at its caller) and function parameters are frozen.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator, List, Optional, Tuple

from ..feature import Choice, Feature, register
from ..gen import Gen, GenError, Fn
from ..types import BOOL, FLOAT, INT, STRING, VOID, Ty, array_of, fn_of

_SCALARS = [INT, INT, STRING, FLOAT, BOOL]
_SHAPES = [
    (0.6, fn_of((INT,), INT)),
    (0.4, fn_of((), STRING)),
    (0.4, fn_of((INT, INT), INT)),
    (0.3, fn_of((STRING,), BOOL)),
    (0.3, fn_of((FLOAT,), FLOAT)),
]
_INT_FN = fn_of((INT,), INT)


@contextmanager
def _sealed(g: Gen) -> Iterator[None]:
    """Hide the mutable function-typed variables from a closure body being generated."""
    saved = [(scope, list(scope)) for scope in g.scopes]
    for scope in g.scopes:
        scope[:] = [v for v in scope if not (v.ty.is_fn and v.mutable)]
    try:
        yield
    finally:
        for scope, items in saved:
            scope[:] = items


def _freeze(g: Gen) -> None:
    for var in g.scopes[-1]:
        if var.ty.is_fn:
            var.mutable = False


def _decl(params: List[Tuple[str, Ty]]) -> str:
    return ", ".join(f"{n}:{t}" for n, t in params)


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
class Closures(Feature):
    name = "closures"
    summary = "local functions, lambdas, captured variables, higher-order helpers, bind, IIFE"
    covers = (
        "EFunction",
        "FKAnonymous",
        "FKNamed",
        "FKArrow",
        "ECall",
        "ETernary",
        "EFor",
        "EWhile",
        "EArrayDecl",
    )
    requires = ("variables", "functions")
    order = 45

    # ---- declarations: higher-order helpers -------------------------------------------

    def declare(self, g: Gen) -> None:
        g.state[self.name] = []
        helpers = [self._apply, self._fold, self._maker, self._compose, self._each, self._select]
        for helper in g.rng.sample(helpers, g.between(2, 4)):
            helper(g)

    def _add(self, g: Gen, name: str, params: List[Tuple[str, Ty]], ret: Ty, body: List[str]) -> None:
        text = [
            f"\tpublic static function {name}({_decl(params)}):{ret} {{",
            *(f"\t\t{line}" for line in body),
            "\t}",
        ]
        g.members.append("\n".join(text))
        fn = Fn(name, tuple(t for _, t in params), ret)
        g.fns.append(fn)
        g.state[self.name].append(fn)

    def _apply(self, g: Gen) -> None:
        arg, ret = g.pick(_SCALARS), g.pick(_SCALARS)
        f, x, r, name = g.fresh("f"), g.fresh("x"), g.fresh("r"), g.fresh("hof")
        params = [(f, fn_of((arg,), ret)), (x, arg)]
        with _costed(g, (name, "")), g.capture(level=2) as lines, g.function(params, ret):
            _freeze(g)
            g.statements(g.between(0, 2))
            g.emit(f"final {r}:{ret} = {f}({x});")
            g.declare_var(r, ret, mutable=False)
            g.statements(g.between(0, 1))
            twice = arg == ret and g.chance(0.4)
            g.emit(f"return {f}({r});" if twice else f"return {r};")
        self._add(g, name, params, ret, [line[2:] for line in lines])

    def _fold(self, g: Gen) -> None:
        f, n, acc, i = g.fresh("f"), g.fresh("n"), g.fresh("acc"), g.fresh("i")
        params = [(f, fn_of((INT, INT), INT)), (n, INT), (acc, INT)]
        loop = g.pick(
            [
                [f"for ({i} in 0...(({n} & 3) + 1)) {acc} = {f}({acc}, {i});"],
                [f"var {i} = 0;", f"while ({i} < ({n} & 3)) {{", f"\t{acc} = {f}({acc}, {i}++);", "}"],
                [
                    f"for ({i} in 0...3) {{",
                    f"\tif ({i} == {n}) continue;",
                    f"\t{acc} = {f}({acc}, {i});",
                    "}",
                ],
            ]
        )
        self._add(g, g.fresh("fold"), params, INT, [*loop, f"return {acc};"])

    def _maker(self, g: Gen) -> None:
        k, c, x = g.fresh("k"), g.fresh("c"), g.fresh("x")
        body = g.pick(
            [
                [f"var {c} = {k};", f"return function({x}:Int):Int {{ {c} += {x}; return {c}; }};"],
                [f"return ({x}:Int) -> {x} * {k};"],
                [f"final {c} = {k} * 2;", f"return {x} -> {x} + {c};"],
                [f"var {c} = 0;", f"return ({x}:Int) -> {c}++ + {x} + {k};"],
            ]
        )
        self._add(g, g.fresh("mk"), [(k, INT)], _INT_FN, body)

    def _compose(self, g: Gen) -> None:
        f, h, x = g.fresh("f"), g.fresh("h"), g.fresh("x")
        params = [(f, _INT_FN), (h, _INT_FN)]
        self._add(g, g.fresh("comp"), params, _INT_FN, [f"return ({x}:Int) -> {f}({h}({x}));"])

    def _each(self, g: Gen) -> None:
        n, f, i = g.fresh("n"), g.fresh("f"), g.fresh("i")
        params = [(n, INT), (f, fn_of((INT,), VOID))]
        self._add(g, g.fresh("each"), params, VOID, [f"for ({i} in 0...(({n} & 3) + 1)) {f}({i});"])

    def _select(self, g: Gen) -> None:
        flag, a, b = g.fresh("flag"), g.fresh("a"), g.fresh("b")
        params = [(flag, BOOL), (a, _INT_FN), (b, _INT_FN)]
        self._add(g, g.fresh("sel"), params, _INT_FN, [f"return {flag} ? {a} : {b};"])

    # ---- types and printing -----------------------------------------------------------

    def types(self, g: Gen, depth: int):
        return _SHAPES if depth == 0 else []

    def show(self, g: Gen, ty: Ty, expr: str):
        if not ty.is_fn or ty.ret == VOID:
            return None
        return g.show(f"({expr})({', '.join(g.expr(t) for t in ty.params)})", ty.ret)

    # ---- lambdas ----------------------------------------------------------------------

    def _lambda(self, g: Gen, ty: Ty, block: bool) -> str:
        params = [(g.fresh("a"), t) for t in ty.params]
        head = _decl(params)
        with _sealed(g), g.function(params, ty.ret, inherit=True):
            _freeze(g)
            if block:
                if g.stmt_depth >= g.cfg.max_stmt_depth:
                    raise GenError("closure bodies are nested too deeply")
                with g.capture(level=g.level + 1) as lines:
                    g.stmt_depth += 1
                    try:
                        g.body(ty.ret, g.between(1, 3))
                    finally:
                        g.stmt_depth -= 1
                return f"function({head}):{ty.ret} {{\n" + "\n".join(lines) + "\n" + "\t" * g.level + "}"
            if ty.ret == VOID:
                return f"({head}) -> " + g.pick(["{}", f"Sys.println({g.show(g.expr(STRING), STRING)})"])
            return f"({head}) -> {g.expr(ty.ret)}"

    def _binds(self, g: Gen, want: Optional[Ty] = None) -> List[Tuple[str, Ty]]:
        """(callable, type) pairs: function variables and the higher-order helpers, whose prefix can be bound."""
        found = [(v.name, v.ty) for v in g.visible() if v.ty.is_fn]
        found += [
            (f"{g.class_name}.{fn.name}", fn_of(fn.params, fn.ret))
            for fn in g.state.get(self.name, [])
            if fn.params
        ]
        return [
            (name, ty)
            for name, ty in found
            if ty.params
            and not ty.ret.is_fn
            and (
                want is None
                or any(
                    ty.params[k:] == want.params and ty.ret == want.ret for k in range(1, len(ty.params) + 1)
                )
            )
        ]

    def _bind(self, g: Gen, want: Optional[Ty] = None) -> Optional[Tuple[str, Ty]]:
        options = self._binds(g, want)
        if not options:
            return None
        name, ty = g.pick(options)
        ks = [
            k
            for k in range(1, len(ty.params) + 1)
            if want is None or ty.params[k:] == want.params and ty.ret == want.ret
        ]
        k = g.pick(ks)
        return f"{name}.bind({', '.join(g.expr(t) for t in ty.params[:k])})", fn_of(ty.params[k:], ty.ret)

    # ---- expressions ------------------------------------------------------------------

    def exprs(self, g: Gen, ty: Ty):
        if ty.is_fn:
            return [
                Choice(3, lambda: self._lambda(g, ty, block=False), leaf=True),
                Choice(1.5, lambda: self._block_lambda(g, ty)),
                Choice(1, lambda: self._bind_text(g, ty)),
            ]
        if ty == VOID:
            return []
        out = [Choice(1.5, lambda: self._invoke(g, ty))]
        fns = [v for v in g.visible() if v.ty.is_fn and v.ty.ret == ty]
        if fns:
            out.append(Choice(3, lambda: self._call_var(g, g.pick(fns))))
        return out

    def _block_lambda(self, g: Gen, ty: Ty) -> Optional[str]:
        try:
            return self._lambda(g, ty, block=True)
        except GenError:
            return None

    def _bind_text(self, g: Gen, ty: Ty) -> Optional[str]:
        bound = self._bind(g, ty)
        return bound[0] if bound else None

    def _call_var(self, g: Gen, var) -> str:
        return f"{var.name}({', '.join(g.expr(t) for t in var.ty.params)})"

    def _invoke(self, g: Gen, ty: Ty) -> str:
        """A function value built on the spot and called at once."""
        shape = fn_of(tuple(g.pick(_SCALARS) for _ in range(g.between(0, 2))), ty)
        return f"({g.expr(shape)})({', '.join(g.expr(t) for t in shape.params)})"

    # ---- statements -------------------------------------------------------------------

    def stmts(self, g: Gen):
        out = [
            Choice(2, lambda: self._local_function(g), nested=True),
            Choice(2, lambda: self._function_local(g)),
            Choice(1.5, lambda: self._counter(g), nested=True),
            Choice(1.5, lambda: self._capture_loop(g), nested=True),
            Choice(1, lambda: self._iife(g), nested=True),
            Choice(1, lambda: self._bound_local(g)),
        ]
        if any(v.ty.is_fn for v in g.visible()):
            out.append(Choice(3, lambda: self._call_stmt(g)))
        return out

    def _shape(self, g: Gen, void: bool = False) -> Ty:
        ret = VOID if void else g.pick(_SCALARS)
        return fn_of(tuple(g.pick(_SCALARS) for _ in range(g.between(0, 2))), ret)

    def _local_function(self, g: Gen) -> bool:
        ty = self._shape(g, void=g.chance(0.25))
        name = g.fresh("fn")
        params = [(g.fresh("a"), t) for t in ty.params]
        with g.block(f"function {name}({_decl(params)}):{ty.ret} {{"):
            with _sealed(g), g.function(params, ty.ret, inherit=True):
                _freeze(g)
                g.body(ty.ret, g.between(1, 3))
        g.declare_var(name, ty, mutable=False)
        return True

    def _function_local(self, g: Gen) -> bool:
        ty = self._shape(g)
        value = g.expr(ty)
        name = g.fresh("f")
        g.emit(f"{g.pick(['var', 'final'])} {name}:{ty} = {value};")
        g.declare_var(name, ty, mutable=False)
        return True

    def _bound_local(self, g: Gen) -> bool:
        bound = self._bind(g)
        if bound is None:
            return False
        name = g.fresh("b")
        g.emit(f"final {name}:{bound[1]} = {bound[0]};")
        g.declare_var(name, bound[1], mutable=False)
        return True

    def _call_stmt(self, g: Gen) -> bool:
        var = g.pick([v for v in g.visible() if v.ty.is_fn])
        g.emit(self._call_var(g, var) + ";")
        return True

    def _iife(self, g: Gen) -> bool:
        g.emit(f"({self._lambda(g, fn_of((), VOID), block=True)})();")
        return True

    def _counter(self, g: Gen) -> bool:
        """A closure that updates a captured variable; both are observed afterwards."""
        c, f, d = g.fresh("c"), g.fresh("f"), g.fresh("d")
        g.emit(f"var {c}:Int = {g.between(0, 9)};")
        g.declare_var(c, INT)
        update = g.pick([f"{c} += {d};", f"{c} = {c} * 2 - {d};", f"{c} ^= {d};", f"{c}++;"])
        with g.block(f"final {f}:{_INT_FN} = function({d}:Int):Int {{", "};"):
            g.emit(update)
            g.emit(f"return {c};")
        g.declare_var(f, _INT_FN, mutable=False)
        for _ in range(g.between(1, 3)):
            call = f"{f}({g.expr(INT)})"
            g.emit(f"Sys.println({g.show(call, INT)});")
        g.emit(f"Sys.println({g.show(c, INT)});")
        return True

    def _capture_loop(self, g: Gen) -> bool:
        """Closures made in a loop capture the loop variable (a fresh binding per iteration) or a counter."""
        fs, f = g.fresh("fs"), g.fresh("g")
        ty = g.pick([fn_of((), INT), _INT_FN])
        g.emit(f"final {fs}:{array_of(ty)} = [];")
        i, limit = g.fresh("i"), g.between(2, 4)
        shared = g.chance(0.4)
        if shared:
            g.emit(f"var {i} = 0;")
            header, footer = f"while ({i} < {limit}) {{", "}"
        else:
            header, footer = f"for ({i} in 0...{limit}) {{", "}"
        with g.block(header, footer):
            g.declare_var(i, INT, mutable=False)
            if not shared:
                j = g.fresh("j")
                g.emit(f"final {j}:Int = {g.expr(INT)};")
                g.declare_var(j, INT, mutable=False)
            params = [(g.fresh("a"), t) for t in ty.params]
            with _sealed(g), g.function(params, INT, inherit=True):
                _freeze(g)
                body = f"{i} + {params[0][0] + ' + ' if params else ''}{g.expr(INT)}"
            g.emit(f"{fs}.push(({_decl(params)}) -> {body});")
            if shared:
                g.emit(f"{i}++;")
        with g.block(f"for ({f} in {fs}) {{"):
            call = f"{f}({g.expr(INT)})" if ty.params else f"{f}()"
            g.emit(f"Sys.println({g.show(call, INT)});")
        return True
