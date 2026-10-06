"""try/catch/throw: typed catch clauses, rethrow, helpers that throw, try as an expression, jumps out of try."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Dict, FrozenSet, Iterator, List, Optional

from ..feature import Choice, Feature, register
from ..gen import Fn, Gen
from ..types import BOOL, DYNAMIC, INT, STRING, VOID, Ty

KINDS = frozenset({"str", "int", "err", "box"})
_CONDS = ["(a & 1) == 1", "a % 3 == 0", "a > 5", "a < 2", "(a & 3) != 0"]


@dataclass(frozen=True)
class Clause:
    """One `catch (name:ty)`: the kinds of thrown value it takes and how to print what it caught."""

    ty: str
    var: Optional[Ty]
    covers: FrozenSet[str]
    show: Callable[[str], str]


@register
class Exceptions(Feature):
    name = "exceptions"
    summary = "try/catch with typed clauses, throw, rethrow, throwing helpers, try as value, jumps out of try"
    covers = (
        "ETry",
        "EThrow",
        "EClass",
        "HExtends",
        "AStatic",
        "APublic",
        "AOverride",
        "FFun",
        "FVar",
        "std:haxe.Exception",
    )
    order = 46

    # ---- declarations -----------------------------------------------------------------

    def declare(self, g: Gen) -> None:
        err, box = g.fresh("Boom"), g.fresh("Crate")
        g.decls.append(
            "\n".join(
                [
                    f"class {err} extends haxe.Exception {{",
                    "\tpublic var code:Int;",
                    "\tpublic function new(code:Int) {",
                    '\t\tsuper("err" + code);',
                    "\t\tthis.code = code;",
                    "\t}",
                    "\toverride public function toString():String {",
                    f'\t\treturn "{err}(" + code + ")";',
                    "\t}",
                    "}",
                ]
            )
        )
        g.decls.append(
            "\n".join(
                [
                    f"class {box} {{",
                    "\tpublic var code:Int;",
                    "\tpublic function new(code:Int) {",
                    "\t\tthis.code = code;",
                    "\t}",
                    "\tpublic function toString():String {",
                    f'\t\treturn "{box}(" + code + ")";',
                    "\t}",
                    "}",
                ]
            )
        )
        state = {"err": err, "box": box, "helpers": [], "cover": []}
        g.state[self.name] = state
        values = {"str": '"odd" + a', "int": "a * 2", "err": f"new {err}(a)", "box": f"new {box}(a)"}
        for kind in g.rng.sample(sorted(KINDS), 2):
            simple = self._helper(
                g, frozenset({kind}), [f"if ({g.pick(_CONDS)}) throw {values[kind]};", "return a * 3;"]
            )
            chain = [simple]
            if g.chance(0.6):
                body = f"try {{ return {simple}(a + 1); }} catch (e:Dynamic) {{ throw e; }}"
                chain.append(self._helper(g, frozenset({kind}), [body]))
            if g.chance(0.6):
                self._helper(g, frozenset({kind}), [f"return {g.pick(chain)}(a - 1) + 1;"])
        if g.chance(0.6):
            mixed = [
                "switch (a % 5) {",
                '\tcase 0: throw "m" + a;',
                "\tcase 1: throw a;",
                f"\tcase 2: throw new {err}(a);",
                f"\tcase 3: throw new {box}(a);",
                "\tdefault: return a;",
                "}",
            ]
            self._helper(g, KINDS, mixed)
        for name, kinds in list(state["helpers"]):
            self._safe(g, name, kinds)

    def _helper(self, g: Gen, kinds: FrozenSet[str], body: List[str]) -> str:
        name = g.fresh("thr")
        g.members.append(
            "\n".join([f"\tstatic function {name}(a:Int):Int {{", *("\t\t" + b for b in body), "\t}"])
        )
        self._state(g)["helpers"].append((name, kinds))
        return name

    def _safe(self, g: Gen, thrower: str, kinds: FrozenSet[str]) -> None:
        """A total wrapper around a throwing helper; this is what other features may call."""
        state = self._state(g)
        handlers = {
            "str": "catch (e:String) { return e.length; }",
            "int": "catch (e:Int) { return e; }",
            "err": f"catch (e:{state['err']}) {{ return e.code; }}",
            "box": f"catch (e:{state['box']}) {{ return e.code; }}",
        }
        picked = [handlers[k] for k in sorted(kinds)]
        if len(kinds) > 1 or g.chance(0.4):
            general = [
                "catch (e:haxe.Exception) { return e.message.length; }",
                "catch (e:Dynamic) { return -1; }",
            ]
            picked.append(g.pick(general))
        name = g.fresh("safe")
        body = [f"\tstatic function {name}(a:Int):Int {{", f"\t\ttry {{ return {thrower}(a); }}"]
        body += [f"\t\t{h}" for h in picked] + ["\t}"]
        g.members.append("\n".join(body))
        g.fns.append(Fn(name, (INT,), INT))

    def _state(self, g: Gen) -> Dict:
        return g.state[self.name]

    # ---- coverage bookkeeping ---------------------------------------------------------

    @contextmanager
    def _covering(self, g: Gen, kinds: FrozenSet[str]) -> Iterator[None]:
        """While active, `throw` of any of `kinds` is known to be caught."""
        frames = self._state(g)["cover"]
        frames.append(kinds)
        try:
            yield
        finally:
            frames.pop()

    def _allowed(self, g: Gen) -> FrozenSet[str]:
        state = g.state.get(self.name)
        return frozenset().union(*state["cover"]) if state and state["cover"] else frozenset()

    # ---- building blocks --------------------------------------------------------------

    def _value(self, g: Gen, kind: str) -> str:
        state = self._state(g)
        if kind == "str":
            return g.expr(STRING)
        if kind == "int":
            return g.expr(INT)
        return f"new {state[kind]}({g.expr(INT)})"

    def _throw(self, g: Gen, allowed: FrozenSet[str]) -> str:
        return f"throw {self._value(g, g.pick(sorted(allowed)))}"

    def _clause(self, g: Gen, kind: str) -> Clause:
        state = self._state(g)
        if kind == "str":
            return Clause("String", STRING, frozenset({"str"}), lambda n: n)
        if kind == "int":
            return Clause("Int", INT, frozenset({"int"}), lambda n: g.show(n, INT))
        if kind in ("err", "box"):
            shown = (
                (lambda n: f'{n}.message + ":" + {n}.code')
                if kind == "err"
                else (lambda n: f'"c" + {n}.code')
            )
            return Clause(state[kind], None, frozenset({kind}), shown)
        if kind == "exc":
            return Clause("haxe.Exception", None, KINDS, lambda n: f"{n}.message")
        return Clause("Dynamic", DYNAMIC, KINDS, lambda n: f"Std.string({n})")

    def _clauses(self, g: Gen, value: bool = False) -> List[Clause]:
        """Specific clauses in random order, then the general ones (a general clause hides what follows it).

        A `try` used as a value gets only general clauses: haxe 4.3.7's HashLink generator fails with
        "Don't know how to cast void" on a typed clause inside an inlined call's argument (`Std.int(1.5 * try ...)`)."""
        specific = [] if value else g.rng.sample(sorted(KINDS), g.between(0, 3))
        general = g.pick(
            [["exc"], ["dyn"], ["exc", "dyn"], ["dyn"]] if value else [[], ["exc"], ["dyn"], ["exc", "dyn"]]
        )
        kinds = specific + general
        return [self._clause(g, k) for k in kinds or ["dyn"]]

    def _jumps(self, g: Gen, allowed: FrozenSet[str]) -> None:
        """Conditional exits: throw (if something catches it), return, break/continue."""
        options: List[Callable[[], str]] = []
        if allowed:
            options.append(lambda: f"if ({g.expr(BOOL)}) {self._throw(g, allowed)};")
        ret = g.ret_ty
        if ret is not None and ret != VOID:
            options.append(lambda: f"if ({g.expr(BOOL)}) return {g.expr(ret)};")
        if g.loop_depth:
            options.append(lambda: f"if ({g.expr(BOOL)}) {g.pick(['break', 'continue'])};")
        if options:
            g.emit(g.pick(options)())

    def _call(self, g: Gen, allowed: FrozenSet[str]) -> bool:
        """`var r = thrN(arg);` where everything it may throw is caught."""
        fits = [name for name, kinds in self._state(g)["helpers"] if kinds <= allowed]
        if not fits:
            return False
        name = g.fresh("r")
        g.emit(f"var {name} = {g.pick(fits)}({g.expr(INT)});")
        g.declare_var(name, INT)
        g.emit(f"Sys.println({g.show(name, INT)});")
        return True

    # ---- statements -------------------------------------------------------------------

    def stmts(self, g: Gen):
        allowed = self._allowed(g)
        out = [
            Choice(5, lambda: self._try(g), nested=True),
            Choice(1, lambda: self._switch(g), nested=True),
        ]
        if allowed:
            out.append(Choice(2, lambda: self._throw_if(g, allowed)))
            out.append(Choice(2, lambda: self._call(g, allowed)))
        return out

    def _throw_if(self, g: Gen, allowed: FrozenSet[str]) -> bool:
        g.emit(f"if ({g.expr(BOOL)}) {self._throw(g, allowed)};")
        return True

    def _try(self, g: Gen) -> bool:
        clauses = self._clauses(g)
        inner = frozenset().union(*(c.covers for c in clauses))
        with g.block("try {", ""):
            with self._covering(g, inner):
                allowed = self._allowed(g)
                if g.chance(0.25) and g.stmt_depth < g.cfg.max_stmt_depth:
                    self._try(g)
                if g.chance(0.5):
                    self._jumps(g, allowed)
                g.statements()
                if g.chance(0.4):
                    self._call(g, allowed)
                if g.chance(0.7):
                    self._jumps(g, allowed)
        outer = self._allowed(g)
        for clause in clauses:
            name = g.fresh("e")
            with g.block(f"}} catch ({name}:{clause.ty}) {{", ""):
                if clause.var is not None:
                    g.declare_var(name, clause.var, mutable=False)
                g.emit(f'Sys.println("{g.pick(["caught", "handler", "got"])} " + {clause.show(name)});')
                if g.chance(0.5):
                    g.statements(g.between(1, 2))
                self._after_catch(g, clause, name, outer)
        g.emit("}")
        return True

    def _after_catch(self, g: Gen, clause: Clause, name: str, outer: FrozenSet[str]) -> None:
        """What a handler does besides printing: rethrow, throw something else, or leave."""
        roll = g.rng.random()
        if roll < 0.25 and clause.covers <= outer:
            g.emit(f"throw {name};")
        elif roll < 0.4 and outer:
            g.emit(f"{self._throw(g, outer)};")
        elif roll < 0.7:
            self._jumps(g, outer)

    def _switch(self, g: Gen) -> bool:
        if g.stmt_depth + 1 >= g.cfg.max_stmt_depth:
            return False
        patterns = g.rng.sample(["0", "1", "2", "3", "5"], g.between(2, 3))
        g.emit(f"switch ({g.expr(INT)}) {{")
        g.level += 1
        for pattern in patterns:
            with g.block(f"case {pattern}:", ""):
                self._try(g)
        with g.block("default:", ""):
            g.statements(1)
        g.level -= 1
        g.emit("}")
        return True

    # ---- expressions ------------------------------------------------------------------

    def exprs(self, g: Gen, ty: Ty):
        if ty == VOID:
            return []
        return [Choice(1.5, lambda: self._try_expr(g, ty))]

    def _try_expr(self, g: Gen, ty: Ty) -> str:
        """`(try body catch (e:T) fallback ...)`: whatever the body throws, some clause takes."""
        clauses = self._clauses(g, value=True)
        inner = frozenset().union(*(c.covers for c in clauses))

        def wrap(text: str) -> str:
            return (
                text
                if ty.args == () and ty.name in ("Int", "Float", "Bool", "String")
                else f"({text} : {ty})"
            )

        with self._covering(g, inner):
            allowed = self._allowed(g)
            fits = [n for n, kinds in self._state(g)["helpers"] if kinds <= allowed]
            if ty == INT and fits and g.chance(0.4):
                body = f"{g.pick(fits)}({g.expr(INT)})"
            elif g.chance(0.6):
                body = f"(if ({g.expr(BOOL)}) {self._throw(g, allowed)} else {wrap(g.expr(ty))})"
            else:
                body = wrap(g.expr(ty))
        catches = []
        for clause in clauses:
            name = g.fresh("e")
            g.scopes.append([])
            try:
                if clause.var is not None:
                    g.declare_var(name, clause.var, mutable=False)
                if ty == STRING and g.chance(0.6):
                    fallback = clause.show(name)
                elif ty == INT and clause.var == INT:
                    fallback = name
                else:
                    fallback = wrap(g.expr(ty))
            finally:
                g.scopes.pop()
            catches.append(f"catch ({name}:{clause.ty}) {fallback}")
        return f"(try {body} {' '.join(catches)})"
