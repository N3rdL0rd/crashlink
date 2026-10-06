"""Enums and enum abstracts: construction, pattern matching (guards, or-patterns, nesting), helper functions."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Tuple

from ..feature import Choice, Feature, register
from ..gen import Fn, Gen, GenError
from ..types import BOOL, FLOAT, INT, STRING, Ty

_CTORS = [
    "Circle",
    "Rect",
    "Tri",
    "Pt",
    "Num",
    "Add",
    "Neg",
    "Str",
    "Empty",
    "Pair",
    "Box",
    "Leaf",
    "Node",
    "Wrap",
    "Bit",
]
_COLORS = ["Red", "Green", "Blue", "Cyan", "Pink", "Gray"]
_SCALARS = (INT, FLOAT, BOOL, STRING)


@dataclass
class Ctor:
    name: str
    args: List[Ty]


@dataclass
class Spec:
    ty: Ty
    ctors: List[Ctor]
    underlying: Optional[Ty] = None  # set for an enum abstract

    @property
    def leaves(self) -> List[Ctor]:
        return [c for c in self.ctors if self.ty not in c.args]

    @property
    def recursive(self) -> bool:
        return any(self.ty in c.args for c in self.ctors)


@dataclass
class Arm:
    pattern: str
    guard: Optional[str]
    binds: List[Tuple[str, Ty]]


@dataclass
class State:
    specs: Dict[Ty, Spec]
    helpers: Dict[Ty, str]  # enum -> name of its static `describe` function


@register
class Enums(Feature):
    name = "enums"
    summary = "enums, enum abstracts, pattern matching with guards/or-patterns/nesting, .match, helpers"
    covers = (
        "EEnum",
        "EAbstract",
        "ESwitch",
        "FVar",
        "FFun",
        "AStatic",
        "AInline",
        "APublic",
        "decl:enum_abstract",
    )
    order = 28

    # ---- declarations -----------------------------------------------------------------

    def declare(self, g: Gen) -> None:
        st = State({}, {})
        g.state[self.name] = st
        names = g.rng.sample(_CTORS, len(_CTORS))
        for i in range(g.between(2, 3)):
            spec = self._enum(g, st, names, recursive=i == 1)
            st.specs[spec.ty] = spec
        if g.chance(0.85):
            st.specs.update({spec.ty: spec for spec in [self._abstract(g)]})
        for spec in st.specs.values():
            st.helpers[spec.ty] = g.fresh("describe")
        for spec in st.specs.values():
            self._describe(g, st, spec)
            for _ in range(g.between(1, 2)):
                self._function(g, st, spec)
            if spec.recursive:
                self._fold(g, st, spec)

    def _enum(self, g: Gen, st: State, names: List[str], recursive: bool) -> Spec:
        ty = Ty(g.fresh("Shape" if not recursive else "Tree"))
        earlier = list(st.specs)
        ctors = [Ctor(names.pop(), [])]
        for _ in range(g.between(1, 3)):
            args = [g.pick(_SCALARS + (FLOAT, INT)) for _ in range(g.between(1, 3))]
            if earlier and g.chance(0.4):
                args[0] = g.pick(earlier)
            ctors.append(Ctor(names.pop(), args))
        if recursive:
            ctors.append(Ctor(names.pop(), [ty, INT, ty]))
            if g.chance(0.6):
                ctors.append(Ctor(names.pop(), [ty]))
        g.rng.shuffle(ctors)
        lines = [
            f"\t{c.name}"
            + (f"({', '.join(f'p{i}:{a}' for i, a in enumerate(c.args))})" if c.args else "")
            + ";"
            for c in ctors
        ]
        g.decls.append(f"enum {ty} {{\n" + "\n".join(lines) + "\n}")
        return Spec(ty, ctors)

    def _abstract(self, g: Gen) -> Spec:
        under = g.pick([INT, STRING])
        ty = Ty(g.fresh("Color"))
        names = g.rng.sample(_COLORS, g.between(2, 4))
        values = [
            str(i * 3 + g.between(0, 2)) if under == INT else f'"{n.lower()}"' for i, n in enumerate(names)
        ]
        lines = [f"\tvar {n} = {v};" for n, v in zip(names, values)]
        inline = g.pick(["", "inline "])
        lines.append(f"\tpublic {inline}function value():{under} {{ return this; }}")
        g.decls.append(f"enum abstract {ty}({under}) {{\n" + "\n".join(lines) + "\n}")
        return Spec(ty, [Ctor(n, []) for n in names], underlying=under)

    def _describe(self, g: Gen, st: State, spec: Spec) -> None:
        arms = []
        for c in spec.ctors:
            binds = [(g.fresh("d"), a) for a in c.args]
            shown = ' + ", " + '.join(g.show(n, t) for n, t in binds)
            body = f'"{c.name}(" + {shown} + ")"' if binds else f'"{c.name}"'
            head = f"{c.name}({', '.join(n for n, _ in binds)})" if binds else c.name
            arms.append(f"case {head}: {body};")
        name = st.helpers[spec.ty]
        g.members.append(
            f"\tpublic static function {name}(e:{spec.ty}):String {{\n\t\treturn switch (e) {{ {' '.join(arms)} }};\n\t}}"
        )
        g.fns.append(Fn(f"{g.class_name}.{name}", (spec.ty,), STRING))

    def _function(self, g: Gen, st: State, spec: Spec) -> None:
        """`static function f(e:Shape):R`: a switch over all the arms, then a fallback return."""
        ret = g.pick(_SCALARS + (FLOAT, INT) + tuple(st.specs))
        name = g.fresh("matchOn")
        with g.capture(level=1) as out, g.function([("e", spec.ty)], ret):
            g.emit(f"public static function {name}(e:{spec.ty}):{ret} {{")
            g.level += 1
            if g.chance(0.5):
                g.emit(f"return {self._switch_value(g, st, ret, spec, 'e')};")
            else:
                self._switch_stmt(g, st, spec, "e", ret)
                g.emit(f"return {g.expr(ret)};")
            g.level -= 1
            g.emit("}")
        g.members.append("\n".join(out))
        g.fns.append(Fn(f"{g.class_name}.{name}", (spec.ty,), ret))

    def _fold(self, g: Gen, st: State, spec: Spec) -> None:
        """A recursive function over a self-referential enum; finite data guarantees termination."""
        ret = g.pick([INT, FLOAT, STRING])
        name = g.fresh("fold")
        arms = []
        for c in spec.ctors:
            binds = [(g.fresh("f"), a) for a in c.args]
            terms = []
            for n, t in binds:
                if t == spec.ty:
                    terms.append(f"{name}({n})")
                elif ret == STRING:
                    terms.append(g.show(n, t))
                elif t == FLOAT and ret == INT:
                    terms.append(f"Std.int({n})")
                elif t in (INT, FLOAT):
                    terms.append(n)
                elif t == BOOL:
                    terms.append(f"({n} ? 1 : 0)")
                elif t == STRING:
                    terms.append(f"{n}.length")
            base = {INT: "1", FLOAT: "0.5", STRING: f'"{c.name}"'}[ret]
            ops = [" + "] if ret == STRING else [" + ", " - "]
            expr = base
            for term in terms:
                expr = f"({expr}{g.pick(ops)}{term})"
            head = f"{c.name}({', '.join(n for n, _ in binds)})" if binds else c.name
            arms.append(f"case {head}: {expr};")
        g.members.append(
            f"\tpublic static function {name}(e:{spec.ty}):{ret} {{\n\t\treturn switch (e) {{ {' '.join(arms)} }};\n\t}}"
        )
        g.fns.append(Fn(f"{g.class_name}.{name}", (spec.ty,), ret))

    # ---- value types ------------------------------------------------------------------

    def types(self, g: Gen, depth: int):
        return [(2 / (1 + depth), ty) for ty in g.state[self.name].specs]

    def show(self, g: Gen, ty: Ty, expr: str) -> Optional[str]:
        helper = g.state[self.name].helpers.get(ty)
        return f"{g.class_name}.{helper}({expr})" if helper else None

    # ---- expressions ------------------------------------------------------------------

    def exprs(self, g: Gen, ty: Ty):
        st: State = g.state[self.name]
        out = [Choice(1.5, lambda: self._switch_value(g, st, ty))]
        spec = st.specs.get(ty)
        if spec:
            out.append(Choice(3, lambda: self._construct(g, spec, g.pick(spec.leaves)), leaf=True))
            out.append(Choice(3, lambda: self._construct(g, spec, g.pick(spec.ctors))))
        for other in st.specs.values():
            if other.underlying == ty:
                out.append(Choice(1.5, lambda: f"({g.expr(other.ty)}).value()", leaf=True))
        if ty == BOOL:
            out.append(Choice(2, lambda: self._equality(g, st)))
            out.append(Choice(2, lambda: self._match(g, st)))
        return out

    def _construct(self, g: Gen, spec: Spec, ctor: Ctor) -> str:
        if not ctor.args:
            return f"{spec.ty}.{ctor.name}"
        return f"{spec.ty}.{ctor.name}({', '.join(g.expr(a) for a in ctor.args)})"

    def _equality(self, g: Gen, st: State) -> Optional[str]:
        abstracts = [s for s in st.specs.values() if s.underlying is not None]
        if not abstracts:
            return None  # Haxe refuses `==` on enums that have constructors with arguments
        spec = g.pick(abstracts)
        nullary = spec.ctors
        return f"({g.expr(spec.ty)} {g.pick(['==', '!='])} {spec.ty}.{g.pick(nullary).name})"

    def _match(self, g: Gen, st: State) -> Optional[str]:
        enums = [s for s in st.specs.values() if s.underlying is None]
        spec = g.pick(enums)
        pattern, _ = self._pattern(g, spec, [], bind=False, refute=g.chance(0.5), depth=0)
        return f"(({g.expr(spec.ty)}).match({pattern}))"

    def _switch_value(
        self, g: Gen, st: State, ty: Ty, spec: Optional[Spec] = None, subject: Optional[str] = None
    ) -> Optional[str]:
        spec = spec or g.pick(list(st.specs.values()))
        try:
            arms, needs_default = self._plan(g, spec)
            parts = []
            for arm in arms:
                with self._scoped(g, arm.binds):
                    parts.append(f"{self._head(arm)} {g.expr(ty)};")
            if needs_default:
                parts.append(f"{g.pick(['default', 'case _'])}: {g.expr(ty)};")
            subject = subject or g.expr(spec.ty)
        except GenError:
            return None
        return f"(switch ({subject}) {{ {' '.join(parts)} }})"

    # ---- statements -------------------------------------------------------------------

    def stmts(self, g: Gen):
        st: State = g.state[self.name]
        out = [Choice(4, lambda: self._switch_stmt(g, st, g.pick(list(st.specs.values()))), nested=True)]
        shown = [v for v in g.visible() if v.ty in st.specs]
        if shown:
            out.append(Choice(2, lambda: self._print(g, g.pick(shown))))
        return out

    def _print(self, g: Gen, var) -> bool:
        g.emit(f"Sys.println({g.show(var.name, var.ty)});")
        return True

    def _switch_stmt(
        self, g: Gen, st: State, spec: Spec, subject: Optional[str] = None, ret: Optional[Ty] = None
    ) -> bool:
        subject = subject or g.expr(spec.ty)
        arms, needs_default = self._plan(g, spec)
        with g.block(f"switch ({subject}) {{"):
            for arm in arms:
                self._arm(g, self._head(arm), arm.binds, ret)
            if needs_default:
                self._arm(g, g.pick(["default:", "case _:"]), [], ret)
        return True

    def _arm(self, g: Gen, head: str, binds: List[Tuple[str, Ty]], ret: Optional[Ty]) -> None:
        g.emit(head)
        g.level += 1
        with self._scoped(g, binds):
            if ret is not None:
                g.statements(g.between(0, 1))
                g.emit(f"return {g.expr(ret)};")
            else:
                if binds and g.chance(0.7):
                    name, ty = g.pick(binds)
                    g.emit(f"Sys.println({g.show(name, ty)});")
                else:
                    g.emit(f'Sys.println("arm" + {g.expr(INT)});')
                g.statements(g.between(0, 2))
        g.level -= 1

    @contextmanager
    def _scoped(self, g: Gen, binds: List[Tuple[str, Ty]]) -> Iterator[None]:
        g.scopes.append([])
        try:
            for name, ty in binds:
                g.declare_var(name, ty, mutable=False)
            yield
        finally:
            g.scopes.pop()

    @staticmethod
    def _head(arm: Arm) -> str:
        return f"case {arm.pattern}{f' if ({arm.guard})' if arm.guard else ''}:"

    # ---- patterns ---------------------------------------------------------------------

    def _plan(self, g: Gen, spec: Spec) -> Tuple[List[Arm], bool]:
        """Arms for a switch over `spec`, and whether a default is still needed for exhaustiveness."""
        order = list(spec.ctors)
        g.rng.shuffle(order)
        covered: set = set()
        arms: List[Arm] = []
        for ctor in order[: g.between(1, len(order))]:
            if ctor.name in covered:
                continue
            style = g.weighted(["plain", "guard", "refine", "or"], [4, 2.5, 2, 1.5])
            if style == "or":
                group = [c for c in order if c.name not in covered]
                group = group[: g.between(2, 3)]
                if len(group) >= 2:
                    pats = [self._pattern(g, spec, [], False, False, 0, c)[0] for c in group]
                    arms.append(Arm(" | ".join(pats), None, []))
                    covered.update(c.name for c in group)
                    continue
                style = "plain"
            binds: List[Tuple[str, Ty]] = []
            if style == "refine":
                pattern, full = self._pattern(g, spec, binds, True, True, 0, ctor)
                arms.append(Arm(pattern, None, binds))
                if full:
                    covered.add(ctor.name)
                continue
            pattern, full = self._pattern(g, spec, binds, True, False, 0, ctor)
            if style == "guard":
                arms.append(Arm(pattern, self._guard(g, binds), binds))
                if g.chance(0.5):
                    continue
                binds = []
                pattern, full = self._pattern(g, spec, binds, True, False, 0, ctor)
            arms.append(Arm(pattern, None, binds))
            if full:
                covered.add(ctor.name)
        return arms, any(c.name not in covered for c in spec.ctors)

    def _pattern(
        self,
        g: Gen,
        spec: Spec,
        binds: List[Tuple[str, Ty]],
        bind: bool,
        refute: bool,
        depth: int,
        ctor: Optional[Ctor] = None,
    ) -> Tuple[str, bool]:
        """A pattern for `ctor` (or any constructor); also whether it matches every value of that constructor."""
        ctor = ctor or g.pick(spec.ctors)
        name = f"{spec.ty}.{ctor.name}" if g.chance(0.2) else ctor.name
        if not ctor.args:
            return name, True
        if not refute and g.chance(0.1):
            return f"{name}(_)", True
        parts, full = [], True
        st: State = g.state[self.name]
        for arg in ctor.args:
            nested = st.specs.get(arg)
            options = [("wild", 2.0), ("var", 5.0 if bind else 0.0)]
            if refute:
                options.append(("const", 3.0 if arg in (INT, STRING, BOOL) else 0.0))
                options.append(("nested", 4.0 if nested and nested.underlying is None and depth < 2 else 0.0))
            kind = g.weighted([k for k, _ in options], [w for _, w in options])
            if kind == "var":
                var = g.fresh("b")
                binds.append((var, arg))
                parts.append(var)
            elif kind == "const":
                full = False
                parts.append(
                    g.pick(
                        {
                            INT: ["0", "1", "3", "7"],
                            STRING: ['"a"', '""', '"hello"'],
                            BOOL: ["true", "false"],
                        }[arg]
                    )
                )
            elif kind == "nested" and nested is not None:
                full = False
                text, _ = self._pattern(g, nested, binds, bind, True, depth + 1)
                parts.append(text)
            else:
                parts.append("_")
        return f"{name}({', '.join(parts)})", full

    def _guard(self, g: Gen, binds: List[Tuple[str, Ty]]) -> str:
        scalars = [(n, t) for n, t in binds if t in _SCALARS]
        if not scalars:
            return g.expr(BOOL)
        name, ty = g.pick(scalars)
        same = [n for n, t in scalars if t == ty and n != name]
        if same and ty != BOOL and g.chance(0.5):
            return f"{name} {g.pick(['==', '!=', '<='])} {same[0]}"
        guard = {
            INT: f"{name} {g.pick(['>', '<', '==', '!='])} {g.pick(['0', '3', '7'])}",
            FLOAT: f"{name} {g.pick(['>', '<'])} {g.pick(['0.0', '1.5', '2.0'])}",
            STRING: g.pick([f"{name}.length > 1", f'{name} == "a"', f'{name} != ""']),
            BOOL: g.pick([name, f"!{name}"]),
        }[ty]
        return f"{guard} {g.pick(['&&', '||'])} {g.expr(BOOL)}" if g.chance(0.2) else guard
