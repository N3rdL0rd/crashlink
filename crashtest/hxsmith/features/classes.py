"""Classes: fields, properties, constructors, statics, inheritance, an interface and virtual dispatch.

Method bodies call each other through `g.fns` (the call sites are built by the `functions` feature,
which consults `g.state["calls"]`). Virtual dispatch could turn the registration-order DAG into a
cycle (`Base.m` calls `x.n()` which lands in `Derived.n` which calls `Base.m`), so a method that
can be dispatched to virtually only calls functions that never reach a virtual call themselves.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Set, Tuple

from ..feature import Choice, Feature, register
from ..gen import Fn, Gen
from ..types import BOOL, FLOAT, INT, STRING, VOID, Ty

_SCALARS = [INT, INT, INT, STRING, FLOAT, BOOL]
_RETS = [INT, INT, STRING, FLOAT, BOOL, VOID]
_INT_OPS = ["+=", "-=", "*=", "^=", "|="]


@dataclass
class Field:
    name: str
    ty: Ty
    owner: str
    static: bool = False
    final: bool = False
    public: bool = True
    kind: str = "var"  # var | gs (get, set) | dn (default, null) | ns (null, set)
    ctor_init: bool = False  # a final instance field assigned in the constructor

    @property
    def readable(self) -> bool:
        return self.public and self.kind != "ns"

    @property
    def writable(self) -> bool:
        return self.public and not self.final and self.kind in ("var", "gs", "ns")


@dataclass
class Method:
    name: str
    params: List[Tuple[str, Ty]]
    ret: Ty
    static: bool = False
    inline: bool = False
    override: bool = False


@dataclass
class Cls:
    name: str
    base: Optional[str]
    fields: List[Field] = field(default_factory=list)
    methods: List[Method] = field(default_factory=list)
    ctor: List[Ty] = field(default_factory=list)  # parameter types, the base's first
    descendants: List[Ty] = field(default_factory=list)


@dataclass
class _Frame:
    tainted: bool = False  # the body being generated calls something that reaches a virtual call


@dataclass
class _State:
    classes: Dict[str, Cls] = field(default_factory=dict)
    iface: str = ""
    iface_methods: List[Method] = field(default_factory=list)
    virtual: Set[str] = field(default_factory=set)
    tainted: Set[Tuple[str, str]] = field(default_factory=set)
    quiet: int = 0  # >0 while generating constructors and initialisers: no `new`, no calls

    def lineage(self, cls: Cls) -> List[Cls]:
        chain = [cls]
        while chain[-1].base:
            chain.append(self.classes[chain[-1].base])
        return chain[::-1]

    def instance_fields(self, cls: Cls) -> List[Field]:
        return [f for c in self.lineage(cls) for f in c.fields if not f.static]

    def types(self) -> Set[Ty]:
        return {Ty(n) for n in self.classes} | {Ty(self.iface)}


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


_SHORT = ['"a"', '"-"', '"xy"', '""']


@register
class Classes(Feature):
    name = "classes"
    summary = "classes: fields, properties, statics, ctors, inheritance, interface, virtual calls"
    covers = (
        "EClass", "HInterface", "HExtends", "HImplements", "APublic", "APrivate", "AStatic", "AOverride",
        "AInline", "AFinal", "FVar", "FFun", "FProp", "ENew", "EFNormal",
    )  # fmt: skip
    requires = ("variables", "functions")
    order = 40

    # ---- planning ---------------------------------------------------------------------

    def declare(self, g: Gen) -> None:
        st = _State()
        g.state[self.name] = st
        st.iface = g.fresh("I")
        st.iface_methods = [self._signature(g) for _ in range(g.between(1, 2))]
        st.virtual |= {m.name for m in st.iface_methods} | {"describe"}
        bases: List[Optional[int]] = [None, 0, None, g.pick([1, 2])]
        order: List[Cls] = []
        for base in bases[: g.between(2, 4)]:
            cls = self._plan(g, st, order[base] if base is not None else None)
            st.classes[cls.name] = cls
            order.append(cls)
            for ancestor in st.lineage(cls)[:-1]:
                ancestor.descendants.append(Ty(cls.name))
        g.subtypes[Ty(st.iface)] = [Ty(c.name) for c in order]
        for cls in order:
            if cls.descendants:
                g.subtypes[Ty(cls.name)] = cls.descendants
        texts = [self._iface_text(st)]
        for cls in order:
            texts.append(self._class_text(g, st, cls))
        g.decls.extend(texts)

    def _signature(self, g: Gen, static: bool = False) -> Method:
        params = [(g.fresh("p"), g.pick(_SCALARS)) for _ in range(g.between(0, 2))]
        return Method(g.fresh("m"), params, g.pick(_RETS), static=static)

    def _plan(self, g: Gen, st: _State, base: Optional[Cls]) -> Cls:
        cls = Cls(g.fresh("C"), base.name if base else None)
        for _ in range(g.between(1, 3)):
            final = g.chance(0.2)
            cls.fields.append(
                Field(
                    g.fresh("f"),
                    g.pick(_SCALARS),
                    cls.name,
                    final=final,
                    public=g.chance(0.75),
                    ctor_init=final and g.chance(0.6),
                )  # fmt: skip
            )
        if g.chance(0.6):
            cls.fields.append(
                Field(g.fresh("f"), INT, cls.name, public=g.chance(0.85), kind=g.pick(["gs", "dn", "ns"]))
            )
        for _ in range(g.between(0, 2)):
            cls.fields.append(
                Field(
                    g.fresh("s"),
                    g.pick(_SCALARS),
                    cls.name,
                    static=True,
                    final=g.chance(0.25),
                    public=g.chance(0.7),
                )
            )
        cls.ctor = (base.ctor if base else []) + [
            g.pick(_SCALARS) for _ in range(g.between(0 if base else 1, 2))
        ]

        if base is None:
            cls.methods += [Method(m.name, self._renamed(g, m), m.ret) for m in st.iface_methods]
        else:
            inherited = {
                m.name: m for c in st.lineage(base) for m in c.methods if not m.static and not m.inline
            }
            inherited.pop("describe", None)
            for m in g.rng.sample(
                sorted(inherited.values(), key=lambda m: m.name), min(len(inherited), g.between(0, 2))
            ):
                cls.methods.append(Method(m.name, self._renamed(g, m), m.ret, override=True))
                st.virtual.add(m.name)
        cls.methods.append(Method("describe", [], STRING, override=base is not None))
        for _ in range(g.between(0, 2)):
            cls.methods.append(self._signature(g))
            cls.methods[-1].inline = g.chance(0.2)
        for _ in range(g.between(0, 2)):
            cls.methods.append(self._signature(g, static=True))
            cls.methods[-1].inline = g.chance(0.2)
        return cls

    def _renamed(self, g: Gen, m: Method) -> List[Tuple[str, Ty]]:
        return [(g.fresh("p"), t) for _, t in m.params]

    # ---- text -------------------------------------------------------------------------

    @staticmethod
    def _sig_text(m: Method) -> str:
        return f"{m.name}({', '.join(f'{n}:{t}' for n, t in m.params)}):{m.ret}"

    def _iface_text(self, st: _State) -> str:
        lines = [f"interface {st.iface} {{", "\tfunction describe():String;"]
        lines += [f"\tfunction {self._sig_text(m)};" for m in st.iface_methods]
        return "\n".join([*lines, "}"])

    def _class_text(self, g: Gen, st: _State, cls: Cls) -> str:
        head = f"class {cls.name}"
        head += f" extends {cls.base}" if cls.base else f" implements {st.iface}"
        lines = [head + " {"]
        for f in cls.fields:
            lines += self._field_lines(g, st, f)
        lines += self._ctor(g, st, cls)
        for m in cls.methods:
            lines += self._method(g, st, cls, m)
        return "\n".join([*lines, "}"])

    def _literal(self, g: Gen, st: _State, ty: Ty) -> str:
        """A constant of `ty` for an initialiser: leaf expressions only, nothing that runs user code."""
        with g.function([], None):
            g.expr_depth = g.cfg.max_expr_depth
            st.quiet += 1
            try:
                return g.expr(ty)
            finally:
                st.quiet -= 1

    def _field_lines(self, g: Gen, st: _State, f: Field) -> List[str]:
        vis = "public " if f.public else g.pick(["", "private "])
        static = "static " if f.static else ""
        if f.kind == "var":
            init = "" if f.ctor_init else f" = {self._literal(g, st, f.ty)}"
            return [f"\t{vis}{static}{'final' if f.final else 'var'} {f.name}:{f.ty}{init};"]
        if f.kind == "dn":
            return [f"\t{vis}var {f.name}(default, null):{f.ty} = {self._literal(g, st, f.ty)};"]
        n, k = f.name, g.between(1, 9)
        if f.kind == "ns":
            return [
                f"\t@:isVar {vis}var {n}(null, set):Int = {self._literal(g, st, INT)};",
                f"\tfunction set_{n}(v:Int):Int {{",
                f"\t\t{n} = {g.pick([f'v * 2 - {k}', '(v > 100) ? 100 : v', f'v ^ {k}'])};",
                f"\t\treturn {n};",
                "\t}",
            ]
        return [
            f"\t{vis}var {n}(get, set):Int;",
            f"\tvar _{n}:Int = {self._literal(g, st, INT)};",
            f"\tfunction get_{n}():Int return {g.pick([f'_{n} + {k}', f'_{n} * 2', f'-_{n}'])};",
            f"\tfunction set_{n}(v:Int):Int {{",
            f"\t\t_{n} = {g.pick([f'v + {k}', '(v < 0) ? 0 : v', 'v & 255'])};",
            f"\t\treturn _{n};",
            "\t}",
        ]

    # ---- bodies -----------------------------------------------------------------------

    @contextmanager
    def _calls(self, g: Gen, st: _State, virtual: bool, quiet: bool = False) -> Iterator[_Frame]:
        """Publish the call policy (`allow`/`note`) the `functions` feature obeys while a body is generated."""
        frame = _Frame()

        def bad(fn: Fn) -> bool:
            return (fn.receiver is not None and fn.name in st.virtual) or _key(fn) in st.tainted

        def allow(fn: Fn) -> bool:
            # Bare names are main-class helpers, which class bodies cannot reach (and which are not yet defined).
            if st.quiet or (fn.receiver is None and "." not in fn.name):
                return False
            return not (virtual and bad(fn))

        def note(fn: Fn) -> None:
            frame.tainted = frame.tainted or bad(fn)

        g.state["calls"] = {"allow": allow, "note": note}
        st.quiet += quiet
        try:
            yield frame
        finally:
            st.quiet -= quiet
            del g.state["calls"]

    def _scope(self, g: Gen, st: _State, cls: Cls, static: bool) -> None:
        if not static:
            for c in st.lineage(cls):
                for f in c.fields:
                    # (default, null) and (null, set) are only reachable from the class that declares them.
                    if not f.static and (f.kind in ("var", "gs") or c is cls):
                        g.declare_var(f"this.{f.name}", f.ty, mutable=not f.final and f.ty != STRING)
        for f in cls.fields:
            if f.static:
                g.declare_var(f"{cls.name}.{f.name}", f.ty, mutable=not f.final and f.ty != STRING)

    def _ctor(self, g: Gen, st: _State, cls: Cls) -> List[str]:
        params = [(g.fresh("p"), t) for t in cls.ctor]
        inherited = len(st.classes[cls.base].ctor) if cls.base else 0
        own = params[inherited:]
        with self._calls(g, st, False, quiet=True), g.capture(level=2) as lines, g.function(params, VOID):
            if cls.base:
                g.emit(f"super({', '.join(n for n, _ in params[:inherited])});")
            fields = [f for f in cls.fields if not f.static]
            for f in fields:
                if f.ctor_init:
                    match = [n for n, t in own if t == f.ty]
                    g.emit(f"this.{f.name} = {g.pick(match) if match and g.chance(0.7) else g.expr(f.ty)};")
            self._scope(g, st, cls, False)
            for name, ty in own:
                targets = [f for f in fields if f.ty == ty and f.kind == "var" and not f.final]
                if targets:
                    g.emit(f"this.{g.pick(targets).name} = {name};")
            g.statements(g.between(0, 2))
        return [f"\tpublic function new({', '.join(f'{n}:{t}' for n, t in params)}) {{", *lines, "\t}"]

    def _method(self, g: Gen, st: _State, cls: Cls, m: Method) -> List[str]:
        virtual = not m.static and m.name in st.virtual
        key = (f"{cls.name}.{m.name}", "") if m.static else (m.name, cls.name)
        with (
            _costed(g, key),
            self._calls(g, st, virtual) as frame,
            g.capture(level=2) as lines,
            g.function(m.params, None if m.inline else m.ret),
        ):
            self._scope(g, st, cls, m.static)
            if m.name == "describe":
                self._describe(g, st, cls)
            else:
                if m.override:
                    call = f"super.{m.name}({', '.join(n for n, _ in m.params)})"
                    if m.ret == VOID:
                        g.emit(call + ";")
                    else:
                        var = g.fresh("s")
                        g.emit(f"var {var}:{m.ret} = {call};")
                        g.declare_var(var, m.ret)
                g.body(m.ret, g.between(1, 3))
        mods = (
            ("override " if m.override else "")
            + "public "
            + ("static " if m.static else "")
            + ("inline " if m.inline else "")
        )
        self._register(g, st, cls, m, frame)
        return [f"\t{mods}function {self._sig_text(m)} {{", *lines, "\t}"]

    def _describe(self, g: Gen, st: _State, cls: Cls) -> None:
        parts = [f'"{f.name}=" + ({g.show(f"this.{f.name}", f.ty)})' for f in cls.fields if not f.static]
        prefix = '(super.describe()) + "/" + ' if cls.base else ""
        g.emit(f'return {prefix}"{cls.name}(" + ' + ' + "," + '.join(parts) + ' + ")";')

    def _register(self, g: Gen, st: _State, cls: Cls, m: Method, frame: _Frame) -> None:
        params = tuple(t for _, t in m.params)
        if m.static:
            fn = Fn(f"{cls.name}.{m.name}", params, m.ret)
        else:
            fn = Fn(m.name, params, m.ret, Ty(cls.name))
            slot = m.name == "describe" or any(m.name == i.name for i in st.iface_methods)
            if slot and not any(f.name == m.name and f.receiver == Ty(st.iface) for f in g.fns):
                g.fns.append(Fn(m.name, params, m.ret, Ty(st.iface)))
        g.fns.append(fn)
        if frame.tainted:
            st.tainted.add(_key(fn))

    # ---- use sites --------------------------------------------------------------------

    def types(self, g: Gen, depth: int):
        st: Optional[_State] = g.state.get(self.name)
        if st is None or st.quiet:
            return []
        return [(2, Ty(n)) for n in st.classes] + [(1.5, Ty(st.iface))]

    def show(self, g: Gen, ty: Ty, expr: str):
        st: Optional[_State] = g.state.get(self.name)
        return f"({expr}).describe()" if st is not None and ty in st.types() else None

    def _new(self, g: Gen, st: _State, name: str) -> str:
        return f"new {name}({', '.join(g.expr(t) for t in st.classes[name].ctor)})"

    def exprs(self, g: Gen, ty: Ty):
        st: Optional[_State] = g.state.get(self.name)
        if st is None or st.quiet:
            return []
        if ty in st.types():
            return [
                Choice(3, lambda t=t: self._new(g, st, t.name), leaf=True)
                for t in g.subtype_choices(ty)
                if t.name in st.classes
            ]
        out = []
        statics = [
            f"{c.name}.{f.name}"
            for c in st.classes.values()
            for f in c.fields
            if f.static and f.readable and f.ty == ty
        ]
        if statics:
            out.append(Choice(1.5, lambda: g.pick(statics), leaf=True))
        reads = [
            f"{v.name}.{f.name}"
            for v in g.visible()
            if v.ty.name in st.classes
            for f in st.instance_fields(st.classes[v.ty.name])
            if f.readable and f.ty == ty
        ]
        if reads:
            out.append(Choice(2, lambda: g.pick(reads), leaf=True))
        fresh = [
            (c, f) for c in st.classes.values() for f in st.instance_fields(c) if f.readable and f.ty == ty
        ]
        if fresh:
            out.append(Choice(0.7, lambda: self._read_new(g, st, g.pick(fresh))))
        return out

    def _read_new(self, g: Gen, st: _State, pair: Tuple[Cls, Field]) -> str:
        return f"({self._new(g, st, pair[0].name)}).{pair[1].name}"

    def stmts(self, g: Gen):
        return [Choice(4, lambda: self._assign(g))] if self.name in g.state else []

    def _assign(self, g: Gen) -> bool:
        st: _State = g.state[self.name]
        targets = [
            (f"{v.name}.{f.name}", f)
            for v in g.visible()
            if v.ty.name in st.classes
            for f in st.instance_fields(st.classes[v.ty.name])
            if f.writable
        ]
        targets += [
            (f"{c.name}.{f.name}", f)
            for c in st.classes.values()
            for f in c.fields
            if f.static and f.writable
        ]
        if not targets:
            return False
        path, f = g.pick(targets)
        if f.ty == STRING:  # never fed back into itself: repeated doubling would exhaust memory
            op = "+=" if f.readable and g.chance(0.5) else "="
            g.emit(f"{path} {op} {g.pick(_SHORT)};")
        elif not f.readable or f.ty == BOOL or g.chance(0.4):
            g.emit(f"{path} = {g.expr(f.ty)};")
        elif f.ty == INT:
            g.emit(g.pick([f"{path}++", f"--{path}", f"{path} {g.pick(_INT_OPS)} {g.expr(INT)}"]) + ";")
        else:
            g.emit(f"{path} {g.pick(['+=', '-=', '*='])} {g.expr(FLOAT)};")
        return True
