"""Anonymous structures: typedefs, object literals, field access, optional fields, structural subtyping."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from ..feature import Choice, Feature, register
from ..gen import Fn, Gen
from ..types import BOOL, FLOAT, INT, STRING, Ty

_NAMES = ["x", "y", "w", "h", "id", "name", "tag", "count", "flag", "ratio", "label", "depth"]
_SCALARS = (INT, FLOAT, BOOL, STRING)


@dataclass
class Field:
    name: str
    ty: Ty
    opt: bool = False

    def hint(self) -> str:
        return f"{'?' if self.opt else ''}{self.name}:{self.ty}"


@dataclass
class State:
    shapes: Dict[Ty, List[Field]]  # every anonymous shape (typedef or inline) -> all its fields
    named: List[Ty]  # the typedefs offered as value types
    helpers: Dict[Ty, str]  # shape -> name of its static show function


def _paths(shapes: Dict[Ty, List[Field]], text: str, ty: Ty, depth: int = 2) -> List[Tuple[str, Field]]:
    """Every field reachable from `text` of shape `ty`, through at most `depth` accesses."""
    found = []
    for f in shapes[ty]:
        path = f"{text}.{f.name}"
        found.append((path, f))
        if f.ty in shapes and depth > 1:
            found += _paths(shapes, path, f.ty, depth - 1)
    return found


@register
class Anon(Feature):
    name = "anon"
    summary = "typedefs of anonymous structures, object literals, optional fields, structural subtyping"
    covers = ("EObjectDecl", "EField", "ECheckType", "ETypedef", "OpNullCoal", "EParenthesis")
    order = 27

    # ---- declarations -----------------------------------------------------------------

    def declare(self, g: Gen) -> None:
        st = State({}, [], {})
        g.state[self.name] = st
        count = g.between(2, 4)
        base = self._fields(g, None, g.between(2, 4), inline=g.chance(0.4), st=st)
        a = self._typedef(g, st, "Pt", base)
        # B = A & {extra}: always assignable to A
        extra = self._fields(g, base, g.between(1, 2), inline=False, st=st)
        b = Ty(g.fresh("Pt"))
        g.decls.append(f"typedef {b} = {a} & {self._body(g, extra)};")
        self._register(st, b, base + extra)
        g.subtypes.setdefault(a, []).append(b)
        if count >= 3:
            # A wider structure that merely repeats A's fields: assignable to A by structure alone
            wide_extra = self._fields(g, base, 1, inline=False, st=st)
            wide = self._typedef(g, st, "Pt", base + wide_extra)
            g.subtypes[a].append(wide)
        for _ in range(count - 3):
            nested = [Field(g.pick(_NAMES), g.pick(st.named))]
            nested += self._fields(g, nested, g.between(1, 2), inline=False, st=st)
            self._typedef(g, st, "Pt", nested)
        for ty in st.shapes:
            self._show_helper(g, st, ty)

    def _fields(self, g: Gen, taken: Optional[List[Field]], n: int, inline: bool, st: State) -> List[Field]:
        used = {f.name for f in taken or ()}
        names = [x for x in _NAMES if x not in used]
        g.rng.shuffle(names)
        fields = [Field(name, g.pick(_SCALARS), g.chance(0.25)) for name in names[:n]]
        if inline:
            inner = [Field("k", INT), Field("s", STRING)] + (
                [Field("f", FLOAT, True)] if g.chance(0.5) else []
            )
            ty = Ty(self._body(g, inner))
            self._register(st, ty, inner)
            fields.append(Field("inner", ty))
        return fields

    def _body(self, g: Gen, fields: List[Field]) -> str:
        if g.chance(0.5):
            return "{" + ", ".join(f.hint() for f in fields) + "}"
        return "{" + " ".join(f"{'@:optional ' if f.opt else ''}var {f.name}:{f.ty};" for f in fields) + "}"

    def _typedef(self, g: Gen, st: State, prefix: str, fields: List[Field]) -> Ty:
        ty = Ty(g.fresh(prefix))
        g.decls.append(f"typedef {ty} = {self._body(g, fields)};")
        self._register(st, ty, fields)
        return ty

    def _register(self, st: State, ty: Ty, fields: List[Field]) -> None:
        st.shapes[ty] = fields
        if not ty.name.startswith("{"):
            st.named.append(ty)

    def _show_helper(self, g: Gen, st: State, ty: Ty) -> None:
        name = g.fresh("showAnon")
        st.helpers[ty] = name
        parts = []
        for i, f in enumerate(st.shapes[ty]):
            shown = g.show(f"p.{f.name}", f.ty)
            if f.opt:
                shown = f'(p.{f.name} == null ? "null" : {shown})'
            parts.append(f'"{"{" if i == 0 else ", "}{f.name}=" + {shown}')
        g.members.append(
            f'\tpublic static function {name}(p:{ty}):String {{\n\t\treturn {" + ".join(parts)} + "}}";\n\t}}'
        )
        g.fns.append(Fn(f"{g.class_name}.{name}", (ty,), STRING))

    # ---- value types ------------------------------------------------------------------

    def types(self, g: Gen, depth: int):
        st: State = g.state[self.name]
        return [(2 / (1 + depth), ty) for ty in st.named]

    def show(self, g: Gen, ty: Ty, expr: str) -> Optional[str]:
        helper = g.state[self.name].helpers.get(ty)
        return f"{g.class_name}.{helper}({expr})" if helper else None

    # ---- expressions ------------------------------------------------------------------

    def exprs(self, g: Gen, ty: Ty):
        st: State = g.state[self.name]
        shaped = [v for v in g.visible() if v.ty in st.shapes]
        out: List[Choice] = []
        if ty in st.shapes:
            out.append(Choice(3, lambda: self._literal(g, st, ty), leaf=True))
            wider = [v for v in g.visible() if v.ty in g.subtypes.get(ty, ())]
            if wider:
                out.append(Choice(3, lambda: g.pick(wider).name, leaf=True))
            sources = [v for v in g.visible() if v.ty == ty or v in wider]
            if sources:
                out.append(Choice(0.5, lambda: f"(({g.pick(sources).name} : Dynamic) : {ty})", leaf=True))
        reads = [(p, f) for v in shaped for p, f in _paths(st.shapes, v.name, v.ty) if f.ty == ty]
        if reads:
            out.append(Choice(4, lambda: self._read_any(g, reads, ty), leaf=True))
        direct = [(v.name, f) for v in shaped for f in st.shapes[v.ty] if f.ty == ty and not f.opt]
        if direct and ty in _SCALARS:
            out.append(Choice(1, lambda: self._dynamic_read(g, direct, ty), leaf=True))
        if ty in _SCALARS:
            carriers = [s for s, fields in st.shapes.items() if any(f.ty == ty and not f.opt for f in fields)]
            if carriers:
                out.append(Choice(0.7, lambda: self._literal_read(g, st, g.pick(carriers), ty)))
        if ty == BOOL:
            opts = [(p, f) for v in shaped for p, f in _paths(st.shapes, v.name, v.ty) if f.opt]
            if opts:
                out.append(Choice(1, lambda: f"({g.pick(opts)[0]} {g.pick(['==', '!='])} null)", leaf=True))
        return out

    def _dynamic_read(self, g: Gen, direct: list, ty: Ty) -> str:
        var, field = g.pick(direct)
        return f"((({var} : Dynamic).{field.name}) : {ty})"

    def _read_any(self, g: Gen, reads: list, ty: Ty) -> str:
        path, field = g.pick(reads)
        return self._read(g, path, field, ty)

    def _read(self, g: Gen, path: str, field: Field, ty: Ty) -> str:
        if not field.opt:
            return path
        default = g.expr(ty)
        if g.chance(0.5):
            return f"(({path} ?? {default}) : {ty})"
        return f"(({path} != null ? {path} : {default}) : {ty})"

    def _literal(self, g: Gen, st: State, ty: Ty) -> str:
        # Omitting an optional field only type-checks where the expected type reaches the literal directly.
        fields = [f for f in st.shapes[ty] if not f.opt or g.expr_depth > 1 or g.chance(0.5)]
        g.rng.shuffle(fields)
        return "({" + ", ".join(f"{f.name}: {g.expr(f.ty)}" for f in fields) + "})"

    def _literal_read(self, g: Gen, st: State, shape: Ty, ty: Ty) -> str:
        field = g.pick([f for f in st.shapes[shape] if f.ty == ty and not f.opt])
        return f"(({self._literal(g, st, shape)} : {shape}).{field.name})"

    # ---- statements -------------------------------------------------------------------

    def stmts(self, g: Gen):
        st: State = g.state[self.name]
        shaped = [v for v in g.visible() if v.ty in st.shapes]
        out = [Choice(2, lambda: self._widen(g, st))]
        if shaped:
            out += [
                Choice(5, lambda: self._write(g, st, shaped)),
                Choice(2, lambda: self._null_check(g, st, shaped)),
                Choice(1.5, lambda: self._dynamic(g, st, shaped)),
                Choice(2, lambda: self._print(g, g.pick(shaped))),
            ]
        return out

    def _write(self, g: Gen, st: State, shaped: list) -> bool:
        var = g.pick(shaped)
        path, field = g.pick(_paths(st.shapes, var.name, var.ty))
        ty = field.ty
        if ty == INT and not field.opt:
            form = g.pick(["=", "+=", "-=", "*=", "^=", "++", "--"])
            g.emit(f"{path}{form};" if form in ("++", "--") else f"{path} {form} {g.expr(INT)};")
        elif ty == FLOAT and not field.opt:
            g.emit(f"{path} {g.pick(['=', '+=', '-=', '*='])} {g.expr(FLOAT)};")
        elif ty == STRING and not field.opt and g.chance(0.5):
            value = g.expr(g.pick([STRING, INT]))
            if var.name in value:  # `s += s` in a loop would double the string every pass
                value = '"+"'
            g.emit(f"{path} += {value};")
        elif ty == BOOL and not field.opt and g.chance(0.4):
            g.emit(f"{path} = !{path};")
        else:
            g.emit(f"{path} = {g.expr(ty)};")
        return True

    def _null_check(self, g: Gen, st: State, shaped: list) -> bool:
        opts = [(p, f) for v in shaped for p, f in _paths(st.shapes, v.name, v.ty) if f.opt]
        if not opts:
            return False
        path, field = g.pick(opts)
        form = g.between(0, 2)
        if form == 0:
            g.emit(f"if ({path} == null) {path} = {g.expr(field.ty)};")
        elif form == 1:
            g.emit(f"if ({path} != null) Sys.println({g.show(path, field.ty)});")
        else:
            g.emit(f"{path} = null;")
        return True

    def _dynamic(self, g: Gen, st: State, shaped: list) -> bool:
        var = g.pick(shaped)
        plain = [(p, f) for p, f in _paths(st.shapes, var.name, var.ty, 1) if not f.opt and f.ty in _SCALARS]
        if not plain:
            return False
        path, field = g.pick(plain)
        dyn = g.fresh("dyn")
        g.emit(f"var {dyn}:Dynamic = {var.name};")
        g.emit(f"{dyn}.{field.name} = {g.expr(field.ty)};")
        g.emit(f"Sys.println({g.show(path, field.ty)});")
        return True

    def _widen(self, g: Gen, st: State) -> bool:
        pairs = [(base, sub) for base, subs in g.subtypes.items() if base in st.shapes for sub in subs]
        if not pairs:
            return False
        base, sub = g.pick(pairs)
        wide, narrow = g.fresh("wide"), g.fresh("narrow")
        g.emit(f"var {wide}:{sub} = {g.expr(sub)};")
        g.declare_var(wide, sub)
        g.emit(f"var {narrow}:{base} = {wide};")
        g.declare_var(narrow, base)
        g.emit(f"Sys.println({g.show(narrow, base)});")
        return True

    def _print(self, g: Gen, var) -> bool:
        g.emit(f"Sys.println({g.show(var.name, var.ty)});")
        return True
