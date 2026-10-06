"""Generic classes and functions: `Box<T>`, `Pair<A, B>`, `@:generic` monomorphisation, constrained type parameters."""

from __future__ import annotations

from typing import List

from ..feature import Choice, Feature, register
from ..gen import Fn, Gen
from ..types import BOOL, FLOAT, INT, STRING, Ty

_ELEMS = (INT, STRING, FLOAT)
_PAIRS = ((INT, STRING), (STRING, INT), (FLOAT, BOOL), (BOOL, FLOAT))
_SCALARS = (INT, FLOAT, BOOL, STRING)


def _box(arg: Ty) -> Ty:
    return Ty("Box", (arg,))


def _gbox(arg: Ty) -> Ty:
    return Ty("GBox", (arg,))


def _pair(a: Ty, b: Ty) -> Ty:
    return Ty("Pair", (a, b))


_DECLS = """\
class Box<T> {
	public var value:T;
	public var count(get, never):Int;
	var sets:Int = 0;

	public function new(value:T) {
		this.value = value;
	}

	function get_count():Int {
		return sets;
	}

	public function get():T {
		return value;
	}

	public function set(v:T):T {
		sets++;
		value = v;
		return v;
	}

	public function map<U>(f:T->U):Box<U> {
		return new Box<U>(f(value));
	}
}

class Pair<A, B> {
	public var first:A;
	public var second:B;

	public function new(first:A, second:B) {
		this.first = first;
		this.second = second;
	}

	public function swap():Pair<B, A> {
		return new Pair<B, A>(second, first);
	}

	public function describe(fa:A->String, fb:B->String):String {
		return "(" + fa(first) + ", " + fb(second) + ")";
	}
}

@:generic
class GBox<T> {
	public var v:T;

	public function new(v:T) {
		this.v = v;
	}

	public function put(x:T):GBox<T> {
		v = x;
		return this;
	}
}"""

_MEMBERS = """\
	static function pick<T>(a:T, b:T, first:Bool):T {
		return first ? a : b;
	}

	static function maxOf<T:Float>(a:T, b:T):T {
		return a > b ? a : b;
	}

	static function sumAll<T:Float>(a:T, b:T):Float {
		return a + b;
	}

	@:generic static function twice<T>(x:T, f:T->T):T {
		return f(f(x));
	}

	@:generic static function fill<T>(x:T, n:Int):Array<T> {
		var out:Array<T> = [];
		for (i in 0...(n & 3)) out.push(x);
		return out;
	}"""


@register
class Generics(Feature):
    name = "generics"
    summary = "Box<T>, Pair<A,B>, @:generic classes/functions, type-parameter constraints, generic methods"
    covers = ("decl:generic", "ENew", "ECall", "ECheckType", "FProp", "FKArrow")
    order = 42

    def declare(self, g: Gen) -> None:
        g.decls.append(_DECLS)
        g.members.append(_MEMBERS)
        for t in _ELEMS:
            g.fns.append(Fn("get", (), t, _box(t)))
            g.fns.append(Fn("set", (t,), t, _box(t)))

    def types(self, g: Gen, depth: int):
        if depth:
            return []
        out = [(1.5, _box(t)) for t in _ELEMS] + [(1.0, _pair(a, b)) for a, b in _PAIRS]
        return out + [(1.0, _gbox(INT)), (0.7, _gbox(STRING))]

    def show(self, g: Gen, ty: Ty, expr: str):
        if ty.name == "Box":
            return g.show(f"({expr}).value", ty.args[0])
        if ty.name == "GBox":
            return g.show(f"({expr}).v", ty.args[0])
        if ty.name == "Pair":
            a, b = ty.args
            return f"({expr}).describe(a -> {g.show('a', a)}, b -> {g.show('b', b)})"
        return None

    # ---- expressions ------------------------------------------------------------------

    def exprs(self, g: Gen, ty: Ty):
        out: List[Choice] = []
        if ty.name in ("Box", "GBox") and ty.args[0] in _ELEMS:
            arg = ty.args[0]
            out.append(Choice(3, lambda: f"new {ty}({g.expr(arg)})", leaf=True))
            if ty.name == "Box":
                out.append(Choice(2, lambda: self._map(g, ty)))
            else:
                out.append(Choice(1, lambda: f"new {ty}({g.expr(arg)}).put({g.expr(arg)})"))
        elif ty.name == "Pair":
            a, b = ty.args
            out.append(Choice(3, lambda: f"new {ty}({g.expr(a)}, {g.expr(b)})", leaf=True))
            out.append(Choice(1.5, lambda: f"{g.expr(_pair(b, a))}.swap()"))
        if ty in _SCALARS:
            out += self._field_reads(g, ty)
            out.append(Choice(1.5, lambda: self._twice(g, ty)))
        if ty in (INT, FLOAT):
            out.append(Choice(1.5, lambda: self._constrained(g, ty)))
        if ty.name == "Array" and ty.args[0] in _SCALARS:
            elem = ty.args[0]
            out.append(Choice(1.5, lambda: f"(fill(({g.expr(elem)} : {elem}), {g.expr(INT)}) : {ty})"))
        if not ty.is_fn and ty.name != "Void":
            out.append(Choice(2, lambda: self._pick(g, ty)))
        return out

    def _field_reads(self, g: Gen, ty: Ty) -> List[Choice]:
        out = []
        for var in g.visible():
            if var.ty.name in ("Box", "GBox") and var.ty.args[0] == ty:
                field = "value" if var.ty.name == "Box" else "v"
                out.append(Choice(1, lambda n=var.name, f=field: f"{n}.{f}", leaf=True))
                if var.ty.name == "Box":
                    out.append(Choice(0.7, lambda n=var.name: f"{n}.get()", leaf=True))
            elif var.ty.name == "Pair":
                for slot, arg in zip(("first", "second"), var.ty.args):
                    if arg == ty:
                        out.append(Choice(1, lambda n=var.name, s=slot: f"{n}.{s}", leaf=True))
            if ty == INT and var.ty.name == "Box":
                out.append(Choice(0.7, lambda n=var.name: f"{n}.count", leaf=True))
        return out

    def _lambda(self, g: Gen, param: Ty, ret: Ty) -> str:
        x = g.fresh("x")
        with g.function([(x, param)], ret, inherit=True):
            body = g.expr(ret)
        return f"({x} -> ({body} : {ret}))"

    def _map(self, g: Gen, ty: Ty) -> str:
        src = _box(g.pick(_ELEMS))
        return f"{g.expr(src)}.map({self._lambda(g, src.args[0], ty.args[0])})"

    def _pick(self, g: Gen, ty: Ty) -> str:
        # The first argument is checked against `ty` so the inferred T is exactly `ty`.
        return f"(pick(({g.expr(ty)} : {ty}), {g.expr(ty)}, {g.expr(BOOL)}) : {ty})"

    def _twice(self, g: Gen, ty: Ty) -> str:
        return f"(twice(({g.expr(ty)} : {ty}), {self._lambda(g, ty, ty)}) : {ty})"

    def _constrained(self, g: Gen, ty: Ty) -> str:
        if ty == FLOAT:
            if g.chance(0.5):
                return f"(sumAll(({g.expr(g.pick([INT, FLOAT]))} : Float), {g.expr(g.pick([INT, FLOAT]))}) : Float)"
            return f"(maxOf(({g.expr(FLOAT)} : Float), {g.expr(INT)}) : Float)"
        return f"(maxOf({g.expr(INT)}, {g.expr(INT)}) : Int)"

    # ---- statements -------------------------------------------------------------------

    def stmts(self, g: Gen):
        boxes = [v for v in g.visible() if v.ty.name in ("Box", "GBox", "Pair")]
        if not boxes:
            return []
        return [Choice(3, lambda: self._mutate(g, g.pick(boxes)))]

    def _mutate(self, g: Gen, var) -> bool:
        ty = var.ty
        if ty.name == "Pair":
            slot, arg = g.pick(list(zip(("first", "second"), ty.args)))
            g.emit(f"{var.name}.{slot} = {g.expr(arg)};")
        elif ty.name == "GBox":
            value = g.expr(ty.args[0])
            g.emit(g.pick([f"{var.name}.v = {value};", f"{var.name}.put({value});"]))
        else:
            value = g.expr(ty.args[0])
            g.emit(g.pick([f"{var.name}.value = {value};", f"{var.name}.set({value});"]))
        return True
