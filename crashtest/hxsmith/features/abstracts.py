"""Abstract types: operator overloading, implicit @:from/@:to casts, array access, @:forward, inline methods."""

from __future__ import annotations

from typing import List

from ..feature import Choice, Feature, register
from ..gen import Fn, Gen, Var
from ..types import BOOL, FLOAT, INT, STRING, Ty

METERS, ID, BAG, COUNTS, TAG = (Ty(n) for n in ("Meters", "Id", "Bag", "Counts", "Tag"))

_DECLS = """\
abstract Meters(Float) {
	public inline function new(v:Float) {
		this = v;
	}

	public inline function toFloat():Float {
		return this;
	}

	@:from public static inline function ofInt(i:Int):Meters {
		return new Meters(i);
	}

	@:to public inline function toStr():String {
		return "m" + this;
	}

	@:op(A + B) public static inline function add(a:Meters, b:Meters):Meters {
		return new Meters(a.toFloat() + b.toFloat());
	}

	@:op(A * B) public inline function mul(o:Meters):Meters {
		return new Meters(this * o.toFloat());
	}

	@:op(-A) public inline function neg():Meters {
		return new Meters(-this);
	}

	@:op(A == B) public static inline function eq(a:Meters, b:Meters):Bool {
		return a.toFloat() == b.toFloat();
	}

	@:op(A < B) public static inline function lt(a:Meters, b:Meters):Bool {
		return a.toFloat() < b.toFloat();
	}

	@:op(A++) public inline function postInc():Meters {
		this += 1;
		return new Meters(this);
	}

	@:op(++A) public inline function preInc():Meters {
		this += 1;
		return cast this;
	}

	public static inline function lift(m:Meters):Meters {
		return m;
	}
}

abstract Id(Int) to Int {
	public inline function new(i:Int) {
		this = i;
	}

	public inline function toInt():Int {
		return this;
	}

	@:from public static inline function ofInt(i:Int):Id {
		return new Id(i);
	}

	@:op(A + B) public static inline function plus(a:Id, b:Int):Id {
		return new Id(a.toInt() + b);
	}

	public static inline function lift(i:Id):Id {
		return i;
	}
}

abstract Bag(Array<Int>) {
	public var length(get, never):Int;

	public inline function new(a:Array<Int>) {
		this = a;
	}

	inline function get_length():Int {
		return this.length;
	}

	@:arrayAccess public inline function at(i:Int):Int {
		return this[i];
	}

	@:arrayAccess public inline function put(i:Int, v:Int):Int {
		this[i] = v;
		return v;
	}

	public inline function push(v:Int):Int {
		return this.push(v);
	}

	public function str():String {
		return this.join(",");
	}
}

abstract Counts(Map<String, Int>) {
	public function new(a:Int, b:Int) {
		this = new Map<String, Int>();
		this.set("a", a);
		this.set("b", b);
	}

	@:arrayAccess public inline function at(k:String):Int {
		var v = this.get(k);
		return v == null ? 0 : v;
	}

	@:arrayAccess public inline function put(k:String, v:Int):Int {
		this.set(k, v);
		return v;
	}

	public function str():String {
		var ks = [for (k in this.keys()) k];
		ks.sort((a, b) -> Reflect.compare(a, b));
		return ks.map(k -> k + "=" + this.get(k)).join(",");
	}
}

@:forward(length, toUpperCase, indexOf)
abstract Tag(String) from String to String {
	public inline function new(s:String) {
		this = s;
	}

	public inline function str():String {
		return this;
	}

	@:op(A + B) public static inline function cat(a:Tag, b:Tag):Tag {
		return new Tag((a.str() + b.str()).substr(0, 12));
	}
}"""

_KEYS = ["a", "b", "z", "key"]


@register
class Abstracts(Feature):
    name = "abstracts"
    summary = "abstract types with @:op, @:from/@:to, @:arrayAccess, @:forward and inline methods"
    covers = ("decl:abstract", "EArray", "EUnop", "EBinop", "ENew", "ECall")
    order = 41

    def declare(self, g: Gen) -> None:
        g.decls.append(_DECLS)
        g.fns += [
            Fn("toFloat", (), FLOAT, METERS),
            Fn("Meters.lift", (METERS,), METERS),
            Fn("Id.lift", (ID,), ID),
            Fn("toInt", (), INT, ID),
            Fn("str", (), STRING, BAG),
            Fn("push", (INT,), INT, BAG),
            Fn("str", (), STRING, COUNTS),
            Fn("str", (), STRING, TAG),
            Fn("toUpperCase", (), STRING, TAG),
        ]

    def types(self, g: Gen, depth: int):
        return [] if depth else [(1.5, METERS), (1.0, ID), (1.0, BAG), (1.0, COUNTS), (1.0, TAG)]

    def show(self, g: Gen, ty: Ty, expr: str):
        if ty == METERS:
            return f"Std.string(({expr}).toFloat())"
        if ty == ID:
            return f"Std.string(({expr}).toInt())"
        if ty in (BAG, COUNTS, TAG):
            return f"({expr}).str()"
        return None

    # ---- expressions ------------------------------------------------------------------

    def exprs(self, g: Gen, ty: Ty):
        out: List[Choice] = []
        if ty == METERS:
            out += [
                Choice(3, lambda: f"new Meters({g.expr(FLOAT)})", leaf=True),
                Choice(2, lambda: f"Meters.ofInt({g.expr(INT)})", leaf=True),
                Choice(2, lambda: f"Meters.lift({g.expr(INT)})", leaf=True),  # implicit @:from at a call site
                Choice(2, lambda: f"({g.expr(METERS)} + {g.expr(METERS)})"),
                Choice(2, lambda: f"({g.expr(METERS)} * {g.expr(METERS)})"),
                Choice(1.5, lambda: f"(-{g.expr(METERS)})"),
            ]
        elif ty == ID:
            out += [
                Choice(3, lambda: f"new Id({g.expr(INT)})", leaf=True),
                Choice(2, lambda: f"Id.lift({g.expr(INT)})", leaf=True),
                Choice(2, lambda: f"({g.expr(ID)} + {g.expr(INT)})"),
            ]
        elif ty == BAG:
            out.append(
                Choice(3, lambda: f"new Bag([{', '.join(g.exprs(*[INT] * g.between(1, 4)))}])", leaf=True)
            )
        elif ty == COUNTS:
            out.append(Choice(3, lambda: f"new Counts({g.expr(INT)}, {g.expr(INT)})", leaf=True))
        elif ty == TAG:
            out += [
                Choice(3, lambda: f"new Tag({g.expr(STRING)})", leaf=True),
                Choice(1.5, lambda: f"({g.expr(TAG)} + {g.expr(TAG)})"),
            ]
        elif ty == BOOL:
            out.append(Choice(1.5, lambda: f"({g.expr(METERS)} {g.pick(['==', '<'])} {g.expr(METERS)})"))
        out += self._reads(g, ty)
        return out

    def _reads(self, g: Gen, ty: Ty) -> List[Choice]:
        out = []
        for var in g.visible():
            name = var.name
            if var.ty == METERS and ty == FLOAT:
                out.append(Choice(1, lambda n=name: f"{n}.toFloat()", leaf=True))
            elif var.ty == ID and ty == INT:
                out.append(Choice(1, lambda n=name: f"{n}.toInt()", leaf=True))
            elif var.ty == BAG and ty == INT:
                out.append(Choice(1.5, lambda n=name: f"{n}[{self._index(g, n)}]", leaf=True))
                out.append(Choice(0.7, lambda n=name: f"{n}.length", leaf=True))
            elif var.ty == COUNTS and ty == INT:
                out.append(Choice(1.5, lambda n=name: f'{n}["{g.pick(_KEYS)}"]', leaf=True))
            elif var.ty == TAG and ty == STRING:
                out.append(Choice(1, lambda n=name: f"{n}.toUpperCase()", leaf=True))
            elif var.ty == TAG and ty == INT:
                out.append(Choice(1, lambda n=name: f"{n}.length", leaf=True))
        return out

    def _index(self, g: Gen, bag: str) -> str:
        return f"{g.pick(['0', '1', '7', '13'])} % {bag}.length"

    # ---- statements -------------------------------------------------------------------

    def stmts(self, g: Gen):
        out: List[Choice] = []
        for var in g.visible():
            if var.ty == METERS and var.mutable:
                out.append(Choice(2, lambda v=var: self._meters(g, v)))
            elif var.ty == ID and var.mutable:
                out.append(Choice(1.5, lambda v=var: self._id(g, v)))
            elif var.ty == ID:
                out.append(Choice(1, lambda v=var: self._unwrap(g, v)))
            elif var.ty == BAG:
                out.append(Choice(2, lambda v=var: self._bag(g, v)))
            elif var.ty == COUNTS:
                out.append(Choice(2, lambda v=var: self._counts(g, v)))
            elif var.ty == TAG and var.mutable:
                out.append(Choice(1, lambda v=var: self._tag(g, v)))
        return out

    def _meters(self, g: Gen, var: Var) -> bool:
        form = g.pick(["post", "pre", "add", "mul", "set"])
        n = var.name
        if form in ("post", "pre"):
            g.emit(f"{n}++;" if form == "post" else f"++{n};")
        elif form == "set":
            g.emit(f"{n} = {g.expr(INT)};")  # implicit @:from Int assignment
        else:
            g.emit(f"{n} {'+=' if form == 'add' else '*='} {g.expr(METERS)};")
        return True

    def _id(self, g: Gen, var: Var) -> bool:
        g.emit(f"{var.name} += {g.expr(INT)};")
        return True

    def _unwrap(self, g: Gen, var: Var) -> bool:
        k = g.fresh("k")
        g.emit(f"var {k}:Int = {var.name};")  # implicit `to Int`
        g.declare_var(k, INT)
        return True

    def _bag(self, g: Gen, var: Var) -> bool:
        n = var.name
        at = f"{n}[{self._index(g, n)}]"
        form = g.pick(["set", "add", "inc", "push"])
        if form == "set":
            g.emit(f"{at} = {g.expr(INT)};")
        elif form == "add":
            g.emit(f"{at} {g.pick(['+=', '-=', '*='])} {g.expr(INT)};")
        elif form == "inc":
            g.emit(f"{at}{g.pick(['++', '--'])};")
        else:
            g.emit(f"{n}.push({g.expr(INT)});")
        return True

    def _counts(self, g: Gen, var: Var) -> bool:
        key = f'"{g.pick(_KEYS)}"' if g.chance(0.7) else g.expr(STRING)
        at = f"{var.name}[{key}]"
        if g.chance(0.5):
            g.emit(f"{at} = {g.expr(INT)};")
        else:
            g.emit(f"{at}{g.pick(['++', '--'])};")
        return True

    def _tag(self, g: Gen, var: Var) -> bool:
        g.emit(f"{var.name} += {g.expr(g.pick([STRING, TAG]))};")
        return True
