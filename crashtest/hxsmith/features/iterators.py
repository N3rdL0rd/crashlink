"""User iterators: Iterator/Iterable classes, KeyValueIterator, anonymous generators, manual hasNext/next loops."""

from __future__ import annotations

from typing import List

from ..feature import Choice, Feature, register
from ..gen import Fn, Gen
from ..types import BOOL, INT, STRING, Ty

COUNTER, SPAN, TABLE = Ty("IntCounter"), Ty("IntSpan"), Ty("StrTable")
ITERABLE = Ty("IntIterable")
ITERATOR = Ty("Iterator", (INT,))

_DECLS = """\
typedef IntIterable = Iterable<Int>;

class IntCounter {
	var cur:Int;
	final end:Int;
	final step:Int;

	public function new(start:Int, len:Int, step:Int = 1) {
		cur = start & 0xffff;
		end = cur + (len & 7);
		this.step = 1 + (step & 3);
	}

	public function hasNext():Bool {
		return cur < end;
	}

	public function next():Int {
		var v = cur;
		cur += step;
		return v;
	}

	public function iterator():Iterator<Int> {
		return this;
	}
}

class IntSpan {
	final start:Int;
	final len:Int;

	public function new(start:Int, len:Int) {
		this.start = start;
		this.len = len;
	}

	public function iterator():Iterator<Int> {
		return new IntCounter(start, len);
	}
}

class TableIter {
	final items:Array<String>;
	var i:Int = 0;

	public function new(items:Array<String>) {
		this.items = items;
	}

	public function hasNext():Bool {
		return i < items.length;
	}

	public function next():{key:Int, value:String} {
		var k = i++;
		return {key: k, value: items[k]};
	}
}

class StrTable {
	final items:Array<String>;

	public function new(items:Array<String>) {
		this.items = items;
	}

	public function keyValueIterator():KeyValueIterator<Int, String> {
		return new TableIter(items);
	}

	public function describe():String {
		var sb = new StringBuf();
		for (k => v in this) sb.add(k + ":" + v + ";");
		return sb.toString();
	}
}

class Iters {
	public static function drain(it:Iterator<Int>):String {
		var parts = [];
		while (it.hasNext()) parts.push(it.next());
		return parts.join(",");
	}

	public static function ints(it:Iterable<Int>):String {
		var parts = [];
		for (x in it) parts.push(x);
		return parts.join(",");
	}

	public static function sum(it:Iterable<Int>):Int {
		var total = 0;
		for (x in it) total += x;
		return total;
	}

	public static function gen(from:Int, count:Int):Iterator<Int> {
		var n = 0;
		return {
			hasNext: () -> n < (count & 7),
			next: () -> from + n++
		};
	}
}"""


@register
class Iterators(Feature):
    name = "iterators"
    summary = "Iterator/Iterable/KeyValueIterator classes, anonymous generators, for-in and manual hasNext/next loops"
    covers = ("EFor", "EWhile", "OpArrow", "EObjectDecl", "FKArrow", "decl:typedef", "ECall")
    order = 43

    def declare(self, g: Gen) -> None:
        g.decls.append(_DECLS)
        g.subtypes[ITERABLE] = [SPAN, COUNTER]
        g.subtypes[ITERATOR] = [COUNTER]
        g.fns += [
            Fn("Iters.sum", (ITERABLE,), INT),
            Fn("Iters.ints", (ITERABLE,), STRING),
            Fn("Iters.drain", (ITERATOR,), STRING),
            Fn("describe", (), STRING, TABLE),
        ]

    def types(self, g: Gen, depth: int):
        if depth:
            return []
        return [(1.5, COUNTER), (1.5, SPAN), (1.5, TABLE), (1.0, ITERABLE), (1.0, ITERATOR)]

    def show(self, g: Gen, ty: Ty, expr: str):
        if ty in (COUNTER, ITERATOR):
            return f"Iters.drain({expr})"
        if ty in (SPAN, ITERABLE):
            return f"Iters.ints({expr})"
        if ty == TABLE:
            return f"({expr}).describe()"
        return None

    # ---- expressions ------------------------------------------------------------------

    def exprs(self, g: Gen, ty: Ty):
        out: List[Choice] = []
        if ty == COUNTER:
            out.append(Choice(3, lambda: self._counter(g), leaf=True))
        elif ty == SPAN:
            out.append(Choice(3, lambda: f"new IntSpan({g.expr(INT)}, {g.expr(INT)})", leaf=True))
        elif ty == ITERABLE:
            out.append(
                Choice(
                    2, lambda: f"([{', '.join(g.exprs(*[INT] * g.between(0, 4)))}] : IntIterable)", leaf=True
                )
            )
            out.append(
                Choice(2, lambda: f"({g.expr(g.pick(g.subtype_choices(ITERABLE)[1:]))} : IntIterable)")
            )
        elif ty == ITERATOR:
            out.append(Choice(2, lambda: f"Iters.gen({g.expr(INT)}, {g.expr(INT)})", leaf=True))
            out.append(Choice(1.5, lambda: f"({g.expr(COUNTER)} : Iterator<Int>)"))
            out.append(
                Choice(
                    1,
                    lambda: f"([{', '.join(g.exprs(*[INT] * g.between(0, 3)))}].iterator() : Iterator<Int>)",
                    leaf=True,
                )
            )
        elif ty == TABLE:
            out.append(
                Choice(
                    3, lambda: f"new StrTable([{', '.join(g.exprs(*[STRING] * g.between(0, 4)))}])", leaf=True
                )
            )
        elif ty == INT:
            out.append(Choice(1.5, lambda: f"Iters.sum({g.expr(g.pick([ITERABLE, SPAN, COUNTER]))})"))
        elif ty == STRING:
            out.append(Choice(1.5, lambda: f"Iters.ints({g.expr(g.pick([ITERABLE, SPAN, COUNTER]))})"))
        elif ty == BOOL:
            out.append(Choice(1, lambda: f"{g.expr(g.pick([ITERATOR, COUNTER]))}.hasNext()"))
        return out

    def _counter(self, g: Gen) -> str:
        if g.chance(0.5):
            return f"new IntCounter({g.expr(INT)}, {g.expr(INT)})"
        return f"new IntCounter({g.expr(INT)}, {g.expr(INT)}, {g.expr(INT)})"

    # ---- statements -------------------------------------------------------------------

    def stmts(self, g: Gen):
        return [
            Choice(3, lambda: self._for_each(g), nested=True),
            Choice(2, lambda: self._for_pairs(g), nested=True),
            Choice(2, lambda: self._manual(g), nested=True),
        ]

    def _for_each(self, g: Gen) -> bool:
        source = g.expr(g.pick([COUNTER, SPAN, ITERABLE, ITERATOR]))
        x = g.fresh("it")
        with g.block(f"for ({x} in {source}) {{"):
            g.loop_depth += 1
            g.declare_var(x, INT, mutable=False)
            g.statements()
            g.loop_depth -= 1
        return True

    def _for_pairs(self, g: Gen) -> bool:
        arrays = [v for v in g.visible() if v.ty.name == "Array"]
        if arrays and g.chance(0.4):
            source = g.pick(arrays)
            src, value_ty = source.name, source.ty.args[0]
        else:
            src, value_ty = g.expr(TABLE), STRING
        k, v = g.fresh("k"), g.fresh("v")
        with g.block(f"for ({k} => {v} in {src}) {{"):
            g.loop_depth += 1
            g.declare_var(k, INT, mutable=False)
            g.declare_var(v, value_ty, mutable=False)
            g.statements()
            g.loop_depth -= 1
        return True

    def _manual(self, g: Gen) -> bool:
        it = g.fresh("iter")
        arrays = [v for v in g.visible() if v.ty.name == "Array"]
        if arrays and g.chance(0.3):
            source = g.pick(arrays)
            elem = source.ty.args[0]
            g.emit(f"var {it} = {source.name}.iterator();")
        else:
            elem = INT
            if g.chance(0.5):
                g.emit(f"var {it}:Iterator<Int> = {g.expr(ITERATOR)};")
            else:
                g.emit(f"var {it} = {g.expr(ITERABLE)}.iterator();")
        g.declare_var(it, Ty("Iterator", (elem,)), mutable=False)
        x = g.fresh("e")
        with g.block(f"while ({it}.hasNext()) {{"):
            g.emit(f"var {x} = {it}.next();")
            g.declare_var(x, elem, mutable=False)
            g.loop_depth += 1
            g.statements()
            g.loop_depth -= 1
        return True
