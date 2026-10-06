"""Metadata and modifiers: inline/extern inline/@:noInline helpers, @:keep, @:analyzer flags, final, inline constants."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from ..feature import Choice, Feature, register
from ..gen import Fn, Gen
from ..types import BOOL, FLOAT, INT, STRING, Ty

ACC = Ty("Acc")
_SCALARS = (INT, FLOAT, BOOL, STRING)
_ANALYZER = ["no_optimize", "no_const_propagation", "no_copy_propagation", "no_local_dce", "no_fusion"]

_NEUTRAL = {INT: "+ 0", FLOAT: "+ 0.0", STRING: '+ ""', BOOL: "&& true"}

# (modifiers before `function`, may contain statements, is inline)
_KINDS: Tuple[Tuple[str, bool, bool], ...] = (
    ("static inline", True, True),
    ("static inline", True, True),
    ("@:keep static", True, False),
    ("@:analyzer(no_optimize) static", True, False),
    ("@:analyzer(no_const_propagation) static", True, False),
    ("@:analyzer(no_local_dce) static inline", True, True),
    ("@:noInline static inline", True, True),
    ("@:noCompletion @:keep static", True, False),
    ("extern inline static", False, True),
)

_ACC = """\
@:keep
class Acc {
	public final base:Int;
	public var total:Int = 0;

	public function new(base:Int) {
		this.base = base;
	}

	public inline function bump(by:Int):Int {
		total += by * by;
		return total + base;
	}

	public inline function twice(by:Int):Int {
		return bump(by) + bump(by);
	}

	@:analyzer(no_optimize) public function peek():Int {
		return total - base;
	}

	public inline function describe():String {
		return base + ":" + total;
	}
}"""


@dataclass
class Helper:
    fn: Fn
    inline: bool


@register
class Metadata(Feature):
    name = "metadata"
    summary = "inline/extern inline helpers, @:keep, @:analyzer flags, final fields, inline constants"
    covers = ("EMeta", "AInline", "AFinal", "AStatic", "AExtern", "APublic", "FVar", "FFun")
    order = 55

    def declare(self, g: Gen) -> None:
        g.decls.append(_ACC)
        consts = [
            (INT, "KI", f"static inline final KI = {g.between(0, 99)};"),
            (STRING, "KS", f'static final KS = "{g.pick(["meta", "k", "inl"])}";'),
            (FLOAT, "KF", f"static inline var KF = {g.pick(['2.5', '0.25', '10.0'])};"),
            (BOOL, "KB", f"static inline final KB = {g.pick(['true', 'false'])};"),
        ]
        g.members += [f"\t{text}" for _, _, text in consts]
        helpers: List[Helper] = []
        g.state[self.name] = {"consts": [(t, n) for t, n, _ in consts], "helpers": helpers}
        g.fns += [
            Fn("bump", (INT,), INT, ACC),
            Fn("twice", (INT,), INT, ACC),
            Fn("peek", (), INT, ACC),
            Fn("describe", (), STRING, ACC),
        ]
        for _ in range(g.between(3, 6)):
            self._helper(g, helpers)

    # ---- helper functions ---------------------------------------------------------------

    def _helper(self, g: Gen, helpers: List[Helper]) -> None:
        modifiers, statements, inline = g.pick(_KINDS)
        params = [(g.fresh("p"), g.pick(_SCALARS)) for _ in range(g.between(1, 3))]
        ret = g.pick(_SCALARS)
        name = g.fresh("h")
        with g.capture(level=2) as body:
            with g.function(params, None if inline else ret):  # an inline body may only return at its end
                if statements:
                    for pname, pty in params:
                        if pty == STRING:  # keep strings fed back through `+=` from growing without bound
                            g.emit(f"{pname} = {pname}.substr(0, 8);")
                    g.statements(g.between(0, 2))
                g.emit(f"return {self._result(g, params, ret)};")
        signature = ", ".join(f"{n}:{t}" for n, t in params)
        g.members.append("\n".join([f"\t{modifiers} function {name}({signature}):{ret} {{", *body, "\t}"]))
        fn = Fn(name, tuple(t for _, t in params), ret)
        g.fns.append(fn)
        helpers.append(Helper(fn, inline))

    def _result(self, g: Gen, params: List[Tuple[str, Ty]], ret: Ty) -> str:
        """Often use one parameter twice: an inlined call must still evaluate its argument once."""
        same = [n for n, t in params if t == ret]
        if not same or g.chance(0.4):
            result = g.expr(ret)
            # Inlined, a bare parameter would make `v = f(v)` read `v = v`, which Haxe rejects.
            return f"({result} {_NEUTRAL[ret]})" if result.strip("()") in {n for n, _ in params} else result
        p = g.pick(same)
        if ret == INT:
            return g.pick([f"({p} * {p} + {g.expr(INT)})", f"({p} + {g.expr(INT)} - {p})"])
        if ret == FLOAT:
            return f"({p} + {p} * {g.expr(FLOAT)})"
        if ret == STRING:
            return f"({p}.substr(0, 3) + {g.expr(STRING)} + {p}.charAt(0))"
        return f"({p} && {g.expr(BOOL)} || {p})"

    # ---- types ------------------------------------------------------------------------

    def types(self, g: Gen, depth: int):
        return [] if depth else [(1.0, ACC)]

    def show(self, g: Gen, ty: Ty, expr: str):
        return f"({expr}).describe()" if ty == ACC else None

    # ---- expressions ------------------------------------------------------------------

    def exprs(self, g: Gen, ty: Ty):
        state = g.state[self.name]
        out: List[Choice] = []
        for const_ty, name in state["consts"]:
            if const_ty == ty:
                out.append(Choice(1.5, lambda n=name: n, leaf=True))
        for helper in state["helpers"]:
            if helper.fn.ret == ty:
                out.append(Choice(3 if helper.inline else 1.5, lambda f=helper.fn: self._call(g, f)))
        if ty == ACC:
            out.append(Choice(3, lambda: f"new Acc({g.expr(INT)})", leaf=True))
        if ty == INT:
            out += self._acc_reads(g)
            out.append(Choice(1.5, lambda: f"{g.expr(ACC)}.{g.pick(['bump', 'twice'])}({g.expr(INT)})"))
        if ty in _SCALARS:
            out.append(Choice(1, lambda: f"(@:analyzer({g.pick(_ANALYZER)}) ({g.expr(ty)}))"))
        return out

    def _call(self, g: Gen, fn: Fn) -> str:
        return f"{fn.name}({', '.join(g.exprs(*fn.params))})"

    def _acc_reads(self, g: Gen) -> List[Choice]:
        out = []
        for var in g.visible(ACC):
            for member in ("base", "total", "peek()", "bump(1)"):
                out.append(Choice(0.8, lambda n=var.name, m=member: f"{n}.{m}", leaf=True))
        return out

    # ---- statements -------------------------------------------------------------------

    def stmts(self, g: Gen):
        out = [
            Choice(2, lambda: self._analyzed_block(g), nested=True),
            Choice(1.5, lambda: self._analyzed_var(g)),
            Choice(1.5, lambda: self._analyzed_print(g)),
        ]
        if [h for h in g.state[self.name]["helpers"] if h.inline and INT in h.fn.params]:
            out.append(Choice(3, lambda: self._effectful_call(g)))
        out += [Choice(2, lambda v=v: self._acc(g, v.name)) for v in g.visible(ACC)]
        return out

    def _analyzed_block(self, g: Gen) -> bool:
        with g.block(f"@:analyzer({g.pick(_ANALYZER)}) {{"):
            g.statements()
        return True

    def _analyzed_var(self, g: Gen) -> bool:
        ty = g.pick(_SCALARS)
        name = g.fresh("m")
        g.emit(f"@:analyzer({g.pick(_ANALYZER)}) var {name}:{ty} = {g.expr(ty)};")
        g.declare_var(name, ty)
        return True

    def _analyzed_print(self, g: Gen) -> bool:
        ty = g.pick(_SCALARS)
        g.emit(f"@:analyzer({g.pick(_ANALYZER)}) Sys.println({g.show(g.expr(ty), ty)});")
        return True

    def _effectful_call(self, g: Gen) -> bool:
        """Call an inline helper with side-effecting arguments, then print the counter they bumped."""
        fn = g.pick([h for h in g.state[self.name]["helpers"] if h.inline and INT in h.fn.params]).fn
        n = g.fresh("c")
        g.emit(f"var {n} = {g.expr(INT)};")
        args = [
            g.pick([f"{n}++", f"--{n}", f"({n} += 2)", f"({n} * {n})"]) if t == INT else g.expr(t)
            for t in fn.params
        ]
        call = f"{fn.name}({', '.join(args)})"
        g.emit(f"Sys.println({g.show(call, fn.ret)});")
        g.emit(f"Sys.println({n});")
        g.declare_var(n, INT, mutable=False)
        return True

    def _acc(self, g: Gen, name: str) -> bool:
        form = g.pick(["total", "bump", "twice", "peek"])
        if form == "total":
            g.emit(f"{name}.total {g.pick(['+=', '-=', '^='])} {g.expr(INT)};")
        elif form == "peek":
            g.emit(f"Sys.println({name}.peek());")
        else:
            g.emit(f"{name}.{form}({g.expr(INT)});")
        return True
