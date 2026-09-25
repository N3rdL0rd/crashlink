"""
Recovery of calls to inline functions.

Haxe copies an inline function's body into every caller, substituting the
arguments for the parameters. With default dead-code elimination the function
itself stays in the bytecode, and since every call was inlined nothing calls it
directly. Such a function is a *template*: its decompiled body, with its
parameters as placeholders, is matched against the IR of other functions, and
each copy found is put back as the call it came from.

Debug positions can't find the tiny ones: HL stamps every opcode with the
position of the last operand it evaluated, so an operation whose operands are
all substituted arguments (`v * v`, `this.base + a`) carries the caller's
line. Matching the body works either way; positions only add confidence.
"""

from __future__ import annotations

import threading
import weakref
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

from ..core import Bytecode, Function, Obj, Opcode, Type, destaticify, fIndex
from ..std_inline import is_std_inline
from .ir import (
    IRArithmetic,
    IRArrayAccess,
    IRAssign,
    IRBlock,
    IRBoolExpr,
    IRCall,
    IRCast,
    IRConst,
    IRExpression,
    IRField,
    IRLocal,
    IRNeg,
    IRNew,
    IRNot,
    IRReturn,
    IRStatement,
    IRStringConvert,
    IRTernary,
)
from .opt import TraversingIROptimizer, _has_observable_effects, _structurally_equal
from .opt.inliner import _is_pure_numeric_cast_tree

#: Bodies larger than this (in opcodes) are not worth decompiling as templates:
#: inline functions are small, and a large body would rarely match exactly.
MAX_TEMPLATE_OPS = 60
#: A match needs this much structure unless debug positions confirm it: a lone
#: field read or store, or `x * 2`, is too common to attribute to a function.
MIN_UNCONFIRMED_WEIGHT = 2

# Methods the runtime or std library call by name, never through a Call opcode.
_CALLED_BY_NAME = frozenset(
    {"toString", "__string", "__compare", "__cast", "__get_field", "__set_field", "hashCode"}
)
_CALL_OPS = frozenset({"Call0", "Call1", "Call2", "Call3", "Call4", "CallN"})
_CLOSURE_OPS = frozenset({"StaticClosure", "InstanceClosure"})
# Nodes that count as structure for MIN_UNCONFIRMED_WEIGHT.
_WEIGHTED = (
    IRArithmetic,
    IRBoolExpr,
    IRField,
    IRCall,
    IRNew,
    IRArrayAccess,
    IRTernary,
    IRNeg,
    IRNot,
    IRStringConvert,
)
_SWAPPED = {
    IRBoolExpr.CompareType.LT: IRBoolExpr.CompareType.GT,
    IRBoolExpr.CompareType.GT: IRBoolExpr.CompareType.LT,
    IRBoolExpr.CompareType.LTE: IRBoolExpr.CompareType.GTE,
    IRBoolExpr.CompareType.GTE: IRBoolExpr.CompareType.LTE,
    IRBoolExpr.CompareType.EQ: IRBoolExpr.CompareType.EQ,
    IRBoolExpr.CompareType.NEQ: IRBoolExpr.CompareType.NEQ,
}

_state = threading.local()


@contextmanager
def _collapsing_disabled() -> Iterator[None]:
    """Decompile template bodies as the compiler wrote them, not with other
    templates already folded back into calls."""
    depth = getattr(_state, "depth", 0)
    _state.depth = depth + 1
    try:
        yield
    finally:
        _state.depth = depth


@dataclass
class InlineTemplate:
    """One inline function, as a pattern to find its copies by."""

    function: Function
    owner: Obj
    name: str
    #: The receiver is parameter 0.
    instance: bool
    param_types: List[Type]
    #: Parameter register -> parameter index.
    param_regs: Dict[int, int]
    #: The body: a returned expression, or statements (a Void function).
    expression: Optional[IRExpression]
    statements: List[IRStatement]
    #: Debug (file, first line, last line) of the function's own code.
    span: Optional[Tuple[int, int, int]]
    weight: int = 0
    uses: Counter = field(default_factory=Counter)
    #: Every non-placeholder node of the body is free of observable effects.
    pure: bool = True
    #: Another template has the same body: a copy can't be attributed.
    ambiguous: bool = False

    def root(self) -> IRStatement:
        return self.expression if self.expression is not None else self.statements[0]


class InlineIndex:
    """Every template of one bytecode image, by the kind of node its body starts with."""

    def __init__(self, templates: List[InlineTemplate]) -> None:
        self.templates = sorted(templates, key=lambda t: -t.weight)
        self.by_findex = {t.function.findex.value: t for t in self.templates}
        self.expressions: Dict[Tuple, List[InlineTemplate]] = {}
        self.statements: Dict[Tuple, List[InlineTemplate]] = {}
        for template in self.templates:
            if template.ambiguous:
                continue
            target = self.expressions if template.expression is not None else self.statements
            target.setdefault(_node_key(template.root()), []).append(template)


def _node_key(node: Any) -> Tuple:
    """What a template's first node and a candidate must share to be worth matching."""
    if isinstance(node, (IRArithmetic, IRNeg, IRNot)):
        return (type(node).__name__, getattr(node, "op", None))
    if isinstance(node, IRBoolExpr):
        # Comparisons match with their operands swapped too.
        op = node.op
        return ("IRBoolExpr", frozenset({op, _SWAPPED.get(op, op)}))
    if isinstance(node, IRField):
        return ("IRField", node.field_name)
    if isinstance(node, IRAssign):
        return ("IRAssign", _node_key(node.target))
    if isinstance(node, IRCall):
        return ("IRCall", node.call_type, _call_target_key(node))
    return (type(node).__name__,)


def _call_target_key(call: IRCall) -> Any:
    target = call.target
    if isinstance(target, IRConst) and isinstance(target.value, Function):
        return target.value.findex.value
    if isinstance(target, IRField):
        return target.field_name
    return None


# --- building the index ----------------------------------------------------------

# Keyed by id(code) with a weakref back to it, like `pseudo._method_registry`:
# Bytecode isn't hashable, and the check guards against a recycled id.
_cache: Dict[int, Tuple["weakref.ReferenceType[Bytecode]", InlineIndex]] = {}
_cache_lock = threading.Lock()


def inline_index(code: Bytecode) -> InlineIndex:
    """The templates of `code`, built once."""
    with _cache_lock:
        cached = _cache.get(id(code))
        if cached is not None and cached[0]() is code:
            return cached[1]
        index = InlineIndex(_build_templates(code))
        _cache[id(code)] = (weakref.ref(code), index)
        return index


def _called(code: Bytecode) -> Tuple[Set[int], Set[str]]:
    """Functions a Call or closure opcode names, and method names reached by
    dispatch (virtual calls, interfaces and dynamic access) or by the runtime."""
    from .. import disasm

    findexes: Set[int] = set()
    names: Set[str] = set(_CALLED_BY_NAME)
    for func in code.functions:
        if not isinstance(func, Function):
            continue
        for op in func.ops:
            name = op.op
            if name in _CALL_OPS or name in _CLOSURE_OPS:
                findexes.add(op.df["fun"].value)
                if name == "InstanceClosure":
                    continue
            if name in ("CallMethod", "CallThis", "VirtualClosure"):
                names.add(_dispatched_name(code, func, op, disasm))
            elif name in ("DynGet", "DynSet"):
                names.add(op.df["field"].resolve(code))
    entry = getattr(code, "entrypoint", None)
    if entry is not None:
        findexes.add(entry.value)
    return findexes, names


def _dispatched_name(code: Bytecode, func: Function, op: Opcode, disasm: Any) -> str:
    if op.op == "CallThis":
        receiver = func.regs[0].resolve(code)
    elif op.op == "VirtualClosure":
        receiver = func.regs[op.df["obj"].value].resolve(code)
    else:
        args = op.df["args"].value
        if not args:
            return ""
        receiver = func.regs[args[0].value].resolve(code)
    return disasm._method_name_for_field(code, receiver, op.df["field"].value)


def _overridden(code: Bytecode) -> Set[Tuple[int, str]]:
    """(class, method) pairs a subclass overrides or that override a parent's."""
    result: Set[Tuple[int, str]] = set()
    for typ in code.types:
        obj = typ.definition
        if not isinstance(obj, Obj) or obj.super is None or obj.super.value < 0:
            continue
        own = {proto.name.resolve(code) for proto in obj.protos}
        parent = obj.super.resolve(code).definition
        seen: Set[int] = set()
        while isinstance(parent, Obj) and id(parent) not in seen:
            seen.add(id(parent))
            for proto in parent.protos:
                name = proto.name.resolve(code)
                if name in own:
                    result.add((id(parent), name))
                    result.add((id(obj), name))
            if parent.super is None or parent.super.value < 0:
                break
            parent = parent.super.resolve(code).definition
    return result


def _build_templates(code: Bytecode) -> List[InlineTemplate]:
    from .. import disasm
    from ..pseudo import _method_registry

    called, dispatched = _called(code)
    overridden = _overridden(code)
    templates: List[InlineTemplate] = []
    for findex, (owner, name, instance) in _method_registry(code).items():
        if (
            findex in called
            or name in dispatched
            or name == "__constructor__"
            or (id(owner), name) in overridden
        ):
            continue
        func = code.fn(findex)
        if not isinstance(func, Function) or len(func.ops) > MAX_TEMPLATE_OPS:
            continue
        # The std keeps methods nothing calls for reflection; its sources say
        # which ones are inline.
        if disasm.is_std(code, func) and not is_std_inline(destaticify(owner.name.resolve(code)), name):
            continue
        template = _template(code, func, owner, name, instance)
        if template is not None:
            templates.append(template)
    by_shape: Dict[str, List[InlineTemplate]] = {}
    for template in templates:
        by_shape.setdefault(_shape(template), []).append(template)
    for same in by_shape.values():
        if len(same) > 1:
            for template in same:
                template.ambiguous = True
    return templates


def _template(
    code: Bytecode, func: Function, owner: Obj, name: str, instance: bool
) -> Optional[InlineTemplate]:
    from .function import IRFunction

    fun_type = func.type.resolve(code).definition
    arg_types = [a.resolve(code) for a in getattr(fun_type, "args", [])]
    if any(t.kind.value == Type.Kind.REF.value for t in arg_types):
        return None  # default arguments: the copies substitute the defaults
    try:
        with _collapsing_disabled():
            ir = IRFunction(code, func)
    except Exception:
        return None
    if ir.default_args:
        return None
    statements = list(ir.block.statements)
    if statements and isinstance(statements[-1], IRReturn) and statements[-1].value is None:
        statements.pop()
    expression: Optional[IRExpression] = None
    if len(statements) == 1 and isinstance(statements[0], IRReturn):
        expression = statements[0].value
        if expression is None:
            return None
        statements = []
    elif not statements or not all(
        (isinstance(s, IRAssign) and not isinstance(s.target, IRLocal)) or isinstance(s, IRCall)
        for s in statements
    ):
        return None
    template = InlineTemplate(
        function=func,
        owner=owner,
        name=name,
        instance=instance,
        param_types=arg_types,
        param_regs={reg: reg for reg in range(len(arg_types))},
        expression=expression,
        statements=statements,
        span=_own_span(func),
    )
    body: List[Any] = [expression] if expression is not None else statements
    if not all(_scan_body(template, node) for node in body):
        return None
    if set(template.uses) != set(range(len(arg_types))):
        return None  # an unused parameter's argument can't be recovered from a copy
    template.weight += sum(n - 1 for n in template.uses.values())
    if template.weight == 0:
        return None
    return template


def _scan_body(template: InlineTemplate, node: Any) -> bool:
    """Count weight and parameter uses; reject bodies with locals of their own,
    control flow, or parameters written."""
    if isinstance(node, IRLocal):
        if node.reg_idx not in template.param_regs or node.web is not None:
            return False
        template.uses[template.param_regs[node.reg_idx]] += 1
        return True
    if isinstance(node, IRBlock) or not isinstance(node, IRStatement):
        return False
    if isinstance(node, IRAssign) and isinstance(node.target, IRLocal):
        return False
    if isinstance(node, _WEIGHTED):
        template.weight += 1
    if isinstance(node, IRExpression) and not isinstance(node, (IRLocal, IRCast)):
        if _node_effects(node):
            template.pure = False
    elif isinstance(node, IRAssign):
        template.pure = False
    if isinstance(node, (IRConst,)):
        return True
    if type(node).__name__ not in _MATCHABLE:
        return False
    return all(_scan_body(template, child) for child in node.get_children())


_NUMERIC_KINDS = frozenset(
    k.value for k in (Type.Kind.U8, Type.Kind.U16, Type.Kind.I32, Type.Kind.I64, Type.Kind.F32, Type.Kind.F64)
)
_TRAPPING = frozenset(
    {
        IRArithmetic.ArithmeticType.SDIV,
        IRArithmetic.ArithmeticType.UDIV,
        IRArithmetic.ArithmeticType.SMOD,
        IRArithmetic.ArithmeticType.UMOD,
    }
)


def _node_effects(node: IRExpression) -> bool:
    """Effects of the node itself, not of its operands (see `_has_observable_effects`)."""
    if isinstance(node, (IRField, IRArrayAccess, IRCall, IRNew)):
        return True
    if isinstance(node, IRArithmetic):
        return node.op in _TRAPPING or node.get_type().kind.value not in _NUMERIC_KINDS
    return False


def _own_span(func: Function) -> Optional[Tuple[int, int, int]]:
    if not func.has_debug or not func.debuginfo or not func.debuginfo.value:
        return None
    refs = func.debuginfo.value
    file = Counter(r.value for r in refs).most_common(1)[0][0]
    lines = [r.line for r in refs if r.value == file]
    return file, min(lines), max(lines)


def _shape(template: InlineTemplate) -> str:
    """Text identifying a body up to its parameters, to find duplicate templates."""
    names = {reg: f"${index}" for reg, index in template.param_regs.items()}

    def text(node: Any) -> str:
        if isinstance(node, IRLocal):
            return names.get(node.reg_idx, "?")
        if isinstance(node, IRConst):
            return f"const({node.const_type}:{getattr(node.value, 'value', node.value)!r})"
        label = type(node).__name__
        for attr in ("op", "field_name", "call_type"):
            if hasattr(node, attr):
                label += f".{getattr(node, attr)}"
        return f"{label}({','.join(text(c) for c in node.get_children())})"

    body = [template.expression] if template.expression is not None else template.statements
    types = ",".join(str(id(t)) for t in template.param_types)
    return f"{types}|" + ";".join(text(n) for n in body)


_MATCHABLE = frozenset(
    {
        "IRArithmetic",
        "IRBoolExpr",
        "IRField",
        "IRArrayAccess",
        "IRCall",
        "IRCast",
        "IRNeg",
        "IRNot",
        "IRTernary",
        "IRNew",
        "IRStringConvert",
        "IRAssign",
    }
)


# --- matching ----------------------------------------------------------------------


class _Match:
    def __init__(self, code: Bytecode, template: InlineTemplate) -> None:
        self.code = code
        self.template = template
        self.env: Dict[int, IRExpression] = {}
        self.order: List[int] = []

    def node(self, p: Any, t: Any) -> bool:
        if isinstance(p, IRLocal):
            return self._bind(self.template.param_regs[p.reg_idx], t)
        if p is None or t is None:
            return p is None and t is None
        if type(p) is not type(t):
            return False
        if isinstance(p, IRConst):
            return _structurally_equal(p, t)
        if isinstance(p, IRArithmetic):
            # An Incr/Decr step is `++`/`--` in source, never a copied `x + 1`.
            if p.op != t.op or p.step != t.step:
                return False
            return self.node(p.left, t.left) and self.node(p.right, t.right)
        if isinstance(p, IRBoolExpr):
            if p.op == t.op and self.node(p.left, t.left) and self.node(p.right, t.right):
                return True
            return (
                _SWAPPED.get(p.op) == t.op
                and p.left is not None
                and p.right is not None
                and self.node(p.left, t.right)
                and self.node(p.right, t.left)
            )
        if isinstance(p, IRField):
            return p.field_name == t.field_name and self.node(p.target, t.target)
        if isinstance(p, IRArrayAccess):
            return self.node(p.array, t.array) and self.node(p.index, t.index)
        if isinstance(p, IRCall):
            return (
                p.call_type == t.call_type
                and len(p.args) == len(t.args)
                and self.node(p.target, t.target)
                and all(self.node(a, b) for a, b in zip(p.args, t.args))
            )
        if isinstance(p, IRCast):
            return p.target_type_idx.value == t.target_type_idx.value and self.node(p.expr, t.expr)
        if isinstance(p, (IRNeg, IRNot)):
            return self.node(p.expr, t.expr)
        if isinstance(p, IRTernary):
            return (
                self.node(p.condition, t.condition)
                and self.node(p.then_expr, t.then_expr)
                and self.node(p.else_expr, t.else_expr)
            )
        if isinstance(p, IRNew):
            return (
                p.alloc_type_idx.value == t.alloc_type_idx.value
                and len(p.constructor_args) == len(t.constructor_args)
                and all(self.node(a, b) for a, b in zip(p.constructor_args, t.constructor_args))
            )
        if isinstance(p, IRStringConvert):
            return self.node(p.value, t.value)
        if isinstance(p, IRAssign):
            return self.node(p.target, t.target) and self.node(p.expr, t.expr)
        return False

    def _bind(self, index: int, t: Any) -> bool:
        if not isinstance(t, IRExpression):
            return False
        bound = self.env.get(index)
        if bound is not None:
            return _structurally_equal(bound, t)
        if not _assignable(self.code, t.get_type(), self.template.param_types[index]):
            return False
        self.env[index] = t
        self.order.append(index)
        return True

    def valid(self) -> bool:
        """The call evaluates each argument once, in parameter order, before the
        body; the copy evaluated them where the body reads them."""
        template = self.template
        effectful = [i for i in self.order if _effectful(self.env[i])]
        if not effectful:
            return True
        if not template.pure or any(template.uses[i] > 1 for i in effectful):
            return False
        return effectful == sorted(effectful)


def _effectful(expr: IRExpression) -> bool:
    """Whether evaluating `expr` once instead of where the body read it, or
    in another order, could be observed."""
    return _has_observable_effects(expr) and not _is_pure_numeric_cast_tree(expr)


def _assignable(code: Bytecode, value: Type, param: Type) -> bool:
    """Whether a value of type `value` can be passed for a parameter of type `param`."""
    if value is param:
        return True
    if value.kind.value != param.kind.value:
        return param.kind.value == Type.Kind.DYN.value
    if isinstance(param.definition, Obj) and isinstance(value.definition, Obj):
        current: Any = value.definition
        seen: Set[int] = set()
        while isinstance(current, Obj) and id(current) not in seen:
            if current is param.definition:
                return True
            seen.add(id(current))
            if current.super is None or current.super.value < 0:
                return False
            current = current.super.resolve(code).definition
        return False
    return True


# --- the pass ----------------------------------------------------------------------


class IRInlineCallRecovery(TraversingIROptimizer):
    """Puts copies of inline functions back as calls (see the module docstring)."""

    def should_run(self) -> bool:
        return getattr(_state, "depth", 0) == 0 and super().should_run()

    def optimize(self) -> None:
        self.index = inline_index(self.func.code)
        if not self.index.templates:
            return
        self.own = self.func.func.findex.value
        debug = self.func.func.debuginfo
        self.positions = debug.value if self.func.func.has_debug and debug else None
        super().optimize()

    def visit_block(self, block: IRBlock) -> None:
        stmts = block.statements
        result: List[IRStatement] = []
        i = 0
        while i < len(stmts):
            replaced = self._statement_call(stmts, i)
            if replaced is not None:
                call, span = replaced
                result.append(call)
                i += span
                continue
            stmt = stmts[i]
            self._rewrite_children(stmt)
            result.append(stmt)
            i += 1
        block.statements = result

    def _statement_call(self, stmts: List[IRStatement], i: int) -> Optional[Tuple[IRStatement, int]]:
        for template in self.index.statements.get(_node_key(stmts[i]), ()):
            n = len(template.statements)
            if template.function.findex.value == self.own or i + n > len(stmts):
                continue
            match = _Match(self.func.code, template)
            if all(match.node(p, t) for p, t in zip(template.statements, stmts[i : i + n])) and self._accept(
                match, stmts[i : i + n]
            ):
                call = self._call(match)
                call.adopt(*stmts[i : i + n])
                return call, n
        return None

    def _rewrite_children(self, node: IRStatement) -> None:
        for name, value in vars(node).items():
            if isinstance(value, IRExpression) and not isinstance(value, IRLocal):
                setattr(node, name, self._rewrite(value))
            elif isinstance(value, list) and value and isinstance(value[0], IRExpression):
                setattr(node, name, [self._rewrite(v) if isinstance(v, IRExpression) else v for v in value])

    def _rewrite(self, expr: IRExpression) -> IRExpression:
        if isinstance(expr, (IRLocal, IRConst)):
            return expr
        for template in self.index.expressions.get(_node_key(expr), ()):
            if template.function.findex.value == self.own:
                continue
            match = _Match(self.func.code, template)
            if match.node(template.expression, expr) and self._accept(match, [expr]):
                call = self._call(match)
                call.adopt(expr)
                # Arguments can hold further copies.
                call.args = [self._rewrite(a) for a in call.args]
                if isinstance(call.target, IRField):
                    call.target.target = self._rewrite(call.target.target)
                return call
        self._rewrite_children(expr)
        return expr

    def _accept(self, match: _Match, nodes: List[IRStatement]) -> bool:
        if not match.valid():
            return False
        return match.template.weight >= MIN_UNCONFIRMED_WEIGHT or self._positioned(match, nodes)

    def _positioned(self, match: _Match, nodes: List[IRStatement]) -> bool:
        """Whether an opcode of the copy (not of its arguments) sits on the
        template's own lines."""
        span = match.template.span
        if span is None or self.positions is None:
            return False
        file, first, last = span
        arguments = {id(v) for v in match.env.values()}
        pending: List[Any] = list(nodes)
        while pending:
            node = pending.pop()
            if id(node) in arguments or not isinstance(node, IRStatement):
                continue
            for op in node.src_op_idxs:
                if op < len(self.positions):
                    ref = self.positions[op]
                    if ref.value == file and first <= ref.line <= last:
                        return True
            pending.extend(node.get_children())
        return False

    def _call(self, match: _Match) -> IRCall:
        template = match.template
        code = self.func.code
        args = [match.env[i] for i in range(len(template.param_types))]
        fun = template.function
        if template.instance:
            target = IRField(code, args[0], template.name, fun.type)
            return IRCall(code, IRCall.CallType.METHOD, target, args[1:])
        index = fIndex()
        index.value = fun.findex.value
        return IRCall(code, IRCall.CallType.FUNC, IRConst(code, IRConst.ConstType.FUN, idx=index), args)


def is_inline_template(code: Bytecode, func: Function) -> bool:
    """Whether class output should declare `func` as `inline`."""
    if getattr(_state, "depth", 0):
        return False  # building the index: nothing is known yet
    from .. import disasm

    # The std isn't recompiled from decompiled output: it declares its own.
    return func.findex.value in inline_index(code).by_findex and not disasm.is_std(code, func)
