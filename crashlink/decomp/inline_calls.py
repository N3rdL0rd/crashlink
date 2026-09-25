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

import copy
import threading
import weakref
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

from ..core import Bytecode, Fun, Function, Obj, Opcode, Type, destaticify, fIndex, tIndex
from ..std_inline import is_std_inline
from .ir import (
    IRInlineCall,
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

    #: The function, or None when it was rebuilt from its copies (see
    #: `_rebuilt_templates`): its body is then what the copies share.
    function: Optional[Function]
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
    #: Another template has the same body: a copy can't be attributed.
    ambiguous: bool = False

    def root(self) -> IRStatement:
        return self.expression if self.expression is not None else self.statements[0]

    def findex(self) -> Optional[int]:
        return self.function.findex.value if self.function is not None else None


class InlineIndex:
    """Every template of one bytecode image, by the kind of node its body starts with."""

    def __init__(self, templates: List[InlineTemplate]) -> None:
        self.templates = sorted(templates, key=lambda t: -t.weight)
        self.by_findex = {t.function.findex.value: t for t in self.templates if t.function is not None}
        #: Rebuilt templates by the class they are declared in.
        self.rebuilt: Dict[int, List[InlineTemplate]] = {}
        for template in self.templates:
            if template.function is None:
                self.rebuilt.setdefault(id(template.owner), []).append(template)
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
    templates.extend(_rebuilt_templates(code, templates))
    by_shape: Dict[str, List[InlineTemplate]] = {}
    for template in templates:
        by_shape.setdefault(_shape(template), []).append(template)
    for same in by_shape.values():
        if len(same) > 1:
            for template in same:
                template.ambiguous = True
    return templates


#: Copies of a function to see before rebuilding it: a function inlined once is
#: just code. Constants count as arguments only where copies of one shape differ.
MIN_REBUILD_COPIES = 2
#: Hosts larger than this aren't decompiled just to read a copy out of them.
MAX_REBUILD_HOST_OPS = 2000


def _rebuilt_templates(code: Bytecode, surviving: List[InlineTemplate]) -> List[InlineTemplate]:
    """Templates for inline functions that no longer exist, from the copies the
    debug positions find (see `inlines.InlineFinder`). In a copy, the code on the
    function's own lines is the body; what the caller computed in place, and the
    constants that differ between copies, are its arguments."""
    from ..inlines import InlineFinder

    if not code.debugfiles or not code.debugfiles.value:
        return []
    try:
        finder = InlineFinder(code)
        found = finder.find()
    except Exception:
        return []
    owners = _classes_by_path(code)
    known = {(t.span[0], t.span[1]) for t in surviving if t.span is not None}
    type_index = {id(t): i for i, t in enumerate(code.types)}
    hosts: Dict[int, Any] = {}
    names: Set[Tuple[int, str]] = set()
    result: List[InlineTemplate] = []
    for inlined in found:
        if (
            inlined.kind != "source"
            or inlined.real_name is not None
            or (inlined.file, inlined.first_line) in known
        ):
            continue
        owner = _owner_of(owners, inlined.path)
        name = f"inlineL{inlined.first_line}"
        if owner is None or (id(owner), name) in names:
            continue
        if len(inlined.sites) < MIN_REBUILD_COPIES:
            continue
        shape = finder.shapes(inlined)[0]
        site = min(shape.sites, key=lambda s: len(getattr(code.fn(s.findex), "ops", ())))
        host = code.fn(site.findex)
        if not isinstance(host, Function) or len(host.ops) > MAX_REBUILD_HOST_OPS:
            continue
        if site.findex not in hosts:
            hosts[site.findex] = _decompile(code, host)
        ir = hosts[site.findex]
        if ir is None:
            continue
        varying = _varying_constant_ops(finder, site, shape)
        template = _rebuild(code, ir, set(site.ops), varying, owner, name, type_index)
        if template is None:
            continue
        template.span = (inlined.file, inlined.first_line, inlined.last_line)
        names.add((id(owner), name))
        result.append(template)
    return result


def _argument_types(code: Bytecode, node: Any) -> List[Type]:
    """Declared types of a call's arguments (`args`, without a method's receiver)."""
    if not isinstance(node, IRCall):
        return []
    target = node.target
    fun_type: Any = None
    if isinstance(target, IRConst) and isinstance(target.value, Function):
        fun_type = target.value.type.resolve(code).definition
        skip = 0
    elif isinstance(target, IRField):
        fun_type = target.get_type().definition
        skip = 1 if node.call_type == IRCall.CallType.METHOD else 0
    if not isinstance(fun_type, Fun):
        return []
    return [a.resolve(code) for a in fun_type.args[skip:]]


def _has_operation(node: Any) -> bool:
    if isinstance(node, _WEIGHTED) and not isinstance(node, IRField):
        return True
    return any(_has_operation(c) for c in node.get_children())


def _decompile(code: Bytecode, func: Function) -> Any:
    from .function import IRFunction

    try:
        with _collapsing_disabled():
            return IRFunction(code, func)
    except Exception:
        return None


def _classes_by_path(code: Bytecode) -> Dict[str, Obj]:
    """Classes by the path of the module that declares them (`tool/Cooldown.hx`)."""
    result: Dict[str, Obj] = {}
    for typ in code.types:
        obj = typ.definition
        if not isinstance(obj, Obj):
            continue
        parts = obj.name.resolve(code).split(".")
        if (
            parts[-1].startswith("$")
            or parts[-1].endswith("_Impl_")
            or any(p.startswith("_") for p in parts[:-1])
        ):
            continue
        result.setdefault("/".join(parts) + ".hx", obj)
    return result


def _owner_of(owners: Dict[str, Obj], path: str) -> Optional[Obj]:
    parts = path.replace("\\", "/").split("/")
    for i in range(len(parts)):
        owner = owners.get("/".join(parts[i:]))
        if owner is not None:
            return owner
    return None


def _varying_constant_ops(finder: Any, site: Any, shape: Any) -> Set[int]:
    """Opcodes of `site` loading a constant that other copies of the same shape
    load differently: an argument, not part of the body. Counts constants the
    way `InlineFinder._canonical` indexes them."""
    from ..inlines import _VALUE_KINDS
    from ..opcodes import opcodes

    varying = {index for index, _, _ in shape.varying_constants}
    if not varying:
        return set()
    func = finder.code.fn(site.findex)
    ops: Set[int] = set()
    position = 0
    for k in site.ops:
        op = func.ops[k]
        kinds = opcodes.get(op.op or "", {})
        for key in op.df:
            if kinds.get(key) in _VALUE_KINDS:
                if position in varying:
                    ops.add(k)
                position += 1
    return ops


def _rebuild(
    code: Bytecode,
    ir: Any,
    body_ops: Set[int],
    varying: Set[int],
    owner: Obj,
    name: str,
    type_index: Dict[int, int],
) -> Optional[InlineTemplate]:
    """A copy's body as a template: the one expression built from `body_ops`,
    its other parts turned into parameters."""
    parents: Dict[int, Any] = {}
    nodes: List[Any] = []
    seen: Set[int] = set()
    pending: List[Tuple[Any, Any]] = [(s, None) for s in ir.block.statements]
    while pending:
        node, parent = pending.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        parents[id(node)] = parent
        nodes.append(node)
        pending.extend((child, node) for child in node.get_children())

    def in_body(node: Any) -> bool:
        ops = node.src_op_idxs
        return bool(ops) and ops <= body_ops and not ops & varying

    roots: Dict[int, Any] = {}
    for node in nodes:
        if not isinstance(node, IRExpression) or isinstance(node, IRLocal) or not in_body(node):
            continue
        while isinstance(parents.get(id(node)), IRExpression) and in_body(parents[id(node)]):
            node = parents[id(node)]
        roots[id(node)] = node
    if len(roots) != 1:
        return None  # several statements: only expression bodies are rebuilt
    root = next(iter(roots.values()))
    # A conversion around the result is the caller's use of it (it carries the
    # body's position because the result was its last operand).
    while isinstance(root, IRCast) and in_body(root.expr):
        root = root.expr

    contains: Dict[int, bool] = {}

    def has_body(node: Any) -> bool:
        key = id(node)
        if key not in contains:
            contains[key] = in_body(node) or any(has_body(c) for c in node.get_children())
        return contains[key]

    def is_parameter(node: IRExpression) -> bool:
        if isinstance(node, IRLocal):
            return True
        if isinstance(node, IRConst):
            # Loaded by the caller, or differently by other copies: an argument.
            ops = node.src_op_idxs
            return bool(ops & varying) or bool(ops) and not ops <= body_ops
        return not has_body(node)

    params: List[IRExpression] = []
    param_types: List[Type] = []
    by_local: Dict[Tuple[str, Optional[int]], int] = {}

    def parameter(node: IRExpression, slot: Optional[Type]) -> Optional[IRLocal]:
        key = (node.name, node.reg_idx) if isinstance(node, IRLocal) else None
        index = by_local.get(key) if key is not None else None
        if index is None:
            index = len(params)
            params.append(node)
            # An untyped `null` takes the type of the argument it is passed as.
            typ = node.get_type()
            if isinstance(node, IRConst) and node.const_type == IRConst.ConstType.NULL and slot is not None:
                typ = slot
            param_types.append(typ)
            if key is not None:
                by_local[key] = index
        typ = param_types[index]
        if id(typ) not in type_index:
            return None
        return IRLocal(f"v{index}", tIndex(type_index[id(typ)]), code, reg_idx=index)

    def build(node: Any, slot: Optional[Type] = None) -> Optional[Any]:
        if isinstance(node, IRBlock) or not isinstance(node, IRStatement):
            return None
        if node is not root and isinstance(node, IRExpression) and is_parameter(node):
            return parameter(node, slot)
        copied = copy.copy(node)
        copied.src_op_idxs = set(node.src_op_idxs)
        slots = _argument_types(code, node)
        for attr, value in vars(node).items():
            if attr == "code":
                continue
            if isinstance(value, IRStatement):
                built = build(value)
                if built is None:
                    return None
                setattr(copied, attr, built)
            elif isinstance(value, list) and any(isinstance(v, IRStatement) for v in value):
                items = [
                    build(v, slots[i] if attr == "args" and i < len(slots) else None)
                    if isinstance(v, IRStatement)
                    else v
                    for i, v in enumerate(value)
                ]
                if any(item is None for item in items):
                    return None
                setattr(copied, attr, items)
        return copied

    expression = build(root)
    if not isinstance(expression, IRExpression) or not _has_operation(expression):
        # A lone constant is an `inline var`; a bare field chain is a receiver
        # another copy reads through, not a function.
        return None
    template = InlineTemplate(
        function=None,
        owner=owner,
        name=name,
        instance=False,
        param_types=param_types,
        param_regs={i: i for i in range(len(params))},
        expression=expression,
        statements=[],
        span=None,
    )
    if not _scan_body(template, expression) or set(template.uses) != set(range(len(params))):
        return None
    template.weight += sum(n - 1 for n in template.uses.values())
    return template if template.weight > 0 else None


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
    if isinstance(node, IRConst):
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
        #: In evaluation order: the index of each effectful argument, and -1 for
        #: each effect of the body itself.
        self.events: List[int] = []

    def node(self, p: Any, t: Any) -> bool:
        if isinstance(p, IRLocal):
            return self._bind(self.template.param_regs[p.reg_idx], t)
        if not self._node(p, t):
            return False
        # Operands evaluate before the operation (children are matched in
        # evaluation order), so this records when the body's own effect happens.
        if isinstance(p, IRAssign) or (isinstance(p, IRExpression) and _node_effects(p)):
            self.events.append(-1)
        return True

    def _node(self, p: Any, t: Any) -> bool:
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
        if _effectful(t):
            self.events.append(index)
        return True

    def valid(self) -> bool:
        """The call evaluates each argument once, in parameter order, before the
        body; the copy evaluated them where the body reads them. The two agree
        when the effectful arguments are read once each, in parameter order,
        before any effect of the body."""
        last = -1
        for event in self.events:
            if event < 0:
                last = len(self.template.param_types)
            elif event < last or self.template.uses[event] > 1:
                return False
            else:
                last = event
        return True


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
            if template.findex() == self.own or i + n > len(stmts):
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
            if template.findex() == self.own:
                continue
            match = _Match(self.func.code, template)
            if match.node(template.expression, expr) and self._accept(match, [expr]):
                call = self._call(match)
                call.adopt(expr)
                # Arguments can hold further copies.
                self._rewrite_children(call)
                if isinstance(call, IRCall) and isinstance(call.target, IRField):
                    call.target.target = self._rewrite(call.target.target)
                return call
        self._rewrite_children(expr)
        return expr

    def _accept(self, match: _Match, nodes: List[IRStatement]) -> bool:
        if not match.valid():
            return False
        # A rebuilt body is only known from the copies positions found.
        if match.template.function is not None and match.template.weight >= MIN_UNCONFIRMED_WEIGHT:
            return True
        return self._positioned(match, nodes)

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

    def _call(self, match: _Match) -> IRExpression:
        template = match.template
        code = self.func.code
        args = [match.env[i] for i in range(len(template.param_types))]
        fun = template.function
        if fun is None:
            assert template.expression is not None
            owner = destaticify(template.owner.name.resolve(code))
            return IRInlineCall(code, owner, template.name, args, template.expression.get_type())
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
