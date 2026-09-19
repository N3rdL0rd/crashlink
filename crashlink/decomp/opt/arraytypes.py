"""
Recover erased Array<T> element types from usage.

HashLink types every object array as hl.types.ArrayObj / ArrayDyn, so the
bytecode carries no element-type info and decompiled declarations render
Array<Dynamic>. This recovers the element type from how the array is *used*
(element reads, element stores, array-literal allocation), propagates it
through field<->parameter assignments and call sites, and applies it to
local/param/field declarations so the recompiled source produces a typed
array (ArrayObj) instead of ArrayDyn.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from ..function import IRClass, IRFunction

from ...core import Bytecode, Function, Obj, Type
from ..ir import (
    IRBlock,
    IRStatement,
    IRExpression,
    IRLocal,
    IRAssign,
    IRField,
    IRArrayAccess,
    IRArrayLiteral,
    IRNativeArrayNew,
    _get_type_in_code,
    IRCall,
    IRConst,
    IRCast,
    IRRef,
    IRRefNew,
)

# Type names that represent element-type-erased object arrays.
_ERASED_ARRAY_TYPES = {"hl.types.ArrayObj", "hl.types.ArrayDyn"}


def _array_type_name(typ: Type, code: Bytecode) -> Optional[str]:
    defn = typ.definition
    if isinstance(defn, Obj) and hasattr(defn, "name"):
        return defn.name.resolve(code)
    return None


def _is_erased_array(expr: IRExpression, code: Bytecode) -> bool:
    try:
        return _array_type_name(expr.get_type(), code) in _ERASED_ARRAY_TYPES
    except Exception:
        return False


def _strip_cast(expr: IRExpression) -> IRExpression:
    while isinstance(expr, IRCast):
        expr = expr.expr
    return expr


def _uniform_element_type(elements: List[IRExpression], code: Bytecode) -> Optional[Type]:
    """Return the shared element type if all elements have the same non-erased
    type, else None (mixed literals are genuinely Array<Dynamic>)."""
    et: Optional[Type] = None
    for elem in elements:
        try:
            t = elem.get_type()
        except Exception:
            return None
        name = _array_type_name(t, code)
        if name in _ERASED_ARRAY_TYPES or t.kind.value in (
            Type.Kind.DYN.value,
            Type.Kind.VOID.value,
            Type.Kind.NULL.value,
        ):
            return None
        if et is None:
            et = t
        elif et != t:
            return None
    return et


def _class_name_of(expr: IRExpression, code: Bytecode) -> Optional[str]:
    """Return the Haxe class name of `expr`'s type, if it's an Obj."""
    try:
        typ = expr.get_type()
        defn = typ.definition
        if isinstance(defn, Obj) and hasattr(defn, "name"):
            return defn.name.resolve(code)
    except Exception:
        pass
    return None


def _walk_block(
    block: IRBlock,
    code: Bytecode,
    visited: Set[int],
    global_cache: Dict[Tuple[str, str], Type],
) -> None:
    if id(block) in visited:
        return
    visited.add(id(block))
    for stmt in block.statements:
        _walk_statement(stmt, code, visited, global_cache)


def _record_array_source(
    expr: IRExpression,
    elem_type: Optional[Type],
    code: Bytecode,
    global_cache: Dict[Tuple[str, str], Type],
) -> None:
    """Record elem_type for the array that `expr` denotes (an IRLocal or IRField)."""
    if elem_type is None:
        return
    if isinstance(expr, IRLocal):
        if _is_erased_array(expr, code):
            if expr.array_elem_type is None:
                expr.array_elem_type = elem_type
    elif isinstance(expr, IRField):
        try:
            arr_type = expr.get_type()
        except Exception:
            return
        if _array_type_name(arr_type, code) in _ERASED_ARRAY_TYPES:
            # A referenced class rendered later can pick up this field type.
            cls = _class_name_of(expr.target, code)
            if cls is not None:
                global_cache[(cls, expr.field_name)] = elem_type


def _walk_statement(
    stmt: IRStatement,
    code: Bytecode,
    visited: Set[int],
    global_cache: Dict[Tuple[str, str], Type],
) -> None:
    if isinstance(stmt, IRAssign):
        # Element read: `x = arr[i]` — the access's type is the element type.
        if isinstance(stmt.expr, IRArrayAccess):
            access = stmt.expr
            try:
                elem_type = access.get_type()
            except Exception:
                elem_type = None
            _record_array_source(access.array, elem_type, code, global_cache)
        # Element write: `arr[i] = v` — v's type is the element type.
        if isinstance(stmt.target, IRArrayAccess):
            access = stmt.target
            val = _strip_cast(stmt.expr)
            try:
                value_type = val.get_type()
            except Exception:
                value_type = None
            _record_array_source(access.array, value_type, code, global_cache)
        # Array literal assigned to a local or field: recover elem type from
        # the allocation site's own type (e.g. `[]`'s alloc_array(Joint, 0))
        # or, failing that, from the literal's elements.
        if isinstance(stmt.target, (IRLocal, IRField)) and isinstance(stmt.expr, IRArrayLiteral):
            if _is_erased_array(stmt.target, code):
                lit = stmt.expr
                if lit.recovered_elem_type is not None:
                    _record_array_source(
                        stmt.target,
                        lit.recovered_elem_type,
                        code,
                        global_cache,
                    )
                elif lit.elements:
                    # Only infer when ALL elements share the same non-erased
                    # type — a mixed literal like [1, "two", 3.0] is
                    # genuinely Array<Dynamic>, not Array<first_element_type>.
                    et = _uniform_element_type(lit.elements, code)
                    if et is not None:
                        _record_array_source(stmt.target, et, code, global_cache)
    for child in stmt.get_children():
        if isinstance(child, IRBlock):
            _walk_block(child, code, visited, global_cache)


def _array_element_type(
    expr: IRExpression, code: Bytecode, global_cache: Dict[Tuple[str, str], Type]
) -> Optional[Type]:
    expr = _strip_cast(expr)
    if isinstance(expr, IRLocal):
        return expr.array_elem_type
    if isinstance(expr, IRField):
        cls = _class_name_of(expr.target, code)
        if cls is not None:
            return global_cache.get((cls, expr.field_name))
    return None


def _propagate_array_assignments(
    block: IRBlock,
    code: Bytecode,
    visited: Set[int],
    global_cache: Dict[Tuple[str, str], Type],
) -> None:
    """Array copies constrain both ends, including reads and writes of fields.

    Keep field identities class-qualified: a method can access arrays on
    several unrelated classes, and static owners retain their `$` prefix.
    """
    if id(block) in visited:
        return
    visited.add(id(block))
    for stmt in block.statements:
        if isinstance(stmt, IRAssign):
            tgt, src = _strip_cast(stmt.target), _strip_cast(stmt.expr)
            if _is_erased_array(tgt, code) and _is_erased_array(src, code):
                src_elem = _array_element_type(src, code, global_cache)
                tgt_elem = _array_element_type(tgt, code, global_cache)
                if src_elem is not None and tgt_elem is None:
                    _record_array_source(tgt, src_elem, code, global_cache)
                elif tgt_elem is not None and src_elem is None:
                    _record_array_source(src, tgt_elem, code, global_cache)
        for child in stmt.get_children():
            if isinstance(child, IRBlock):
                _propagate_array_assignments(child, code, visited, global_cache)


def _is_instance_method(ir_func: "IRFunction") -> bool:
    if not ir_func.locals:
        return False
    return ir_func.locals[0].name == "this"


def _propagate_call_sites(
    block: IRBlock,
    code: Bytecode,
    visited: Set[int],
    name_to_irfunc: Dict[str, "IRFunction"],
    findex_to_irfunc: Dict[int, "IRFunction"],
    global_cache: Dict[Tuple[str, str], Type],
) -> None:
    if id(block) in visited:
        return
    visited.add(id(block))
    for stmt in block.statements:
        _propagate_calls_in_stmt(stmt, code, visited, name_to_irfunc, findex_to_irfunc, global_cache)


def _propagate_calls_in_stmt(
    stmt: IRStatement,
    code: Bytecode,
    visited: Set[int],
    name_to_irfunc: Dict[str, "IRFunction"],
    findex_to_irfunc: Dict[int, "IRFunction"],
    global_cache: Dict[Tuple[str, str], Type],
) -> None:
    for expr in _collect_calls(stmt):
        callee: Optional["IRFunction"] = None
        skip_args = 0
        if expr.call_type == IRCall.CallType.FUNC and isinstance(expr.target, IRConst):
            val = expr.target.value
            if isinstance(val, Function):
                callee = findex_to_irfunc.get(val.findex.value)
        elif expr.call_type == IRCall.CallType.METHOD and isinstance(expr.target, IRField):
            callee = name_to_irfunc.get(expr.target.field_name)
            skip_args = 1  # args[0] is the receiver
        if callee is None:
            continue
        is_instance = _is_instance_method(callee)
        # For FUNC calls to instance methods, args[0] is the receiver too
        # (CallThis/CallMethod lower to FUNC with the receiver as first arg).
        if is_instance and expr.call_type == IRCall.CallType.FUNC:
            skip_args = 1
        start_arg = 1 if is_instance else 0
        for i, arg in enumerate(expr.args[skip_args:], start=start_arg):
            # Forward: arg has elem type → set callee param.
            arg_elem: Optional[Type] = None
            if isinstance(arg, IRLocal) and arg.array_elem_type is not None:
                arg_elem = arg.array_elem_type
            elif isinstance(arg, IRField):
                # Field argument: look up the recovered elem type from the
                # global cache (e.g. `p1.joints` → Permut.joints → Joint).
                cls = _class_name_of(arg.target, code)
                if cls is not None:
                    arg_elem = global_cache.get((cls, arg.field_name))
            if arg_elem is not None and i < len(callee.locals):
                param_local = callee.locals[i]
                if param_local.array_elem_type is None and _is_erased_array(param_local, code):
                    param_local.array_elem_type = arg_elem
            # Reverse: the parameter also constrains local and field arguments.
            if i < len(callee.locals):
                param_local = callee.locals[i]
                if param_local.array_elem_type is not None and _is_erased_array(arg, code):
                    if isinstance(arg, IRLocal) and arg.array_elem_type is None:
                        arg.array_elem_type = param_local.array_elem_type
                    elif isinstance(arg, IRField):
                        cls = _class_name_of(arg.target, code)
                        if cls is not None:
                            global_cache.setdefault((cls, arg.field_name), param_local.array_elem_type)
    for child in stmt.get_children():
        if isinstance(child, IRBlock):
            _propagate_call_sites(child, code, visited, name_to_irfunc, findex_to_irfunc, global_cache)


def _collect_calls(stmt: IRStatement) -> List[IRCall]:
    calls: List[IRCall] = []
    if isinstance(stmt, IRAssign) and isinstance(stmt.expr, IRExpression):
        _collect_calls_expr(stmt.expr, calls)
    elif isinstance(stmt, IRCall):
        _collect_calls_expr(stmt, calls)
    return calls


def _collect_calls_expr(expr: IRExpression, calls: List[IRCall]) -> None:
    if isinstance(expr, IRCall):
        calls.append(expr)
    for child in expr.get_children():
        if isinstance(child, IRExpression):
            _collect_calls_expr(child, calls)


def _recover_native_local_types(ir_func: "IRFunction", code: Bytecode) -> None:
    """A register declaration must cover every native-array value assigned to it.

    Allocation metadata belongs to the expression, not a reused register. A
    backing-field read has erased element type; mixing it with a typed alloc
    must not leave the allocation's narrower type on the shared declaration.
    """
    evidence: Dict[int, Optional[Type]] = {}
    targets: Dict[int, IRLocal] = {}
    pending: List[IRStatement] = [ir_func.block]
    visited: Set[int] = set()
    while pending:
        stmt = pending.pop()
        if id(stmt) in visited:
            continue
        visited.add(id(stmt))
        if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal):
            local = stmt.target
            if local.get_type().kind.value == Type.Kind.ARRAY.value:
                key = id(local)
                elem_type = stmt.expr.elem_type if isinstance(stmt.expr, IRNativeArrayNew) else None
                if key not in evidence:
                    evidence[key] = elem_type
                elif evidence[key] != elem_type:
                    evidence[key] = None
                targets[key] = local
        pending.extend(stmt.get_children())
    for key, local in targets.items():
        local.native_elem_type = evidence[key] or _get_type_in_code(code, "Dyn")


def _is_arrayobj_alloc(expr: IRExpression, code: Bytecode) -> bool:
    """Recognize the exact factory that installs and sizes its backing array.

    A source filename or erased return type alone also matches constructors
    and unrelated ArrayObj helpers; neither is evidence of element forwarding.
    """
    if not isinstance(expr, IRCall) or expr.call_type != IRCall.CallType.FUNC or len(expr.args) != 1:
        return False
    if not isinstance(expr.target, IRConst) or not isinstance(expr.target.value, Function):
        return False
    func = expr.target.value
    try:
        if not func.resolve_file(code).replace("\\", "/").endswith("hl/types/ArrayObj.hx"):
            return False
        sig = func.resolve_fun(code)
        ret = sig.ret.resolve(code)
        if (
            len(sig.args) != 1
            or sig.args[0].resolve(code).kind.value != Type.Kind.ARRAY.value
            or _array_type_name(ret, code) != "hl.types.ArrayObj"
        ):
            return False
        ops = func.ops
        if [op.op for op in ops] != ["New", "SetField", "ArraySize", "SetField", "Ret"]:
            return False
        obj = ops[0].df["dst"].value
        size = ops[2].df["dst"].value
        fields = ret.definition.resolve_fields(code)
        backing = fields[ops[1].df["field"].value]
        length = fields[ops[3].df["field"].value]
        return (
            obj != 0
            and size not in (0, obj)
            and func.regs[obj].resolve(code) == ret
            and ops[1].df["obj"].value == obj
            and ops[1].df["src"].value == 0
            and backing.name.resolve(code) == "array"
            and backing.type.resolve(code).kind.value == Type.Kind.ARRAY.value
            and ops[2].df["array"].value == 0
            and ops[3].df["obj"].value == obj
            and ops[3].df["src"].value == size
            and length.name.resolve(code) == "length"
            and length.type.resolve(code).kind.value == Type.Kind.I32.value
            and ops[4].df["ret"].value == obj
        )
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        return False


def _recover_wrapper_element_types(
    block: IRBlock, code: Bytecode, global_cache: Dict[Tuple[str, str], Type]
) -> None:
    """Forward allocation-site evidence, not a reused backing local's type.

    Definitions are snapshots of the value at each assignment. Control-flow
    boundaries discard them rather than guessing a reaching branch/iteration.
    A public array declaration is narrowed only when every assignment agrees.
    """
    evidence: Dict[IRLocal, Optional[Type]] = {}
    fields: Dict[Tuple[str, str], Optional[Type]] = {}
    visited: Set[int] = set()
    candidates: Set[IRLocal] = set()
    field_candidates: Set[Tuple[str, str]] = set()
    referenced: Set[IRLocal] = set()
    pending: List[IRStatement] = [block]
    seen: Set[int] = set()
    while pending:
        node = pending.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, (IRRef, IRRefNew)) and isinstance(node.target, IRLocal):
            referenced.add(node.target)
        pending.extend(node.get_children())

    def walk(current: IRBlock) -> None:
        if id(current) in visited:
            return
        visited.add(id(current))
        definitions: Dict[IRLocal, Type] = {}
        for stmt in current.statements:
            if isinstance(stmt, IRAssign):
                source = stmt.expr
                elem_type = None
                wrapper = _is_arrayobj_alloc(source, code)
                allocation = isinstance(source, IRArrayLiteral) or wrapper
                if isinstance(source, IRCall) and wrapper:
                    arg = source.args[0]
                    if isinstance(arg, IRNativeArrayNew):
                        elem_type = arg.elem_type
                    elif isinstance(arg, IRLocal):
                        elem_type = definitions.get(arg)
                elif isinstance(source, IRArrayLiteral):
                    elem_type = source.recovered_elem_type or _uniform_element_type(source.elements, code)
                if isinstance(stmt.target, IRLocal):
                    local = stmt.target
                    if _is_erased_array(local, code):
                        if allocation:
                            candidates.add(local)
                        if local not in evidence:
                            evidence[local] = elem_type
                        elif evidence[local] != elem_type:
                            evidence[local] = None
                    # Kill aliases of the VM register as well as this IR name.
                    native_type = None
                    if isinstance(source, IRNativeArrayNew):
                        native_type = source.elem_type
                    elif isinstance(source, IRLocal):
                        native_type = definitions.get(source)
                    for previous in list(definitions):
                        if previous == local or previous.same_register(local):
                            del definitions[previous]
                    if native_type is not None and not any(
                        ref == local or ref.same_register(local) for ref in referenced
                    ):
                        definitions[local] = native_type
                elif isinstance(stmt.target, IRField) and _is_erased_array(stmt.target, code):
                    owner = _class_name_of(stmt.target.target, code)
                    if owner is not None:
                        key = (owner, stmt.target.field_name)
                        if allocation:
                            field_candidates.add(key)
                        if key not in fields:
                            fields[key] = elem_type
                        elif fields[key] != elem_type:
                            fields[key] = None
            children = [child for child in stmt.get_children() if isinstance(child, IRBlock)]
            if children:
                definitions.clear()
                for child in children:
                    walk(child)

    walk(block)
    for local in candidates:
        # Unknown or conflicting reaching values are a Dynamic constraint,
        # not missing evidence that a later propagation pass may narrow.
        local.array_elem_type = evidence[local] or _get_type_in_code(code, "Dyn")
    for key in field_candidates:
        elem_type = fields[key] or _get_type_in_code(code, "Dyn")
        previous = global_cache.get(key)
        global_cache[key] = elem_type if previous in (None, elem_type) else _get_type_in_code(code, "Dyn")


def recover_array_element_types(ir_class: "IRClass") -> None:
    """Recover Array<T> element types for fields, params, and locals of an IRClass."""
    code = ir_class.code

    global_cache: Dict[Tuple[str, str], Type] = code._global_field_elem_types

    methods = ir_class.static_methods + ir_class.methods
    for ir_func in methods:
        if not hasattr(ir_func, "block"):
            continue
        visited: Set[int] = set()
        _walk_block(ir_func.block, code, visited, global_cache)
        _recover_wrapper_element_types(ir_func.block, code, global_cache)

    name_to_irfunc: Dict[str, "IRFunction"] = {}
    findex_to_irfunc: Dict[int, "IRFunction"] = {}
    for ir_func in methods:
        fname = code.partial_func_name(ir_func.func)
        if fname:
            name_to_irfunc[fname] = ir_func
        findex_to_irfunc[ir_func.func.findex.value] = ir_func

    for ir_func in methods:
        if hasattr(ir_func, "block"):
            _recover_native_local_types(ir_func, code)

    # Field copies and calls form chains across methods. Iterate to a fixed
    # point so declaration types do not depend on the method traversal order.
    previous_count = -1
    while True:
        recovered_count = len(global_cache) + sum(
            local.array_elem_type is not None for ir_func in methods for local in ir_func.locals
        )
        if recovered_count == previous_count:
            break
        previous_count = recovered_count
        for ir_func in methods:
            if not hasattr(ir_func, "block"):
                continue
            _propagate_array_assignments(ir_func.block, code, set(), global_cache)
            _propagate_call_sites(ir_func.block, code, set(), name_to_irfunc, findex_to_irfunc, global_cache)

    # Only publish fields belonging to this class; foreign fields stay in the
    # class-qualified cache for their own declarations to consume later.
    owners = {obj.name.resolve(code) for obj in (ir_class.dynamic, ir_class.static) if obj is not None}
    ir_class.field_elem_types = {
        fname: etype for (owner, fname), etype in global_cache.items() if owner in owners
    }
