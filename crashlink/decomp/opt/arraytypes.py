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
    IRCall,
    IRConst,
    IRCast,
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
        e = _strip_cast(elem)
        try:
            t = e.get_type()
        except Exception:
            return None
        name = _array_type_name(t, code)
        if name in _ERASED_ARRAY_TYPES or name in ("Dyn", "Dynamic", "Void", "Null"):
            return None
        if et is None:
            et = t
        elif _array_type_name(et, code) != name:
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
    field_elem_types: Dict[str, Type],
    local_elem_types: Dict[int, Type],
    global_cache: Dict[Tuple[str, str], Type],
) -> None:
    if id(block) in visited:
        return
    visited.add(id(block))
    for stmt in block.statements:
        _walk_statement(stmt, code, visited, field_elem_types, local_elem_types, global_cache)


def _record_array_source(
    expr: IRExpression,
    elem_type: Optional[Type],
    code: Bytecode,
    field_elem_types: Dict[str, Type],
    local_elem_types: Dict[int, Type],
    global_cache: Dict[Tuple[str, str], Type],
) -> None:
    """Record elem_type for the array that `expr` denotes (an IRLocal or IRField)."""
    if elem_type is None:
        return
    if isinstance(expr, IRLocal):
        if _is_erased_array(expr, code):
            local_elem_types[id(expr)] = elem_type
            if expr.array_elem_type is None:
                expr.array_elem_type = elem_type
    elif isinstance(expr, IRField) and isinstance(expr.target, IRLocal):
        try:
            arr_type = expr.get_type()
        except Exception:
            return
        if _array_type_name(arr_type, code) in _ERASED_ARRAY_TYPES:
            field_elem_types[expr.field_name] = elem_type
            # Also store in the global cache keyed by (class_name, field_name)
            # so a referenced class rendered later can pick up the type.
            cls = _class_name_of(expr.target, code)
            if cls is not None:
                global_cache[(cls, expr.field_name)] = elem_type


def _walk_statement(
    stmt: IRStatement,
    code: Bytecode,
    visited: Set[int],
    field_elem_types: Dict[str, Type],
    local_elem_types: Dict[int, Type],
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
            _record_array_source(access.array, elem_type, code, field_elem_types, local_elem_types, global_cache)
        # Element write: `arr[i] = v` — v's type is the element type.
        if isinstance(stmt.target, IRArrayAccess):
            access = stmt.target
            val = _strip_cast(stmt.expr)
            try:
                value_type = val.get_type()
            except Exception:
                value_type = None
            _record_array_source(access.array, value_type, code, field_elem_types, local_elem_types, global_cache)
        # Array literal assigned to a local: recover elem type from elements.
        if isinstance(stmt.target, IRLocal) and isinstance(stmt.expr, IRArrayLiteral):
            if _is_erased_array(stmt.target, code):
                lit = stmt.expr
                if lit.recovered_elem_type is not None:
                    local_elem_types[id(stmt.target)] = lit.recovered_elem_type
                    if stmt.target.array_elem_type is None:
                        stmt.target.array_elem_type = lit.recovered_elem_type
                elif lit.elements:
                    # Only infer when ALL elements share the same non-erased
                    # type — a mixed literal like [1, "two", 3.0] is
                    # genuinely Array<Dynamic>, not Array<first_element_type>.
                    et = _uniform_element_type(lit.elements, code)
                    if et is not None:
                        local_elem_types[id(stmt.target)] = et
                        if stmt.target.array_elem_type is None:
                            stmt.target.array_elem_type = et
    for child in stmt.get_children():
        if isinstance(child, IRBlock):
            _walk_block(child, code, visited, field_elem_types, local_elem_types, global_cache)


def _propagate_field_to_params(
    block: IRBlock,
    code: Bytecode,
    visited: Set[int],
    field_elem_types: Dict[str, Type],
) -> None:
    if id(block) in visited:
        return
    visited.add(id(block))
    for stmt in block.statements:
        if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRField):
            if stmt.target.field_name in field_elem_types:
                elem_type = field_elem_types[stmt.target.field_name]
                src = stmt.expr
                if isinstance(src, IRLocal) and _is_erased_array(src, code):
                    if src.array_elem_type is None:
                        src.array_elem_type = elem_type
        for child in stmt.get_children():
            if isinstance(child, IRBlock):
                _propagate_field_to_params(child, code, visited, field_elem_types)


def _propagate_local_copies(
    block: IRBlock,
    code: Bytecode,
    visited: Set[int],
    local_elem_types: Dict[int, Type],
) -> None:
    if id(block) in visited:
        return
    visited.add(id(block))
    for stmt in block.statements:
        if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal) and isinstance(stmt.expr, IRLocal):
            tgt, src = stmt.target, stmt.expr
            if _is_erased_array(tgt, code) and _is_erased_array(src, code):
                et = local_elem_types.get(id(src)) or src.array_elem_type
                if et is not None and tgt.array_elem_type is None:
                    tgt.array_elem_type = et
                    local_elem_types[id(tgt)] = et
                et2 = local_elem_types.get(id(tgt)) or tgt.array_elem_type
                if et2 is not None and src.array_elem_type is None:
                    src.array_elem_type = et2
                    local_elem_types[id(src)] = et2
        for child in stmt.get_children():
            if isinstance(child, IRBlock):
                _propagate_local_copies(child, code, visited, local_elem_types)


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
            # Reverse: callee param has elem type → propagate to arg's field.
            if i < len(callee.locals):
                param_local = callee.locals[i]
                if param_local.array_elem_type is not None and isinstance(arg, IRField):
                    cls = _class_name_of(arg.target, code)
                    if cls is not None:
                        key = (cls, arg.field_name)
                        if key not in global_cache:
                            global_cache[key] = param_local.array_elem_type
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


def recover_array_element_types(ir_class: "IRClass") -> None:
    """Recover Array<T> element types for fields, params, and locals of an IRClass."""
    code = ir_class.code
    field_elem_types: Dict[str, Type] = {}
    local_elem_types: Dict[int, Type] = {}

    if not hasattr(code, "_global_field_elem_types"):
        code._global_field_elem_types = {}  # type: ignore[attr-defined]
    global_cache: Dict[Tuple[str, str], Type] = code._global_field_elem_types  # type: ignore[attr-defined]

    # Seed from the global cache: fields recovered by other classes.
    primary_obj = ir_class.dynamic if ir_class.dynamic else ir_class.static
    class_name = primary_obj.name.resolve(code) if primary_obj else None
    if class_name is not None:
        for (cn, fname), etype in global_cache.items():
            if cn == class_name:
                field_elem_types[fname] = etype

    methods = ir_class.static_methods + ir_class.methods
    for ir_func in methods:
        if not hasattr(ir_func, "block"):
            continue
        visited: Set[int] = set()
        _walk_block(ir_func.block, code, visited, field_elem_types, local_elem_types, global_cache)

    if field_elem_types:
        for ir_func in methods:
            if not hasattr(ir_func, "block"):
                continue
            vis: Set[int] = set()
            _propagate_field_to_params(ir_func.block, code, vis, field_elem_types)
        for ir_func in methods:
            if not hasattr(ir_func, "block"):
                continue
            vis = set()
            _propagate_local_copies(ir_func.block, code, vis, local_elem_types)

    if local_elem_types and not field_elem_types:
        for ir_func in methods:
            if not hasattr(ir_func, "block"):
                continue
            vis = set()
            _propagate_local_copies(ir_func.block, code, vis, local_elem_types)

    name_to_irfunc: Dict[str, "IRFunction"] = {}
    findex_to_irfunc: Dict[int, "IRFunction"] = {}
    for ir_func in methods:
        fname = code.partial_func_name(ir_func.func)
        if fname:
            name_to_irfunc[fname] = ir_func
        findex_to_irfunc[ir_func.func.findex.value] = ir_func

    for ir_func in methods:
        if not hasattr(ir_func, "block"):
            continue
        vis = set()
        _propagate_call_sites(ir_func.block, code, vis, name_to_irfunc, findex_to_irfunc, global_cache)

    # Seed the global cache from this class's own recovered fields.
    if class_name is not None:
        for fname, etype in field_elem_types.items():
            global_cache[(class_name, fname)] = etype

    ir_class.field_elem_types = field_elem_types  # type: ignore[attr-defined]
