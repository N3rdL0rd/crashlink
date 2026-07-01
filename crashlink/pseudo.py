"""
Pseudocode generation routines to create a Haxe representation of the decompiled IR.
"""

from __future__ import annotations

import re
import weakref
from abc import ABC, abstractmethod
from typing import Optional, List, Set, Dict, Tuple, Union, cast, Any

from .core import Bytecode, Obj, Ref, Type, Function, Fun, Native, Enum, destaticify, gIndex
from . import disasm
from .decomp import (
    IRBreak,
    IRContinue,
    IRCast,
    IRNativeStub,
    IRClass,
    IRField,
    IRFunction,
    IRBlock,
    IRNew,
    IRStatement,
    IRExpression,
    IRAssign,
    IRLocal,
    IRConst,
    IRArithmetic,
    IRNeg,
    IRNot,
    IRTypeOf,
    IRTypeKind,
    IRBoolExpr,
    IRCall,
    IRConditional,
    IRTrace,
    IRTryCatch,
    IRUnliftedOpcode,
    IRArrayAccess,
    IRRef,
    IRArrayLiteral,
    IRObjectLiteral,
    IREnumConstruct,
    IREnumIndex,
    IREnumField,
    IRWhileLoop,
    IRForEachLoop,
    IRIntRangeLoop,
    IRNativeArrayNew,
    IRNativeMapNew,
    IRPrimitiveLoop,
    IRReturn,
    IRThrow,
    IRPrimitiveJump,
    IRSwitch,
    _get_type_in_code,
)


def _indent_str(level: int) -> str:
    return "    " * level  # 4 spaces for indentation


class _PseudoClass:
    """Lightweight stand-in for IRClass when pseudo() is called on a bare IRFunction."""

    __slots__ = ("dynamic", "static", "methods")

    def __init__(self, obj: Obj, methods: List[IRFunction]):
        # Bindings (e.g. a __constructor__ wrapper) are registered against the
        # *static* companion class, not the dynamic/instance one — if `obj`
        # is static, route it to its real dynamic counterpart so the actual
        # class hierarchy (super chain, instance fields) is visible.
        self.static: Optional[Obj] = None
        if obj.is_static and obj.dynamic is not None:
            self.dynamic = obj.dynamic
            self.static = obj
        else:
            self.dynamic = obj
        self.methods = methods


# Keyed by id(code), but the value carries a weakref back to `code` so a lookup
# can confirm the cached entry is still for *this* object. A plain id()-keyed
# dict without that check is a latent bug: once `code` is GC'd, a later,
# unrelated Bytecode can be allocated at the same address and silently get
# served someone else's stale registry. `Bytecode` (via Serialisable.__eq__)
# isn't hashable, so a WeakKeyDictionary keyed on `code` itself isn't an option.
_method_registry_cache: Dict[int, Tuple["weakref.ReferenceType[Bytecode]", Dict[int, Tuple[Obj, str, bool]]]] = {}


def _method_registry(code: Bytecode) -> Dict[int, Tuple[Obj, str, bool]]:
    """Map findex -> (class Obj, method name, is_instance) using Obj protos/bindings."""
    cache_key = id(code)
    cached = _method_registry_cache.get(cache_key)
    if cached is not None and cached[0]() is code:
        return cached[1]
    registry: Dict[int, Tuple[Obj, str, bool]] = {}
    for t in code.types:
        if t.kind.value != Type.Kind.OBJ.value:
            continue
        obj = t.definition
        if not isinstance(obj, Obj):
            continue
        for proto in obj.protos:
            fn = proto.findex.resolve(code)
            if isinstance(fn, Function):
                registry[fn.findex.value] = (obj, proto.name.resolve(code), True)
        for binding in obj.bindings:
            fn = binding.findex.resolve(code)
            if isinstance(fn, Function):
                field = binding.field.resolve_obj(code, obj)
                registry[fn.findex.value] = (obj, field.name.resolve(code), False)
    _method_registry_cache[cache_key] = (weakref.ref(code), registry)
    return registry


def _containing_class_for(ir_func: IRFunction, code: Bytecode) -> Optional[_PseudoClass]:
    """Return a lightweight containing class for instance methods, or None."""
    info = _method_registry(code).get(ir_func.func.findex.value)
    if info is None:
        return None
    # Constructors are registered as bindings (is_instance=False in the
    # registry, since they aren't virtual/vtable methods), but they still
    # need their containing class attached — e.g. to detect a `super(...)`
    # delegation call to the parent's own constructor.
    if not info[2] and code.partial_func_name(ir_func.func) != "__constructor__":
        return None
    return _PseudoClass(info[0], [ir_func])


def _containing_class_name(ir_function: Optional[IRFunction], code: Bytecode) -> Optional[str]:
    """Return the de-staticified name of the class containing the current function."""
    if ir_function is None:
        return None
    containing = getattr(ir_function, "_containing_class", None)
    if not containing or not containing.dynamic:
        return None
    return destaticify(containing.dynamic.name.resolve(code))


def global_name(const: "IRConst") -> str:
    """Synthesized name for a raw HL global with no source-level name (see varN)."""
    assert isinstance(const.original_index, gIndex)
    return f"global{const.original_index.value}"


def _collect_assigned_names(stmts: List[IRStatement]) -> set[str]:
    names: set[str] = set()
    for s in stmts:
        if isinstance(s, IRAssign) and isinstance(s.target, IRLocal):
            names.add(s.target.name)
    return names


def _is_expression_switch(
    switch_stmt: IRSwitch,
) -> Optional[Tuple[IRLocal, Dict[IRConst, IRExpression], Optional[IRExpression]]]:
    """Detect `switch (v) { case X: target = eX; ... default: target = eD; }`."""
    target: Optional[IRLocal] = None
    cases: Dict[IRConst, IRExpression] = {}
    for val, block in switch_stmt.cases.items():
        if not isinstance(val, IRConst):
            return None
        if len(block.statements) != 1:
            return None
        s = block.statements[0]
        if not isinstance(s, IRAssign) or not isinstance(s.target, IRLocal):
            return None
        if target is None:
            target = s.target
        elif s.target.name != target.name:
            return None
        cases[val] = s.expr
    default_expr: Optional[IRExpression] = None
    if switch_stmt.default:
        if len(switch_stmt.default.statements) != 1:
            return None
        s = switch_stmt.default.statements[0]
        if not isinstance(s, IRAssign) or not isinstance(s.target, IRLocal):
            return None
        if target is None:
            target = s.target
        elif s.target.name != target.name:
            return None
        default_expr = s.expr
    if target is None:
        return None
    return target, cases, default_expr


# Haxe operator precedence (higher number = tighter binding).  Used to emit
# parentheses only where precedence would otherwise change the meaning.
_HAXE_OP_PRECEDENCE = {
    "||": 1,
    "&&": 2,
    "|": 3,
    "^": 4,
    "&": 5,
    "==": 6,
    "!=": 6,
    "<": 6,
    "<=": 6,
    ">": 6,
    ">=": 6,
    "<<": 7,
    ">>": 7,
    ">>>": 7,
    "+": 8,
    "-": 8,
    "*": 9,
    "/": 9,
    "%": 9,
}


def _expr_to_haxe_with_precedence(
    expr: Optional[IRExpression], code: Bytecode, ir_function: Optional[IRFunction], parent_op: str
) -> str:
    """Render an expression, wrapping it in parentheses if its operator is
    lower-precedence than the parent's and would otherwise bind incorrectly."""
    rendered = _expression_to_haxe(expr, code, ir_function)
    if isinstance(expr, IRArithmetic):
        child_prec = _HAXE_OP_PRECEDENCE.get(expr.op.value, 10)
        parent_prec = _HAXE_OP_PRECEDENCE.get(parent_op, 10)
        if child_prec < parent_prec:
            return f"({rendered})"
    elif isinstance(expr, IRBoolExpr) and expr.op in (IRBoolExpr.CompareType.OR, IRBoolExpr.CompareType.AND):
        child_sym = "||" if expr.op == IRBoolExpr.CompareType.OR else "&&"
        child_prec = _HAXE_OP_PRECEDENCE.get(child_sym, 10)
        parent_prec = _HAXE_OP_PRECEDENCE.get(parent_op, 10)
        if child_prec < parent_prec:
            return f"({rendered})"
    return rendered


def _is_untyped_array_access_class(typ: "Type", code: Bytecode) -> bool:
    """True if `typ` is hl.types.ArrayBase/ArrayAccess — the type-erased base
    classes that back every concrete typed array (ArrayBytes_T, ArrayObj,
    ArrayDyn) but, unlike them, define no `@:arrayAccess` of their own."""
    name = disasm.type_name(code, typ)
    return name in ("hl.types.ArrayBase", "hl.types.ArrayAccess")


def _resolve_array_access(
    expr: "IRArrayAccess", code: Bytecode, ir_function: Optional[IRFunction]
) -> Tuple[str, str, Optional[str]]:
    """Return (array_str, index_str, method_kind) for rendering an IRArrayAccess.

    method_kind is None when ordinary `array[index]` bracket syntax is valid
    (a typed-array wrapper's own `@:arrayAccess`, or hl.Bytes's only actual
    bracket overload, the 1-byte `getUI8`/`setUI8`). Otherwise it's the
    hl.Bytes accessor suffix ("UI16", "I32", "F32", "F64") the caller must
    render as an explicit `.getX(...)`/`.setX(..., ...)` call instead, since
    hl.Bytes has no `@:arrayAccess` overload for those widths.
    """
    if isinstance(expr.array, IRLocal):
        arr_str = expr.array.name
    else:
        arr_str = _expression_to_haxe(expr.array, code, ir_function)
    idx_str = _expression_to_haxe(expr.index, code, ir_function)
    # HashLink stores array data in a `.bytes` field and indexes by element
    # size. `this.bytes` inside an ArrayBytes impl indexes the BytesAccess<T>
    # backing buffer directly, so keep `.bytes[idx]`. A user-facing array local
    # only exposes its own bracket operator, so strip `.bytes` → `arr[idx]`.
    if (
        isinstance(expr.array, IRField)
        and expr.array.field_name == "bytes"
        and isinstance(expr.index, IRArithmetic)
        and expr.index.op.value == "<<"
        and isinstance(expr.index.right, IRConst)
    ):
        target = expr.array.target
        keep_bytes = (isinstance(target, IRLocal) and target.name == "this") or (
            disasm.type_name(code, target.get_type()) == "String"
        )
        if keep_bytes:
            arr_str = _expression_to_haxe(expr.array, code, ir_function)
        else:
            arr_str = _expression_to_haxe(target, code, ir_function)
        idx_str = _expression_to_haxe(expr.index.left, code, ir_function)
        return arr_str, idx_str, None
    # Raw hl.Bytes temporaries that feed ArrayBase.alloc* are upgraded to
    # hl.BytesAccess<T>; render `bytes[idx << n]` as `bytes[idx]`.
    if (
        isinstance(expr.array, IRLocal)
        and disasm.type_to_haxe(disasm.type_name(code, expr.array.get_type())).startswith("hl.BytesAccess")
        and isinstance(expr.index, IRArithmetic)
        and expr.index.op.value == "<<"
        and isinstance(expr.index.right, IRConst)
    ):
        return expr.array.name, _expression_to_haxe(expr.index.left, code, ir_function), None
    kind = getattr(expr, "bytes_access_kind", None)
    if kind and kind != "UI8":
        return arr_str, idx_str, kind
    return arr_str, idx_str, None


def _expression_to_haxe(
    expr: Optional[IRStatement],
    code: Bytecode,
    ir_function: Optional[IRFunction] = None,
) -> str:
    assert expr is not None, "Found empty statement!"

    if isinstance(expr, IRLocal):
        if ir_function is not None:
            subs = getattr(ir_function, "_render_subs", None)
            if subs and expr in subs:
                rendered = subs[expr][0]
                return f"({rendered})"
        return expr.name

    elif isinstance(expr, IRConst):
        if isinstance(expr.value, Function):  # crashlink.core.Function
            func = expr.value
            # For function constants, use their partial name or findex
            name: Optional[str] = code.partial_func_name(func)
            if not name or name == "<none>":
                name = None
            is_std = _is_std_function(func, code)
            if name and "." in name and not is_std:
                return name
            # Static wrappers often drop the class from the partial name; use
            # the full name so method/closure references are qualified.
            if not is_std:
                parts = _func_name_parts(func, code)
                if parts:
                    class_name, method_name = parts
                    fun_type = func.type.resolve(code).definition
                    if isinstance(fun_type, Fun) and fun_type.args:
                        first_arg_type = fun_type.args[0].resolve(code)
                        first_arg_type_name = destaticify(disasm.type_name(code, first_arg_type))
                        if first_arg_type_name == class_name and ir_function is not None:
                            receiver = _find_receiver_local(class_name, ir_function, code)
                            if receiver:
                                return f"{receiver}.{method_name}"
                    return f"{class_name}.{method_name}"
            if name:
                return name
            return f"__anon_{func.findex.value}"
        elif isinstance(expr.value, str):
            # Basic string quoting, may need more sophisticated escaping for real Haxe
            return '"' + expr.value.replace('"', '\\"') + '"'
        elif isinstance(expr.value, bool):
            return "true" if expr.value else "false"
        elif expr.value is None:  # For IRConst.ConstType.NULL
            return "null"
        elif isinstance(expr.value, Type):
            if isinstance(expr.original_index, gIndex):
                # A real mutable global slot (from GetGlobal/SetGlobal), not a
                # compile-time class/type reference (those come from the `Type`
                # opcode). Mirrors Haxe's actual `untyped $name(...)` idiom for
                # raw HL globals (zero-arg call to read, one-arg call to write
                # — see e.g. `get_allTypes()`/`init()` in hl/_std/Type.hx),
                # with a synthesized name (see varN) since there's no
                # source-level name to recover.
                return f"untyped ${global_name(expr)}()"
            # Types as runtime values are used internally by the HashLink stdlib.
            # There is no direct Haxe equivalent, so emit null as a placeholder.
            return "null"
        elif isinstance(expr.value, Native):
            return f"Native.{expr.value.name.resolve(code)}"
        elif expr.const_type == IRConst.ConstType.INT:
            val = expr.value.value if hasattr(expr.value, "value") else expr.value
            val = int(val)
            if val >= 0x80000000:
                val = val - 0x100000000
            return str(val)
        return str(expr.value)

    elif isinstance(expr, IRArithmetic):
        left = _expr_to_haxe_with_precedence(expr.left, code, ir_function, expr.op.value)
        right = _expr_to_haxe_with_precedence(expr.right, code, ir_function, expr.op.value)
        return f"{left} {expr.op.value} {right}"

    elif isinstance(expr, IRNeg):
        inner = _expression_to_haxe(expr.expr, code, ir_function)
        if isinstance(expr.expr, IRArithmetic):
            inner = f"({inner})"
        return f"-{inner}"

    elif isinstance(expr, IRNot):
        inner = _expression_to_haxe(expr.expr, code, ir_function)
        if isinstance(expr.expr, (IRArithmetic, IRBoolExpr)):
            inner = f"({inner})"
        return f"!{inner}"

    elif isinstance(expr, IRTypeOf):
        inner = _expression_to_haxe(expr.expr, code, ir_function)
        return f"hl.Type.getDynamic({inner})"

    elif isinstance(expr, IRTypeKind):
        # `hl.Type.kind` is `hl.TypeKind`, an enum abstract over Int that doesn't
        # implicitly unify with Int (our dst register's real, lifted type) — an
        # explicit untyped cast is needed so e.g. `var x: Int = ...` type-checks.
        inner = _expression_to_haxe(expr.expr, code, ir_function)
        return f"cast {inner}.kind"

    elif isinstance(expr, IRBoolExpr):
        op_map = {
            IRBoolExpr.CompareType.EQ: "==",
            IRBoolExpr.CompareType.NEQ: "!=",
            IRBoolExpr.CompareType.LT: "<",
            IRBoolExpr.CompareType.LTE: "<=",
            IRBoolExpr.CompareType.GT: ">",
            IRBoolExpr.CompareType.GTE: ">=",
        }
        swap_map = {  # operand-swap equivalents: a op b == b swap_op a
            IRBoolExpr.CompareType.EQ: IRBoolExpr.CompareType.EQ,
            IRBoolExpr.CompareType.NEQ: IRBoolExpr.CompareType.NEQ,
            IRBoolExpr.CompareType.LT: IRBoolExpr.CompareType.GT,
            IRBoolExpr.CompareType.LTE: IRBoolExpr.CompareType.GTE,
            IRBoolExpr.CompareType.GT: IRBoolExpr.CompareType.LT,
            IRBoolExpr.CompareType.GTE: IRBoolExpr.CompareType.LTE,
        }
        if expr.op == IRBoolExpr.CompareType.NULL:
            return f"{_expression_to_haxe(expr.left, code, ir_function)} == null"
        elif expr.op == IRBoolExpr.CompareType.NOT_NULL:
            return f"{_expression_to_haxe(expr.left, code, ir_function)} != null"
        elif expr.op == IRBoolExpr.CompareType.ISTRUE:
            return _expression_to_haxe(expr.left, code, ir_function)
        elif expr.op == IRBoolExpr.CompareType.ISFALSE:
            return f"!{_expression_to_haxe(expr.left, code, ir_function)}"
        elif expr.op == IRBoolExpr.CompareType.NOT:
            return f"!{_expression_to_haxe(expr.left, code, ir_function)}"
        elif expr.op == IRBoolExpr.CompareType.TRUE:
            return "true"
        elif expr.op == IRBoolExpr.CompareType.FALSE:
            return "false"
        elif expr.op in (IRBoolExpr.CompareType.OR, IRBoolExpr.CompareType.AND):
            sym = "||" if expr.op == IRBoolExpr.CompareType.OR else "&&"
            left = _expr_to_haxe_with_precedence(expr.left, code, ir_function, sym)
            right = _expr_to_haxe_with_precedence(expr.right, code, ir_function, sym)
            return f"{left} {sym} {right}"
        elif expr.left and expr.right and expr.op in op_map:
            # Normalize: constants on the right side for natural-reading output.
            actual_op: IRBoolExpr.CompareType = expr.op
            left_expr, right_expr = expr.left, expr.right
            if isinstance(left_expr, IRConst) and not isinstance(right_expr, IRConst) and actual_op in swap_map:
                left_expr, right_expr = right_expr, left_expr
                actual_op = swap_map[actual_op]
            left = _expression_to_haxe(left_expr, code, ir_function)
            right = _expression_to_haxe(right_expr, code, ir_function)
            return f"{left} {op_map[actual_op]} {right}"
        elif expr.left:
            raise NotImplementedError(f"Unhandled unary IRBoolExpr op: {expr.op} on {expr.left}")
        else:
            raise NotImplementedError(f"Unhandled IRBoolExpr: {expr}")

    elif isinstance(expr, IRField):
        # Render the field base without render-time substitutions: substituting
        # a different local here would change the object the field is read from.
        if isinstance(expr.target, IRLocal):
            target_str = expr.target.name
        else:
            target_str = _expression_to_haxe(expr.target, code, ir_function)
        target_type = expr.target.get_type()
        type_name = disasm.type_name(code, target_type)
        # Static field access on a class type constant: Type.field -> Class.field
        if isinstance(expr.target, IRConst) and isinstance(expr.target.value, Type):
            defn = expr.target.value.definition
            if isinstance(defn, Obj):
                return f"{destaticify(defn.name.resolve(code))}.{expr.field_name}"
        # Enum constructor parameters are not real Haxe fields. Cast to Dynamic.
        if isinstance(target_type.definition, Enum) and expr.field_name.startswith("param"):
            return f"({target_str} : Dynamic).{expr.field_name}"
        return f"{target_str}.{expr.field_name}"

    elif isinstance(expr, IRArrayAccess):
        arr_str, idx_str, method_kind = _resolve_array_access(expr, code, ir_function)
        if method_kind is not None:
            return f"{arr_str}.get{method_kind}({idx_str})"
        return f"{arr_str}[{idx_str}]"

    elif isinstance(expr, IRArrayLiteral):
        elements = ", ".join(_expression_to_haxe(e, code, ir_function) for e in expr.elements)
        return f"[{elements}]"

    elif isinstance(expr, IRObjectLiteral):
        fields = ", ".join(f"{k}: {_expression_to_haxe(v, code, ir_function)}" for k, v in expr.fields)
        return f"{{ {fields} }}" if fields else "{}"

    elif isinstance(expr, IRRef):
        # TODO: handle IRRef more cleanly
        inner = _expression_to_haxe(expr.target, code, ir_function)
        return inner

    elif isinstance(expr, IREnumConstruct):
        if expr.args:
            args_str = ", ".join(_expression_to_haxe(a, code, ir_function) for a in expr.args)
            return f"{expr.construct_name}({args_str})"
        return expr.construct_name

    elif isinstance(expr, IREnumIndex):
        inner = _expression_to_haxe(expr.value, code, ir_function)
        return f"/* enum_index({inner}) */"

    elif isinstance(expr, IREnumField):
        inner = _expression_to_haxe(expr.value, code, ir_function)
        # Enum constructor parameters are not real Haxe fields. Cast to Dynamic.
        return f"({inner} : Dynamic).{expr.field_name}"

    elif isinstance(expr, IRCall):
        callee_str: str
        if expr.target is not None and isinstance(expr.target, IRConst) and isinstance(expr.target.value, Function):
            func = expr.target.value
            partial = code.partial_func_name(func)
            # Rewrite String.__add__ to Haxe's + operator (or interpolation).
            if _is_std_function(func, code) and partial == "__add__" and len(expr.args) == 2:
                rendered = _render_string_concat(expr, code, ir_function)
                if rendered is not None:
                    return rendered
            # Replace String.__alloc__(itos(x, &x), x) with just x.
            alloc_simple = _try_simplify_string_alloc(expr, code, ir_function)
            if alloc_simple is not None:
                return alloc_simple

        # HashLink emits array push/pop as static calls on the internal array
        # implementation classes. Render them as the instance methods Haxe expects.
        if (
            expr.target is not None
            and isinstance(expr.target, IRConst)
            and isinstance(expr.target.value, Function)
            and _is_std_function(expr.target.value, code)
            and expr.args
        ):
            partial = code.partial_func_name(expr.target.value)
            if partial in ("push", "pop"):
                instance = _try_instance_method_call(expr.target.value, expr.args[0], code, ir_function)
                if instance is not None:
                    rest = expr.args[1:] if partial == "push" else []
                    args_str = ", ".join(_expression_to_haxe(arg, code, ir_function) for arg in rest)
                    return f"{instance}({args_str})"
            # ArrayDyn/ArrayObj length may be accessed via a static get_length helper.
            if partial == "get_length" and len(expr.args) == 1:
                arr = _expression_to_haxe(expr.args[0], code, ir_function)
                return f"{arr}.length"

        # Render HL array getDyn/setDyn method calls as plain index reads/writes
        # — but only when the receiver actually has a real `@:arrayAccess` for
        # it. Concrete typed arrays (Array<Int>, Array<Float>, ...) implement
        # `[]` via exactly these methods, so collapsing is just undoing that.
        # The abstract `hl.types.ArrayBase`/`ArrayAccess` base classes (used
        # when the concrete element type isn't known statically) define no
        # such operator at all — bracket syntax on them doesn't compile.
        if isinstance(expr.target, IRField) and not _is_untyped_array_access_class(expr.target.target.get_type(), code):
            if expr.target.field_name in ("getDyn", "get") and len(expr.args) == 1:
                arr = _expression_to_haxe(expr.target.target, code, ir_function)
                idx = _expression_to_haxe(expr.args[0], code, ir_function)
                return f"{arr}[{idx}]"
            if expr.target.field_name in ("setDyn", "set") and len(expr.args) == 2:
                arr = _expression_to_haxe(expr.target.target, code, ir_function)
                idx = _expression_to_haxe(expr.args[0], code, ir_function)
                val = _expression_to_haxe(expr.args[1], code, ir_function)
                return f"{arr}[{idx}] = {val}"

        if expr.call_type == IRCall.CallType.THIS and expr.target is None:
            callee_str = "this.unknownMethod"
        elif expr.target:
            # Static constructor calls wrap HL's New/Call pair.  Replace them
            # with a plain `new Type(...)` expression (or `super()` when inside
            # a constructor).
            if (
                isinstance(expr.target, IRConst)
                and isinstance(expr.target.value, Function)
                and _is_constructor_call(expr.target.value, code)
            ):
                ctor_expr = _rewrite_constructor_call(expr, code, ir_function)
                if ctor_expr is not None:
                    return ctor_expr

            # Instance method calls are emitted as `obj.method(args)` rather
            # than `method(obj, args)`, which avoids shadowing issues and is
            # valid Haxe syntax. This also covers std static wrappers like
            # ArrayBytes.__expand(this, len) -> this.__expand(len).
            if isinstance(expr.target, IRConst) and isinstance(expr.target.value, Function) and expr.args:
                instance_method = _try_instance_method_call(expr.target.value, expr.args[0], code, ir_function)
                if instance_method:
                    callee_str = instance_method
                    args_str = ", ".join(_expression_to_haxe(arg, code, ir_function) for arg in expr.args[1:])
                    return f"{callee_str}({args_str})"

            # Anonymous ArrayObj alloc factory: render `alloc(arr)` instead of a
            # synthetic StdFuncs stub. Qualify as `ArrayObj.alloc` when used
            # outside the ArrayObj class itself.
            if (
                isinstance(expr.target, IRConst)
                and isinstance(expr.target.value, Function)
                and _is_arrayobj_alloc_call(expr.target.value, expr, code)
            ):
                arg_str = _expression_to_haxe(expr.args[0], code, ir_function)
                if _containing_class_name(ir_function, code) == "hl.types.ArrayObj":
                    return f"alloc({arg_str})"
                return f"ArrayObj.alloc({arg_str})"

            # String.__alloc__(bytes, length) is rendered as the source idiom.
            # Inside String.hx methods it's unqualified; elsewhere keep the class.
            if (
                isinstance(expr.target, IRConst)
                and isinstance(expr.target.value, Function)
                and _is_string_alloc_call(expr.target.value, expr, code)
            ):
                bytes_str = _expression_to_haxe(expr.args[0], code, ir_function)
                len_str = _expression_to_haxe(expr.args[1], code, ir_function)
                if _containing_class_name(ir_function, code) == "String":
                    return f"__alloc__({bytes_str}, {len_str})"
                return f"String.__alloc__({bytes_str}, {len_str})"

            callee_str = _expression_to_haxe(expr.target, code, ir_function)
            # Std functions used as direct call targets can usually be rendered
            # with their Haxe-qualified name (e.g. Std.random, Math.random)
            # instead of a synthetic extern stub.
            if (
                isinstance(expr.target, IRConst)
                and isinstance(expr.target.value, Function)
                and _is_std_function(expr.target.value, code)
            ):
                std_name = _std_call_name(expr.target.value, code)
                if std_name:
                    # Inside a class, static calls to the same class need no
                    # package qualifier (e.g. ArrayDyn.concat returns
                    # `alloc(..., true)` rather than `hl.types.ArrayDyn.alloc`).
                    if "." in std_name:
                        call_class, call_method = std_name.rsplit(".", 1)
                        if _containing_class_name(ir_function, code) == call_class:
                            callee_str = call_method
                        else:
                            callee_str = std_name
                    else:
                        callee_str = std_name
                else:
                    callee_str = f"StdFuncs.{_std_func_name(expr.target.value, code)}"
        else:
            raise ValueError(f"IRCall missing target or unhandled type: {expr.call_type}")

        args_str = ", ".join(_expression_to_haxe(arg, code, ir_function) for arg in expr.args)
        # HashLink's internal ArrayBase.alloc* helpers return ArrayBytes_* types
        # that are not directly assignable to Array<T> locals. Insert a cast so
        # the decompiled output recompiles without changing the underlying call.
        call_name = ""
        if expr.target is not None and isinstance(expr.target, IRConst) and isinstance(expr.target.value, Function):
            call_name = code.full_func_name(expr.target.value) or code.partial_func_name(expr.target.value) or ""
        if "ArrayBase.alloc" in call_name:
            return f"cast {callee_str}({args_str})"
        # Mixed-type dynamic array literals lower to ArrayDyn.alloc([...], true).
        # Rendering the wrapper as the literal itself lets Haxe infer the target
        # as Array<Dynamic> and recompile.
        if call_name.endswith("ArrayDyn.alloc") and len(expr.args) == 2 and isinstance(expr.args[0], IRArrayLiteral):
            return f"({_expression_to_haxe(expr.args[0], code, ir_function)} : Array<Dynamic>)"
        return f"{callee_str}({args_str})"

    elif isinstance(expr, IRUnliftedOpcode):
        regs = ir_function.func.regs if ir_function is not None else []
        return f"/* UNLIFTED OPCODE: {expr.op.op} {disasm.pseudo_from_op(expr.op, 0, regs, code, terse=True)} */"

    elif isinstance(expr, IRNew):
        type_name = disasm.type_name(code, expr.get_type())
        if type_name == "DynObj" or type_name.startswith("Virtual["):
            return "{}"
        else:
            args_str = ", ".join(_expression_to_haxe(a, code, ir_function) for a in expr.constructor_args)
            return f"new {disasm.type_to_haxe(type_name)}({args_str})"

    elif isinstance(expr, IRNativeArrayNew):
        elem_haxe_type = disasm.type_to_haxe(disasm.type_name(code, expr.elem_type))
        size_str = _expression_to_haxe(expr.size, code, ir_function)
        return f"new hl.NativeArray<{elem_haxe_type}>({size_str})"

    elif isinstance(expr, IRNativeMapNew):
        return f"new {expr.haxe_class_name}()"

    elif isinstance(expr, IRCast):
        target_name = disasm.type_name(code, expr.get_type())
        source_name = disasm.type_name(code, expr.expr.get_type())
        inner = _expression_to_haxe(expr.expr, code, ir_function)
        if target_name == "I32" and source_name in {"F32", "F64"}:
            return f"Std.int({inner})"
        return inner

    elif isinstance(expr, IRPrimitiveJump):  # Should be gone, but as a fallback
        return f"/* GOTO_LIKE({expr.op.op}) */"

    # Fallback for unknown expressions
    return f"/* <UnknownExpr: {type(expr).__name__}> */"


def _inverted_bool_expr_to_haxe(expr: IRBoolExpr, code: Bytecode, ir_function: IRFunction) -> str:
    op_map = {
        IRBoolExpr.CompareType.EQ: "!=",
        IRBoolExpr.CompareType.NEQ: "==",
        IRBoolExpr.CompareType.LT: ">=",
        IRBoolExpr.CompareType.LTE: ">",
        IRBoolExpr.CompareType.GT: "<=",
        IRBoolExpr.CompareType.GTE: "<",
    }
    if expr.op == IRBoolExpr.CompareType.NULL:
        return f"{_expression_to_haxe(expr.left, code, ir_function)} != null"
    if expr.op == IRBoolExpr.CompareType.NOT_NULL:
        return f"{_expression_to_haxe(expr.left, code, ir_function)} == null"
    if expr.op == IRBoolExpr.CompareType.ISTRUE:
        return f"!{_expression_to_haxe(expr.left, code, ir_function)}"
    if expr.op == IRBoolExpr.CompareType.ISFALSE:
        return _expression_to_haxe(expr.left, code, ir_function)
    if expr.op == IRBoolExpr.CompareType.TRUE:
        return "false"
    if expr.op == IRBoolExpr.CompareType.FALSE:
        return "true"
    if expr.left and expr.right and expr.op in op_map:
        swap_map = {
            IRBoolExpr.CompareType.EQ: IRBoolExpr.CompareType.EQ,
            IRBoolExpr.CompareType.NEQ: IRBoolExpr.CompareType.NEQ,
            IRBoolExpr.CompareType.LT: IRBoolExpr.CompareType.GT,
            IRBoolExpr.CompareType.LTE: IRBoolExpr.CompareType.GTE,
            IRBoolExpr.CompareType.GT: IRBoolExpr.CompareType.LT,
            IRBoolExpr.CompareType.GTE: IRBoolExpr.CompareType.LTE,
        }
        actual_op: IRBoolExpr.CompareType = expr.op
        left_expr, right_expr = expr.left, expr.right
        if isinstance(left_expr, IRConst) and not isinstance(right_expr, IRConst) and actual_op in swap_map:
            left_expr, right_expr = right_expr, left_expr
            actual_op = swap_map[actual_op]
        left = _expression_to_haxe(left_expr, code, ir_function)
        right = _expression_to_haxe(right_expr, code, ir_function)
        return f"{left} {op_map[actual_op]} {right}"
    return f"!({_expression_to_haxe(expr, code, ir_function)})"


def _is_simple_render_expr(expr: IRExpression) -> bool:
    """Expressions safe to substitute into every later use of a local.

    Restricted to bare locals (aliases). Constants are deliberately excluded
    here even though they're "simple": duplicating a constant into multiple
    expressions can let Haxe's own compiler constant-fold arithmetic that the
    original bytecode computed at runtime (e.g. `x << n` becoming `x << 4`),
    which changes the recompiled opcodes. See _is_single_use_render_expr for
    the narrower, single-use-safe variant that does allow constants.
    """
    return isinstance(expr, IRLocal)


def _is_single_use_render_expr(expr: IRExpression) -> bool:
    """Expressions safe to substitute when the local is read exactly once.

    With only one read to satisfy, substituting a constant can't trigger the
    multi-use constant-folding problem _is_simple_render_expr avoids, so this
    additionally allows IRConst (and casts of locals/constants) — covering
    compiler temps like a single-use ToSFloat/ToDyn result or boxed literal
    that would otherwise be declared and then never referenced by name.
    """
    if isinstance(expr, (IRLocal, IRConst)):
        return True
    if isinstance(expr, IRCast):
        return _is_single_use_render_expr(expr.expr)
    return False


def _free_locals_in_expr(expr: IRExpression) -> Set[IRLocal]:
    found: Set[IRLocal] = set()

    def walk(e: Optional[IRExpression]) -> None:
        if e is None:
            return
        if isinstance(e, IRLocal):
            found.add(e)
        elif isinstance(e, (IRArithmetic, IRBoolExpr)):
            walk(e.left)
            walk(e.right)
        elif isinstance(e, IRCall):
            if e.target is not None:
                walk(e.target)
            for arg in e.args:
                walk(arg)
        elif isinstance(e, IRField):
            walk(e.target)
        elif isinstance(e, IRCast):
            walk(e.expr)
        elif isinstance(e, IRArrayAccess):
            walk(e.array)
            walk(e.index)

    walk(expr)
    return found


def _count_local_reads_and_writes(root: IRStatement, name: str) -> Tuple[int, int]:
    """Count read vs write occurrences of a local by name across an IR subtree.

    A write is an IRAssign whose target is exactly that local; every other
    occurrence (including as the array/field base of a write, which is itself
    a read of the base pointer) counts as a read.
    """
    reads = 0
    writes = 0
    seen: Set[int] = set()

    def walk(s: Optional[IRStatement]) -> None:
        nonlocal reads, writes
        if s is None or id(s) in seen:
            return
        seen.add(id(s))
        if isinstance(s, IRAssign) and isinstance(s.target, IRLocal) and s.target.name == name:
            writes += 1
            walk(s.expr)
            return
        if isinstance(s, IRLocal) and s.name == name:
            reads += 1
        # IRArithmetic doesn't expose left/right via get_children (several
        # passes rely on that to avoid auto-recursing into operands), so walk
        # them explicitly here instead.
        if isinstance(s, IRArithmetic):
            walk(s.left)
            walk(s.right)
            return
        for child in s.get_children():
            if isinstance(child, IRBlock):
                for child_stmt in child.statements:
                    walk(child_stmt)
            else:
                walk(child)

    walk(root)
    return reads, writes


def _redefined_locals(stmt: IRStatement) -> Set[IRLocal]:
    found: Set[IRLocal] = set()

    def walk(s: IRStatement) -> None:
        if isinstance(s, IRAssign):
            if isinstance(s.target, IRLocal):
                found.add(s.target)
            # Array/field writes mutate the object referenced by their base local.
            elif isinstance(s.target, IRArrayAccess):
                arr = s.target.array
                if isinstance(arr, IRLocal):
                    found.add(arr)
                elif isinstance(arr, IRField) and isinstance(arr.target, IRLocal):
                    found.add(arr.target)
            elif isinstance(s.target, IRField) and isinstance(s.target.target, IRLocal):
                found.add(s.target.target)
        for child in s.get_children():
            if isinstance(child, IRBlock):
                for child_stmt in child.statements:
                    walk(child_stmt)
            else:
                walk(child)

    walk(stmt)
    return found


def _redefined_before_expression(stmt: IRStatement) -> Set[IRLocal]:
    """Locals assigned by `stmt` before its own expression(s) are evaluated.

    Only IRAssignments to a local fall into this category (the RHS is read
    before the target is overwritten).  Array/field writes mutate their base
    object after the index/value expressions are evaluated, so they are not
    included here.
    """
    found: Set[IRLocal] = set()
    if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal):
        found.add(stmt.target)
    return found


def _contains_top_level_call(stmt: IRStatement) -> bool:
    """True if any expression evaluated by `stmt` itself (not nested blocks) is a call."""

    def walk(e: Optional[IRExpression]) -> bool:
        if e is None:
            return False
        if isinstance(e, IRCall):
            return True
        return any(walk(child) for child in e.get_children() if isinstance(child, IRExpression))

    if isinstance(stmt, IRAssign):
        return walk(stmt.expr) or walk(stmt.target)
    if isinstance(stmt, (IRReturn, IRThrow)) and stmt.value is not None:
        return walk(stmt.value)
    if isinstance(stmt, IRTrace):
        return walk(stmt.msg)
    if isinstance(stmt, (IRConditional, IRWhileLoop)) and stmt.condition is not None:
        return walk(stmt.condition)
    if isinstance(stmt, IRSwitch) and stmt.value is not None:
        return walk(stmt.value)
    if isinstance(stmt, IRExpression):
        return walk(stmt)
    return False


def _contains_call(stmt: IRStatement) -> bool:
    """True if a statement contains any IRCall expression (including nested blocks)."""
    found = False

    def walk(e: Optional[IRExpression]) -> None:
        nonlocal found
        if e is None:
            return
        if isinstance(e, IRCall):
            found = True
        for child in e.get_children():
            if isinstance(child, IRExpression):
                walk(child)

    for child in stmt.get_children():
        if isinstance(child, IRExpression):
            walk(child)
        elif isinstance(child, IRBlock):
            for child_stmt in child.statements:
                if isinstance(child_stmt, IRExpression):
                    walk(child_stmt)
    return found


def _generate_statements(
    statements: List[IRStatement],
    code: Bytecode,
    ir_function: IRFunction,
    indent_level: int,
    # Track declared variables in the current scope to decide between "var x =" and "x ="
    # This is a simplification; a proper symbol table would be more robust.
    declared_vars_in_scope: set[str],
    inline_declarations: Optional[Dict[IRStatement, Tuple[str, str]]] = None,
    render_subs: Optional[Dict[IRLocal, Tuple[str, Set[IRLocal]]]] = None,
    op_to_line: Optional[Dict[int, int]] = None,
    base_offset: int = 0,
) -> List[str]:
    output_lines: List[str] = []
    indent = _indent_str(indent_level)
    if inline_declarations is None:
        inline_declarations = {}
    if render_subs is None:
        render_subs = {}
    if op_to_line is None:
        op_to_line = {}

    # Recurse while sharing the op→line map; base_offset + current length is the
    # absolute line where the child's lines will land (they're extended in next).
    def _gen(
        stmts: List[IRStatement],
        indent_lvl: int,
        decls: set[str],
        subs: Dict[IRLocal, Tuple[str, Set[IRLocal]]],
    ) -> List[str]:
        return _generate_statements(
            stmts,
            code,
            ir_function,
            indent_lvl,
            decls,
            inline_declarations=inline_declarations,
            render_subs=subs,
            op_to_line=op_to_line,
            base_offset=base_offset + len(output_lines),
        )

    prev_render_subs = getattr(ir_function, "_render_subs", None)
    ir_function._render_subs = render_subs  # type: ignore[attr-defined]

    for stmt in statements:
        stmt_start_line = len(output_lines)
        # Substitutions are valid for the statement's own expressions unless a
        # local they depend on is overwritten before that expression is evaluated.
        # For loops, any assignment in the body invalidates pre-loop substitutions
        # because the condition is re-evaluated after the body runs.
        if isinstance(stmt, (IRWhileLoop, IRPrimitiveLoop, IRForEachLoop, IRIntRangeLoop)):
            redefined_before = _redefined_locals(stmt)
        else:
            redefined_before = _redefined_before_expression(stmt)
        for key in list(render_subs.keys()):
            if key in redefined_before or render_subs[key][1] & redefined_before:
                del render_subs[key]

        if isinstance(stmt, IRBlock):  # Nested block, usually from if/else/loop bodies
            # HaxeBlock's content is generated by recursively calling _generate_statements
            # The parent (if/while) handles the "{" and "}"
            output_lines.extend(_gen(stmt.statements, indent_level, declared_vars_in_scope.copy(), render_subs.copy()))
        elif isinstance(stmt, IRAssign) and stmt in inline_declarations:
            # Emit as `var name: type = value;` at its natural position.
            local_name, type_str = inline_declarations[stmt]

            # A compiler-temp (`varN`) holding a bare local/constant that is
            # read exactly once, right where it's defined, doesn't need its
            # own declaration at all — it can be substituted in directly at
            # that one use site (handled by the render_subs registration
            # below). Skipping the otherwise-pointless `var varN = ...;` line
            # avoids it lingering as a leftover, never-referenced-by-name
            # declaration after substitution (e.g. when copy-propagation
            # leaves a single-use ToSFloat/cast result with no other reads).
            skip_declaration = False
            if (
                isinstance(stmt.target, IRLocal)
                and re.fullmatch(r"var\d+", local_name)
                and _is_single_use_render_expr(stmt.expr)
            ):
                reads, writes = _count_local_reads_and_writes(ir_function.block, local_name)
                skip_declaration = reads == 1 and writes == 1

            if not skip_declaration:
                value_str = _expression_to_haxe(stmt.expr, code, ir_function)
                # A raw native alloc_bytes returns Dynamic; cast it when assigning to
                # a typed BytesAccess local.
                if type_str.startswith("hl.BytesAccess") and not value_str.startswith("cast "):
                    value_str = f"cast {value_str}"
                # HL has no real function-type info, so a closure-typed local
                # (e.g. `var f = obj.method;`) renders its declared type as the
                # opaque "Dynamic". Writing that out explicitly as `:Dynamic`
                # changes Haxe's codegen for the call versus letting it infer the
                # type from the right-hand side, so omit it in that case.
                if (
                    type_str == "Dynamic"
                    and isinstance(stmt.expr, IRField)
                    and isinstance(stmt.expr.get_type().definition, Fun)
                ):
                    output_lines.append(f"{indent}var {local_name} = {value_str};")
                else:
                    output_lines.append(f"{indent}var {local_name}: {type_str} = {value_str};")
                declared_vars_in_scope.add(local_name)

        elif (
            isinstance(stmt, IRAssign)
            and isinstance(stmt.target, IRConst)
            and stmt.target.const_type == IRConst.ConstType.GLOBAL_OBJ
            and isinstance(stmt.target.original_index, gIndex)
        ):
            # Raw HL globals (from SetGlobal) have no source-level name and
            # aren't real Haxe fields, so they can't be written with normal
            # `x = y;` syntax. Haxe's actual idiom for this is the one-arg
            # `untyped $name(value)` call form (see `untyped $allTypes(...)`
            # in hl/_std/Type.hx), which is what this mirrors.
            value_str = _expression_to_haxe(stmt.expr, code, ir_function)
            output_lines.append(f"{indent}untyped ${global_name(stmt.target)}({value_str});")

        elif isinstance(stmt, IRAssign):
            # hl.Bytes has no `@:arrayAccess` setter for anything but the
            # 1-byte `setUI8` — `bytes[idx] = value` for any wider element
            # (Int/Single/Float) doesn't compile, so this needs the explicit
            # `bytes.setX(idx, value)` call form instead.
            if isinstance(stmt.target, IRArrayAccess):
                arr_str, idx_str, method_kind = _resolve_array_access(stmt.target, code, ir_function)
                if method_kind is not None:
                    value_str = _expression_to_haxe(stmt.expr, code, ir_function)
                    output_lines.append(f"{indent}{arr_str}.set{method_kind}({idx_str}, {value_str});")
                    if stmt.comment:
                        output_lines[-1] += f" // {stmt.comment}"
                    continue
            # HashLink's String is backed by a private `.bytes` field. For reads
            # we hide it so String usage looks natural, but assignments to it
            # need to render as `this.bytes = ...` to be valid Haxe. When the
            # source value is another String's `.bytes` field, expose it as well.
            if (
                isinstance(stmt.target, IRField)
                and stmt.target.field_name == "bytes"
                and disasm.type_name(code, stmt.target.target.get_type()) == "String"
            ):
                target_str = f"{_expression_to_haxe(stmt.target.target, code, ir_function)}.bytes"
                value_expr = stmt.expr
                if (
                    isinstance(value_expr, IRField)
                    and value_expr.field_name == "bytes"
                    and disasm.type_name(code, value_expr.target.get_type()) == "String"
                ):
                    value_str = f"{_expression_to_haxe(value_expr.target, code, ir_function)}.bytes"
                else:
                    value_str = _expression_to_haxe(value_expr, code, ir_function)
            else:
                target_str = _expression_to_haxe(stmt.target, code, ir_function)
                value_str = _expression_to_haxe(stmt.expr, code, ir_function)

            # Compare locals by name since splitting can create different instances.
            def _same_local(a: Optional[IRStatement], b: Optional[IRStatement]) -> bool:
                return isinstance(a, IRLocal) and isinstance(b, IRLocal) and a.name == b.name

            _is_self_ref_arith = (
                isinstance(stmt.target, IRLocal)
                and isinstance(stmt.expr, IRArithmetic)
                and _same_local(stmt.expr.left, stmt.target)
            )

            _compound_ops = {
                IRArithmetic.ArithmeticType.ADD: "+=",
                IRArithmetic.ArithmeticType.SUB: "-=",
                IRArithmetic.ArithmeticType.MUL: "*=",
                IRArithmetic.ArithmeticType.SDIV: "/=",
                IRArithmetic.ArithmeticType.UDIV: "/=",
                IRArithmetic.ArithmeticType.SMOD: "%=",
                IRArithmetic.ArithmeticType.UMOD: "%=",
            }

            # Detect x++ / x-- patterns: target = target ± 1
            def _const_int_value(expr: IRConst) -> Optional[int]:
                if expr.const_type != IRConst.ConstType.INT:
                    return None
                val = expr.value.value if hasattr(expr.value, "value") else expr.value
                return int(val)

            def _field_eq(a: IRStatement, b: IRStatement) -> bool:
                return (
                    isinstance(a, IRField)
                    and isinstance(b, IRField)
                    and a.field_name == b.field_name
                    and isinstance(a.target, IRLocal)
                    and isinstance(b.target, IRLocal)
                    and a.target.name == b.target.name
                )

            if (
                isinstance(stmt.expr, IRArithmetic)
                and isinstance(stmt.expr.right, IRConst)
                and _const_int_value(stmt.expr.right) == 1
                and stmt.expr.op in (IRArithmetic.ArithmeticType.ADD, IRArithmetic.ArithmeticType.SUB)
                and (
                    (isinstance(stmt.target, IRLocal) and _same_local(stmt.expr.left, stmt.target))
                    or (isinstance(stmt.target, IRField) and _field_eq(stmt.expr.left, stmt.target))
                )
            ):
                op_sym = "++" if stmt.expr.op == IRArithmetic.ArithmeticType.ADD else "--"
                output_lines.append(f"{indent}{target_str}{op_sym};")
            # Detect x += y patterns: target = target op expr
            elif (
                _is_self_ref_arith
                and isinstance(stmt.target, IRLocal)
                and isinstance(stmt.expr, IRArithmetic)
                and _same_local(stmt.expr.left, stmt.target)
                and stmt.expr.op in _compound_ops
            ):
                rhs_str = _expression_to_haxe(stmt.expr.right, code, ir_function)
                output_lines.append(f"{indent}{target_str} {_compound_ops[stmt.expr.op]} {rhs_str};")
            else:
                output_lines.append(f"{indent}{target_str} = {value_str};")

        elif isinstance(stmt, IRTrace):
            msg_str = _expression_to_haxe(stmt.msg, code, ir_function)
            pos_info_str = ", ".join(f"{k}: {v!r}" for k, v in stmt.pos_info.items())
            output_lines.append(f"{indent}trace({msg_str}); // {{ {pos_info_str} }}")

        elif isinstance(stmt, IRUnliftedOpcode):
            output_lines.append(
                f"{indent}// UNLIFTED OPCODE: {stmt.op.op} "
                f"{disasm.pseudo_from_op(stmt.op, 0, ir_function.func.regs, code, terse=True)}"
            )

        elif isinstance(stmt, IRNativeStub):
            name = ir_function.code.full_func_name(ir_function.func)
            if name and name != "<none>.<none>":
                output_lines.append(f"{indent}// native stub: {name}")
            else:
                native_name = getattr(stmt.native, "name", None)
                if native_name is not None:
                    native_name = native_name.resolve(ir_function.code)
                output_lines.append(f"{indent}// native stub: {native_name or '?'}")

        elif isinstance(stmt, IRConditional):
            true_stmts = stmt.true_block.statements if stmt.true_block else []
            false_stmts = stmt.false_block.statements if stmt.false_block else []

            # Simplify: if (cond) { continue; } else { break; }  →  if (!cond) { break; }
            # Also handles: if (cond) { break; } else { continue; } → if (cond) { break; }
            def _is_single(stmts: List[IRStatement], typ: type) -> bool:
                return len(stmts) == 1 and isinstance(stmts[0], typ)

            if _is_single(true_stmts, IRContinue) and _is_single(false_stmts, IRBreak):
                inv_cond = (
                    _inverted_bool_expr_to_haxe(stmt.condition, code, ir_function)
                    if isinstance(stmt.condition, IRBoolExpr)
                    else f"!({_expression_to_haxe(stmt.condition, code, ir_function)})"
                )
                output_lines.append(f"{indent}if ({inv_cond}) {{")
                output_lines.append(f"{indent}    break;")
                output_lines.append(f"{indent}}}")
            elif _is_single(true_stmts, IRBreak) and _is_single(false_stmts, IRContinue):
                cond_str = _expression_to_haxe(stmt.condition, code, ir_function)
                output_lines.append(f"{indent}if ({cond_str}) {{")
                output_lines.append(f"{indent}    break;")
                output_lines.append(f"{indent}}}")
            elif not true_stmts and false_stmts:
                # Empty true block: flip condition and show false block as the body
                if isinstance(stmt.condition, IRBoolExpr):
                    inv_cond = _inverted_bool_expr_to_haxe(stmt.condition, code, ir_function)
                else:
                    inv_cond = f"!({_expression_to_haxe(stmt.condition, code, ir_function)})"
                false_subs = render_subs.copy()
                output_lines.append(f"{indent}if ({inv_cond}) {{")
                output_lines.extend(_gen(false_stmts, indent_level + 1, declared_vars_in_scope.copy(), false_subs))
                output_lines.append(f"{indent}}}")
                declared_vars_in_scope.update(_collect_assigned_names(false_stmts))
                for key in list(render_subs.keys()):
                    if key not in false_subs:
                        del render_subs[key]
            else:
                cond_str = _expression_to_haxe(stmt.condition, code, ir_function)
                output_lines.append(f"{indent}if ({cond_str}) {{")
                true_subs = render_subs.copy()
                output_lines.extend(_gen(true_stmts, indent_level + 1, declared_vars_in_scope.copy(), true_subs))
                # If the true block ends with a control-flow statement, the else is unnecessary.
                true_ends_with_cf = bool(true_stmts) and isinstance(true_stmts[-1], (IRBreak, IRContinue, IRReturn))
                false_subs = render_subs.copy()
                if false_stmts and not true_ends_with_cf:
                    output_lines.append(f"{indent}}} else {{")
                    output_lines.extend(_gen(false_stmts, indent_level + 1, declared_vars_in_scope.copy(), false_subs))
                    output_lines.append(f"{indent}}}")
                elif false_stmts and true_ends_with_cf:
                    output_lines.append(f"{indent}}}")
                    # Render former else block as plain statements (no else keyword needed)
                    output_lines.extend(_gen(false_stmts, indent_level, declared_vars_in_scope.copy(), false_subs))
                else:
                    output_lines.append(f"{indent}}}")
                declared_vars_in_scope.update(_collect_assigned_names(true_stmts))
                declared_vars_in_scope.update(_collect_assigned_names(false_stmts))
                valid_keys = set(render_subs.keys()) & set(true_subs.keys())
                if false_stmts:
                    valid_keys &= set(false_subs.keys())
                for key in list(render_subs.keys()):
                    if key not in valid_keys:
                        del render_subs[key]

        elif isinstance(stmt, IRWhileLoop):
            rendered_as_do_while = False
            if (
                isinstance(stmt.condition, IRBoolExpr)
                and stmt.condition.op == IRBoolExpr.CompareType.TRUE
                and stmt.body.statements
            ):
                last_stmt = stmt.body.statements[-1]
                if (
                    isinstance(last_stmt, IRConditional)
                    and isinstance(last_stmt.condition, IRBoolExpr)
                    and len(last_stmt.true_block.statements) == 1
                    and isinstance(last_stmt.true_block.statements[0], IRBreak)
                    and (not last_stmt.false_block or not last_stmt.false_block.statements)
                ):
                    output_lines.append(f"{indent}do {{")
                    body_subs = render_subs.copy()
                    output_lines.extend(
                        _gen(stmt.body.statements[:-1], indent_level + 1, declared_vars_in_scope.copy(), body_subs)
                    )
                    cond_str = _inverted_bool_expr_to_haxe(last_stmt.condition, code, ir_function)
                    output_lines.append(f"{indent}}} while ({cond_str});")
                    rendered_as_do_while = True
                    for key in list(render_subs.keys()):
                        if key not in body_subs:
                            del render_subs[key]

            if not rendered_as_do_while:
                cond_str = _expression_to_haxe(stmt.condition, code, ir_function)
                output_lines.append(f"{indent}while ({cond_str}) {{")
                body_subs = render_subs.copy()
                output_lines.extend(
                    _gen(stmt.body.statements, indent_level + 1, declared_vars_in_scope.copy(), body_subs)
                )
                output_lines.append(f"{indent}}}")
                for key in list(render_subs.keys()):
                    if key not in body_subs:
                        del render_subs[key]

        elif isinstance(stmt, IRPrimitiveLoop):  # Fallback if not optimized to IRWhileLoop
            output_lines.append(f"{indent}// Primitive Loop (condition first, then body)")
            output_lines.append(f"{indent}{{ // Condition Block")
            cond_subs = render_subs.copy()
            output_lines.extend(
                _gen(stmt.condition.statements, indent_level + 1, declared_vars_in_scope.copy(), cond_subs)
            )
            output_lines.append(f"{indent}}}")
            output_lines.append(f"{indent}{{ // Body Block")
            body_subs = render_subs.copy()
            output_lines.extend(_gen(stmt.body.statements, indent_level + 1, declared_vars_in_scope.copy(), body_subs))
            output_lines.append(f"{indent}}}")
            for key in list(render_subs.keys()):
                if key not in cond_subs or key not in body_subs:
                    del render_subs[key]

        elif isinstance(stmt, IRForEachLoop):
            elem_str = stmt.elem.name
            array_str = _expression_to_haxe(stmt.array, code, ir_function)
            output_lines.append(f"{indent}for ({elem_str} in {array_str}) {{")
            body_subs = render_subs.copy()
            output_lines.extend(_gen(stmt.body.statements, indent_level + 1, declared_vars_in_scope.copy(), body_subs))
            output_lines.append(f"{indent}}}")
            for key in list(render_subs.keys()):
                if key not in body_subs:
                    del render_subs[key]

        elif isinstance(stmt, IRIntRangeLoop):
            elem_str = stmt.elem.name
            start_str = _expression_to_haxe(stmt.start, code, ir_function)
            end_str = _expression_to_haxe(stmt.end, code, ir_function)
            output_lines.append(f"{indent}for ({elem_str} in {start_str}...{end_str}) {{")
            body_subs = render_subs.copy()
            output_lines.extend(_gen(stmt.body.statements, indent_level + 1, declared_vars_in_scope.copy(), body_subs))
            output_lines.append(f"{indent}}}")
            for key in list(render_subs.keys()):
                if key not in body_subs:
                    del render_subs[key]

        elif isinstance(stmt, IRReturn):
            if stmt.value:
                if isinstance(stmt.value, IRLocal) and stmt.value.type.resolve(code).kind.value == Type.Kind.VOID.value:
                    output_lines.append(
                        f"{indent}return; // implicit void return from reg{ir_function.locals.index(stmt.value) + 1}"
                    )
                else:
                    val_str = _expression_to_haxe(stmt.value, code, ir_function)
                    output_lines.append(f"{indent}return {val_str};")
            else:
                output_lines.append(f"{indent}return;")

        elif isinstance(stmt, IRThrow):
            val_str = _expression_to_haxe(stmt.value, code, ir_function)
            output_lines.append(f"{indent}throw {val_str};")

        elif isinstance(stmt, IRSwitch):
            value_str = _expression_to_haxe(stmt.value, code, ir_function)
            enum_type: Optional["Enum"] = None
            enum_value_str = value_str
            if isinstance(stmt.value, IREnumIndex):
                enum_value_str = _expression_to_haxe(stmt.value.value, code, ir_function)
                enum_type = cast(Optional[Enum], stmt.value.value.get_type().definition)
            elif isinstance(stmt.value.get_type().definition, Enum):
                enum_type = cast(Optional[Enum], stmt.value.get_type().definition)
            else:
                # Switch on an int that may be an enum index — detect from case blocks.
                detected = _detect_enum_value_from_cases(stmt)
                if detected is not None:
                    enum_value_str = _expression_to_haxe(detected, code, ir_function)
                    enum_type = cast(Optional[Enum], detected.get_type().definition)

            expr_switch = _is_expression_switch(stmt)
            if expr_switch is not None:
                target, case_exprs, default_expr = expr_switch
                if stmt in inline_declarations:
                    local_name, type_str = inline_declarations[stmt]
                    output_lines.append(f"{indent}var {local_name}: {type_str} = switch ({enum_value_str}) {{")
                    declared_vars_in_scope.add(local_name)
                else:
                    output_lines.append(f"{indent}{target.name} = switch ({enum_value_str}) {{")
                for case_value, case_block in stmt.cases.items():
                    case_str = _case_value_to_haxe(case_value, enum_type, code, ir_function)
                    expr_str = _expression_to_haxe(case_exprs[case_value], code, ir_function)
                    output_lines.append(f"{indent}    case {case_str}: {expr_str};")
                if default_expr is not None:
                    expr_str = _expression_to_haxe(default_expr, code, ir_function)
                    output_lines.append(f"{indent}    default: {expr_str};")
                output_lines.append(f"{indent}}}")
                declared_vars_in_scope.add(target.name)
                continue

            output_lines.append(f"{indent}switch ({enum_value_str}) {{")
            if isinstance(stmt.value, IREnumIndex):
                switch_value_expr = stmt.value.value
            elif enum_type is not None:
                # Use the detected enum expression as the switch value for param matching.
                detected2 = _detect_enum_value_from_cases(stmt)
                switch_value_expr = detected2 if detected2 is not None else stmt.value
            else:
                switch_value_expr = stmt.value
            case_subs: List[Dict[IRLocal, Tuple[str, Set[IRLocal]]]] = []
            for case_value, case_block in stmt.cases.items():
                param_names = _enum_case_params(case_block, switch_value_expr)
                case_str = _case_value_to_haxe(case_value, enum_type, code, ir_function, param_names)
                output_lines.append(f"{indent}    case {case_str}:")
                case_statements = case_block.statements[len(param_names) if param_names else 0 :]
                branch_subs = render_subs.copy()
                output_lines.extend(_gen(case_statements, indent_level + 2, declared_vars_in_scope.copy(), branch_subs))
                case_subs.append(branch_subs)
                if param_names:
                    for name in param_names:
                        declared_vars_in_scope.add(name)
                else:
                    for s in case_statements:
                        if isinstance(s, IRAssign) and isinstance(s.target, IRLocal):
                            declared_vars_in_scope.add(s.target.name)
            if stmt.default and stmt.default.statements:
                output_lines.append(f"{indent}    default:")
                default_subs = render_subs.copy()
                output_lines.extend(
                    _gen(stmt.default.statements, indent_level + 2, declared_vars_in_scope.copy(), default_subs)
                )
                case_subs.append(default_subs)
                for s in stmt.default.statements:
                    if isinstance(s, IRAssign) and isinstance(s.target, IRLocal):
                        declared_vars_in_scope.add(s.target.name)
            output_lines.append(f"{indent}}}")
            valid_keys = set(render_subs.keys())
            for subs in case_subs:
                valid_keys &= set(subs.keys())
            for key in list(render_subs.keys()):
                if key not in valid_keys:
                    del render_subs[key]

        elif isinstance(stmt, IRTryCatch):
            catch_name = "e"
            catch_type = "Dynamic"
            if stmt.catch_local and stmt.catch_local.name and not stmt.catch_local.name.startswith("var"):
                catch_name = stmt.catch_local.name
            elif stmt.catch_local:
                # The auto-generated `varN` name is only a display fallback for the
                # `catch (...)` header — rename the local itself so references to
                # it inside the catch body render as the same identifier.
                stmt.catch_local.name = catch_name
            if stmt.catch_local:
                t = disasm.type_name(code, stmt.catch_local.get_type())
                if t and t != "Dyn":
                    catch_type = disasm.type_to_haxe(t)
            output_lines.append(f"{indent}try {{")
            try_subs = render_subs.copy()
            output_lines.extend(
                _gen(stmt.try_block.statements, indent_level + 1, declared_vars_in_scope.copy(), try_subs)
            )
            # An explicit `:Dynamic` annotation on the catch variable changes
            # Haxe's codegen (it emits an extra init op, and changes how the
            # caught value unifies with Dynamic-typed call args) versus
            # leaving it untyped, even though both infer to the same type —
            # reproduce whichever the original source used.
            omit_type = catch_type == "Dynamic" and not stmt.explicit_catch_type
            catch_decl = catch_name if omit_type else f"{catch_name}:{catch_type}"
            output_lines.append(f"{indent}}} catch ({catch_decl}) {{")
            catch_subs = render_subs.copy()
            output_lines.extend(
                _gen(stmt.catch_block.statements, indent_level + 1, declared_vars_in_scope.copy(), catch_subs)
            )
            output_lines.append(f"{indent}}}")
            valid_keys = set(render_subs.keys()) & set(try_subs.keys()) & set(catch_subs.keys())
            for key in list(render_subs.keys()):
                if key not in valid_keys:
                    del render_subs[key]

        elif isinstance(stmt, IRBreak):
            output_lines.append(f"{indent}break;")

        elif isinstance(stmt, IRContinue):
            output_lines.append(f"{indent}continue;")

        elif isinstance(stmt, IRExpression):  # e.g. a standalone IRCall not assigned
            expr_str = _expression_to_haxe(stmt, code, ir_function)
            output_lines.append(f"{indent}{expr_str};")

        else:
            output_lines.append(f"{indent}// <Unhandled IRStatement: {type(stmt).__name__}> {str(stmt)[:50]}...")

        # Map every opcode this statement represents to the first line it produced
        # (absolute in the function body) — a statement folded from several opcodes
        # (see IRStatement.adopt) registers all of them, not just one, so disasm<->
        # pseudocode sync and per-opcode comments resolve for any of the originals.
        # Child statements record their own ops via _gen.
        if len(output_lines) > stmt_start_line:
            for src_op in getattr(stmt, "src_op_idxs", ()):
                op_to_line.setdefault(src_op, base_offset + stmt_start_line)

        # After rendering this statement, drop substitutions that are invalidated by
        # any assignment it performs (including in nested blocks) or by calls inside it.
        redefined_full = _redefined_locals(stmt)
        for key in list(render_subs.keys()):
            if key in redefined_full or render_subs[key][1] & redefined_full:
                del render_subs[key]
        if _contains_call(stmt):
            render_subs.clear()

        # Register simple assignments for render-time substitution into later uses.
        if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal):
            registerable = _is_simple_render_expr(stmt.expr)
            if not registerable and re.fullmatch(r"var\d+", stmt.target.name) and _is_single_use_render_expr(stmt.expr):
                reads, writes = _count_local_reads_and_writes(ir_function.block, stmt.target.name)
                registerable = reads == 1 and writes == 1
            if registerable:
                free_locals = _free_locals_in_expr(stmt.expr)
                if stmt.target not in free_locals:
                    rendered_expr = _expression_to_haxe(stmt.expr, code, ir_function)
                    render_subs[stmt.target] = (rendered_expr, free_locals)

        if stmt.comment:
            # Add comment at the end of the line or on a new line
            if output_lines:
                output_lines[-1] += f" // {stmt.comment}"
            else:  # Should not happen if statement generated something
                output_lines.append(f"{indent}// {stmt.comment}")

    ir_function._render_subs = prev_render_subs  # type: ignore[attr-defined]
    return output_lines


def _generate_function_pseudo(ir_func: IRFunction) -> str:
    """Generates the Haxe pseudocode for a single function, without the class wrapper."""
    return _generate_function_pseudo_mapped(ir_func)[0]


def _generate_function_pseudo_mapped(ir_func: IRFunction) -> Tuple[str, Dict[int, int]]:
    """Like _generate_function_pseudo, but also returns an opcode→line map (body-relative)."""
    code: Bytecode = ir_func.code
    func_core: Function = ir_func.func

    output_lines: List[str] = []
    base_indent = 0

    if isinstance(func_core, Native):
        native_name = func_core.name.resolve(code) if func_core.name else f"native{func_core.findex.value}"
        return f"// native stub: {native_name}", {}

    raw_name = code.partial_func_name(func_core)
    func_name_str = raw_name if raw_name and raw_name != "<none>" else f"f{func_core.findex.value}"
    func_name_str = getattr(ir_func, "_anon_name", func_name_str)
    is_constructor = func_name_str == "__constructor__"
    setattr(ir_func, "_is_constructor", is_constructor)
    if is_constructor:
        func_name_str = "new"
    static_kw = ""

    containing = getattr(ir_func, "_containing_class", None)
    if containing is None:
        containing = _containing_class_for(ir_func, code)
        if containing is not None:
            ir_func._containing_class = containing  # type: ignore[attr-defined]
    is_instance = containing is not None and ir_func in containing.methods
    if is_constructor:
        is_instance = True

    # Some bytecode has functions with no proto/field registration at all (no
    # debug name, not listed in any class's vtable) — e.g. the implicit
    # default-field-initializer body HL synthesizes for a class. There's no
    # name or class membership to look up, but if its first argument is `this`
    # (an Obj/Virtual instance type), render it as an unnamed instance method
    # of that class instead of bailing out into a contentless stub. Only do
    # this when the name itself was unresolvable too — a real static method
    # (e.g. String.__add__(a, b)) can legitimately take an Obj-typed first
    # parameter without being an instance method of that class.
    if containing is None and not is_instance and (not raw_name or raw_name == "<none>"):
        core_fun_type = func_core.type.resolve(code).definition
        if isinstance(core_fun_type, Fun) and core_fun_type.args:
            first_arg_type = core_fun_type.args[0].resolve(code)
            if isinstance(first_arg_type.definition, Obj):
                is_instance = True

    if getattr(ir_func, "_force_static", False):
        is_instance = False

    # A better way might be to just call disasm.is_static
    if not is_instance:
        static_kw = "static "

    override_kw = ""
    if is_instance and not is_constructor and containing is not None:
        if _method_overrides(func_name_str, containing, code):
            override_kw = "override "

    params_str_list = []
    return_type_str = "Void"

    core_fun_type_def = func_core.type.resolve(code).definition
    if isinstance(core_fun_type_def, Fun):
        start_arg = 1 if is_instance or is_constructor else 0
        for i, arg_type_idx in enumerate(core_fun_type_def.args[start_arg:]):
            arg_core_type = arg_type_idx.resolve(code)
            arg_haxe_type_name = disasm.type_to_haxe(disasm.type_name(code, arg_core_type))

            param_name = f"arg{i}"
            local_idx = start_arg + i
            if local_idx < len(ir_func.locals):
                candidate = ir_func.locals[local_idx].name
                if candidate and candidate != "this":
                    param_name = candidate
            elif func_core.has_debug and func_core.assigns:
                # Fallback to raw debug assigns if locals aren't available.
                arg_assigns = [a for a in func_core.assigns if a[1].value <= 0]
                if i < len(arg_assigns):
                    param_name = arg_assigns[i][0].resolve(code)

            param_type_decl = f": {arg_haxe_type_name}" if arg_haxe_type_name else ""
            params_str_list.append(f"{param_name}{param_type_decl}")

        ret_core_type = core_fun_type_def.ret.resolve(code)
        return_type_str = disasm.type_to_haxe(disasm.type_name(code, ret_core_type))

    # Constructors do not declare a return type in Haxe.
    if is_constructor:
        return_type_str = ""

    params_joined_str = ", ".join(params_str_list)
    ret_decl = f": {return_type_str}" if return_type_str else ""
    access_kw = "public "
    func_header = f"{access_kw}{static_kw}{override_kw}function {func_name_str}({params_joined_str}){ret_decl} {{"
    output_lines.append(func_header)

    initial_declared_vars = {p.split(":")[0].strip() for p in params_str_list}
    # For instance methods and constructors, register 0 is `this` — skip it.
    if (is_instance or is_constructor) and ir_func.locals:
        initial_declared_vars.add(ir_func.locals[0].name)

    # Classify locals: those with an unconditional first assignment can be declared
    # inline at that assignment site (`var x = expr;`); those without must be
    # pre-declared at the top of the function to avoid Haxe block-scoping errors
    # (the variable would otherwise be undefined at the point of first *use*).
    local_types = _collect_locals(ir_func.block)
    receiver_types = _virtual_receiver_static_types(ir_func, code)
    for name, haxe_type in receiver_types.items():
        if name in local_types:
            local_types[name] = haxe_type
    catch_locals = _collect_catch_local_names(ir_func.block)
    # Variables used only as the value of an enum-detected switch (the enum index temp)
    # don't need to be declared at all — the switch renders `switch(c)` not `switch(var4)`.
    enum_switch_index_vars = _collect_enum_switch_index_names(ir_func.block)
    foreach_elem_names = _collect_foreach_elem_names(ir_func.block)
    inline_declarations: Dict[IRStatement, Tuple[str, str]] = {}  # stmt → (name, type_str)
    for local_name in local_types:
        if local_name in initial_declared_vars or local_name == "this":
            continue
        # Catch-clause locals are declared by the `catch (e:T)` syntax; skip them.
        if local_name in catch_locals:
            continue
        # Enum switch index temps are rendered as the enum expression, not declared.
        if local_name in enum_switch_index_vars:
            continue
        # For-each loop variables are declared by the `for (x in y)` syntax.
        if local_name in foreach_elem_names:
            continue
        type_str = local_types[local_name]
        defining_stmt = _find_defining_assignment(local_name, ir_func.block)
        if defining_stmt is not None:
            # If the same local is also assigned inside a compound statement that
            # appears earlier in the block, declaring it at the later assignment
            # site would produce a use-before-declaration.  Fall back to a top-level
            # declaration instead.
            if not _assigned_before_in_block(local_name, ir_func.block, defining_stmt):
                # Emit inline at the assignment site, preserving statement order.
                inline_declarations[defining_stmt] = (local_name, type_str)
                continue
        # If the variable only lives inside a single compound statement, declare
        # it inline there rather than pre-declaring at function level.
        inner_stmt = _find_inner_defining_assignment(local_name, ir_func.block)
        if inner_stmt is not None:
            inline_declarations[inner_stmt] = (local_name, type_str)
            continue
        # No unconditional first assignment found — pre-declare at function level.
        # If the variable is definitely assigned (in every branch of the first
        # compound statement that mentions it) before any read, omit the default
        # initializer: the synthetic `= 0` would emit a spurious extra opcode.
        if _is_definitely_assigned_before_use(local_name, ir_func.block):
            output_lines.append(f"    var {local_name}: {type_str};")
            continue
        default_init = {
            "Int": "0",
            "Float": "0.0",
            "Bool": "false",
            "String": '""',
            "Dynamic": "null",
        }.get(type_str)
        if type_str.startswith("Array<"):
            default_init = "[]"
        init = f" = {default_init}" if default_init is not None else ""
        output_lines.append(f"    var {local_name}: {type_str}{init};")

    op_to_line: Dict[int, int] = {}
    body_lines = _generate_statements(
        ir_func.block.statements,
        code,
        ir_func,
        base_indent + 1,
        initial_declared_vars,
        inline_declarations=inline_declarations,
        op_to_line=op_to_line,
        base_offset=len(output_lines),
    )
    # Suppress trailing bare `return;` for Void functions and constructors — it's implicit.
    is_void_return = return_type_str in ("Void", "void") or is_constructor
    if is_void_return and body_lines and body_lines[-1].strip() == "return;":
        body_lines = body_lines[:-1]
    output_lines.extend(body_lines)

    output_lines.append("}")

    return "\n".join(output_lines), op_to_line


def pseudo(ir_func: IRFunction) -> str:
    """
    Generates Haxe pseudocode from a given IRFunction, wrapped in a class for context.
    """
    return pseudo_oplines(ir_func)[0]


def pseudo_oplines(ir_func: IRFunction) -> Tuple[str, Dict[int, int]]:
    """pseudo() plus a body-relative opcode→line map.

    Line indices match the function body as shown after the class wrapper is
    stripped (the map is partial — optimizer-created statements have no src op).
    """
    function_body_str, op_to_line = _generate_function_pseudo_mapped(ir_func)

    full_name = ir_func.code.full_func_name(ir_func.func)
    class_name_suggestion = "DecompiledClass"
    if "." in full_name and full_name != "<none>.<none>":
        class_name_part = full_name.rsplit(".", 1)[0]
        if class_name_part and class_name_part != "<none>":
            class_name_suggestion = class_name_part.lstrip("$")
    elif not isinstance(ir_func.func, Native):
        # No proto/field registration at all to get a name from (see the
        # matching fallback in _generate_function_pseudo) — fall back to the
        # first argument's type if it looks like a `this` receiver.
        core_fun_type = ir_func.func.type.resolve(ir_func.code).definition
        if isinstance(core_fun_type, Fun) and core_fun_type.args:
            first_arg_type = core_fun_type.args[0].resolve(ir_func.code)
            if isinstance(first_arg_type.definition, Obj):
                class_name_suggestion = destaticify(disasm.type_name(ir_func.code, first_arg_type))

    final_output = [f"class {class_name_suggestion} {{"]
    final_output.extend(["    " + line for line in function_body_str.split("\n")])
    final_output.append("}")

    return "\n".join(final_output), op_to_line


def _collect_foreach_elem_names(block: IRBlock) -> Set[str]:
    """Collect names of IRForEachLoop element locals at any depth in block."""
    names: Set[str] = set()
    for stmt in block.statements:
        if isinstance(stmt, (IRForEachLoop, IRIntRangeLoop)):
            if stmt.elem.name:
                names.add(stmt.elem.name)
            names.update(_collect_foreach_elem_names(stmt.body))
        elif isinstance(stmt, IRConditional):
            names.update(_collect_foreach_elem_names(stmt.true_block))
            if stmt.false_block:
                names.update(_collect_foreach_elem_names(stmt.false_block))
        elif isinstance(stmt, (IRWhileLoop, IRPrimitiveLoop)):
            names.update(_collect_foreach_elem_names(stmt.body))
        elif isinstance(stmt, IRTryCatch):
            names.update(_collect_foreach_elem_names(stmt.try_block))
            names.update(_collect_foreach_elem_names(stmt.catch_block))
        elif isinstance(stmt, IRSwitch):
            for case_block in stmt.cases.values():
                names.update(_collect_foreach_elem_names(case_block))
            if stmt.default:
                names.update(_collect_foreach_elem_names(stmt.default))
    return names


def _collect_catch_local_names(block: IRBlock) -> Set[str]:
    """Collect names of all catch-clause locals at any depth in block."""
    names: Set[str] = set()
    for stmt in block.statements:
        if isinstance(stmt, IRTryCatch):
            if stmt.catch_local and stmt.catch_local.name:
                names.add(stmt.catch_local.name)
            names.update(_collect_catch_local_names(stmt.try_block))
            names.update(_collect_catch_local_names(stmt.catch_block))
        elif isinstance(stmt, IRConditional):
            names.update(_collect_catch_local_names(stmt.true_block))
            if stmt.false_block:
                names.update(_collect_catch_local_names(stmt.false_block))
        elif isinstance(stmt, (IRWhileLoop, IRPrimitiveLoop)):
            names.update(_collect_catch_local_names(stmt.body))
    return names


def _switch_defines_local(switch_stmt: IRSwitch, local_name: str) -> Optional[IRLocal]:
    """Return the target local if `switch_stmt` is an expression switch that
    unconditionally assigns to `local_name` in every branch."""
    expr_switch = _is_expression_switch(switch_stmt)
    if expr_switch is None:
        return None
    target, case_exprs, default_expr = expr_switch
    if target.name != local_name:
        return None
    sources: Set[str] = set()
    for expr in case_exprs.values():
        sources.update(_collect_local_names(expr))
    if default_expr is not None:
        sources.update(_collect_local_names(default_expr))
    if local_name in sources:
        return None
    return target


def _is_definitely_assigned_before_use(local_name: str, block: IRBlock) -> bool:
    """Return True if, at the point `local_name` first appears in `block`, it is
    definitely assigned in every branch before being read.

    Used to decide whether a pre-declared variable can omit its synthetic
    default initializer. Conservative: only recognises the case where the first
    top-level statement mentioning the local is an IRConditional (with both
    branches present) or IRSwitch (with a default), and each branch assigns the
    local before any read of it.
    """
    for stmt in block.statements:
        if not _contains_local_name(local_name, stmt) and _find_assignment_recursive(local_name, stmt) is None:
            continue
        # First statement that touches the local.
        if isinstance(stmt, IRConditional):
            branches = [stmt.true_block, stmt.false_block]
            if any(b is None for b in branches):
                return False
            # The condition itself must not read the local before assignment.
            if _contains_local_name(local_name, stmt.condition):
                return False
            return all(_assigns_before_read(local_name, b) for b in branches)
        if isinstance(stmt, IRSwitch):
            if _contains_local_name(local_name, stmt.value):
                return False
            branches = list(stmt.cases.values())
            if stmt.default is None:
                return False
            branches.append(stmt.default)
            return all(_assigns_before_read(local_name, b) for b in branches)
        return False
    return False


def _assigns_before_read(local_name: str, block: Optional[IRBlock]) -> bool:
    """Return True if `block` assigns `local_name` before any read of it.

    Recurses into nested conditionals/switches only when the construct itself
    definitely assigns before use; otherwise conservatively returns False.
    """
    if block is None:
        return False
    for stmt in block.statements:
        if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal) and stmt.target.name == local_name:
            # A read in the RHS still counts as use-before-full-assignment.
            return not _contains_local_name(local_name, stmt.expr)
        if _contains_local_name(local_name, stmt) or _find_assignment_recursive(local_name, stmt) is not None:
            if isinstance(stmt, (IRConditional, IRSwitch)):
                return _branch_definitely_assigns(local_name, stmt)
            return False
    return False


def _branch_definitely_assigns(local_name: str, stmt: IRStatement) -> bool:
    """Whether a nested conditional/switch definitely assigns the local first."""
    if isinstance(stmt, IRConditional):
        if stmt.false_block is None or _contains_local_name(local_name, stmt.condition):
            return False
        return _assigns_before_read(local_name, stmt.true_block) and _assigns_before_read(local_name, stmt.false_block)
    if isinstance(stmt, IRSwitch):
        if stmt.default is None or _contains_local_name(local_name, stmt.value):
            return False
        branches = list(stmt.cases.values()) + [stmt.default]
        return all(_assigns_before_read(local_name, b) for b in branches)
    return False


def _find_defining_assignment(local_name: str, block: IRBlock) -> Optional[Union[IRAssign, IRSwitch]]:
    """Return the top-level assignment (or expression switch) that defines a local
    if it happens unconditionally before any read of that local.

    The assignment is folded into `var name = ...` at its existing statement
    position, so it is safe as long as the statement itself does not read the
    local being defined.
    """
    for stmt in block.statements:
        if isinstance(stmt, IRAssign):
            if isinstance(stmt.target, IRLocal) and stmt.target.name == local_name:
                if _contains_local_name(local_name, stmt.expr):
                    return None
                return stmt
        elif isinstance(stmt, IRSwitch):
            target = _switch_defines_local(stmt, local_name)
            if target is not None:
                expr_switch = _is_expression_switch(stmt)
                assert expr_switch is not None
                _, case_exprs, default_expr = expr_switch
                sources: Set[str] = set()
                for expr in case_exprs.values():
                    sources.update(_collect_local_names(expr))
                if default_expr is not None:
                    sources.update(_collect_local_names(default_expr))
                if local_name in sources:
                    return None
                return stmt
        if _contains_local_name(local_name, stmt):
            return None
    return None


def _find_inner_defining_assignment(local_name: str, block: IRBlock) -> Optional[Union[IRAssign, IRSwitch]]:
    """If `local_name` is only used inside a single sub-block of a single top-level
    compound statement, return the first assignment to it in that sub-block.

    Safe cases:
    - IRTryCatch: variable only in try_block or only in catch_block (not both).
    - IRConditional: variable only in true_block or only in false_block (not both),
      with no other reads/writes in the function.
    """
    # Ensure the variable doesn't appear in top-level assignments or reads.
    compound_types = (IRTryCatch, IRConditional, IRSwitch, IRWhileLoop, IRPrimitiveLoop)
    compound_stmts = [s for s in block.statements if isinstance(s, compound_types)]
    non_compound = [s for s in block.statements if not isinstance(s, compound_types)]
    if any(
        _contains_local_name(local_name, s) or _find_assignment_recursive(local_name, s) is not None
        for s in non_compound
    ):
        return None
    # Must appear in exactly one compound statement.
    containing = [
        s
        for s in compound_stmts
        if _find_assignment_recursive(local_name, s) is not None or _contains_local_name(local_name, s)
    ]
    if len(containing) != 1:
        return None
    stmt = containing[0]

    if isinstance(stmt, IRTryCatch):
        in_try = _find_assignment_recursive(local_name, stmt.try_block) is not None or _contains_local_name(
            local_name, stmt.try_block
        )
        in_catch = _find_assignment_recursive(local_name, stmt.catch_block) is not None or _contains_local_name(
            local_name, stmt.catch_block
        )
        if in_try and not in_catch:
            # Use _find_defining_assignment on the sub-block to ensure it's safe.
            return _find_defining_assignment(local_name, stmt.try_block)
        if in_catch and not in_try:
            return _find_defining_assignment(local_name, stmt.catch_block)

    elif isinstance(stmt, IRConditional):
        true_block = stmt.true_block
        false_block = stmt.false_block
        in_true = true_block is not None and (
            _find_assignment_recursive(local_name, true_block) is not None
            or _contains_local_name(local_name, true_block)
        )
        in_false = false_block is not None and (
            _find_assignment_recursive(local_name, false_block) is not None
            or _contains_local_name(local_name, false_block)
        )
        if in_true and not in_false:
            return _find_defining_assignment(local_name, true_block)
        if in_false and not in_true:
            return _find_defining_assignment(local_name, false_block)

    elif isinstance(stmt, IRSwitch):
        candidate_block: Optional[IRBlock] = None
        for case_block in stmt.cases.values():
            if _find_assignment_recursive(local_name, case_block) is not None or _contains_local_name(
                local_name, case_block
            ):
                if candidate_block is not None:
                    return None
                candidate_block = case_block
        if stmt.default and (
            _find_assignment_recursive(local_name, stmt.default) is not None
            or _contains_local_name(local_name, stmt.default)
        ):
            if candidate_block is not None:
                return None
            candidate_block = stmt.default
        if candidate_block is not None:
            return _find_defining_assignment(local_name, candidate_block)

    elif isinstance(stmt, (IRWhileLoop, IRPrimitiveLoop)):
        # The local lives only inside this loop. Declare it inline at its first
        # assignment in the loop body, recursing in case it nests deeper.
        if _contains_local_name(local_name, stmt.condition):
            return None
        inner = _find_defining_assignment(local_name, stmt.body)
        if inner is not None:
            return inner
        return _find_inner_defining_assignment(local_name, stmt.body)

    return None


def _contains_local_name(local_name: str, stmt: IRStatement) -> bool:
    """Recursively search `stmt` for a read of the named local."""
    if isinstance(stmt, IRLocal):
        return stmt.name == local_name
    if isinstance(stmt, IRArithmetic):
        return _contains_local_name(local_name, stmt.left) or _contains_local_name(local_name, stmt.right)
    if isinstance(stmt, IRBoolExpr):
        return (stmt.left is not None and _contains_local_name(local_name, stmt.left)) or (
            stmt.right is not None and _contains_local_name(local_name, stmt.right)
        )
    if isinstance(stmt, IRCall):
        if stmt.target is not None and _contains_local_name(local_name, stmt.target):
            return True
        return any(_contains_local_name(local_name, arg) for arg in stmt.args)
    if isinstance(stmt, IRField):
        return _contains_local_name(local_name, stmt.target)
    if isinstance(stmt, IRArrayAccess):
        return _contains_local_name(local_name, stmt.array) or _contains_local_name(local_name, stmt.index)
    if isinstance(stmt, IRCast):
        return _contains_local_name(local_name, stmt.expr)
    if isinstance(stmt, IRNeg):
        return _contains_local_name(local_name, stmt.expr)
    if isinstance(stmt, IRNot):
        return _contains_local_name(local_name, stmt.expr)
    if isinstance(stmt, IRRef):
        return _contains_local_name(local_name, stmt.target)
    if isinstance(stmt, IREnumConstruct):
        return any(_contains_local_name(local_name, arg) for arg in stmt.args)
    if isinstance(stmt, (IREnumIndex, IREnumField)):
        return _contains_local_name(local_name, stmt.value)
    if isinstance(stmt, IRNew):
        return any(_contains_local_name(local_name, arg) for arg in stmt.constructor_args)
    if isinstance(stmt, IRTrace):
        return _contains_local_name(local_name, stmt.msg)
    if isinstance(stmt, IRReturn):
        return stmt.value is not None and _contains_local_name(local_name, stmt.value)
    if isinstance(stmt, IRAssign):
        # Only consider the expression side; the target is a write.
        return _contains_local_name(local_name, stmt.expr)
    if isinstance(stmt, IRBlock):
        return any(_contains_local_name(local_name, child) for child in stmt.statements)
    if isinstance(stmt, IRConditional):
        return (
            _contains_local_name(local_name, stmt.condition)
            or _contains_local_name(local_name, stmt.true_block)
            or _contains_local_name(local_name, stmt.false_block)
        )
    if isinstance(stmt, (IRWhileLoop, IRPrimitiveLoop)):
        return _contains_local_name(local_name, stmt.condition) or _contains_local_name(local_name, stmt.body)
    if isinstance(stmt, IRSwitch):
        if _contains_local_name(local_name, stmt.value):
            return True
        return any(_contains_local_name(local_name, block) for block in stmt.cases.values()) or (
            stmt.default is not None and _contains_local_name(local_name, stmt.default)
        )
    if isinstance(stmt, IRTryCatch):
        return (
            _contains_local_name(local_name, stmt.try_block)
            or _contains_local_name(local_name, stmt.catch_block)
            or (stmt.catch_local is not None and stmt.catch_local.name == local_name)
        )
    return any(_contains_local_name(local_name, child) for child in stmt.get_children())


def _collect_local_names(stmt: IRStatement) -> Set[str]:
    """Recursively collect the names of all `IRLocal` nodes in `stmt`."""
    names: Set[str] = set()
    if isinstance(stmt, IRLocal):
        names.add(stmt.name)
        return names
    for child in stmt.get_children():
        names.update(_collect_local_names(child))
    return names


def _has_multiple_assignments(local_name: str, block: IRBlock) -> bool:
    """Return True if `local_name` is assigned more than once at the top level of `block`."""
    count = 0
    for stmt in block.statements:
        if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal) and stmt.target.name == local_name:
            count += 1
            if count > 1:
                return True
    return False


def _assigned_before_in_block(local_name: str, block: IRBlock, stmt: IRStatement) -> bool:
    """Return True if `local_name` is assigned anywhere inside a statement that
    appears before `stmt` in the block (including nested compound statements).
    """
    for s in block.statements:
        if s is stmt:
            return False
        if _find_assignment_recursive(local_name, s) is not None:
            return True
    return False


def _find_assignment_recursive(local_name: str, stmt: IRStatement) -> Optional[IRAssign]:
    """Recursively search `stmt` for a top-level assignment to `local_name`."""
    if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal) and stmt.target.name == local_name:
        return stmt
    for child in stmt.get_children():
        found = _find_assignment_recursive(local_name, child)
        if found is not None:
            return found
    return None


def _flatten_string_concat(expr: IRExpression, code: Bytecode) -> Optional[List[IRExpression]]:
    """Flatten a nested chain of String.__add__ calls into an ordered operand list.

    `(((a + b) + c) + d)` is stored as nested two-arg __add__ calls; return
    `[a, b, c, d]`. Returns None if `expr` is not a String.__add__ call.
    """
    if not (
        isinstance(expr, IRCall)
        and isinstance(expr.target, IRConst)
        and isinstance(expr.target.value, Function)
        and _is_std_function(expr.target.value, code)
        and code.partial_func_name(expr.target.value) == "__add__"
        and len(expr.args) == 2
    ):
        return None
    operands: List[IRExpression] = []
    left, right = expr.args[0], expr.args[1]
    left_flat = _flatten_string_concat(left, code)
    if left_flat is not None:
        operands.extend(left_flat)
    else:
        operands.append(left)
    right_flat = _flatten_string_concat(right, code)
    if right_flat is not None:
        operands.extend(right_flat)
    else:
        operands.append(right)
    return operands


_INTERP_SAFE_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _render_string_concat(expr: IRCall, code: Bytecode, ir_function: Optional[IRFunction]) -> Optional[str]:
    """Render a String.__add__ chain as Haxe.

    Dense chains (with several interpolated values) become single-quote string
    interpolation; otherwise a flat `a + b + c` without redundant parentheses.
    """
    operands = _flatten_string_concat(expr, code)
    if operands is None or len(operands) < 2:
        return None

    # Classify each operand as a string literal or a value to interpolate.
    parts: List[Tuple[str, Any]] = []  # (kind, payload); kind in {"lit", "val"}
    interp_count = 0
    for operand in operands:
        if isinstance(operand, IRConst) and isinstance(operand.value, str):
            parts.append(("lit", operand.value))
        else:
            simple = _try_simplify_string_alloc(operand, code, ir_function)
            if simple is None:
                simple = _expression_to_haxe(operand, code, ir_function)
            parts.append(("val", (operand, simple)))
            interp_count += 1

    # Use interpolation only for dense chains (multiple interpolated values),
    # and only when there is at least one literal to host the interpolation.
    has_literal = any(kind == "lit" for kind, _ in parts)
    if interp_count >= 2 and has_literal:
        return _render_interpolated(parts)

    # Otherwise: flat `a + b + c`, no redundant wrapping parentheses.
    rendered = []
    for kind, payload in parts:
        if kind == "lit":
            rendered.append('"' + payload.replace('"', '\\"') + '"')
        else:
            rendered.append(payload[1])
    return " + ".join(rendered)


def _render_interpolated(parts: List[Tuple[str, Any]]) -> str:
    """Build a single-quoted Haxe interpolation string from classified parts."""
    out = ["'"]
    for kind, payload in parts:
        if kind == "lit":
            text = payload
            # Escape for single-quoted interpolation context.
            text = text.replace("\\", "\\\\").replace("'", "\\'").replace("$", "$$")
            out.append(text)
        else:
            operand, simple = payload
            if isinstance(operand, IRLocal) and _INTERP_SAFE_IDENT.match(simple):
                out.append(f"${simple}")
            else:
                out.append("${" + simple + "}")
    out.append("'")
    return "".join(out)


def _try_simplify_string_alloc(expr: IRExpression, code: Bytecode, ir_function: Optional[IRFunction]) -> Optional[str]:
    """
    HashLink compiles `string + int` as:
        String.__add__(left, String.__alloc__(std.itos(int, &int), int))
    The std.itos call is often inlined into a temporary local, so also accept:
        String.__alloc__(tmp, int) where tmp = std.itos(int, &int)
    Recognise those patterns and return just the integer expression so it can
    be emitted with Haxe's `+` operator.
    """
    if not isinstance(expr, IRCall):
        return None
    if not (isinstance(expr.target, IRConst) and isinstance(expr.target.value, Function)):
        return None
    func = expr.target.value
    if not (_is_std_function(func, code) and code.partial_func_name(func) == "__alloc__" and len(expr.args) == 2):
        return None

    int_expr: Optional[IRExpression] = None
    bytes_expr = expr.args[0]

    if (
        isinstance(bytes_expr, IRCall)
        and isinstance(bytes_expr.target, IRConst)
        and isinstance(bytes_expr.target.value, Native)
    ):
        native = bytes_expr.target.value
        if (
            native.name.resolve(code) == "itos"
            and len(bytes_expr.args) >= 1
            and isinstance(bytes_expr.args[0], IRLocal)
        ):
            int_expr = bytes_expr.args[0]
    elif isinstance(bytes_expr, IRLocal):
        # The itos result may have been inlined into a temporary local.
        if ir_function is None:
            return None
        defn = _find_assignment_recursive(bytes_expr.name, ir_function.block)
        if (
            defn is not None
            and isinstance(defn.expr, IRCall)
            and isinstance(defn.expr.target, IRConst)
            and isinstance(defn.expr.target.value, Native)
            and defn.expr.target.value.name.resolve(code) == "itos"
            and len(defn.expr.args) >= 1
            and isinstance(defn.expr.args[0], IRLocal)
        ):
            int_expr = defn.expr.args[0]

    if int_expr is None:
        return None
    if not isinstance(int_expr, IRLocal):
        return None
    second_arg = expr.args[1]
    if not isinstance(second_arg, IRLocal):
        return None
    if second_arg.name != int_expr.name:
        return None
    return _expression_to_haxe(int_expr, code, ir_function)


def _is_std_function(func: "Function", code: Bytecode) -> bool:
    """Return True if the function originates from the Haxe standard library."""
    try:
        path = func.resolve_file(code)
    except Exception:
        return False
    return "/std/" in path.replace("\\", "/")


def _collect_enum_switch_index_names(block: IRBlock) -> Set[str]:
    """Collect names of integer locals that serve only as enum index temporaries
    for switch statements where we can detect the real enum value from case blocks.
    These don't need to be declared since pseudo renders `switch(c)` not `switch(var4)`.
    """
    names: Set[str] = set()
    for stmt in block.statements:
        if isinstance(stmt, IRSwitch):
            if isinstance(stmt.value, IRLocal) and not isinstance(stmt.value, IREnumIndex):
                detected = _detect_enum_value_from_cases(stmt)
                # Only a genuine index temp (distinct from the real enum value
                # used in the case bodies) is safe to skip. If the switch already
                # operates directly on the enum-typed local, that local is a real
                # variable that still needs its own declaration.
                if detected is not None and detected is not stmt.value:
                    names.add(stmt.value.name)
    return names


def _detect_enum_value_from_cases(stmt: "IRSwitch") -> Optional["IRExpression"]:
    """For a switch on an integer (enum index) look inside case blocks to find
    the actual enum expression being indexed.  Returns it if all enum-field
    accesses agree on the same base expression, else None.
    """
    candidate: Optional["IRExpression"] = None
    for case_block in stmt.cases.values():
        for s in case_block.statements:
            if isinstance(s, IRAssign) and isinstance(s.expr, IREnumField):
                base = s.expr.value
                if candidate is None:
                    candidate = base
                elif candidate is not base:
                    return None
    return candidate


def _enum_case_params(case_block: IRBlock, switch_value: IRExpression) -> Optional[List[str]]:
    """
    Detect the lowered form of a Haxe enum pattern match.
    A case like `case Rgb(r, g, b):` is compiled as a block that starts with
    assignments `r = value.param0; g = value.param1; b = value.param2;`.
    If such a sequence is found, return the parameter names so they can be
    emitted as part of the case pattern instead of as separate statements.
    """

    def _same_expr(a: IRExpression, b: IRExpression) -> bool:
        if isinstance(a, IRLocal) and isinstance(b, IRLocal):
            return a.name == b.name
        return a is b

    params: List[str] = []
    for stmt in case_block.statements:
        if not isinstance(stmt, IRAssign) or not isinstance(stmt.target, IRLocal):
            break
        if not isinstance(stmt.expr, IREnumField):
            break
        if not _same_expr(stmt.expr.value, switch_value):
            break
        expected = f"param{len(params)}"
        if stmt.expr.field_name != expected:
            break
        params.append(stmt.target.name)
    return params if params else None


def _case_value_to_haxe(
    case_value: IRConst,
    enum_type: Optional["Enum"],
    code: Bytecode,
    ir_function: IRFunction,
    param_names: Optional[List[str]] = None,
) -> str:
    if enum_type and isinstance(case_value, IRConst) and isinstance(case_value.value, str):
        case_str = case_value.value
        for construct in enum_type.constructs:
            if construct.name.resolve(code) == case_value.value:
                params = param_names if param_names else [f"arg{i}" for i in range(len(construct.params))]
                # DAE may have dropped assignments for trailing params that go
                # unused, so the captured prefix can be shorter than the
                # constructor's arity. Haxe requires every constructor arg to
                # be matched, so pad the rest with `_` wildcards.
                if len(params) < len(construct.params):
                    params = params + ["_"] * (len(construct.params) - len(params))
                if params:
                    case_str = f"{case_str}({', '.join(params)})"
                break
        return case_str
    if enum_type and isinstance(case_value, IRConst) and case_value.const_type == IRConst.ConstType.INT:
        idx = int(case_value.value.value if hasattr(case_value.value, "value") else case_value.value)
        if idx < len(enum_type.constructs):
            construct = enum_type.constructs[idx]
            name = construct.name.resolve(code)
            params = (
                param_names
                if param_names
                else ([f"arg{i}" for i in range(len(construct.params))] if construct.params else [])
            )
            if len(params) < len(construct.params):
                params = params + ["_"] * (len(construct.params) - len(params))
            if params:
                return f"{name}({', '.join(params)})"
            return name
        return _expression_to_haxe(case_value, code, ir_function)
    return _expression_to_haxe(case_value, code, ir_function)


def _func_name_parts(func: "Function", code: Bytecode) -> Optional[Tuple[str, str]]:
    """Return (class_name, method_name) for a function named like 'Class.method'."""
    name: Optional[str] = code.partial_func_name(func)
    if not name or name == "<none>":
        name = None
    if name and "." in name:
        class_name, method_name = name.rsplit(".", 1)
        return class_name, method_name
    # Static wrappers often drop the class from the partial name; use the full name.
    full = code.full_func_name(func)
    if full and full != "<none>.<none>" and "." in full:
        class_name, method_name = full.rsplit(".", 1)
        return destaticify(class_name), method_name
    return None


def _is_constructor_call(func: "Function", code: Bytecode) -> bool:
    """Return True if this function is a static __constructor__ wrapper."""
    parts = _func_name_parts(func, code)
    if not parts:
        return False
    return parts[1] == "__constructor__"


def _rewrite_constructor_call(call: IRCall, code: Bytecode, ir_function: Optional[IRFunction]) -> Optional[str]:
    """Rewrite a call to a static __constructor__ into Haxe syntax.

    - `__constructor__(new X())` -> `new X()`
    - `__constructor__(this)` inside a constructor -> `super()` or ``
    """
    if not call.args:
        return None
    arg = call.args[0]

    if not (isinstance(call.target, IRConst) and isinstance(call.target.value, Function)):
        return None
    func = call.target.value
    parts = _func_name_parts(func, code)
    if not parts:
        return None
    ctor_class_name = parts[0].lstrip("$")

    if isinstance(arg, IRNew):
        # The constructor wrapper is being applied to a freshly allocated
        # object; the Haxe `new` expression already includes the constructor.
        return _expression_to_haxe(arg, code, ir_function)

    if (
        isinstance(arg, IRLocal)
        and arg.name in ("this", "var0")
        and ir_function is not None
        and getattr(ir_function, "_is_constructor", False)
    ):
        # Inside a constructor the first local is the implicit `this`.
        # Calling the superclass constructor becomes `super(...)`.
        containing = getattr(ir_function, "_containing_class", None)
        if containing:
            primary_obj = containing.dynamic if containing.dynamic else containing.static
            if primary_obj and primary_obj.super and primary_obj.super.value > 0:
                super_type = primary_obj.super.resolve(code)
                if isinstance(super_type.definition, Obj):
                    super_name = destaticify(super_type.definition.name.resolve(code))
                    if ctor_class_name == super_name:
                        rest_args = ", ".join(_expression_to_haxe(a, code, ir_function) for a in call.args[1:])
                        return f"super({rest_args})"
        return ""

    return None


def _try_instance_method_call(
    func: "Function", first_arg: IRExpression, code: Bytecode, ir_function: Optional[IRFunction] = None
) -> Optional[str]:
    """If func is an instance method and first_arg is the `this` argument,
    return Haxe syntax `expr.methodName` for the call target.

    HL compiles `super.foo()` as a direct (non-virtual) call straight to the
    parent class's own implementation of `foo`, passing `this` as the first
    argument — the same shape as any other "call an instance method, passing
    its receiver as arg 0" pattern. The only way to tell it apart from a
    plain `this.foo()` is that the callee's declaring class differs from
    (and is an ancestor of) the *caller's* containing class: rendering it as
    `this.foo()` would dispatch virtually back to the override and (for a
    same-named override calling its parent, e.g. an overridden `toString`)
    recurse infinitely instead of reaching the parent's implementation.
    """
    parts = _func_name_parts(func, code)
    if not parts:
        return None
    class_name, method_name = parts
    # Static wrapper names like $PatchMe.main have a '$' prefix on the class.
    class_name = class_name.lstrip("$")

    # Instance methods have the receiver as their first typed argument.
    fun_type = func.type.resolve(code).definition
    if not isinstance(fun_type, Fun) or not fun_type.args:
        return None
    first_arg_type = fun_type.args[0].resolve(code)
    first_arg_type_name = destaticify(disasm.type_name(code, first_arg_type))
    if first_arg_type_name != class_name:
        return None

    if (
        isinstance(first_arg, IRLocal)
        and first_arg.name == "this"
        and ir_function is not None
        and _is_super_call(class_name, ir_function, code)
    ):
        return f"super.{method_name}"

    arg_expr_str = _expression_to_haxe(first_arg, code, None)
    return f"{arg_expr_str}.{method_name}"


def _is_super_call(callee_class_name: str, ir_function: IRFunction, code: Bytecode) -> bool:
    """True if `callee_class_name` is the direct superclass of the function
    that's currently being rendered (i.e. this call is `super.foo()`, not a
    same-class `this.foo()`)."""
    containing = getattr(ir_function, "_containing_class", None)
    if containing is None:
        return False
    primary_obj = containing.dynamic if containing.dynamic else containing.static
    if primary_obj is None or not primary_obj.super or primary_obj.super.value <= 0:
        return False
    super_type = primary_obj.super.resolve(code)
    if not isinstance(super_type.definition, Obj):
        return False
    super_name = destaticify(super_type.definition.name.resolve(code))
    return super_name == callee_class_name


def _find_receiver_local(class_name: str, ir_function: IRFunction, code: Bytecode) -> Optional[str]:
    """Find a local variable of the given class type that is assigned in the function."""
    candidates: List[str] = []
    seen: Set[int] = set()

    def visit(stmt: IRStatement) -> None:
        if id(stmt) in seen:
            return
        seen.add(id(stmt))
        if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal):
            tname = destaticify(disasm.type_name(code, stmt.target.get_type()))
            if tname == class_name:
                candidates.append(stmt.target.name)
        for child in stmt.get_children():
            visit(child)

    visit(ir_function.block)
    return candidates[0] if candidates else None


def _method_overrides(method_name: str, ir_class: "Union[IRClass, _PseudoClass]", code: Bytecode) -> bool:
    """Return True if ir_class declares a method that overrides a superclass method."""
    primary_obj = ir_class.dynamic if ir_class.dynamic else ir_class.static
    if not primary_obj or not primary_obj.super or primary_obj.super.value <= 0:
        return False
    try:
        super_type = primary_obj.super.resolve(code)
        super_obj = super_type.definition
        if not isinstance(super_obj, Obj):
            return False
        for proto in super_obj.protos:
            if proto.name.resolve(code) == method_name:
                return True
    except Exception:
        pass
    return False


def _find_type_by_haxe_name(code: Bytecode, haxe_name: str) -> Optional[Type]:
    for t in code.types:
        if destaticify(disasm.type_name(code, t)) == haxe_name:
            return t
    return None


def _base_class_for_virtual_method(func: "Function", code: Bytecode) -> Optional[str]:
    """If `func` is an overridden virtual method, return the Haxe name of the
    superclass that originally declared it."""
    parts = _func_name_parts(func, code)
    if not parts:
        return None
    class_name, method_name = parts
    try:
        typ = _find_type_by_haxe_name(code, class_name)
        if typ is None:
            return None
        obj = typ.definition
        if not isinstance(obj, Obj):
            return None
        if obj.is_static:
            obj = obj.dynamic
        if obj is None:
            return None
        super_idx = obj.super
        while super_idx is not None and super_idx.value >= 0:
            super_type = super_idx.resolve(code)
            super_obj = super_type.definition
            if not isinstance(super_obj, Obj):
                break
            check_obj = super_obj
            if check_obj.is_static:
                check_obj = check_obj.dynamic
            if check_obj is not None:
                for proto in check_obj.protos:
                    if proto.name.resolve(code) == method_name:
                        return destaticify(disasm.type_name(code, super_type))
            super_idx = super_obj.super
    except Exception:
        pass
    return None


def _virtual_receiver_static_types(ir_function: IRFunction, code: Bytecode) -> Dict[str, str]:
    """Map receiver local names to the static superclass type implied by virtual
    dispatch (e.g. myObject -> Base when myObject is used as a Base closure)."""
    result: Dict[str, str] = {}
    seen: Set[int] = set()

    def visit(stmt: IRStatement) -> None:
        if id(stmt) in seen:
            return
        seen.add(id(stmt))
        # Only a *captured* function constant (the StaticClosure lift shape,
        # `dst_local = IRConst(Function)` — i.e. `var f = SomeClass.method;`)
        # implies anything about the receiver's static type: the closure is
        # invoked later through `dst_local`, separately from this assignment,
        # so its virtual-dispatch behavior depends on the receiver's
        # *declared* type at that later point, not its concrete one here.
        # An IRConst(Function) used directly as an IRCall's target (a normal
        # `obj.method(...)` call) carries no such implication — the call
        # already resolves to a specific, possibly-overridden implementation
        # regardless of how `obj` is declared, so widening obj's type here
        # would be both unnecessary and wrong.
        if isinstance(stmt, IRAssign) and isinstance(stmt.expr, IRConst) and isinstance(stmt.expr.value, Function):
            func = stmt.expr.value
            parts = _func_name_parts(func, code)
            if parts is not None:
                class_name, _ = parts
                base = _base_class_for_virtual_method(func, code)
                if base is not None:
                    receiver = _find_receiver_local(class_name, ir_function, code)
                    if receiver is not None:
                        result[receiver] = base
        if isinstance(stmt, IRField) and stmt.virtual_dispatch_fun is not None and isinstance(stmt.target, IRLocal):
            base = _base_class_for_virtual_method(stmt.virtual_dispatch_fun, code)
            if base is not None:
                result[stmt.target.name] = base
        for child in stmt.get_children():
            visit(child)

    visit(ir_function.block)
    return result


def _collect_locals(root: IRStatement) -> Dict[str, str]:
    """
    Collect all local variables referenced in an IR tree, mapping name to a
    Haxe type name. This is used to hoist variable declarations to the top of a
    function, avoiding Haxe's block-scoping issues with decompiled output.
    """
    locals: Dict[str, str] = {}
    seen: Set[int] = set()
    pattern_locals: Set[str] = set()

    def visit(stmt: IRStatement) -> None:
        if id(stmt) in seen:
            return
        seen.add(id(stmt))
        if isinstance(stmt, IRSwitch):
            if isinstance(stmt.value, IREnumIndex):
                switch_value = stmt.value.value
            else:
                detected = _detect_enum_value_from_cases(stmt)
                switch_value = detected if detected is not None else stmt.value
            for case_block in stmt.cases.values():
                params = _enum_case_params(case_block, switch_value)
                if params:
                    pattern_locals.update(params)
            if stmt.default is not None:
                params = _enum_case_params(stmt.default, switch_value)
                if params:
                    pattern_locals.update(params)
        if isinstance(stmt, IRLocal):
            if stmt.name in pattern_locals:
                return
            if stmt.native_elem_type is not None:
                elem_haxe_type = disasm.type_to_haxe(disasm.type_name(stmt.code, stmt.native_elem_type))
                type_name = f"hl.NativeArray<{elem_haxe_type}>"
            elif stmt.native_map_class is not None:
                type_name = stmt.native_map_class
            else:
                local_type = stmt.get_type()
                if isinstance(local_type.definition, Ref):
                    # hl.Ref<T> is modelled transparently (Ref/Unref/Setref all
                    # lift to plain copies), so the local just holds a T value;
                    # declaring it as the opaque "Ref" type isn't valid Haxe.
                    local_type = local_type.definition.type.resolve(stmt.code)
                type_name = disasm.type_to_haxe(disasm.type_name(stmt.code, local_type))
                if stmt.is_unsigned and type_name == "Int":
                    type_name = "UInt"
            if stmt.name in locals and locals[stmt.name] != type_name:
                locals[stmt.name] = "Dynamic"
            else:
                locals[stmt.name] = type_name
        for child in stmt.get_children():
            visit(child)

    visit(root)

    # Upgrade raw hl.Bytes temporaries that feed ArrayBase.alloc* calls to
    # hl.BytesAccess<T>. This lets the decompiled byte-manipulation pattern
    # recompile as typed array-access stores.
    def _alloc_element_type(func_name: str) -> str:
        if "allocF64" in func_name:
            return "Float"
        if "allocF32" in func_name:
            return "Single"
        if "allocUI16" in func_name:
            return "Int"
        if "allocI32" in func_name:
            return "Int"
        return "Int"

    seen_upgrade: Set[int] = set()

    def _upgrade_bytes(stmt: IRStatement) -> None:
        if id(stmt) in seen_upgrade:
            return
        seen_upgrade.add(id(stmt))
        if isinstance(stmt, IRAssign) and isinstance(stmt.expr, IRCall):
            call = stmt.expr
            if call.target is not None and isinstance(call.target, IRConst) and isinstance(call.target.value, Function):
                func = call.target.value
                name = root.code.full_func_name(func) or root.code.partial_func_name(func) or ""
                if "ArrayBase.alloc" in name and call.args:
                    first_arg = call.args[0]
                    if isinstance(first_arg, IRLocal) and locals.get(first_arg.name) == "hl.Bytes":
                        locals[first_arg.name] = f"hl.BytesAccess<{_alloc_element_type(name)}>"
        for child in stmt.get_children():
            _upgrade_bytes(child)

    _upgrade_bytes(root)
    return locals


def _collect_natives(root: IRStatement) -> List[Native]:
    """
    Recursively collect all Native constants referenced in an IR tree.
    """
    natives: Dict[int, Native] = {}
    seen: Set[int] = set()

    def visit(stmt: IRStatement) -> None:
        if id(stmt) in seen:
            return
        seen.add(id(stmt))
        if isinstance(stmt, IRConst) and isinstance(stmt.value, Native):
            natives[id(stmt.value)] = stmt.value
        for child in stmt.get_children():
            visit(child)

    visit(root)
    return list(natives.values())


def _std_func_name(func: "Function", code: Bytecode) -> str:
    """Return a unique, valid Haxe identifier for a std library function."""
    base = code.partial_func_name(func) or "anon"
    if base == "<none>":
        base = "anon"
    base = base.replace("<", "").replace(">", "").replace(".", "_")
    return f"__std_{func.findex.value}_{base}"


def _std_call_name(func: "Function", code: Bytecode) -> Optional[str]:
    """Return a Haxe-qualified name like 'Std.random' for a std call, or None."""
    full = code.full_func_name(func)
    if not full or full == "<none>.<none>":
        return None
    if "." not in full:
        return None
    class_name, method_name = full.rsplit(".", 1)
    class_name = destaticify(class_name).lstrip("$")
    # Keep synthetic internal helpers as extern stubs.
    if method_name.startswith("__") and method_name != "__init__":
        return None
    return f"{class_name}.{method_name}"


def _is_arrayobj_alloc_call(func: "Function", call: "IRCall", code: Bytecode) -> bool:
    """Return True for anonymous ArrayObj factory calls like alloc(arr)."""
    try:
        path = func.resolve_file(code)
    except Exception:
        return False
    if "ArrayObj.hx" not in path.replace("\\", "/"):
        return False
    fun_type = func.type.resolve(code).definition
    if not isinstance(fun_type, Fun):
        return False
    if len(fun_type.args) != 1 or len(call.args) != 1:
        return False
    ret_name = disasm.type_name(code, fun_type.ret.resolve(code))
    return "ArrayObj" in ret_name


def _is_string_alloc_call(func: "Function", call: "IRCall", code: Bytecode) -> bool:
    """Return True for String.__alloc__(bytes, length) factory calls."""
    try:
        path = func.resolve_file(code)
    except Exception:
        return False
    if "String.hx" not in path.replace("\\", "/"):
        return False
    if code.partial_func_name(func) != "__alloc__":
        return False
    fun_type = func.type.resolve(code).definition
    if not isinstance(fun_type, Fun):
        return False
    return len(fun_type.args) == 2 and len(call.args) == 2


def _collect_function_externs(root: IRStatement, code: Bytecode) -> Dict[int, Tuple[str, int]]:
    """
    Collect Function constants that are used as call targets and are not defined
    in user code (i.e. they come from the HashLink std library). Returns a dict
    mapping findex to (valid Haxe identifier, max arity seen).
    """
    externs: Dict[int, Tuple[str, int]] = {}
    seen: Set[int] = set()

    def is_std_func(func: "Function") -> bool:
        try:
            path = func.resolve_file(code)
        except Exception:
            return False
        return "/std/" in path.replace("\\", "/")

    def visit(stmt: IRStatement) -> None:
        if id(stmt) in seen:
            return
        seen.add(id(stmt))
        if isinstance(stmt, IRCall) and isinstance(stmt.target, IRConst) and isinstance(stmt.target.value, Function):
            func = stmt.target.value
            if is_std_func(func) and _call_renders_as_std_stub(func, stmt, code):
                name = _std_func_name(func, code)
                arity = len(stmt.args)
                if func.findex.value in externs:
                    externs[func.findex.value] = (name, max(externs[func.findex.value][1], arity))
                else:
                    externs[func.findex.value] = (name, arity)
        for child in stmt.get_children():
            visit(child)

    visit(root)
    return externs


def _call_renders_as_std_stub(func: "Function", call: "IRCall", code: Bytecode) -> bool:
    """Return True if this std call actually renders as a `StdFuncs.` stub.

    Calls that resolve to a Haxe-qualified name (Std.random, Math.random, ...)
    or that get folded away (String.__add__ -> `+`, String.__alloc__ -> the
    interpolated value) do not need an extern declaration.
    """
    # Resolves to a real Haxe name, e.g. Std.random / Math.random.
    if _std_call_name(func, code) is not None:
        return False
    # Anonymous ArrayObj alloc factory is rendered as `alloc(arr)`.
    if _is_arrayobj_alloc_call(func, call, code):
        return False
    partial = code.partial_func_name(func)
    # String.__add__(a, b) is rendered with the `+` operator.
    if partial == "__add__" and len(call.args) == 2:
        return False
    # String.__alloc__(bytes, length) is rendered as `__alloc__(...)` (or
    # `String.__alloc__(...)` outside the String class), so it never needs a stub.
    if partial == "__alloc__" and _is_string_alloc_call(func, call, code):
        return False
    return True


def _function_extern(externs: Dict[int, Tuple[str, int]], code: Bytecode) -> str:
    """
    Generate an extern class that declares std library functions called by the IR.
    Signatures are loose (Dynamic) so the decompiled output recompiles cleanly.
    """
    if not externs:
        return ""

    lines = ["extern class StdFuncs {"]
    for findex, (name, arity) in sorted(externs.items()):
        params = ", ".join(f"arg{i}: Dynamic" for i in range(arity))
        lines.append(f"    static function {name}({params}): Dynamic;")
    lines.append("}")
    return "\n".join(lines)


def _native_extern(natives: List[Native], code: Bytecode) -> str:
    """
    Generate an extern class that declares all Native functions used in the IR.
    Signatures are kept intentionally loose (Dynamic) so the decompiled output
    recompiles without requiring perfect type recovery for every std native.
    """
    if not natives:
        return ""

    lines = ["extern class Native {"]
    for native in sorted(natives, key=lambda n: n.name.resolve(code)):
        name = native.name.resolve(code)
        # Derive arity from the native's Fun type if possible, otherwise allow
        # a single Dynamic argument.
        try:
            fun_type = native.type.resolve(code)
            fun = fun_type.definition
            arity = len(fun.args) if isinstance(fun, Fun) else 1
        except Exception:
            arity = 1
        params = ", ".join(f"arg{i}: Dynamic" for i in range(arity))
        lines.append(f"    static function {name}({params}): Dynamic;")
    lines.append("}")
    return "\n".join(lines)


def _collect_referenced_user_classes(root: IRStatement, code: Bytecode, exclude: Set[str]) -> Set[str]:
    """
    Recursively collect names of user-defined (non-std) classes referenced in the
    IR via type constants, object allocation, field access, etc.
    """
    names: Set[str] = set()
    seen: Set[int] = set()

    def is_user_type(typ: Type) -> bool:
        if not isinstance(typ.definition, Obj):
            return False
        try:
            obj = typ.definition
            for proto in obj.protos:
                fn = proto.findex.resolve(code)
                if isinstance(fn, Function) and "/std/" not in fn.resolve_file(code).replace("\\", "/"):
                    return True
            for binding in obj.bindings:
                fn = binding.findex.resolve(code)
                if isinstance(fn, Function) and "/std/" not in fn.resolve_file(code).replace("\\", "/"):
                    return True
            return not obj.protos and not obj.bindings
        except Exception:
            return False

    def visit(stmt: IRStatement) -> None:
        if id(stmt) in seen:
            return
        seen.add(id(stmt))
        if isinstance(stmt, IRConst) and isinstance(stmt.value, Type) and isinstance(stmt.value.definition, Obj):
            name = destaticify(stmt.value.definition.name.resolve(code))
            if name not in exclude and is_user_type(stmt.value):
                names.add(name)
        elif isinstance(stmt, IRNew):
            new_type = stmt.get_type()
            if isinstance(new_type.definition, Obj):
                name = destaticify(disasm.type_name(code, new_type))
                if name not in exclude and is_user_type(new_type):
                    names.add(name)
        elif isinstance(stmt, IRField):
            target_type = stmt.target.get_type()
            if isinstance(target_type.definition, Obj):
                name = destaticify(target_type.definition.name.resolve(code))
                if name not in exclude and is_user_type(target_type):
                    names.add(name)
        for child in stmt.get_children():
            visit(child)

    visit(root)
    return names


def _collect_anonymous_functions(root: IRStatement, code: Bytecode) -> Dict[int, "Function"]:
    """
    Collect user-defined anonymous functions (closures) referenced in the IR.
    These are emitted as private static helper methods so the decompiled output
    compiles cleanly.
    """
    funcs: Dict[int, "Function"] = {}
    seen: Set[int] = set()

    def is_user_func(func: "Function") -> bool:
        try:
            path = func.resolve_file(code)
        except Exception:
            return False
        return "/std/" not in path.replace("\\", "/")

    def visit(stmt: IRStatement) -> None:
        if id(stmt) in seen:
            return
        seen.add(id(stmt))
        if isinstance(stmt, IRConst) and isinstance(stmt.value, Function):
            func = stmt.value
            name = code.partial_func_name(func)
            if (not name or name == "<none>") and is_user_func(func):
                funcs[func.findex.value] = func
        for child in stmt.get_children():
            visit(child)

    visit(root)
    return funcs


def _collect_referenced_enums(root: IRStatement, code: Bytecode) -> Dict[str, "Enum"]:
    """Collect enum types referenced in the IR."""
    enums: Dict[str, "Enum"] = {}
    seen: Set[int] = set()

    def visit(stmt: IRStatement) -> None:
        if id(stmt) in seen:
            return
        seen.add(id(stmt))
        if isinstance(stmt, IRConst) and isinstance(stmt.value, Type) and isinstance(stmt.value.definition, Enum):
            name = destaticify(stmt.value.definition.name.resolve(code))
            enums[name] = stmt.value.definition
        elif isinstance(stmt, IRField):
            target_type = stmt.target.get_type()
            if isinstance(target_type.definition, Enum):
                name = destaticify(target_type.definition.name.resolve(code))
                enums[name] = target_type.definition
        elif isinstance(stmt, IREnumConstruct):
            target_type = stmt.get_type()
            if isinstance(target_type.definition, Enum):
                name = destaticify(target_type.definition.name.resolve(code))
                enums[name] = target_type.definition
        for child in stmt.get_children():
            visit(child)

    visit(root)
    return enums


def _enum_pseudo(enum_def: "Enum", code: Bytecode) -> str:
    """Generate a Haxe enum declaration from a HashLink Enum definition."""
    name = destaticify(enum_def.name.resolve(code))
    lines = [f"enum {name} {{"]
    for construct in enum_def.constructs:
        cname = construct.name.resolve(code)
        params = []
        for i, pidx in enumerate(construct.params):
            ptype = pidx.resolve(code)
            ptype_name = disasm.type_to_haxe(disasm.type_name(code, ptype))
            params.append(f"arg{i}: {ptype_name}")
        if params:
            lines.append(f"    {cname}({', '.join(params)});")
        else:
            lines.append(f"    {cname};")
    lines.append("}")
    return "\n".join(lines)


def class_pseudo(ir_class: "IRClass") -> str:
    """
    Generates Haxe pseudocode for an entire IRClass, including any user-defined
    super classes or other referenced classes needed for recompilation.
    """
    return "\n\n".join(_class_pseudo_recursive(ir_class, set()))


def _class_pseudo_recursive(ir_class: "IRClass", emitted: Set[str]) -> List[str]:
    """
    Recursive helper for class_pseudo. Returns a list of class source strings.
    """
    code: Bytecode = ir_class.code

    primary_obj = ir_class.dynamic if ir_class.dynamic else ir_class.static
    if not primary_obj:
        return ["// Error: IRClass contains no valid Obj definitions."]

    class_name = destaticify(primary_obj.name.resolve(code))
    if class_name in emitted:
        return []
    emitted.add(class_name)

    output_lines: List[str] = []
    indent_str = _indent_str(1)

    header = f"class {class_name}"
    super_name: Optional[str] = None
    if ir_class.dynamic and ir_class.dynamic.super and ir_class.dynamic.super.value > 0:
        super_type = ir_class.dynamic.super.resolve(code)
        if isinstance(super_type.definition, Obj):
            super_name = destaticify(super_type.definition.name.resolve(code))
            header += f" extends {super_name}"
    header += " {"

    # Collect natives, std functions, referenced classes and referenced enums.
    natives: List[Native] = []
    func_externs: Dict[int, Tuple[str, int]] = {}
    referenced_classes: Set[str] = set()
    referenced_enums: Dict[str, Enum] = {}
    for ir_func in ir_class.static_methods + ir_class.methods:
        natives.extend(_collect_natives(ir_func.block))
        func_externs.update(_collect_function_externs(ir_func.block, code))
        referenced_classes.update(_collect_referenced_user_classes(ir_func.block, code, {class_name}))
        referenced_enums.update(_collect_referenced_enums(ir_func.block, code))
    native_extern = _native_extern(natives, code)
    func_extern = _function_extern(func_externs, code)
    if native_extern:
        output_lines.append(native_extern)
        output_lines.append("")
    if func_extern:
        output_lines.append(func_extern)
        output_lines.append("")
    for enum_name in sorted(referenced_enums):
        output_lines.append(_enum_pseudo(referenced_enums[enum_name], code))
        output_lines.append("")

    output_lines.append(header)

    if ir_class.static_fields:
        for field_name, field_type in ir_class.static_fields:
            field_type_haxe = disasm.type_to_haxe(disasm.type_name(code, field_type))
            output_lines.append(f"{indent_str}public static var {field_name}: {field_type_haxe};")
        output_lines.append("")

    if ir_class.fields:
        for field_name, field_type in ir_class.fields:
            field_type_haxe = disasm.type_to_haxe(disasm.type_name(code, field_type))
            output_lines.append(f"{indent_str}public var {field_name}: {field_type_haxe};")
        output_lines.append("")

    for ir_func in ir_class.static_methods:
        setattr(ir_func, "_containing_class", ir_class)
        func_str = _generate_function_pseudo(ir_func)
        for line in func_str.split("\n"):
            output_lines.append(f"{indent_str}{line}")
        output_lines.append("")

    for ir_func in ir_class.methods:
        setattr(ir_func, "_containing_class", ir_class)
        func_str = _generate_function_pseudo(ir_func)
        for line in func_str.split("\n"):
            output_lines.append(f"{indent_str}{line}")
        output_lines.append("")

    # Emit any anonymous closures referenced by this class as private helpers.
    anon_funcs: Dict[int, "Function"] = {}
    for ir_func in ir_class.static_methods + ir_class.methods:
        anon_funcs.update(_collect_anonymous_functions(ir_func.block, code))
    for findex in sorted(anon_funcs):
        func = anon_funcs[findex]
        helper_ir = IRFunction(code, func)
        setattr(helper_ir, "_containing_class", ir_class)
        setattr(helper_ir, "_force_static", True)
        setattr(helper_ir, "_anon_name", f"__anon_{findex}")
        func_str = _generate_function_pseudo(helper_ir)
        for line in func_str.split("\n"):
            output_lines.append(f"{indent_str}{line}")
        output_lines.append("")

    if output_lines and output_lines[-1] == "":
        output_lines.pop()

    output_lines.append("}")
    result = ["\n".join(output_lines)]

    # Recursively emit the super class and any other referenced user classes.
    to_emit: Set[str] = referenced_classes
    if super_name and super_name != class_name:
        to_emit.add(super_name)

    for other_name in sorted(to_emit):
        if other_name in emitted:
            continue
        try:
            other_obj = code.get_test_obj(other_name)
            other_ir = IRClass(code, other_obj)
            result.extend(_class_pseudo_recursive(other_ir, emitted))
        except Exception:
            # Fall back to a stub if the class cannot be decompiled.
            result.append(f"class {other_name} {{}}")
            emitted.add(other_name)

    return result
