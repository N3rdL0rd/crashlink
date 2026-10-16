"""
Type-kind checks, cast rendering and literal-type ascription helpers for the renderer.
"""

from __future__ import annotations

import re
from typing import Optional, Set, Dict, Tuple
from .doc import strip
from ..core import Bytecode, Obj, Type, Function, Fun, Enum, Null
from .. import disasm
from .. import mapargs
from ..decomp import (
    IRCast,
    IRStatement,
    IRExpression,
    IRAssign,
    IRLocal,
    IRConst,
    IRBoolExpr,
    IRCall,
    IRArrayLiteral,
    IREnumField,
)
from ..decomp.opt.arraytypes import function_return_elem_type


def _is_int_kind(typ: "Type") -> bool:
    # true for HL's integer kinds, where Haxe's `/` needs Std.int() to stay truncating
    return typ.kind.value in (
        Type.Kind.U8.value,
        Type.Kind.U16.value,
        Type.Kind.I32.value,
        Type.Kind.I64.value,
    )


# HashLink's `hl.TypeKind` is an enum abstract over Int.  The bytecode stores the
# raw integer, but Haxe rejects `t.kind == 11` because the enum abstract expects
# a `TypeKind` on the right.  Map known kind values to their source names so the
# decompiled output matches the original `t.kind == HObj` style.
_TYPEKIND_NAMES: Dict[int, str] = {
    0: "HVoid",
    1: "HUI8",
    2: "HUI16",
    3: "HI32",
    4: "HI64",
    5: "HF32",
    6: "HF64",
    7: "HBool",
    8: "HBytes",
    9: "HDyn",
    10: "HFun",
    11: "HObj",
    12: "HArray",
    13: "HType",
    14: "HRef",
    15: "HVirtual",
    16: "HDynObj",
    17: "HAbstract",
    18: "HEnum",
    19: "HNull",
}


_NON_NULLABLE_KINDS = {
    Type.Kind.U8.value,
    Type.Kind.U16.value,
    Type.Kind.I32.value,
    Type.Kind.I64.value,
    Type.Kind.F32.value,
    Type.Kind.F64.value,
    Type.Kind.BOOL.value,
}


def _constant_null_compare(
    left: IRExpression, right: IRExpression, op: IRBoolExpr.CompareType
) -> Optional[str]:
    """The constant a comparison of a basic type against a `null` literal is."""
    if op not in (IRBoolExpr.CompareType.EQ, IRBoolExpr.CompareType.NEQ):
        return None
    for value, other in ((left, right), (right, left)):
        while isinstance(value, IRCast):  # boxing it as `Null<T>` doesn't make it null
            value = value.expr
        if (
            isinstance(other, IRConst)
            and other.const_type == IRConst.ConstType.NULL
            and isinstance(value, (IRLocal, IRConst))
            and value is not other
            and value.get_type().kind.value in _NON_NULLABLE_KINDS
        ):
            return "false" if op == IRBoolExpr.CompareType.EQ else "true"
    return None


def _literal_key(name: str) -> str:
    """A field name as an object literal writes it: quoted when it is not an identifier."""
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        return name
    return '"' + disasm._escape_str(name, '"') + '"'


def _is_dynamic_int_read(operand: Optional[IRExpression]) -> bool:
    """An Int that is the conversion of a boxed value some expression produced. The box's
    source type may be Dynamic (a generic's erased result), which types arithmetic as Float."""
    if not isinstance(operand, IRCast) or operand.get_type().kind.value != Type.Kind.I32.value:
        return False
    source: IRStatement = operand.expr
    while isinstance(source, IRCast):
        source = source.expr
    return not isinstance(source, (IRLocal, IRConst)) and source.get_type().kind.value in (
        Type.Kind.DYN.value,
        Type.Kind.NULL.value,
    )


def _return_annotation(code: Bytecode, func: Function, ret_type: Type) -> str:
    """The declared return type of `func`: an erased array gets the element type its returns recover."""
    annotation = disasm._haxe_annotation(code, ret_type)
    if annotation == "Array<Dynamic>":
        elem = function_return_elem_type(code, func)
        if elem is not None:
            return f"Array<{disasm._haxe_annotation(code, elem)}>"
    return annotation


def _widens_typed_array(expr: IRExpression, code: Bytecode) -> bool:
    """Whether `expr` converts a typed array to the erased ArrayDyn."""
    return (
        isinstance(expr, IRCast)
        and disasm.type_name(code, expr.get_type()) == "hl.types.ArrayDyn"
        and disasm.type_name(code, expr.expr.get_type()) == "hl.types.ArrayObj"
    )


def _strip_casts(expr: IRExpression) -> IRExpression:
    while isinstance(expr, IRCast):
        expr = expr.expr
    return expr


_NULLABLE_BASIC_KINDS = frozenset(
    kind.value
    for kind in (
        Type.Kind.I32,
        Type.Kind.F64,
        Type.Kind.F32,
        Type.Kind.BOOL,
        Type.Kind.U8,
        Type.Kind.U16,
        Type.Kind.I64,
    )
)


def _checked_dynamic_cast(expr: IRExpression, code: Bytecode) -> Optional[str]:
    """The type a checked conversion out of Dynamic (a SafeCast from Dyn) is written to, when the
    conversion has to be spelled out: a slot typed Dynamic (an erased or `Dynamic` parameter,
    an operand) makes none of its own, so only `(cast v : T)` gives the value its source type
    `T` (a `Dynamic<Array<Dynamic>>` field read, a property read at its applied type)."""
    if not isinstance(expr, IRCast) or expr.untyped or expr.unsafe:
        return None
    if expr.expr.get_type().kind.value != Type.Kind.DYN.value:
        return None
    boxed = expr.expr
    if isinstance(boxed, IRCast) and boxed.expr.get_type().kind.value in _NULLABLE_BASIC_KINDS:
        # `cast (v : Dynamic)` converts `v` itself: the ascription types the value, it doesn't box it.
        return None
    target = expr.get_type()
    definition = target.definition
    if isinstance(definition, Null):
        if definition.type.resolve(code).kind.value not in _NULLABLE_BASIC_KINDS:
            return None
    elif (
        not isinstance(definition, (Obj, Enum, Fun)) or disasm.type_name(code, target) == "hl.types.ArrayObj"
    ):
        # An `ArrayObj` is the `Array<T>` of some class T the cast does not name.
        return None
    annotation = disasm._haxe_annotation(code, target)
    return None if annotation == "Dynamic" else annotation


def _spell_dynamic_cast(expr: IRExpression, text: str, code: Bytecode) -> str:
    """`text` (the rendering of `expr`) as `(cast v : T)` if `expr` is a checked conversion out of
    Dynamic not already written as a cast."""
    annotation = _checked_dynamic_cast(expr, code)
    plain = strip(text)
    if annotation is None or plain.startswith(("cast", "(cast")):
        return text
    operand = text if re.fullmatch(r"[\w.]+(\(.*\))?", plain) else f"({text})"
    return f"(cast {operand} : {annotation})"


def _ascribe_literal_for_dynamic(arg: IRExpression, rendered: str, code: Bytecode) -> str:
    """An array literal handed to a Dynamic parameter: Haxe types the literal from that expected
    type (an `Array<Dynamic>`), so it has to be ascribed the element type the bytecode records."""
    if isinstance(arg, IRArrayLiteral) and arg.elements and _array_literal_ascription(arg, code) is None:
        annotation = _literal_type_annotation(arg, code)
        if annotation is not None:
            return f"({rendered} : {annotation})"
    return rendered


_ARRAY_WRAPPERS = frozenset({"hl.types.ArrayObj", "hl.types.ArrayDyn"})


def _called_return_is_typed(call: IRCall, code: Bytecode) -> bool:
    """Whether the call's callee declares an `Array<T>` result (see `_return_annotation`)."""
    return (
        call.call_type == IRCall.CallType.FUNC
        and isinstance(call.target, IRConst)
        and isinstance(call.target.value, Function)
        and function_return_elem_type(code, call.target.value) is not None
    )


def _erased_array_into_typed(value_str: str, value: IRExpression, code: Bytecode) -> str:
    """`cast` an array whose element type was erased (`Array<Dynamic>`) before it is stored in an
    `Array<T>` declaration: Haxe does not convert between the two implicitly."""
    if strip(value_str).startswith("cast ") or not isinstance(value, (IRCall, IREnumField, IRLocal)):
        return value_str
    if isinstance(value, IRLocal) and value.array_elem_type is not None and not value.is_enum_binding:
        return value_str
    if disasm._haxe_annotation(code, value.get_type()) != "Array<Dynamic>":
        return value_str
    if isinstance(value, IRCall) and _called_return_is_typed(value, code):
        return value_str
    return f"cast {value_str}"


def _literal_type_annotation(expr: IRArrayLiteral, code: Bytecode) -> Optional[str]:
    """The `Array<T>` type the bytecode records for an array literal, or None when unknown.

    A literal whose element type was erased (`Array<Dynamic>`, as for arrays of arrays) takes its
    type from its own literal elements, when they all agree.
    """
    if expr.recovered_elem_type is None:
        return None
    elem = disasm._haxe_annotation(code, expr.recovered_elem_type)
    if elem == "Dynamic":
        return None
    if elem != "Array<Dynamic>":
        return f"Array<{elem}>"
    if not expr.elements or not all(isinstance(e, IRArrayLiteral) for e in expr.elements):
        return None
    inner = {_literal_type_annotation(e, code) for e in expr.elements if isinstance(e, IRArrayLiteral)}
    if len(inner) != 1 or None in inner:
        return None
    return f"Array<{next(iter(inner))}>"


def _array_literal_ascription(expr: IRArrayLiteral, code: Bytecode) -> Optional[str]:
    """The `Array<T>` to ascribe to a literal so Haxe allocates the element type the bytecode records.

    Haxe infers a non-empty literal's element type from its elements, so only an empty literal or
    an erased outer array (whose inner arrays Haxe cannot infer) needs the ascription.
    """
    if expr.recovered_elem_type is None:
        return None
    erased = disasm._haxe_annotation(code, expr.recovered_elem_type) == "Array<Dynamic>"
    if expr.elements and not erased:
        return None
    annotation = _literal_type_annotation(expr, code)
    return mapargs.refine(annotation, getattr(expr, "map_value", None)) if annotation is not None else None


def _type_i64_literals(
    left_expr: IRExpression, right_expr: IRExpression, left: str, right: str
) -> Tuple[str, str]:
    """The rendered operands of a comparison, an Int literal against an I64 typed as one:
    Haxe won't compare the two otherwise."""

    def is_i64(expr: IRExpression) -> bool:
        return expr.get_type().kind.value == Type.Kind.I64.value

    def is_literal(expr: IRExpression) -> bool:
        return isinstance(expr, IRConst) or (isinstance(expr, IRCast) and isinstance(expr.expr, IRConst))

    if is_i64(left_expr) and not is_literal(left_expr) and is_literal(right_expr):
        right = f"({right} : hl.I64)"
    elif is_i64(right_expr) and not is_literal(right_expr) and is_literal(left_expr):
        left = f"({left} : hl.I64)"
    return left, right


def _literal_array_types(root: IRStatement, code: Bytecode) -> Dict[str, str]:
    """The `Array<T>` the array literal a local is assigned names, by local name (only where all agree)."""
    seen: Set[int] = set()
    found: Dict[str, Set[str]] = {}

    def visit(stmt: IRStatement) -> None:
        if id(stmt) in seen:
            return
        seen.add(id(stmt))
        if (
            isinstance(stmt, IRAssign)
            and isinstance(stmt.target, IRLocal)
            and isinstance(stmt.expr, IRArrayLiteral)
        ):
            annotation = _literal_type_annotation(stmt.expr, code)
            found.setdefault(stmt.target.name, set()).add(annotation or "")
        for child in stmt.get_children():
            visit(child)

    visit(root)
    return {name: next(iter(types)) for name, types in found.items() if len(types) == 1 and "" not in types}
