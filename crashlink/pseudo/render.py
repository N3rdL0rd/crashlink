"""
The rendering core: expression and statement rendering (one mutually recursive unit).
"""

from __future__ import annotations

import re
from typing import Optional, List, Set, Dict, Tuple, cast, Any
from .annotate import annotate_expression, annotate_type
from .doc import OPEN, CLOSE, mark, marking, strip
from .symbols import SymbolRef
from ..core import (
    Bytecode,
    Obj,
    Ref,
    Type,
    Function,
    Fun,
    Native,
    Enum,
    destaticify,
    is_static_name,
    gIndex,
    Virtual,
    Dyn,
    Null,
)
from .. import disasm
from ..errors import MalformedBytecode
from .. import abstracts, arrayelems, enumparams, generics, ifacenames, mapargs
from ..classgenerics import class_generics
from ..decomp import (
    IRBreak,
    IRContinue,
    IRCast,
    IRClassCast,
    IRDowncast,
    IRNativeStub,
    IRField,
    IRBoundClosure,
    IRStoreExpr,
    IRPostIncrement,
    IRFunction,
    IRBlock,
    IRNew,
    IRStringConvert,
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
    IRRefNew,
    IRPosInfos,
    IRRefGet,
    IRRefSet,
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
    IRBytesNew,
    IRPrimitiveLoop,
    IRReturn,
    IRThrow,
    IRPrimitiveJump,
    IRSwitch,
    IRTernary,
    IRNullCoalesce,
)
from ..decomp.ir import IREnumPattern, IRInlineCall, basic_type_of_global
from ..decomp.opt.clean import (
    default_arg_value,
    nullable_basic_name,
    optional_basic_name,
    overriding_default_arg_regs,
)
from ..decomp.opt.switches import conjuncts, parse_enum_match
from ..decomp.inline_calls import is_inline_template
from .naming import (
    _BASIC_TYPE_NAMES,
    _method_registry,
    _basic_type_globals,
    _rtti_member_meta,
    _containing_class_for,
    _containing_class_name,
    global_name,
    _std_property_accessor_name,
    _is_std_private_type,
    _is_std_call,
    _is_std_function,
    _std_private_access,
    _call_needs_private_access,
    _func_name_parts,
    _is_constructor_call,
    _std_func_name,
    _std_call_name,
    _is_arrayobj_alloc_call,
    _is_string_alloc_call,
    _std_native_api,
    _std_native_value,
    _native_binding_name,
)
from .casts import (
    _is_int_kind,
    _TYPEKIND_NAMES,
    _NON_NULLABLE_KINDS,
    _constant_null_compare,
    _literal_key,
    _is_dynamic_int_read,
    _return_annotation,
    _widens_typed_array,
    _strip_casts,
    _NULLABLE_BASIC_KINDS,
    _checked_dynamic_cast,
    _spell_dynamic_cast,
    _ascribe_literal_for_dynamic,
    _ARRAY_WRAPPERS,
    _erased_array_into_typed,
    _array_literal_ascription,
    _type_i64_literals,
    _literal_array_types,
)
from .enums import (
    _is_expression_switch,
    _switch_enum,
    _same_value,
    _switch_is_exhaustive,
    _detect_enum_value_from_cases,
    _unbound_reads,
    _pattern_captures,
)
from .closures import (
    _is_lambda_text,
    _inline_closure,
    _CTX_MARK,
    _written_after,
    _CTX_REF,
    _unshadow_captures,
    _function_header,
    _split_params,
    _unwrap_span,
    _plain_sub,
    _closure_adapter,
    _inline_anonymous,
)
from .hierarchy import (
    _has_array_access,
    _instance_method,
    _is_static_function,
    _static_owner_path,
    _static_member_path,
    _abstract_ref,
    _PRIVATE_STD_ABSTRACT_PROPERTIES,
    _abstract_constructor_body,
    _is_super_call,
    _find_receiver_local,
    _is_ancestor,
    _is_dynamic_method,
    _is_static_dynamic_method,
    _method_overrides,
    _virtual_receiver_static_types,
    _find_constructor,
    _method_slot_text,
    _constraint_text,
    _type_variable_name,
    _own_type_variables,
    _erased_parameters,
)
from .strings import (
    _indent_str,
    _grouped,
    _elided_position,
    _with_comment,
    _flatten_string_concat,
    _render_interpolated,
)
from .locals import (
    _collect_assigned_names,
    _null_guarded_ref_source,
    _is_simple_render_expr,
    _is_single_use_render_expr,
    _free_locals_in_expr,
    _source_redefined_before_use,
    _count_local_reads_and_writes,
    _redefined_locals,
    _redefined_before_expression,
    _contains_call,
    _contains_loop_continue,
    _unused_static_aliases,
    _all_statements,
    _local_def,
    _param_def,
    _plan_declarations,
    _collect_foreach_elem_names,
    _collect_catch_local_names,
    _find_defining_assignment,
    _memoized_local_reads,
    _collect_locals,
    _tag_map_allocations,
)


def _render_typekind_comparison(
    left_expr: IRExpression,
    right_expr: IRExpression,
    code: Bytecode,
    ir_function: Optional[IRFunction],
) -> Optional[Tuple[str, str]]:
    """
    If one side is `IRTypeKind` and the other is a mapped integer constant,
    render the type-kind read as `t.kind` (no cast) and the constant as the
    corresponding `hl.TypeKind` enum abstract member name.
    """
    type_kind_expr: Optional[IRTypeKind] = None
    const_expr: Optional[IRConst] = None

    if isinstance(left_expr, IRTypeKind) and isinstance(right_expr, IRConst):
        type_kind_expr = left_expr
        const_expr = right_expr
    elif isinstance(right_expr, IRTypeKind) and isinstance(left_expr, IRConst):
        type_kind_expr = right_expr
        const_expr = left_expr

    if type_kind_expr is None or const_expr is None or const_expr.const_type != IRConst.ConstType.INT:
        return None

    kind_name = _TYPEKIND_NAMES.get(
        int(const_expr.value.value if hasattr(const_expr.value, "value") else const_expr.value)
    )
    if kind_name is None:
        return None

    base = _expression_to_haxe(type_kind_expr.expr, code, ir_function)
    return f"{base}.kind", kind_name


# Haxe operator precedence (higher number = tighter binding).  Used to emit
# parentheses only where precedence would otherwise change the meaning.
_HAXE_OP_PRECEDENCE = {
    "||": 1,
    "&&": 2,
    # Haxe gives &, |, ^ equal precedence, left-to-right (not C-style tiers).
    "|": 3,
    "^": 3,
    "&": 3,
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


# Operators that are not associative/distributive with same-tier siblings on
# their right: a - (b + c) != a - b + c, a / (b * c) != a / b * c.
_HAXE_NON_ASSOC_OPS = {"-", "/", "%"}


# &, |, ^ share a precedence tier but aren't cross-associative: a & (b | c) != (a & b) | c.
# Same-operator chains (a & b & c) ARE associative and stay flat.
_HAXE_BITWISE_OPS = {"&", "|", "^"}


def _expr_to_haxe_with_precedence(
    expr: Optional[IRExpression],
    code: Bytecode,
    ir_function: Optional[IRFunction],
    parent_op: str,
    is_right: bool = False,
) -> str:
    """Render an expression, wrapping it in parentheses if its operator is
    lower-precedence than the parent's and would otherwise bind incorrectly.
    For the right operand of a non-associative op, same-tier children also
    need parens since flattening would silently change the value."""
    rendered = _expression_to_haxe(expr, code, ir_function)
    if _is_lambda_text(rendered):
        return _grouped(rendered, expr, code)
    # A conversion that renders as its operand (Int to Float) binds like the operand.
    outer = expr
    while isinstance(expr, IRCast) and strip(rendered) == strip(
        _expression_to_haxe(expr.expr, code, ir_function)
    ):
        expr = expr.expr
    if isinstance(expr, IRArithmetic):
        child_prec = _HAXE_OP_PRECEDENCE.get(expr.op.symbol, 10)
        parent_prec = _HAXE_OP_PRECEDENCE.get(parent_op, 10)
        needs_parens = (
            child_prec < parent_prec
            or (is_right and parent_op in _HAXE_NON_ASSOC_OPS and child_prec == parent_prec)
            or (
                is_right
                and parent_op in _HAXE_BITWISE_OPS
                and expr.op.symbol in _HAXE_BITWISE_OPS
                and expr.op.symbol != parent_op
            )
        )
        if needs_parens:
            return _grouped(rendered, outer, code)
    elif isinstance(expr, IRBoolExpr) and expr.op in (
        IRBoolExpr.CompareType.OR,
        IRBoolExpr.CompareType.AND,
    ):
        child_sym = "||" if expr.op == IRBoolExpr.CompareType.OR else "&&"
        child_prec = _HAXE_OP_PRECEDENCE.get(child_sym, 10)
        parent_prec = _HAXE_OP_PRECEDENCE.get(parent_op, 10)
        if child_prec < parent_prec:
            return _grouped(rendered, outer, code)
    return rendered


def _null_operand(expr: Optional[IRExpression], code: Bytecode, ir_function: Optional[IRFunction]) -> str:
    """The operand of a null test; a lambda (`(x) -> x`) takes the `== null` into its body
    unless grouped."""
    rendered = _expression_to_haxe(expr, code, ir_function)
    if expr is not None:
        # A Dynamic value tested as the type it was read at (`Dynamic<Array<Dynamic>>`'s field).
        rendered = _spell_dynamic_cast(expr, rendered, code)
    return f"({rendered})" if _is_lambda_text(rendered) else rendered


def _null_test(
    expr: Optional[IRExpression], code: Bytecode, ir_function: Optional[IRFunction], op: str
) -> str:
    """`expr == null` / `expr != null`. A basic type is never null (an inlined `isNull<T>`
    on an `Int`), and Haxe rejects the comparison on a static target: it's a constant."""
    if isinstance(expr, (IRLocal, IRConst)) and expr.get_type().kind.value in _NON_NULLABLE_KINDS:
        return "false" if op == "==" else "true"
    return f"{_null_operand(expr, code, ir_function)} {op} null"


def _paren_comparison_operand(
    expr: Optional[IRExpression], code: Bytecode, ir_function: Optional[IRFunction]
) -> str:
    """Render a comparison operand, parenthesizing it when it's itself a
    comparison — `<`/`==` are left-associative in Haxe, so `a < b == c < d`
    parses as `((a<b)==c)<d`, not `(a<b)==(c<d)`."""
    rendered = _expression_to_haxe(expr, code, ir_function)
    if _is_lambda_text(rendered):
        return f"({rendered})"
    if isinstance(expr, IRBoolExpr) and expr.op in (
        IRBoolExpr.CompareType.LT,
        IRBoolExpr.CompareType.LTE,
        IRBoolExpr.CompareType.GT,
        IRBoolExpr.CompareType.GTE,
        IRBoolExpr.CompareType.EQ,
        IRBoolExpr.CompareType.NEQ,
        IRBoolExpr.CompareType.ULT,
        IRBoolExpr.CompareType.UGTE,
    ):
        return f"({rendered})"
    return rendered


def _null_guarded_copy(
    stmt: IRConditional, code: Bytecode, ir_function: Optional[IRFunction]
) -> Optional[IRAssign]:
    """`v = x` for `if (x == null) v = null else v = <x as it renders>`."""
    condition = stmt.condition
    if not (
        isinstance(condition, IRBoolExpr)
        and condition.op in (IRBoolExpr.CompareType.NULL, IRBoolExpr.CompareType.NOT_NULL)
        and isinstance(condition.left, IRLocal)
        and stmt.false_block is not None
    ):
        return None
    null_arm, copy_arm = stmt.true_block, stmt.false_block
    if condition.op == IRBoolExpr.CompareType.NOT_NULL:
        null_arm, copy_arm = copy_arm, null_arm
    if len(null_arm.statements) != 1 or len(copy_arm.statements) != 1:
        return None
    nulled, copied = null_arm.statements[0], copy_arm.statements[0]
    if not (
        isinstance(nulled, IRAssign)
        and isinstance(copied, IRAssign)
        and isinstance(nulled.target, IRLocal)
        and nulled.target == copied.target
        and isinstance(nulled.expr, IRConst)
        and nulled.expr.const_type == IRConst.ConstType.NULL
        and isinstance(copied.expr, IRBoundClosure)
    ):
        return None
    if _expression_to_haxe(copied.expr, code, ir_function) != condition.left.name:
        return None
    return IRAssign(code, copied.target, condition.left)


def _call_args(expr: IRCall, code: Bytecode, ir_function: Optional[IRFunction], skip: int = 0) -> List[str]:
    """Rendered arguments of a call. HL passes an optional basic argument as an
    `hl.Ref` (null when omitted); Haxe source leaves an omitted trailing one out, and
    gives a declared basic parameter the value rather than a reference to it."""
    pos_comment = ""
    call_args = expr.args[skip:]
    # A typed array passed on as an erased `Array<Dynamic>` argument is a run-time conversion
    # that Haxe only makes through an explicit cast; an implicit one would keep the element type.
    rendered = [
        f"(cast {_expression_to_haxe(arg, code, ir_function)} : Array<Dynamic>)"
        if _widens_typed_array(arg, code)
        else _expression_to_haxe(arg, code, ir_function)
        for arg in call_args
    ]
    position = _elided_position(call_args[-1], ir_function, code) if call_args else None
    if position is not None:
        # The compiler fills the position in; source leaves it out, and the position stays as a comment.
        call_args = call_args[:-1]
        rendered = rendered[:-1]
        comment = f"/* pos: {position} */"
        pos_comment = comment
    if expr.target is None:
        return _with_comment(rendered, pos_comment)
    signature = expr.target.get_type().definition
    if not isinstance(signature, Fun):
        return _with_comment(rendered, pos_comment)
    # Parameters line up with the arguments from the end of the full argument list, before an
    # elided position is dropped from it.
    offset = len(signature.args) - len(expr.args) + skip
    if offset < 0:
        return _with_comment(rendered, pos_comment)
    params = [arg.resolve(code).definition for arg in signature.args[offset : offset + len(call_args)]]
    for i, arg in enumerate(call_args):
        if not isinstance(params[i], Dyn):
            continue
        rendered[i] = _ascribe_literal_for_dynamic(arg, rendered[i], code)
        annotation = _checked_dynamic_cast(arg, code)
        if annotation is None:
            continue
        target = arg.get_type().definition
        if "<" in annotation and any(
            j != i and _strip_casts(other).get_type().definition is target
            for j, other in enumerate(call_args)
        ):
            # Another argument may fix a type parameter at the same type with other type
            # arguments than the erased `<Dynamic>` the cast would name.
            continue
        rendered[i] = _spell_dynamic_cast(arg, rendered[i], code)
    for i, arg in enumerate(call_args):
        if not isinstance(arg.get_type().definition, Ref):
            continue
        # A reference made for this call only stands for the value it holds.
        made = arg
        if isinstance(arg, IRLocal) and ir_function is not None:
            defining = _find_defining_assignment(arg.name, ir_function.block)
            if isinstance(defining, IRAssign) and isinstance(defining.expr, IRRefNew):
                made = defining.expr
        guarded = (
            _null_guarded_ref_source(arg, ir_function.block)
            if isinstance(arg, IRLocal) and ir_function is not None and made is arg
            else None
        )
        if guarded is not None and isinstance(params[i], Ref):
            rendered[i] = _expression_to_haxe(guarded, code, ir_function)
        elif isinstance(made, IRRefNew) and isinstance(params[i], Ref):
            rendered[i] = _expression_to_haxe(made.target, code, ir_function)
        elif not isinstance(params[i], Ref):
            rendered[i] = f"{rendered[i]}.get()"
    while rendered:
        last = call_args[len(rendered) - 1]
        if not (
            isinstance(last, IRConst)
            and last.const_type == IRConst.ConstType.NULL
            and isinstance(params[len(rendered) - 1], Ref)
        ):
            break
        rendered.pop()

    # An omitted optional argument before required ones is left out too, which Haxe resolves
    # by type; `null` is not accepted for a basic type. Only when no later argument could be
    # taken for it, i.e. none has the same type.
    def _basic(param: object) -> str:
        return optional_basic_name(code, param)

    kept = []
    for i, text in enumerate(rendered):
        arg = call_args[i]
        if (
            isinstance(arg, IRConst)
            and arg.const_type == IRConst.ConstType.NULL
            and isinstance(params[i], Ref)
            and all(
                _basic(params[i]) != nullable_basic_name(code, call_args[j].get_type())
                for j in range(i + 1, len(rendered))
            )
            and all(_basic(params[i]) != _basic(params[j]) for j in range(i + 1, len(rendered)))
        ):
            continue
        kept.append(text)
    return _with_comment(kept, pos_comment)


def _store_chain(expr: "IRStoreExpr", code: Bytecode, ir_function: Optional[IRFunction]) -> str:
    """`a = b = value` for a chain of assignment expressions, without the outer parentheses."""
    value = expr.value
    value_str = (
        _store_chain(value, code, ir_function)
        if isinstance(value, IRStoreExpr)
        else _expression_to_haxe(value, code, ir_function)
    )
    return f"{_expression_to_haxe(expr.target, code, ir_function)} = {value_str}"


def _receiver_text(expr: IRExpression, code: Bytecode, ir_function: Optional[IRFunction]) -> str:
    """Render an array or field receiver. A Dynamic value the compiler typed by a cast to a class
    keeps that type named: without it a read of its field or element is typed through Dynamic."""
    text = _expression_to_haxe(expr, code, ir_function)
    if (
        isinstance(expr, IRCast)
        and not expr.untyped
        and expr.expr.get_type().kind.value == Type.Kind.DYN.value
        and isinstance(expr.get_type().definition, Obj)
        and not strip(text).startswith(("cast ", "(cast "))
    ):
        return f"({text} : {mapargs.refine(disasm._haxe_annotation(code, expr.get_type()), expr.map_value)})"
    return text


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
        arr_str = _receiver_text(expr.array, code, ir_function)
    idx_str = _expression_to_haxe(expr.index, code, ir_function)
    # ArrayObj/ArrayDyn stores element data in a `.array` backing field, exposed
    # via a plain `Field .array` read (unlike `.bytes`, no index shift). Strip
    # it so `wrapper.array[i] = v` renders as the public `wrapper[i] = v`.
    if isinstance(expr.array, IRField) and expr.array.field_name == "array":
        try:
            wrapper_type = disasm.type_name(code, expr.array.target.get_type())
        except IndexError:
            # Corrupt bytecode: the receiver's type/name table index is out of
            # range — treat it as an ordinary access, not an ArrayObj wrapper.
            wrapper_type = None
        if wrapper_type in ("hl.types.ArrayObj", "hl.types.ArrayDyn"):
            return _expression_to_haxe(expr.array.target, code, ir_function), idx_str, None
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
            kind = getattr(expr, "bytes_access_kind", None)
            if kind and kind != "UI8" and disasm.type_name(code, target.get_type()) == "String":
                # hl.Bytes indexes by byte; only its own accessor reads a wider element.
                return arr_str, _expression_to_haxe(expr.index, code, ir_function), kind
        else:
            arr_str = _expression_to_haxe(target, code, ir_function)
        idx_str = _expression_to_haxe(expr.index.left, code, ir_function)
        return arr_str, idx_str, None
    # Raw hl.Bytes temporaries that feed ArrayBase.alloc* are upgraded to
    # hl.BytesAccess<T>; render `bytes[idx << n]` as `bytes[idx]`.
    if (
        isinstance(expr.array, IRLocal)
        and disasm._haxe_annotation(code, expr.array.get_type()).startswith("hl.BytesAccess")
        and isinstance(expr.index, IRArithmetic)
        and expr.index.op.value == "<<"
        and isinstance(expr.index.right, IRConst)
    ):
        return (
            expr.array.name,
            _expression_to_haxe(expr.index.left, code, ir_function),
            None,
        )
    kind = getattr(expr, "bytes_access_kind", None)
    if kind and kind != "UI8":
        return arr_str, idx_str, kind
    return arr_str, idx_str, None


def _expression_for_type(
    expr: IRExpression, typ: Type, code: Bytecode, ir_function: Optional[IRFunction]
) -> str:
    value = _expression_to_haxe(expr, code, ir_function)
    if typ.kind.value == Type.Kind.BYTES.value and disasm.type_name(code, expr.get_type()) == "String":
        return f"(@:privateAccess ({value}).bytes)"
    return value


def _expression_to_haxe(
    expr: Optional[IRStatement],
    code: Bytecode,
    ir_function: Optional[IRFunction] = None,
) -> str:
    text = _render_expression(expr, code, ir_function)
    if marking() and isinstance(expr, IRExpression):
        return annotate_type(expr, annotate_expression(expr, text, code, ir_function), code)
    return text


def _render_expression(
    expr: Optional[IRStatement],
    code: Bytecode,
    ir_function: Optional[IRFunction] = None,
) -> str:
    assert expr is not None, "Found empty statement!"

    if isinstance(expr, IRLocal):
        if ir_function is not None:
            subs = getattr(ir_function, "_render_subs", None)
            if subs and expr in subs:
                # Render substitutions contain only bare local/constant atoms.
                return str(subs[expr][0])
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
            if is_std and name and "." not in name:
                # A std static used as a value (`var rd = Std.random`) is named through its class.
                full = code.full_func_name(func) or ""
                std_name = _std_call_name(func, code)
                if std_name and re.search(r"(^|\.)\$[^.]+\.[^.]+$", full):
                    return std_name
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
                        is_static_member = (
                            (code.full_func_name(func) or "")
                            .rsplit(".", 1)[0]
                            .rsplit(".", 1)[-1]
                            .startswith("$")
                        )
                        if (
                            first_arg_type_name == class_name
                            and ir_function is not None
                            and not is_static_member
                        ):
                            receiver = _find_receiver_local(class_name, ir_function, code)
                            if receiver:
                                return f"{receiver}.{method_name}"
                    return f"{class_name}.{method_name}"
            if name and is_std and "." not in name:
                # A std static used as a value (`Reflect.compareMethods(String.fromCharCode, ..)`).
                std_name = _std_call_name(func, code)
                if std_name and "." in std_name:
                    return std_name
            if name:
                return name
            inline = _inline_anonymous(func, code, ir_function)
            if inline is not None:
                return inline
            return f"__anon_{func.findex.value}"
        elif isinstance(expr.value, str):
            # Control characters are escaped (not just `"`) so an embedded
            # raw newline can't split the literal across physical lines -
            # otherwise a `/`-heavy remainder (e.g. base64) on the next line
            # reads as a real `//` comment instead of string data.
            return '"' + disasm._escape_str(expr.value, '"') + '"'
        elif isinstance(expr.value, bool):
            return "true" if expr.value else "false"
        elif expr.value is None:  # For IRConst.ConstType.NULL
            return "null"
        elif isinstance(expr.value, Type):
            if isinstance(expr.original_index, gIndex):
                # A global holding a class/enum's runtime type object — the base
                # of `Std.isOfType(x, C)`, `Type.resolveClass`, static-field
                # access (`C.field` lowers to GetGlobal C + Field), etc. Recover
                # the source-level name (`C`) instead of the opaque
                # `untyped $globalN()` fallback whenever the global's type is a
                # named class or enum.
                basic = _basic_type_globals(code).get(expr.original_index.value)
                if basic is not None:
                    return basic
                defn = expr.value.definition
                if isinstance(defn, Obj) and defn.name.resolve(code) == "hl.BaseType":
                    # The runtime type object of a primitive: Std.isOfType(x, Int), catch (e:Bool)...
                    basic = basic_type_of_global(code, expr.original_index.value)
                    basic_name = _BASIC_TYPE_NAMES.get(basic.kind.value) if basic is not None else None
                    if basic_name is not None:
                        return basic_name
                if isinstance(defn, (Obj, Enum)):
                    abstract = abstracts.abstract_of(code, defn) if isinstance(defn, Obj) else None
                    if abstract is not None:
                        return _abstract_ref(abstract, code, ir_function)
                    try:
                        resolved = defn.name.resolve(code)
                    except IndexError:
                        # Corrupt bytecode: the class/enum name's string index is
                        # out of range — keep the `$global` fallback below.
                        resolved = None
                    if resolved:
                        return destaticify(resolved)
                # Otherwise a genuine raw HL global with no source-level name.
                # Mirrors Haxe's `untyped $name(...)` idiom (zero-arg call to
                # read — see e.g. `get_allTypes()` in hl/_std/Type.hx).
                return f"untyped ${global_name(expr)}()"
            # Types as runtime values are used internally by the HashLink stdlib.
            # There is no direct Haxe equivalent, so emit null as a placeholder.
            return "null"
        elif isinstance(expr.value, Native):
            return _std_native_value(expr.value, code) or f"Native.{_native_binding_name(expr.value, code)}"
        elif expr.const_type == IRConst.ConstType.INT:
            val = expr.value.value if hasattr(expr.value, "value") else expr.value
            val = int(val)
            if val >= 0x80000000:
                val = val - 0x100000000
            return str(val)
        return str(expr.value)

    elif isinstance(expr, IRArithmetic):
        symbol = expr.op.symbol
        left = _expr_to_haxe_with_precedence(expr.left, code, ir_function, symbol)
        right = _expr_to_haxe_with_precedence(expr.right, code, ir_function, symbol, is_right=True)
        arithmetic = IRArithmetic.ArithmeticType
        if expr.get_type().kind.value == Type.Kind.I64.value:
            if expr.op in (arithmetic.SDIV, arithmetic.SMOD):
                return f"({left} : hl.I64) {symbol} ({right} : hl.I64)"
            if expr.op in (arithmetic.UDIV, arithmetic.UMOD):
                # Haxe has no UInt64. For a positive divisor, dividing half
                # the unsigned dividend gives a signed-safe quotient estimate
                # that needs at most one correction. A high-bit divisor fits
                # at most once. Flipping the sign bit gives unsigned ordering.
                result = "q" if expr.op == arithmetic.UDIV else "r"
                return (
                    "(function(a:hl.I64, b:hl.I64):hl.I64 { "
                    "var q:hl.I64 = 0; var r:hl.I64 = 0; "
                    "var sign:hl.I64 = (1 : hl.I64) << 63; "
                    "if (b != (0 : hl.I64)) { "
                    "if (b < (0 : hl.I64)) { "
                    "q = (a ^ sign) >= (b ^ sign) ? (1 : hl.I64) : (0 : hl.I64); r = a - q * b; "
                    "} else { "
                    "q = ((a >>> 1) / b) << 1; r = a - q * b; "
                    "if ((r ^ sign) >= (b ^ sign)) { q++; r -= b; } "
                    "} } "
                    f"return {result}; }})( {left}, {right} )"
                )
        if expr.op == arithmetic.UDIV and _is_int_kind(expr.get_type()):
            # UInt division is floating-point in Haxe. Std.int() cannot convert
            # quotients >= 2^31 back to their original I32 bit pattern. Widen
            # each operand once, zero-extend its low 32 bits, divide as I64,
            # then explicitly narrow the quotient without a float conversion.
            left = f"((({left} : hl.I64) << 32) >>> 32)"
            right = f"((({right} : hl.I64) << 32) >>> 32)"
            return f"(({left} / {right}) : hl.I64).toInt()"
        if _is_int_kind(expr.get_type()) and expr.op in (
            arithmetic.SDIV,
            arithmetic.SMOD,
            arithmetic.UMOD,
        ):
            # HL stores UInt in I32 registers. Explicit operand types prevent
            # signedness from being lost (or leaking in from another use) —
            # except where the operand is already written as an Int-typed
            # local or literal, where the annotation says nothing.
            operand_type = "UInt" if expr.op == arithmetic.UMOD else "Int"

            def annotate(operand: IRExpression, rendered: str) -> str:
                if operand_type == "Int" and _is_int_kind(operand.get_type()):
                    if isinstance(operand, (IRConst, IRLocal)):
                        return rendered
                return f"({rendered} : {operand_type})"

            result = f"{annotate(expr.left, left)} {symbol} {annotate(expr.right, right)}"
            if expr.op == arithmetic.SDIV:
                # Haxe recognizes Std.int(integer / integer) as integer division.
                return f"Std.int({result})"
            return result
        if expr.get_type().kind.value == Type.Kind.I32.value and symbol in ("-", "*"):
            # Haxe types arithmetic on a Dynamic operand as Float; the bytecode read it as an Int.
            left, right = (
                f"({text} : Int)" if _is_dynamic_int_read(operand) else text
                for operand, text in ((expr.left, left), (expr.right, right))
            )
        return f"{left} {symbol} {right}"

    elif isinstance(expr, IRNeg):
        inner = _expression_to_haxe(expr.expr, code, ir_function)
        if isinstance(expr.expr, IRArithmetic) or strip(inner).startswith("-"):
            inner = f"({inner})"  # `--1` would lex as a decrement
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
        negated_ops = {
            IRBoolExpr.CompareType.NOT_LT: "<",
            IRBoolExpr.CompareType.NOT_LTE: "<=",
            IRBoolExpr.CompareType.NOT_GT: ">",
            IRBoolExpr.CompareType.NOT_GTE: ">=",
        }
        if expr.op in negated_ops:
            symbol = negated_ops[expr.op]
            left = _expr_to_haxe_with_precedence(expr.left, code, ir_function, symbol)
            right = _expr_to_haxe_with_precedence(expr.right, code, ir_function, symbol, is_right=True)
            return f"!({left} {symbol} {right})"
        if expr.op in (IRBoolExpr.CompareType.ULT, IRBoolExpr.CompareType.UGTE):
            symbol = "<" if expr.op == IRBoolExpr.CompareType.ULT else ">="
            left = _expression_to_haxe(expr.left, code, ir_function)
            right = _expression_to_haxe(expr.right, code, ir_function)
            if expr.left is not None and expr.left.get_type().kind.value == Type.Kind.I64.value:
                sign = "((1 : hl.I64) << 63)"
                return f"(({left} : hl.I64) ^ {sign}) {symbol} (({right} : hl.I64) ^ {sign})"
            return f"({left} : UInt) {symbol} ({right} : UInt)"
        if expr.op == IRBoolExpr.CompareType.NULL:
            return _null_test(expr.left, code, ir_function, "==")
        elif expr.op == IRBoolExpr.CompareType.NOT_NULL:
            return _null_test(expr.left, code, ir_function, "!=")
        elif expr.op == IRBoolExpr.CompareType.ISTRUE:
            return _expression_to_haxe(expr.left, code, ir_function)
        elif expr.op == IRBoolExpr.CompareType.ISFALSE:
            return f"!{_expression_to_haxe(expr.left, code, ir_function)}"
        elif expr.op == IRBoolExpr.CompareType.NOT:
            return f"!({_expression_to_haxe(expr.left, code, ir_function)})"
        elif expr.op == IRBoolExpr.CompareType.TRUE:
            return "true"
        elif expr.op == IRBoolExpr.CompareType.FALSE:
            return "false"
        elif expr.op in (IRBoolExpr.CompareType.OR, IRBoolExpr.CompareType.AND):
            sym = "||" if expr.op == IRBoolExpr.CompareType.OR else "&&"
            matched = _enum_match_prefix(expr, code, ir_function) if sym == "&&" else None
            if matched is not None:
                return matched
            left = _expr_to_haxe_with_precedence(expr.left, code, ir_function, sym)
            right = _expr_to_haxe_with_precedence(expr.right, code, ir_function, sym)
            return f"{left} {sym} {right}"
        elif expr.left and expr.right and expr.op in op_map:
            # Normalize: constants on the right side for natural-reading output.
            actual_op: IRBoolExpr.CompareType = expr.op
            left_expr, right_expr = expr.left, expr.right
            if (
                isinstance(left_expr, IRConst)
                and not isinstance(right_expr, IRConst)
                and actual_op in swap_map
            ):
                left_expr, right_expr = right_expr, left_expr
                actual_op = swap_map[actual_op]
            constant = _constant_null_compare(left_expr, right_expr, actual_op)
            if constant is not None:
                return constant
            typekind_render = _render_typekind_comparison(left_expr, right_expr, code, ir_function)
            if typekind_render is not None:
                left, right = typekind_render
            else:
                # Comparison operands of an equality/relational op need parens:
                # `a < b == c < d` would otherwise parse as `((a<b)==c)<d`.
                left = _spell_dynamic_cast(
                    left_expr, _paren_comparison_operand(left_expr, code, ir_function), code
                )
                right = _spell_dynamic_cast(
                    right_expr, _paren_comparison_operand(right_expr, code, ir_function), code
                )
                left, right = _type_i64_literals(left_expr, right_expr, left, right)
            if (
                actual_op in (IRBoolExpr.CompareType.EQ, IRBoolExpr.CompareType.NEQ)
                and isinstance(right_expr, IRConst)
                and right_expr.const_type == IRConst.ConstType.NULL
                and isinstance(left_expr, IRCast)
                and left_expr.get_type().kind.value == Type.Kind.NULL.value
                and left_expr.expr.get_type().kind.value
                in (Type.Kind.I32.value, Type.Kind.F64.value, Type.Kind.BOOL.value)
            ):
                # A primitive compared with null goes through `Null<T>`; bare `i == null`
                # is an error on static targets.
                left = f"({left} : {disasm._haxe_annotation(code, left_expr.get_type())})"
            return f"{left} {op_map[actual_op]} {right}"
        elif expr.left:
            raise NotImplementedError(f"Unhandled unary IRBoolExpr op: {expr.op} on {expr.left}")
        else:
            raise NotImplementedError(f"Unhandled IRBoolExpr: {expr}")

    elif isinstance(expr, IRTernary):
        # `cond ? a : b`. Parenthesize the condition when it's a compound
        # boolean so it reads correctly against the `?`.
        cond = _expression_to_haxe(expr.condition, code, ir_function)
        then = _expression_to_haxe(expr.then_expr, code, ir_function)
        otherwise = _expression_to_haxe(expr.else_expr, code, ir_function)
        return f"({cond} ? {then} : {otherwise})"

    elif isinstance(expr, IRNullCoalesce):
        # `value ?? default`. The null test is the guard of the unboxing, so an unboxing cast on the
        # left (which would turn a null into zero before the test) is not part of the source.
        operand = expr.value
        while isinstance(operand, IRCast) and operand.get_type().kind.value in (
            Type.Kind.I32.value,
            Type.Kind.F64.value,
            Type.Kind.BOOL.value,
        ):
            operand = operand.expr
        value = _expression_to_haxe(operand, code, ir_function)
        default = _expression_to_haxe(expr.default, code, ir_function)
        return f"({value} ?? {default})"

    elif isinstance(expr, IRField):
        # Render the field base without render-time substitutions: substituting
        # a different local here would change the object the field is read from.
        if isinstance(expr.target, IRLocal):
            target_str = expr.target.name
        else:
            target_str = _receiver_text(expr.target, code, ir_function)
        target_type = expr.target.get_type()
        type_name = disasm.type_name(code, target_type)
        if isinstance(expr.target, IRCast) and isinstance(target_type.definition, Virtual):
            # A class or Dynamic value viewed as an interface to read one of its fields: the value itself has no such field.
            # A class converted to one of its interfaces caches the conversion, which only naming the interface repeats.
            source_def = expr.target.expr.get_type().definition
            interface = (
                ifacenames.conversion(code, source_def, target_type.definition)
                if isinstance(source_def, Obj)
                else None
            )
            annotation = (
                disasm.type_to_haxe(interface.name)
                if interface is not None
                else disasm._haxe_annotation(code, target_type)
            )
            target_str = f"(cast {target_str} : {mapargs.refine(annotation, expr.target.map_value)})"
        if isinstance(target_type.definition, Obj) and is_static_name(type_name):
            if expr.dynamic:
                # `var d:Dynamic = Cls; d.field`: the class object read through Dynamic.
                class_name = _static_owner_path(code, target_type.definition, type_name, ir_function)
                return f"({class_name} : Dynamic).{expr.field_name}"
            # A typed HL static-storage access must stay statically visible to
            # Haxe's DCE; a Dynamic alias can discard the referenced field.
            return _std_private_access(
                _static_member_path(code, target_type.definition, type_name, expr.field_name, ir_function),
                target_type.definition,
                expr.field_name,
                code,
                ir_function,
            )
        if expr.dynamic and (
            isinstance(target_type.definition, Obj) or disasm.type_name(code, expr.get_type()) == "Dyn"
        ):
            # The compiler read a field through Dynamic. A null or structural receiver would
            # otherwise type the access statically, so keep the Dynamic cast. A read the compiler
            # typed itself (a method closure of a structure) is not one the cast belongs to.
            return f"({target_str} : Dynamic).{expr.field_name}"
        if type_name == "String" and expr.field_name == "bytes":
            return f"(@:privateAccess {target_str}.bytes)"
        # Public Array<T> hides the fields of its concrete HL representation.
        # Retained reads still need to evaluate that field (including a possible
        # null fault), not become invalid `array.bytes` source or disappear.
        backing_type = None
        if type_name.startswith("hl.types.ArrayBytes_") and expr.field_name in ("bytes", "size"):
            backing_type = disasm.type_to_haxe(type_name).replace("Array<", "hl.types.ArrayBytes<", 1)
        elif type_name == "hl.types.ArrayObj" and expr.field_name == "array":
            backing_type = "hl.types.ArrayObj<Dynamic>"
        elif type_name == "hl.types.ArrayDyn" and expr.field_name in ("array", "allowReinterpret"):
            backing_type = "hl.types.ArrayDyn"
        if backing_type is not None:
            return f"(@:privateAccess (cast {target_str} : {backing_type}).{expr.field_name})"
        # Static field access on a class type constant: Type.field -> Class.field
        if isinstance(expr.target, IRConst) and isinstance(expr.target.value, Type):
            defn = expr.target.value.definition
            if isinstance(defn, Obj):
                return _std_private_access(
                    _static_member_path(code, defn, defn.name.resolve(code), expr.field_name, ir_function),
                    defn,
                    expr.field_name,
                    code,
                    ir_function,
                )
        # Enum constructor parameters are not real Haxe fields. Cast to Dynamic.
        if isinstance(target_type.definition, Enum) and expr.field_name.startswith("param"):
            return f"({target_str} : Dynamic).{expr.field_name}"
        # A std class's private field (an inlined `BytesBuffer.addByte` reads `pos`).
        if isinstance(target_type.definition, Obj):
            return _std_private_access(
                f"{target_str}.{expr.field_name}", target_type.definition, expr.field_name, code, ir_function
            )
        if strip(target_str) == "{}":
            return f"({{}} : Dynamic).{expr.field_name}"  # a bare `{}.x` isn't an expression
        return f"{target_str}.{expr.field_name}"

    elif isinstance(expr, IRBoundClosure):
        # InstanceClosure captures the current environment value, not the
        # mutable local holding it. Bind it now so later local assignments do
        # not retarget the closure, while mutations of that environment remain
        # visible to every closure sharing it.
        if expr.captures is not None:
            ctx_entry = getattr(ir_function, "_ctx_closure_bodies", {}).get(expr.fun.findex.value)
            if ctx_entry is not None:
                getattr(ir_function, "_inlined_closures", set()).add(expr.fun.findex.value)
                captured = [_expression_to_haxe(c, code, ir_function) for c in expr.captures]
                params, body = ctx_entry
                body = _unshadow_captures(body, captured)
                body = re.sub(
                    rf"(?:{OPEN}.)?{_CTX_MARK}(\d+){_CTX_MARK}(?:{CLOSE})?",
                    lambda m: captured[int(m.group(1))],
                    body,
                )
                return f"({', '.join(params[1:])}) -> {body}"
        # The function is the head of a `.bind`, so it takes the environment as its first parameter and
        # has to stay a typed helper rather than become a lambda.
        previous = getattr(ir_function, "_bind_head", False)
        setattr(ir_function, "_bind_head", True)
        try:
            fun_str = _expression_to_haxe(expr.fun_const, code, ir_function)
        finally:
            setattr(ir_function, "_bind_head", previous)
        obj_str = _expression_to_haxe(expr.obj, code, ir_function)
        fun_type = expr.fun.type.resolve(code).definition
        extra_args = fun_type.args[1:] if isinstance(fun_type, Fun) else []
        adapted = _closure_adapter(expr, obj_str, code, ir_function)
        if adapted is not None:
            return adapted
        # A lambda reads its captured local when it runs; the closure bound the value when it was
        # made, so a later write to the local needs the `bind` form (a lambda would box the variable).
        stale = _written_after(expr, ir_function)
        inline = None if stale else _inline_closure(expr, obj_str, len(extra_args), code, ir_function)
        if inline is not None:
            return inline
        block = None if stale else _inline_block_closure(expr, obj_str, len(extra_args), code, ir_function)
        if block is not None:
            return block
        context_bind = _context_bind(expr, code, ir_function)
        if context_bind is not None:
            return context_bind
        forwarded = _forwarded_bind(expr, obj_str, code, ir_function)
        if forwarded is not None:
            # `Type.method.bind(a, _)`: the compiler wraps the function in a helper that only calls it.
            return forwarded
        bind_args = ", ".join([obj_str] + ["_"] * len(extra_args))
        return f"({fun_str}).bind({bind_args})"

    elif isinstance(expr, IRArrayAccess):
        arr_str, idx_str, method_kind = _resolve_array_access(expr, code, ir_function)
        if method_kind is not None:
            return f"{arr_str}.get{method_kind}({idx_str})"
        if idx_str == "0" and strip(arr_str) in getattr(ir_function, "_unboxed_captures", ()):
            return arr_str  # the variable itself: its capture box is not part of the source
        return f"{arr_str}[{idx_str}]"

    elif isinstance(expr, IRClassCast):
        return f"cast({_expression_to_haxe(expr.value, code, ir_function)}, {_expression_to_haxe(expr.class_ref, code, ir_function)})"

    elif isinstance(expr, IRDowncast):
        class_text = _expression_to_haxe(expr.class_ref, code, ir_function)
        if strip(class_text) == "hl.types.ArrayBase":
            class_text = "Array"  # the class object `Array` reaches HashLink as its base class
        return f"Std.downcast({_expression_to_haxe(expr.value, code, ir_function)}, {class_text})"

    elif isinstance(expr, IRPostIncrement):
        target_text = _expression_to_haxe(expr.target, code, ir_function)
        step = "++" if expr.delta > 0 else "--"
        unwrapped = _unwrap_span(target_text)
        if unwrapped.startswith("(@:privateAccess ") and unwrapped.endswith(")"):
            return f"{unwrapped[:-1]}{step})"  # the access wraps the whole place, not just its value
        return f"{target_text}{step}"

    elif isinstance(expr, IRStoreExpr):
        return f"({_store_chain(expr, code, ir_function)})"

    elif isinstance(expr, IRArrayLiteral):
        if id(expr) in getattr(ir_function, "_unboxed_literals", ()):
            return _expression_to_haxe(expr.elements[0], code, ir_function)
        elements = ", ".join(_expression_to_haxe(e, code, ir_function) for e in expr.elements)
        literal = f"[{elements}]"
        ascription = _array_literal_ascription(expr, code)
        return f"({literal} : {ascription})" if ascription is not None else literal

    elif isinstance(expr, IRObjectLiteral):
        fields = ", ".join(
            f"{_literal_key(k)}: {_expression_to_haxe(v, code, ir_function)}" for k, v in expr.fields
        )
        return f"{{ {fields} }}" if fields else "{}"

    elif isinstance(expr, IRRef):
        # TODO: handle IRRef more cleanly
        inner = _expression_to_haxe(expr.target, code, ir_function)
        return inner

    elif isinstance(expr, IRPosInfos):
        return _expression_to_haxe(expr.original, code, ir_function)

    elif isinstance(expr, IRStringConvert):
        return f"Std.string({_expression_to_haxe(expr.value, code, ir_function)})"

    elif isinstance(expr, IRRefNew):
        # A reference takes the address of the VM local, not its current
        # render-time substitution (which may be a constant or computation).
        inner = (
            expr.target.name
            if isinstance(expr.target, IRLocal)
            else _expression_to_haxe(expr.target, code, ir_function)
        )
        return f"new hl.Ref({inner})"

    elif isinstance(expr, IRRefGet):
        ref_str = _expression_to_haxe(expr.ref, code, ir_function)
        return f"{ref_str}.get()"

    elif isinstance(expr, IREnumConstruct):
        # Qualified with the enum: a bare constructor only resolves where Haxe can infer
        # the enum from context, which a Dynamic or generic argument does not give it.
        # (A synthesized anonymous enum, see disasm.type_name, is qualified the same way,
        # so its construct isn't taken for whatever real global shares the name.)
        construct_name = expr.construct_name
        enum_def = expr.enum_type_idx.resolve(code).definition
        if isinstance(enum_def, Enum):
            construct_name = f"{destaticify(disasm._enum_name(code, enum_def))}.{construct_name}"
        if expr.args:
            params: List[Any] = []
            if isinstance(enum_def, Enum):
                params = next(
                    (c.params for c in enum_def.constructs if c.name.resolve(code) == expr.construct_name), []
                )
            rendered_args = []
            for i, a in enumerate(expr.args):
                arg = _expression_to_haxe(a, code, ir_function)
                if (
                    i < len(params)
                    and params[i].resolve(code).kind.value == Type.Kind.DYN.value
                    and a.get_type().kind.value != Type.Kind.DYN.value
                    and arg != "null"
                ):
                    # A generic constructor's parameter is erased to Dynamic; Haxe would infer the
                    # argument's own type (`Option<Int>`) for the value, which the erased `Option<Dynamic>`
                    # signatures it is passed to and returned from do not accept.
                    arg = f"({arg} : Dynamic)"
                rendered_args.append(arg)
            return f"{construct_name}({', '.join(rendered_args)})"
        return construct_name

    elif isinstance(expr, IREnumIndex):
        inner = _expression_to_haxe(expr.value, code, ir_function)
        return f"Type.enumIndex({inner})"

    elif isinstance(expr, IREnumField):
        if expr.binding is not None:
            return expr.binding.name
        if (
            isinstance(expr.value, IRLocal)
            and getattr(ir_function, "_ctx_param", None) == expr.value.name
            and expr.field_name.startswith("param")
        ):
            return f"{_CTX_MARK}{int(expr.field_name.removeprefix('param'))}{_CTX_MARK}"
        inner = _expression_to_haxe(expr.value, code, ir_function)
        index = int(expr.field_name.removeprefix("param"))
        enum_def = expr.value.get_type().definition
        if isinstance(enum_def, Enum) and len(enum_def.constructs) == 1:
            # The only constructor needs no index test: the compiler read the parameter straight
            # from the value, which only a pattern match on it does in source.
            slots = ["_"] * len(enum_def.constructs[0].params)
            slots[index] = "__param"
            name = disasm.enum_construct_name(code, enum_def, 0)
            # Qualified: a bare constructor name can be shadowed by a type of the same name.
            name = f"{destaticify(disasm._enum_name(code, enum_def))}.{name}"
            return f"(switch ({inner}) {{ case {name}({', '.join(slots)}): __param; }})"
        raw = f"Type.enumParameters({inner})[{index}]"
        # The parameter list is Array<Dynamic>; give the read back the field's own type, or an
        # expression such as `a[0] + param[0]` is typed as Dynamic arithmetic (Float).
        annotation = disasm._haxe_annotation(code, expr.get_type())
        if annotation in ("Dynamic", "Array<Dynamic>", "Void") or "<" in annotation.split("Array<", 1)[0]:
            return raw
        return f"({raw} : {annotation})"

    elif isinstance(expr, IRInlineCall):
        args_str = ", ".join(_expression_to_haxe(a, code, ir_function) for a in expr.args)
        return f"{expr.owner}.{expr.name}({args_str})"
    elif isinstance(expr, IRCall):
        callee_str: str
        if (
            expr.target is not None
            and isinstance(expr.target, IRConst)
            and isinstance(expr.target.value, Function)
        ):
            func = expr.target.value
            partial = code.partial_func_name(func)
            # Rewrite String.__add__ to Haxe's + operator (or interpolation).
            if _is_std_function(func, code) and partial == "__add__" and len(expr.args) == 2:
                if code.full_func_name(func) == "$Std.__add__":
                    # Dynamic addition: the result stays Dynamic even with a String operand, so
                    # keep one side Dynamic or Haxe types `"4" + b` as String at its use.
                    left, right = expr.args
                    operands = []
                    for operand in (left, right):
                        text = _expression_to_haxe(operand, code, ir_function)
                        if operand.get_type().kind.value != Type.Kind.DYN.value:
                            # A String operand beside a Dynamic one is a String concatenation; only
                            # two Dynamic operands add through Std.__add__.
                            text = f"({text} : Dynamic)"
                        operands.append(text)
                    return f"({operands[0]} + {operands[1]})"
                rendered = _render_string_concat(expr, code, ir_function)
                if rendered is not None:
                    return rendered
            # `Reflect.makeVarArgs(f)` is an extern generic over the function's return type; the
            # compiler calls the private `_makeVarArgs` with `f` adapted to return Dynamic.
            if (
                _is_std_function(func, code)
                and code.full_func_name(func) == "$Reflect._makeVarArgs"
                and len(expr.args) == 1
            ):
                return f"Reflect.makeVarArgs({_expression_to_haxe(expr.args[0], code, ir_function)})"
            # `cast(v, C)` and `Std.isOfType(v, C)` on a class reach `hl.BaseType.check` with the
            # class object as receiver; source has no such call, `Std.isOfType` is the same test.
            if (
                _is_std_function(func, code)
                and code.full_func_name(func) == "hl.BaseType.check"
                and len(expr.args) == 2
            ):
                cls = _expression_to_haxe(expr.args[0], code, ir_function)
                return f"Std.isOfType({_expression_to_haxe(expr.args[1], code, ir_function)}, {cls})"

        # An abstract's members are statics of its `_Impl_` class, which source can't
        # name: go back to the abstract's own syntax.
        if isinstance(expr.target, IRConst) and isinstance(expr.target.value, Function):
            abstract = abstracts.abstract_of_function(code, expr.target.value)
            if abstract is not None:
                return _render_abstract_call(expr, expr.target.value, abstract, code, ir_function)

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
        if isinstance(expr.target, IRField) and _has_array_access(expr.target.target.get_type(), code):
            if expr.target.field_name in ("getDyn", "get") and len(expr.args) == 1:
                arr = _expression_to_haxe(expr.target.target, code, ir_function)
                idx = _expression_to_haxe(expr.args[0], code, ir_function)
                return f"{arr}[{idx}]"
            if expr.target.field_name in ("setDyn", "set") and len(expr.args) == 2:
                arr = _expression_to_haxe(expr.target.target, code, ir_function)
                idx = _expression_to_haxe(expr.args[0], code, ir_function)
                val = _expression_to_haxe(expr.args[1], code, ir_function)
                return f"{arr}[{idx}] = {val}"

        accessor_call = expr.target.expr if isinstance(expr.target, IRCast) else expr.target
        if isinstance(accessor_call, IRField):
            prop = disasm.structure_accessor_name(
                code, accessor_call.target.get_type(), accessor_call.field_name, len(expr.args)
            )
            if prop is not None:
                obj = _expression_to_haxe(accessor_call.target, code, ir_function)
                if not expr.args:
                    return f"{obj}.{prop}"
                return f"{obj}.{prop} = {_expression_to_haxe(expr.args[0], code, ir_function)}"

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
                instance_method = _try_instance_method_call(
                    expr.target.value, expr.args[0], code, ir_function
                )
                if instance_method:
                    rest_args = expr.args[1:]
                    # get_X()/set_X(v) calls into a std-lib property accessor
                    # collapse to `obj.X` / `obj.X = v` sugar, since the
                    # accessor method itself is private and can't be called
                    # directly.
                    prop_name = _std_property_accessor_name(expr.target.value, code, len(rest_args))
                    if prop_name is not None:
                        obj_str = instance_method.rsplit(".", 1)[0]
                        if not rest_args:
                            if isinstance(expr.get_type().definition, Obj) and disasm.type_name(
                                code, expr.get_type()
                            ).startswith("hl.types.Array"):
                                # The property may be an abstract over an array (`Exception.stack` is
                                # a `CallStack`); the bytecode only knows the array it wraps.
                                return f"(cast {obj_str}.{prop_name} : {_return_annotation(code, expr.target.value, expr.get_type())})"
                            return f"{obj_str}.{prop_name}"
                        return (
                            f"{obj_str}.{prop_name} = {_expression_to_haxe(rest_args[0], code, ir_function)}"
                        )
                    callee_str = instance_method
                    args_str = ", ".join(
                        _call_args(expr, code, ir_function, skip=len(expr.args) - len(rest_args))
                    )
                    rendered_call = f"{callee_str}({args_str})"
                    if _call_needs_private_access(expr.target.value, code):
                        return f"(@:privateAccess {rendered_call})"
                    return rendered_call

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
                return f"cast hl.types.ArrayObj.alloc({arg_str})"

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
                return f"(@:privateAccess String.__alloc__({bytes_str}, {len_str}))"

            callee_str = _expression_to_haxe(expr.target, code, ir_function)
            if strip(callee_str) == "null":
                # A constant-propagated optional callback (an inlined `?onDone`): Haxe
                # only calls it once the type says it's a function, which the call gives.
                params = ", ".join(disasm._haxe_annotation(code, arg.get_type()) for arg in expr.args)
                ret = disasm._haxe_annotation(code, expr.get_type())
                callee_str = f"(null : ({params}) -> {ret})"
            elif expr.dynamic_callee and expr.target.get_type().kind.value != Type.Kind.DYN.value:
                # Called through Dynamic, the call returns Dynamic, not the function's own type.
                callee_str = f"({callee_str} : Dynamic)"
            elif expr.call_type == IRCall.CallType.CLOSURE:
                # A function read out of Dynamic at its type (`iterable.iterator`), then called.
                callee_str = _spell_dynamic_cast(expr.target, callee_str, code)
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

        if isinstance(expr.target, IRConst) and isinstance(expr.target.value, Native):
            signature = expr.target.value.type.resolve(code).definition
            if not isinstance(signature, Fun) or len(signature.args) != len(expr.args):
                raise ValueError("Native call does not match its recovered signature")
            arg_strs = [
                _expression_for_type(arg, typ.resolve(code), code, ir_function)
                for arg, typ in zip(expr.args, signature.args)
            ]
            std_api = _std_native_api(expr.target.value, code)
            if std_api is not None:
                owner, method, is_static, is_public = std_api
                call = None
                if is_static:
                    call = f"{owner}.{method}({', '.join(arg_strs)})"
                elif arg_strs:
                    call = f"{_wrap_receiver(arg_strs[0])}.{method}({', '.join(arg_strs[1:])})"
                if call is not None:
                    return call if is_public else f"(@:privateAccess {call})"
            args_str = ", ".join(arg_strs)
        else:
            args_str = ", ".join(_call_args(expr, code, ir_function))
        # HashLink's internal ArrayBase.alloc* helpers return ArrayBytes_* types
        # that are not directly assignable to Array<T> locals. Insert a cast so
        # the decompiled output recompiles without changing the underlying call.
        call_name = ""
        if (
            expr.target is not None
            and isinstance(expr.target, IRConst)
            and isinstance(expr.target.value, Function)
        ):
            call_name = (
                code.full_func_name(expr.target.value) or code.partial_func_name(expr.target.value) or ""
            )
        if "ArrayBase.alloc" in call_name:
            return f"cast {callee_str}({args_str})"
        if call_name.endswith("ArrayDyn.alloc") and len(expr.args) == 2:
            value = _expression_to_haxe(expr.args[0], code, ir_function)
            source_type = expr.args[0].get_type()
            if disasm._haxe_annotation(code, source_type).startswith("Array<"):
                # Public erased arrays are ArrayDyn wrappers. The native
                # allocation helper accepts their ArrayBase storage instead.
                value = f"(@:privateAccess (cast {value} : hl.types.ArrayDyn).array)"
            flag = _expression_to_haxe(expr.args[1], code, ir_function)
            if isinstance(expr.args[1].get_type().definition, Ref):
                flag = f"({flag}).get()"
            return f"cast {callee_str}({value}, {flag})"
        unwrapped_callee = _unwrap_span(callee_str)
        if (
            isinstance(expr.target, IRField)
            and unwrapped_callee.startswith("(@:privateAccess ")
            and unwrapped_callee.endswith(")")
        ):
            # A private method: calling the wrapped field would call a closure of it.
            return f"(@:privateAccess {unwrapped_callee[len('(@:privateAccess ') : -1]}({args_str}))"
        if _is_lambda_text(callee_str):
            callee_str = f"({callee_str})"
        elif (
            expr.call_type == IRCall.CallType.CLOSURE
            and expr.target is not None
            and unwrapped_callee.startswith("new ")
            and isinstance(expr.target.get_type().definition, Fun)
        ):
            # A constructed abstract over a function isn't callable itself (`@:callable` is
            # lost); the function it holds is.
            callee_str = f"({callee_str} : {disasm._haxe_annotation(code, expr.target.get_type())})"
        result = f"{callee_str}({args_str})"
        if (
            isinstance(expr.target, IRConst)
            and isinstance(expr.target.value, Function)
            and _call_needs_private_access(expr.target.value, code)
            # `__`-prefixed internals render as our own `StdFuncs` extern stub,
            # which is public and needs no annotation.
            and _std_call_name(expr.target.value, code) is not None
        ):
            return f"(@:privateAccess {result})"
        return result

    elif isinstance(expr, IRUnliftedOpcode):
        regs = ir_function.func.regs if ir_function is not None else []
        try:
            op_str = disasm.pseudo_from_op(expr.op, 0, regs, code, terse=True)
        except (KeyError, IndexError, ValueError, MalformedBytecode):
            # Lifted/reconstructed streams carry placeholder register types and
            # corrupt operands index past their table; fall back to the
            # exception-guarded compact printer.
            op_str = disasm.fmt_op_compact(
                code, regs, expr.op, 0, func=ir_function.func if ir_function else None
            )
        return f"/* UNLIFTED OPCODE: {expr.op.op} {op_str} */"

    elif isinstance(expr, IRNew):
        type_name = disasm.type_name(code, expr.get_type())
        if type_name == "DynObj":
            return "{}"
        if type_name.startswith("Virtual["):
            # A structure whose fields are stored one by one (a literal that could not be
            # folded): an empty literal does not satisfy the structure.
            return "cast {}" if type_name != "Virtual[]" else "{}"
        elif type_name == "hl.types.ArrayObj" and not expr.constructor_args:
            # `new ArrayObj()` is Haxe's `new Array<T>()`; a literal `[]` allocates the native
            # array and wraps it instead. The context (the local's declared Array<T>) gives T.
            # ArrayDyn (`new Array<Dynamic>()`) uses a different allocation
            # pattern, so leave it as `new Array<Dynamic>()`.
            return "new Array()"
        else:
            ctor_args = [_expression_to_haxe(a, code, ir_function) for a in expr.constructor_args]
            ctor_owner = expr.get_type().definition
            ctor = _find_constructor(code, ctor_owner) if isinstance(ctor_owner, Obj) else None
            ctor_sig = ctor.type.resolve(code).definition if ctor is not None else None
            if isinstance(ctor_sig, Fun) and len(ctor_sig.args) == len(expr.constructor_args) + 1:
                for i, a in enumerate(expr.constructor_args):
                    if isinstance(ctor_sig.args[i + 1].resolve(code).definition, Dyn):
                        ctor_args[i] = _ascribe_literal_for_dynamic(a, ctor_args[i], code)
            args_str = ", ".join(ctor_args)
            rendered = f"new {mapargs.refine(disasm.STD_WRAPPED.get(type_name) or disasm.type_to_haxe(type_name), getattr(expr, 'map_value', None))}{disasm.generic_arguments(code, expr.get_type())}({args_str})"
            owner = expr.get_type().definition
            # A private constructor of a std class (an inlined `JsonParser.parse`).
            return (
                _std_private_access(rendered, owner, "new", code, ir_function)
                if isinstance(owner, Obj)
                else rendered
            )

    elif isinstance(expr, IRNativeArrayNew):
        elem_haxe_type = disasm._haxe_annotation(code, expr.elem_type)
        size_str = _expression_to_haxe(expr.size, code, ir_function)
        return f"new hl.NativeArray<{elem_haxe_type}>({size_str})"

    elif isinstance(expr, IRNativeMapNew):
        return f"new {expr.haxe_class_name}()"

    elif isinstance(expr, IRBytesNew):
        return f"new hl.Bytes({_expression_to_haxe(expr.size, code, ir_function)})"

    elif isinstance(expr, IRCast):
        if expr.untyped:
            return f"cast ({_expression_to_haxe(expr.expr, code, ir_function)})"
        target_name = disasm.type_name(code, expr.get_type())
        # `(T)null` for a non-nullable primitive T (a HL verifier-satisfying
        # placeholder, e.g. pre-growing an Array<Int>'s backing storage) isn't
        # valid Haxe on static targets — it is the explicit conversion of null, which reads as
        # the type's own default value and compiles to the same Null + SafeCast.
        if isinstance(expr.expr, IRConst) and expr.expr.const_type == IRConst.ConstType.NULL:
            default_literal = {"I32": "Int", "F32": "Single", "F64": "Float", "Bool": "Bool"}.get(target_name)
            if default_literal is not None:
                return f"cast(null, {default_literal})"
            if isinstance(expr.get_type().definition, Obj):
                return "cast null"  # a SafeCast of the Dynamic null to a class
        source_name = disasm.type_name(code, expr.expr.get_type())
        if expr.unsafe and isinstance(expr.expr, IRField) and expr.expr.dynamic:
            # An unchecked read of a Dynamic<T> field: the compiler types the read through Dynamic<T>.
            field = expr.expr
            if isinstance(field.target, IRLocal):
                target_str = field.target.name
            else:
                target_str = _expression_to_haxe(field.target, code, ir_function)
            return f"(({target_str} : Dynamic<{disasm._haxe_annotation(code, expr.get_type())}>).{field.field_name})"
        widened = expr.expr
        if (
            isinstance(widened, IRCast)
            and not widened.untyped
            and not expr.unsafe
            and not isinstance(widened.expr, IRConst)
            and widened.get_type().kind.value == Type.Kind.F64.value
            and widened.expr.get_type().kind.value == Type.Kind.I32.value
            and (
                expr.get_type().kind.value == Type.Kind.DYN.value
                or isinstance(expr.get_type().definition, Null)
            )
        ):
            # An Int widened to a Float and boxed at once: only the ascription makes the Int a Float,
            # a bare Int would be boxed as one.
            return f"({_expression_to_haxe(widened.expr, code, ir_function)} : Float)"
        inner = _expression_to_haxe(expr.expr, code, ir_function)
        boxed = expr.expr
        if (
            expr.unsafe
            and isinstance(boxed, IRCall)
            and isinstance(boxed.target, IRConst)
            and isinstance(boxed.target.value, Function)
            and generics.return_variable(code, boxed.target.value) is not None
        ):
            # The compiler's own cast of a call that returns a type variable: the context fixes it.
            return inner
        if (
            not expr.unsafe
            and expr.get_type().kind.value != Type.Kind.DYN.value
            and isinstance(boxed, IRCast)
            and not boxed.untyped
            and boxed.get_type().kind.value == Type.Kind.DYN.value
            and boxed.expr.get_type().kind.value in _NULLABLE_BASIC_KINDS
        ):
            # A value converted out of Dynamic right after being boxed into it: the compiler folded
            # a Dynamic local or field into its value but kept it typed Dynamic.
            inner = f"({_expression_to_haxe(boxed.expr, code, ir_function)} : Dynamic)"
        elif expr.get_type().kind.value in _NULLABLE_BASIC_KINDS:
            # A `Null<T>` read out of Dynamic (a `Null<T>` field or return of a type parameter),
            # then unboxed: the read is a conversion of its own, which a `T` context would skip.
            inner = _spell_dynamic_cast(boxed, inner, code)
        if target_name == "I32" and source_name in {"F32", "F64"}:
            return f"Std.int({inner})"
        if target_name in ("F32", "F64") and source_name == "I32" and isinstance(expr.expr, IRConst):
            # A bare integer literal stays an Int wherever it is boxed (a Dynamic parameter);
            # the ascription makes it a Single. For a Float it is the run-time widening the
            # compiler makes of a literal it was not told is a Float (a constant given as one
            # is folded): `f(2)` loads the Float directly, `f(cast 2)` widens an Int (an ascription would also fix a type variable to Float).
            return f"({inner} : Single)" if target_name == "F32" else f"cast {inner}"
        if target_name == "I32" and source_name == "I64":
            # `Int64.low` of an inlined std call: the cast truncates to the low 32 bits.
            return f"{inner}.toInt()" if re.fullmatch(r"\w+", strip(inner)) else f"({inner} : hl.I64).toInt()"
        if target_name in {"I32", "F64", "Bool"} and source_name not in {
            "I32",
            "F32",
            "F64",
            "I64",
            "U8",
            "U16",
            "Bool",
        }:
            # From Dynamic, `Null<T>` or an object this is the run-time conversion (null reads as
            # zero, a mismatched value throws); an implicit one vanishes in a Dynamic context.
            haxe_name = {"I32": "Int", "F64": "Float", "Bool": "Bool"}[target_name]
            return f"cast({inner}, {haxe_name})"
        target_inner = expr.get_type().definition
        if (
            isinstance(target_inner, Null)
            and target_inner.type.resolve(code).kind.value == Type.Kind.I64.value
            and expr.expr.get_type().kind.value == Type.Kind.I32.value
        ):
            # An Int reaches a nullable 64-bit integer only through `cast`, a single SafeCast;
            # `(v : hl.I64)` would widen it first (ToInt), then box it.
            operand = inner if re.fullmatch(r"[\w.]+", strip(inner)) else f"({inner})"
            return f"(cast {operand} : Null<hl.I64>)"
        target_def, source_def = expr.get_type().definition, expr.expr.get_type().definition
        if (
            isinstance(target_def, Virtual)
            and isinstance(expr.expr, IRObjectLiteral)
            and isinstance(expr.expr.allocated, Virtual)
            and expr.expr.allocated is not target_def
        ):
            # The compiler built the literal as a structure of exactly its own fields, then
            # converted it to the structure the context wants. A literal under an expected
            # structure is built dynamically instead, so only `cast` leaves it typed by itself.
            return f"cast {inner}"
        if isinstance(target_def, Null) != isinstance(source_def, Null) or (
            isinstance(target_def, Null) and isinstance(source_def, Null)
        ):
            # A boxed number read as another number type (`Null<Float>` as `Null<Int>`) is a
            # run-time conversion Haxe will not make implicitly; through Dynamic it will.
            target_basic = target_def.type.resolve(code) if isinstance(target_def, Null) else expr.get_type()
            source_basic = (
                source_def.type.resolve(code) if isinstance(source_def, Null) else expr.expr.get_type()
            )
            numeric = {Type.Kind.I32.value, Type.Kind.F32.value, Type.Kind.F64.value}
            if (
                target_basic.kind.value != source_basic.kind.value
                and target_basic.kind.value in numeric
                and source_basic.kind.value in numeric
            ):
                if isinstance(target_def, Null) and isinstance(source_def, Null):
                    # A single SafeCast: the boxed value was held in a Dynamic variable the
                    # compiler aliased to it. Converting it directly (also through `(v : Dynamic)`)
                    # unboxes, converts and reboxes it; only a variable keeps it typed Dynamic.
                    return f"{{ var dyn: Dynamic = {inner}; dyn; }}"
                return f"({inner} : Dynamic)"
        if (
            isinstance(target_def, Virtual)
            and isinstance(expr.expr, IRObjectLiteral)
            and {name for name, _ in expr.expr.fields} - {f.name.resolve(code) for f in target_def.fields}
            # A structure type can't name a field that isn't an identifier (`"a-b"`).
            and all(name.isidentifier() for name, _ in expr.expr.fields)
        ):
            # A fresh literal may not carry fields its expected structure lacks; typing it
            # as its own wider structure first makes the narrowing an ordinary subtype use.
            members = " ".join(
                f"var {name}: {disasm._haxe_annotation(code, value.get_type())};"
                for name, value in expr.expr.fields
            )
            return f"({inner} : {{ {members} }})"
        if (
            isinstance(target_def, Virtual)
            and isinstance(source_def, Virtual)
            and target_def is not source_def
            and isinstance(expr.expr, IRCast)
            and not expr.expr.untyped
            and isinstance(expr.expr.expr.get_type().definition, Obj)
        ):
            # A class converted to one structure, then to another (`Iterable<Int>`, then the
            # erased `Iterable<A>` of a generic parameter): the context only gives the last
            # one, so the first is ascribed or the class would convert to the last directly.
            return f"({inner} : {disasm._haxe_annotation(code, expr.expr.get_type())})"
        if (
            target_name == "hl.types.ArrayObj"
            and source_name == "hl.types.ArrayDyn"
            and not _is_std_call(expr.expr)
        ):
            # The one conversion between the two a `T` array makes: it is a cast, never implicit.
            # (A std function returning `Array<T>` hands back an ArrayDyn that the compiler converts
            # for its caller; the source has no cast there.)
            return f"(cast ({inner}))"
        if target_name in _ARRAY_WRAPPERS and source_name in _ARRAY_WRAPPERS:
            # ArrayObj/ArrayDyn are one Haxe `Array<T>`; the element type comes from the context,
            # and `(cast x : Array<Dynamic>)` would pin it to Dynamic.
            return inner
        if (
            isinstance(target_def, Obj)
            and (
                (
                    isinstance(source_def, Obj)
                    and target_def is not source_def
                    and not _is_ancestor(code, target_def, source_def)
                )
                or isinstance(source_def, Virtual)  # a structural value only reaches a class via `cast`
                or (
                    source_name
                    == "Dyn"  # an implicit Dynamic->class conversion vanishes when a type parameter is fixed by another argument (`eq(null, cast dyn)`)
                    and isinstance(expr.expr, IRCall)
                    and expr.expr.call_type
                    == IRCall.CallType.FUNC  # an erased result of a user function, not a native or field read
                    # a generic target would be rendered with its type argument pinned to Dynamic, which Haxe rejects
                    and "<" not in disasm.type_to_haxe(target_name)
                )
            )
            and not strip(inner).startswith("cast ")  # already unchecked, typed by its context
        ):
            # A downcast (`Entity` to `en.Hero`) is only implicit from Dynamic; from a
            # class it needs `cast`, which compiles to the same SafeCast.
            # `cast (v : T).m()` reads as the typed cast `cast (v : T)`, so group the operand.
            operand = f"({inner})" if strip(inner).startswith("(") else inner
            return f"(cast {operand} : {disasm.type_to_haxe(target_name)}{disasm.generic_arguments(code, expr.get_type())})"
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
        return _null_test(expr.left, code, ir_function, "!=")
    if expr.op == IRBoolExpr.CompareType.NOT_NULL:
        return _null_test(expr.left, code, ir_function, "==")
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
        constant = _constant_null_compare(left_expr, right_expr, actual_op)
        if constant is not None:
            return "true" if constant == "false" else "false"
        left = _expression_to_haxe(left_expr, code, ir_function)
        right = _expression_to_haxe(right_expr, code, ir_function)
        left, right = _type_i64_literals(left_expr, right_expr, left, right)
        return f"{left} {op_map[actual_op]} {right}"
    # Inverting a NaN-safe `!(a < b)` gives back the ordered comparison itself.
    ordered = {
        IRBoolExpr.CompareType.NOT_LT: "<",
        IRBoolExpr.CompareType.NOT_LTE: "<=",
        IRBoolExpr.CompareType.NOT_GT: ">",
        IRBoolExpr.CompareType.NOT_GTE: ">=",
    }
    if expr.op in ordered:
        symbol = ordered[expr.op]
        left = _expr_to_haxe_with_precedence(expr.left, code, ir_function, symbol)
        right = _expr_to_haxe_with_precedence(expr.right, code, ir_function, symbol, is_right=True)
        return f"{left} {symbol} {right}"
    if expr.op == IRBoolExpr.CompareType.NOT and expr.left is not None:
        inner = _expression_to_haxe(expr.left, code, ir_function)
        compound = isinstance(expr.left, IRBoolExpr) and expr.left.op in (
            IRBoolExpr.CompareType.AND,
            IRBoolExpr.CompareType.OR,
        )
        return f"({inner})" if compound else inner
    if (
        expr.op in (IRBoolExpr.CompareType.AND, IRBoolExpr.CompareType.OR)
        and isinstance(expr.left, IRBoolExpr)
        and isinstance(expr.right, IRBoolExpr)
    ):
        # De Morgan: !(a && b) is !a || !b. An inverted `&&` operand becomes an `||`, which
        # needs parentheses once it sits inside the `&&` an inverted `||` turns into.
        joiner = "||" if expr.op == IRBoolExpr.CompareType.AND else "&&"
        parts = []
        for side in (expr.left, expr.right):
            text = _inverted_bool_expr_to_haxe(side, code, ir_function)
            if joiner == "&&" and side.op == IRBoolExpr.CompareType.AND:
                text = f"({text})"
            parts.append(text)
        return f"{parts[0]} {joiner} {parts[1]}"
    return f"!({_expression_to_haxe(expr, code, ir_function)})"


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
    unused_static_aliases: Optional[Set[str]] = None,
) -> List[str]:
    output_lines: List[str] = []
    indent = _indent_str(indent_level)
    if inline_declarations is None:
        inline_declarations = {}
    if render_subs is None:
        render_subs = {}
    if op_to_line is None:
        op_to_line = {}
    if unused_static_aliases is None:
        unused_static_aliases = _unused_static_aliases(ir_function.block, code)

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
            unused_static_aliases=unused_static_aliases,
        )

    prev_render_subs = getattr(ir_function, "_render_subs", None)
    ir_function._render_subs = render_subs

    for stmt in statements:
        if (
            isinstance(stmt, IRAssign)
            and isinstance(stmt.target, IRLocal)
            and stmt.target.name in unused_static_aliases
        ):
            continue
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
            output_lines.extend(
                _gen(
                    stmt.statements,
                    indent_level,
                    declared_vars_in_scope.copy(),
                    render_subs.copy(),
                )
            )
        elif isinstance(stmt, IRAssign) and stmt in inline_declarations:
            # Emit as `var name: type = value;` at its natural position.
            local_name, type_str = inline_declarations[stmt]

            # IR optimizers own value elimination. Keep the declaration even
            # when a later expression can be substituted: field/address reads
            # deliberately retain the local and substitutions can expire.
            value_str = _expression_to_haxe(stmt.expr, code, ir_function)
            if type_str.startswith("hl.BytesAccess") and not strip(value_str).startswith("cast "):
                value_str = f"cast {value_str}"
            if type_str.startswith("Array<") and type_str != "Array<Dynamic>":
                value_str = _erased_array_into_typed(value_str, stmt.expr, code)
            if (
                type_str == "Dynamic"
                and (
                    isinstance(stmt.expr, IRConst)
                    and isinstance(stmt.expr.value, Type)
                    or isinstance(stmt.expr, IRField)
                    and isinstance(stmt.expr.get_type().definition, Fun)
                )
                # An `Array<T>` result that the bytecode types as the erased ArrayBase
                # (`slice`) is not assignable to that class in Haxe; let it infer.
                or type_str in ("hl.types.ArrayBase", "hl.types.ArrayAccess")
                # A std private type (`haxe.ds.List.ListNode`) can't be named outside its module.
                or _is_std_private_type(stmt.target.get_type(), code)
            ):
                output_lines.append(f"{indent}var {_local_def(local_name, ir_function)} = {value_str};")
            else:
                output_lines.append(
                    f"{indent}var {_local_def(local_name, ir_function)}: {type_str} = {value_str};"
                )
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
                value_str = (
                    _store_chain(stmt.expr, code, ir_function)
                    if isinstance(stmt.expr, IRStoreExpr)
                    else _expression_to_haxe(stmt.expr, code, ir_function)
                )
                if isinstance(stmt.target, IRLocal) and stmt.target.array_elem_type is not None:
                    value_str = _erased_array_into_typed(value_str, stmt.expr, code)
            # A private field can't be written through `(@:privateAccess x.f)`: the
            # metadata has to cover the whole assignment.
            access = ""
            unwrapped_target = _unwrap_span(target_str)
            if unwrapped_target.startswith("(@:privateAccess ") and unwrapped_target.endswith(")"):
                access = "@:privateAccess "
                target_str = unwrapped_target[len("(@:privateAccess ") : -1]

            # Compare locals by name since splitting can create different instances.
            def _same_local(a: Optional[IRStatement], b: Optional[IRStatement]) -> bool:
                return isinstance(a, IRLocal) and isinstance(b, IRLocal) and a.name == b.name

            _compound_ops = {
                IRArithmetic.ArithmeticType.ADD: "+=",
                IRArithmetic.ArithmeticType.SUB: "-=",
                IRArithmetic.ArithmeticType.MUL: "*=",
                IRArithmetic.ArithmeticType.SDIV: "/=",
                IRArithmetic.ArithmeticType.SMOD: "%=",
            }

            # Detect x++ / x-- patterns: target = target ± 1
            def _const_int_value(expr: IRConst) -> Optional[int]:
                if expr.const_type != IRConst.ConstType.INT:
                    return None
                val = expr.value.value if hasattr(expr.value, "value") else expr.value
                return int(val)

            def _same_receiver(a: IRExpression, b: IRExpression) -> bool:
                if isinstance(a, IRLocal) and isinstance(b, IRLocal):
                    return a.name == b.name
                # A static field's receiver is its class's global object.
                return (
                    isinstance(a, IRConst)
                    and isinstance(b, IRConst)
                    and a.const_type == b.const_type == IRConst.ConstType.GLOBAL_OBJ
                    and a.value is b.value
                )

            def _field_eq(a: IRStatement, b: IRStatement) -> bool:
                return (
                    isinstance(a, IRField)
                    and isinstance(b, IRField)
                    and a.field_name == b.field_name
                    and _same_receiver(a.target, b.target)
                )

            def _plain_index(expr: IRExpression) -> bool:
                if isinstance(expr, (IRLocal, IRConst)):
                    return True
                return (
                    isinstance(expr, IRArithmetic)
                    and expr.op == IRArithmetic.ArithmeticType.SHL
                    and _plain_index(expr.left)
                    and _plain_index(expr.right)
                )

            def _element_eq(a: IRStatement, b: IRStatement) -> bool:
                # x[i]++ reads and writes one element: both sides must render as the same array element.
                return (
                    isinstance(a, IRArrayAccess)
                    and isinstance(b, IRArrayAccess)
                    and isinstance(a.array, (IRLocal, IRField))
                    and isinstance(b.array, (IRLocal, IRField))
                    and _plain_index(a.index)
                    and _plain_index(b.index)
                    and strip(_expression_to_haxe(a, code, ir_function)) == strip(target_str)
                    and strip(_expression_to_haxe(b, code, ir_function)) == strip(target_str)
                )

            if (
                isinstance(stmt.expr, IRArithmetic)
                and stmt.expr.step
                and isinstance(stmt.expr.right, IRConst)
                and _const_int_value(stmt.expr.right) == 1
                and stmt.expr.op in (IRArithmetic.ArithmeticType.ADD, IRArithmetic.ArithmeticType.SUB)
                and (
                    (isinstance(stmt.target, IRLocal) and _same_local(stmt.expr.left, stmt.target))
                    or (isinstance(stmt.target, IRField) and _field_eq(stmt.expr.left, stmt.target))
                    or (isinstance(stmt.target, IRArrayAccess) and _element_eq(stmt.expr.left, stmt.target))
                )
            ):
                op_sym = "++" if stmt.expr.op == IRArithmetic.ArithmeticType.ADD else "--"
                output_lines.append(f"{indent}{access}{target_str}{op_sym};")
            # Detect x += y and o.f += y patterns: target = target op expr
            elif (
                isinstance(stmt.expr, IRArithmetic)
                and (
                    (isinstance(stmt.target, IRLocal) and _same_local(stmt.expr.left, stmt.target))
                    or (isinstance(stmt.target, IRField) and _field_eq(stmt.expr.left, stmt.target))
                )
                and stmt.expr.op in _compound_ops
                and not (
                    stmt.expr.op in (IRArithmetic.ArithmeticType.SDIV, IRArithmetic.ArithmeticType.SMOD)
                    and _is_int_kind(stmt.expr.get_type())
                )
            ):
                rhs_str = _expression_to_haxe(stmt.expr.right, code, ir_function)
                output_lines.append(f"{indent}{access}{target_str} {_compound_ops[stmt.expr.op]} {rhs_str};")
            else:
                output_lines.append(f"{indent}{access}{target_str} = {value_str};")

        elif isinstance(stmt, IRTrace):
            args = [_expression_to_haxe(stmt.msg, code, ir_function)]
            args.extend(_expression_to_haxe(arg, code, ir_function) for arg in stmt.extra_args)
            pos_info_str = ", ".join(f"{k}: {v!r}" for k, v in stmt.pos_info.items())
            output_lines.append(f"{indent}trace({', '.join(args)}); // {{ {pos_info_str} }}")

        elif isinstance(stmt, IRUnliftedOpcode):
            try:
                op_str = disasm.pseudo_from_op(stmt.op, 0, ir_function.func.regs, code, terse=True)
            except (KeyError, IndexError, ValueError, MalformedBytecode):
                # Lifted/reconstructed streams carry placeholder register types and
                # corrupt operands index past their table; fall back to the
                # exception-guarded compact printer.
                op_str = disasm.fmt_op_compact(code, ir_function.func.regs, stmt.op, 0, func=ir_function.func)
            output_lines.append(f"{indent}// UNLIFTED OPCODE: {stmt.op.op} {op_str}")

        elif isinstance(stmt, IRNativeStub):
            name = ir_function.code.full_func_name(ir_function.func)
            if name and name != "<none>.<none>":
                output_lines.append(f"{indent}// native stub: {name}")
            else:
                native_name = getattr(stmt.native, "name", None)
                if native_name is not None:
                    native_name = native_name.resolve(ir_function.code)
                output_lines.append(f"{indent}// native stub: {native_name or '?'}")

        elif isinstance(stmt, IRConditional) and (
            null_guarded_copy := _null_guarded_copy(stmt, code, ir_function)
        ):
            # `v = x == null ? null : x` once the converting closure is dropped: the source
            # assigned `x`, and the compiler adds the same guard when it converts it.
            output_lines.extend(_gen([null_guarded_copy], indent_level, declared_vars_in_scope, render_subs))
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
                output_lines.extend(
                    _gen(
                        false_stmts,
                        indent_level + 1,
                        declared_vars_in_scope.copy(),
                        false_subs,
                    )
                )
                output_lines.append(f"{indent}}}")
                declared_vars_in_scope.update(_collect_assigned_names(false_stmts))
                for key in list(render_subs.keys()):
                    if key not in false_subs:
                        del render_subs[key]
            else:
                cond_str = _expression_to_haxe(stmt.condition, code, ir_function)
                output_lines.append(f"{indent}if ({cond_str}) {{")
                true_subs = render_subs.copy()
                output_lines.extend(
                    _gen(
                        true_stmts,
                        indent_level + 1,
                        declared_vars_in_scope.copy(),
                        true_subs,
                    )
                )
                # If the true block ends with a control-flow statement, the else is unnecessary.
                true_ends_with_cf = bool(true_stmts) and isinstance(
                    true_stmts[-1], (IRBreak, IRContinue, IRReturn)
                )
                false_subs = render_subs.copy()
                if false_stmts and not true_ends_with_cf:
                    output_lines.append(f"{indent}}} else {{")
                    output_lines.extend(
                        _gen(
                            false_stmts,
                            indent_level + 1,
                            declared_vars_in_scope.copy(),
                            false_subs,
                        )
                    )
                    output_lines.append(f"{indent}}}")
                elif false_stmts and true_ends_with_cf:
                    output_lines.append(f"{indent}}}")
                    # Render former else block as plain statements (no else keyword needed)
                    output_lines.extend(
                        _gen(
                            false_stmts,
                            indent_level,
                            declared_vars_in_scope.copy(),
                            false_subs,
                        )
                    )
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
                tail_condition = None
                body_end = len(stmt.body.statements) - 1
                if (
                    isinstance(last_stmt, IRConditional)
                    and isinstance(last_stmt.condition, IRBoolExpr)
                    and len(last_stmt.true_block.statements) == 1
                    and isinstance(last_stmt.true_block.statements[0], IRBreak)
                    and (not last_stmt.false_block or not last_stmt.false_block.statements)
                ):
                    tail_condition = _inverted_bool_expr_to_haxe(last_stmt.condition, code, ir_function)
                elif isinstance(last_stmt, IRBreak) and len(stmt.body.statements) >= 2:
                    tail = stmt.body.statements[-2]
                    if (
                        isinstance(tail, IRConditional)
                        and isinstance(tail.condition, IRBoolExpr)
                        and len(tail.true_block.statements) == 1
                        and isinstance(tail.true_block.statements[0], IRContinue)
                        and (not tail.false_block or not tail.false_block.statements)
                    ):
                        tail_condition = _expression_to_haxe(tail.condition, code, ir_function)
                        body_end -= 1
                # An earlier continue currently skips the tail test. In a do-while
                # it would evaluate that test, possibly changing values or effects.
                if tail_condition is not None and not any(
                    _contains_loop_continue(body_stmt) for body_stmt in stmt.body.statements[:body_end]
                ):
                    output_lines.append(f"{indent}do {{")
                    body_subs = render_subs.copy()
                    output_lines.extend(
                        _gen(
                            stmt.body.statements[:body_end],
                            indent_level + 1,
                            declared_vars_in_scope.copy(),
                            body_subs,
                        )
                    )
                    output_lines.append(f"{indent}}} while ({tail_condition});")
                    rendered_as_do_while = True
                    for key in list(render_subs.keys()):
                        if key not in body_subs:
                            del render_subs[key]

            if not rendered_as_do_while:
                cond_str = _expression_to_haxe(stmt.condition, code, ir_function)
                output_lines.append(f"{indent}while ({cond_str}) {{")
                body_subs = render_subs.copy()
                output_lines.extend(
                    _gen(
                        stmt.body.statements,
                        indent_level + 1,
                        declared_vars_in_scope.copy(),
                        body_subs,
                    )
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
                _gen(
                    stmt.condition.statements,
                    indent_level + 1,
                    declared_vars_in_scope.copy(),
                    cond_subs,
                )
            )
            output_lines.append(f"{indent}}}")
            output_lines.append(f"{indent}{{ // Body Block")
            body_subs = render_subs.copy()
            output_lines.extend(
                _gen(
                    stmt.body.statements,
                    indent_level + 1,
                    declared_vars_in_scope.copy(),
                    body_subs,
                )
            )
            output_lines.append(f"{indent}}}")
            for key in list(render_subs.keys()):
                if key not in cond_subs or key not in body_subs:
                    del render_subs[key]

        elif isinstance(stmt, IRForEachLoop):
            elem_str = stmt.elem.name
            array_str = _expression_to_haxe(stmt.array, code, ir_function)
            source = stmt.array
            while isinstance(source, IRCast):  # a Dynamic-to-array cast prints as its operand
                source = source.expr
            if not isinstance(source, IRArrayLiteral) and source.get_type().kind.value == Type.Kind.DYN.value:
                # An array out of an erased container (a `Map<Int, Array<T>>` value):
                # Haxe won't iterate Dynamic, but a Dynamic value checks as any type.
                elem_type = disasm._haxe_annotation(code, stmt.elem.get_type())
                array_str = f"({array_str} : Array<{elem_type}>)"
            if isinstance(source, IRArrayLiteral) and not stmt.rerolled:
                # Haxe unrolls `for (x in [1, 2, 3])` itself; a loop that survived in the
                # bytecode iterated a temp (an inlined `[1, 2, 3].map(f)`), so bind one.
                output_lines.append(f"{indent}var {elem_str}_src = {array_str};")
                array_str = f"{elem_str}_src"
            output_lines.append(f"{indent}for ({elem_str} in {array_str}) {{")
            body_subs = render_subs.copy()
            output_lines.extend(
                _gen(
                    stmt.body.statements,
                    indent_level + 1,
                    declared_vars_in_scope.copy(),
                    body_subs,
                )
            )
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
            output_lines.extend(
                _gen(
                    stmt.body.statements,
                    indent_level + 1,
                    declared_vars_in_scope.copy(),
                    body_subs,
                )
            )
            output_lines.append(f"{indent}}}")
            for key in list(render_subs.keys()):
                if key not in body_subs:
                    del render_subs[key]

        elif isinstance(stmt, IRRefSet):
            ref_str = _expression_to_haxe(stmt.ref, code, ir_function)
            value_str = _expression_to_haxe(stmt.value, code, ir_function)
            output_lines.append(f"{indent}{ref_str}.set({value_str});")

        elif isinstance(stmt, IRReturn):
            if stmt.value:
                if (
                    isinstance(stmt.value, IRLocal)
                    and stmt.value.type.resolve(code).kind.value == Type.Kind.VOID.value
                ):
                    output_lines.append(
                        f"{indent}return; // implicit void return from reg{ir_function.locals.index(stmt.value) + 1}"
                    )
                else:
                    val_str = _expression_to_haxe(stmt.value, code, ir_function)
                    if getattr(ir_function, "_free_return", False) and not strip(val_str).startswith("cast "):
                        val_str = (
                            f"cast {val_str}"
                            if re.fullmatch(r"[\w.]+", strip(val_str))
                            else f"cast ({val_str})"
                        )
                    output_lines.append(f"{indent}return {val_str};")
            else:
                output_lines.append(f"{indent}return;")

        elif isinstance(stmt, IRThrow):
            # `throw` takes Dynamic: a value thrown as the type it was read at keeps its cast.
            val_str = _spell_dynamic_cast(
                stmt.value, _expression_to_haxe(stmt.value, code, ir_function), code
            )
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
                    output_lines.append(
                        f"{indent}var {local_name}: {type_str} = switch ({enum_value_str}) {{"
                    )
                    declared_vars_in_scope.add(local_name)
                else:
                    output_lines.append(f"{indent}{target.name} = switch ({enum_value_str}) {{")
                _, tested = _switch_enum(stmt)
                for case_value, case_block in stmt.cases.items():
                    values = stmt.case_values(case_value)
                    case_str = ", ".join(
                        _case_value_to_haxe(value, enum_type, code, ir_function) for value in values
                    )
                    case_expr = case_exprs[case_value]
                    if (
                        len(values) == 1
                        and isinstance(case_expr, IREnumField)
                        and _same_value(case_expr.value, tested)
                        and case_expr.field_name.startswith("param")
                    ):
                        # The case's own capture, which `_case_value_to_haxe` names argN.
                        expr_str = f"arg{case_expr.field_name.removeprefix('param')}"
                    else:
                        expr_str = _expression_to_haxe(case_expr, code, ir_function)
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
                pattern = stmt.enum_patterns.get(case_value)
                unbound: Optional[Set[str]] = getattr(ir_function, "_unbound_reads", None)
                if unbound is None and ir_function is not None:
                    unbound = _unbound_reads(ir_function.block)
                    setattr(ir_function, "_unbound_reads", unbound)
                captures = (
                    None
                    if pattern or unbound is None
                    else _pattern_captures(case_block, switch_value_expr, unbound)
                )
                param_names = [capture for capture, _ in captures] if captures else None
                case_str = ", ".join(
                    _enum_pattern_to_haxe(stmt.enum_patterns[value], code)
                    if pattern
                    else _case_value_to_haxe(value, enum_type, code, ir_function, param_names)
                    for value in stmt.case_values(case_value)
                )
                output_lines.append(f"{indent}    case {case_str}:")
                for capture, local in captures or ():
                    if local is not None:
                        output_lines.append(f"{indent}        {local} = {capture};")
                case_statements = case_block.statements[len(param_names) if param_names else 0 :]
                branch_subs = render_subs.copy()
                output_lines.extend(
                    _gen(
                        case_statements,
                        indent_level + 2,
                        declared_vars_in_scope.copy(),
                        branch_subs,
                    )
                )
                case_subs.append(branch_subs)
                if captures:
                    for capture, local in captures:
                        declared_vars_in_scope.add(local or capture)
                else:
                    for s in case_statements:
                        if isinstance(s, IRAssign) and isinstance(s.target, IRLocal):
                            declared_vars_in_scope.add(s.target.name)
            if stmt.default and stmt.default.statements:
                output_lines.append(f"{indent}    default:")
                default_subs = render_subs.copy()
                output_lines.extend(
                    _gen(
                        stmt.default.statements,
                        indent_level + 2,
                        declared_vars_in_scope.copy(),
                        default_subs,
                    )
                )
                case_subs.append(default_subs)
                for s in stmt.default.statements:
                    if isinstance(s, IRAssign) and isinstance(s.target, IRLocal):
                        declared_vars_in_scope.add(s.target.name)
            elif _switch_enum(stmt)[0] is not None and not _switch_is_exhaustive(stmt):
                # The source had a `case _:` with nothing in it; Haxe rejects the switch without it.
                output_lines.append(f"{indent}    default:")
            output_lines.append(f"{indent}}}")
            valid_keys = set(render_subs.keys())
            for subs in case_subs:
                valid_keys &= set(subs.keys())
            for key in list(render_subs.keys()):
                if key not in valid_keys:
                    del render_subs[key]

        elif isinstance(stmt, IRTryCatch):
            # Keep the IR identifier: declarations and references are already
            # keyed by this name, and a display-only rename can shadow a
            # different typed local used by the catch body.
            catch_name = stmt.catch_local.name if stmt.catch_local and stmt.catch_local.name else "e"
            catch_type = "Dynamic"
            if stmt.catch_local:
                t = disasm.type_name(code, stmt.catch_local.get_type())
                if t and t != "Dyn":
                    # An interface (or enum) is caught by its class object, `pkg.$Name`.
                    catch_type = disasm.type_to_haxe(destaticify(t))
            output_lines.append(f"{indent}try {{")
            try_subs = render_subs.copy()
            output_lines.extend(
                _gen(
                    stmt.try_block.statements,
                    indent_level + 1,
                    declared_vars_in_scope.copy(),
                    try_subs,
                )
            )
            # An untyped `catch (e)` is `catch (e:haxe.Exception)` since Haxe 4.1, not Dynamic, so the
            # type is always written; the bytecode differs only by a dead scratch store.
            catch_decl = f"{catch_name}:{catch_type}"
            output_lines.append(f"{indent}}} catch ({catch_decl}) {{")
            # The catch variable is a fresh binding: a substitution recorded for an earlier
            # local of the same name (a dead `x = null`) must not replace its reads.
            catch_subs = {
                key: value
                for key, value in render_subs.items()
                if key.name != catch_name and catch_name not in {local.name for local in value[1]}
            }
            output_lines.extend(
                _gen(
                    stmt.catch_block.statements,
                    indent_level + 1,
                    declared_vars_in_scope.copy(),
                    catch_subs,
                )
            )
            all_subs = [try_subs, catch_subs]
            for extra_local, extra_block in stmt.extra_catches:
                extra_name = extra_local.name or "e"
                extra_haxe = disasm._haxe_annotation(code, extra_local.get_type())
                output_lines.append(f"{indent}}} catch ({extra_name}:{extra_haxe}) {{")
                extra_subs = render_subs.copy()
                all_subs.append(extra_subs)
                output_lines.extend(
                    _gen(
                        extra_block.statements,
                        indent_level + 1,
                        declared_vars_in_scope.copy(),
                        extra_subs,
                    )
                )
            output_lines.append(f"{indent}}}")
            valid_keys = set(render_subs.keys())
            for subs in all_subs:
                valid_keys &= set(subs.keys())
            for key in list(render_subs.keys()):
                if key not in valid_keys:
                    del render_subs[key]

        elif isinstance(stmt, IRBreak):
            output_lines.append(f"{indent}break;")

        elif isinstance(stmt, IRContinue):
            output_lines.append(f"{indent}continue;")

        elif isinstance(stmt, IRExpression):  # e.g. a standalone IRCall not assigned
            expr_str = _expression_to_haxe(stmt, code, ir_function)
            if expr_str:  # elided redundant calls (e.g. double ctor) render as ""
                output_lines.append(f"{indent}{expr_str};")

        else:
            output_lines.append(
                f"{indent}// <Unhandled IRStatement: {type(stmt).__name__}> {str(stmt)[:50]}..."
            )

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
            registerable = _is_simple_render_expr(stmt.expr) and not (
                # `half = var7`: the source reads `half`; printing its reads as the
                # compiler temp it was copied from only loses the name.
                isinstance(stmt.expr, IRLocal)
                and re.fullmatch(r"var\d+", stmt.expr.name)
                and not re.fullmatch(r"var\d+", stmt.target.name)
            )
            widened_dyn = (
                stmt.target.get_type().kind.value == Type.Kind.DYN.value
                and stmt.expr.get_type().kind.value != Type.Kind.DYN.value
            )  # `var d:Any = "s"`: the cast read back out of it is checked, so the temp has to stay
            if (
                not registerable
                and not widened_dyn
                and re.fullmatch(r"var\d+", stmt.target.name)
                and _is_single_use_render_expr(stmt.expr)
            ):
                reads, writes = _count_local_reads_and_writes(ir_function.block, stmt.target.name)
                registerable = (
                    reads == 1
                    and writes == 1
                    and not _source_redefined_before_use(
                        ir_function.block,
                        stmt,
                        stmt.target.name,
                        {loc.name for loc in _free_locals_in_expr(stmt.expr)},
                    )
                )
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

    ir_function._render_subs = prev_render_subs
    return output_lines


def _context_bind(expr: "IRBoundClosure", code: Bytecode, ir_function: Optional[IRFunction]) -> Optional[str]:
    """`f.bind(a, _)` for a closure over a capture context whose body only calls what the context
    holds with what it holds and its own parameters.

    `f.bind(args)` evaluates the arguments into variables and calls `f` inside a closure over
    them, so all of them (and the receiver of a method value) travel in one context. The helper's
    body is `<ctx 1>.process(<ctx 0>)` or `<ctx 0>(<ctx 1>, x)`; the bound values come out in the
    order of the call, `_` stands for each parameter of the closure."""
    entry = getattr(ir_function, "_ctx_closure_bodies", {}).get(expr.fun.findex.value)
    context = expr.obj
    if entry is None or not isinstance(context, IREnumConstruct) or expr.captures is not None:
        return None
    enum_def = context.get_type().definition
    if not (isinstance(enum_def, Enum) and enum_def.name.value == 0):
        return None
    # The arguments are evaluated before the closure is made and, in source, in call order: values
    # whose evaluation could be told apart from that order are not rebound.
    impure = [a for a in context.args if not isinstance(a, (IRLocal, IRConst))]
    if len(impure) > 1:
        return None
    params, body = entry
    body = strip(body)  # placeholders and callee are matched textually; spans are re-added by `captured`
    if "\n" in body or '"' in body or "'" in body or not body.endswith(")"):
        return None
    depth = 0
    for at in range(len(body) - 1, -1, -1):
        depth += {")": 1, "(": -1}.get(body[at], 0)
        if depth == 0:
            break
    callee, inner = body[:at], body[at + 1 : -1]
    if not re.fullmatch(r"[\w.$\x00]+", callee) or depth != 0:
        return None
    arguments = [part.strip() for part in _split_params(inner)] if inner.strip() else []
    captured = [_expression_to_haxe(a, code, ir_function) for a in context.args]
    used: List[int] = []
    unbound = iter(params[1:])
    slots: List[str] = []
    for argument in arguments:
        reference = _CTX_REF.fullmatch(argument)
        if reference is not None:
            used.append(int(reference.group(1)))
            slots.append(captured[used[-1]] if used[-1] < len(captured) else "")
            continue
        param = next(unbound, None)
        if param is not None and argument == strip(param):
            slots.append("_")
        else:
            return None
    if next(unbound, None) is not None:
        return None
    head = _CTX_REF.match(callee)
    if head is not None:
        used.append(int(head.group(1)))
        if used[-1] >= len(captured):
            return None
        receiver = captured[used[-1]] + callee[head.end() :]
        if _is_lambda_text(receiver):
            receiver = f"({receiver})"
    elif _CTX_MARK in callee:
        return None
    else:
        receiver = callee
    if sorted(used) != list(range(len(captured))) or "" in slots:
        return None
    while slots and slots[-1] == "_":
        slots.pop()
    getattr(ir_function, "_inlined_closures", set()).add(expr.fun.findex.value)
    return f"{receiver}.bind({', '.join(slots)})"


def _inline_block_closure(
    expr: "IRBoundClosure",
    obj_str: str,
    extra_arg_count: int,
    code: Bytecode,
    ir_function: Optional[IRFunction],
) -> Optional[str]:
    """A closure over `this` whose body takes several statements, as the block lambda it came
    from: `n -> { ... }`. The helper's first parameter is the bound `this`."""
    obj_name = strip(obj_str)
    if ir_function is None or not (obj_name == "this" or re.fullmatch(r"[A-Za-z_]\w*", obj_name)):
        return None
    if obj_name == "this" and getattr(ir_function, "_force_static", False):
        return None
    helpers = getattr(ir_function, "_helper_irs", None)
    helper = helpers.get(expr.fun.findex.value) if helpers else None
    if helper is None:
        return None
    signature = helper.func.type.resolve(code).definition
    if not isinstance(signature, Fun) or len(signature.args) != extra_arg_count + 1:
        return None
    names = [local.name for local in helper.locals[: len(signature.args)]]
    if not names or any(
        isinstance(s, IRAssign) and isinstance(s.target, IRLocal) and s.target.name == names[0]
        for s in _all_statements(helper.block)
    ):
        return None
    text = _generate_function_pseudo(helper)
    lines = text.splitlines()
    open_at = next(
        (i for i, line in enumerate(lines) if line.rstrip().endswith("{") and "function " in line), None
    )
    if open_at is None or not lines[-1].strip() == "}":
        return None
    header = _function_header(lines[open_at])
    if header is None:
        return None
    parts = [part.strip() for part in _split_params(header.group(1))]
    declared = [part.split(":")[0].strip() for part in parts]
    if len(declared) != extra_arg_count + 1:
        return None
    returns = header.group(2)
    base = len(lines[open_at]) - len(lines[open_at].lstrip()) + 4
    body = [line[base:] if line.startswith(" " * base) else line.lstrip() for line in lines[open_at + 1 : -1]]
    if obj_name != "this" and strip(declared[0]) != obj_name:
        return None  # a closure over a local sees the very same variable
    pattern = re.compile(rf"(?<![\w.]){re.escape(strip(declared[0]))}(?!\w)")
    inner = disasm.outside_literals("\n".join(body), lambda chunk: _plain_sub(pattern, "this", chunk))
    if obj_name != "this":
        inner = "\n".join(body)
    getattr(ir_function, "_inlined_closures", set()).add(expr.fun.findex.value)
    # A function expression, typed like the declaration: an arrow takes its return type from its
    # first `return` and cannot be annotated.
    params = ", ".join(name if "{" in part else part for name, part in zip(declared[1:], parts[1:]))
    ret = f": {returns.strip()}" if returns and strip(returns.strip()) not in ("", "Void") else ""
    indented = "\n".join(("    " + line) if line else line for line in inner.splitlines())
    return f"function({params}){ret} {{\n{indented}\n}}"


def _enum_match_prefix(expr: IRBoolExpr, code: Bytecode, ir_function: Optional[IRFunction]) -> Optional[str]:
    """`e.match(Ctor(_, 0, Inner))` for `enumIndex(e) == K && e.param1 == 0 && enumIndex(e.param2) == J`.

    A pattern compiles to the constructor test followed by the payload comparisons and the
    nested constructor tests, in order. Only a leading run of such tests becomes the pattern;
    whatever follows stays a plain conjunction."""
    parts = conjuncts(expr)
    parsed = parse_enum_match(parts, code)
    if parsed is None or parsed[2] == 1:
        return None
    value, pattern, used = parsed
    rendered = (
        f"{_expression_to_haxe(value, code, ir_function)}.match({_enum_pattern_to_haxe(pattern, code, True)})"
    )
    for part in parts[used:]:
        rendered += f" && {_expr_to_haxe_with_precedence(part, code, ir_function, '&&')}"
    return rendered


def _forwarded_bind(
    expr: "IRBoundClosure", obj_str: str, code: Bytecode, ir_function: Optional[IRFunction]
) -> Optional[str]:
    """`Class.function.bind(..)` (or `Class.new.bind(..)`) when the helper a bound closure runs only
    forwards its parameters to that function: the bound value in one slot, the closure's own
    arguments (as `_`, in order) in the others."""
    helpers = getattr(ir_function, "_helper_irs", None)
    helper = helpers.get(expr.fun.findex.value) if helpers else None
    if helper is None:
        return None
    signature = helper.func.type.resolve(code).definition
    if not isinstance(signature, Fun):
        return None
    params = [local.name for local in helper.locals[: len(signature.args)]]
    statements = [s for s in helper.block.statements if not (isinstance(s, IRReturn) and s.value is None)]
    if len(statements) != 1:
        return None
    if isinstance(statements[0], IRReturn) and statements[0].value is not None:
        call = statements[0].value
    elif isinstance(statements[0], IRCall):
        call = statements[0]  # a void helper: the forwarded call is the whole body
    else:
        return None
    if isinstance(call, IRNew) and not call.constructor_args:
        return None
    args = (
        call.constructor_args if isinstance(call, IRNew) else call.args if isinstance(call, IRCall) else None
    )
    if args is None or not params or any(not isinstance(a, IRLocal) for a in args):
        return None
    names = [a.name for a in args if isinstance(a, IRLocal)]
    bound, unbound = params[0], params[1:]
    if names.count(bound) != 1 or [n for n in names if n != bound] != unbound:
        return None  # the bound value is used once, and the closure's own arguments keep their order
    slots = [obj_str if n == bound else "_" for n in names]
    while len(slots) > 1 and slots[-1] == "_":
        slots.pop()
    method = _instance_method(call, code)
    if names[0] == bound and method is not None:
        # The receiver is the bound value and the closure's arguments follow it in order. The compiler
        # keeps `obj.method.bind()` as an instance closure on the helper; a plain `obj.method` value is
        # built around a capture context instead.
        receiver = f"({obj_str})" if _is_lambda_text(obj_str) else obj_str
        rendered = f"{receiver}.{code.partial_func_name(method)}.bind()"
    else:
        callee = _forwarded_callee(call, code, ir_function)
        if callee is None:
            return None
        rendered = f"{callee}.bind({', '.join(slots)})"
    getattr(ir_function, "_inlined_closures", set()).add(expr.fun.findex.value)
    return rendered


def _forwarded_callee(call: IRExpression, code: Bytecode, ir_function: Optional[IRFunction]) -> Optional[str]:
    if isinstance(call, IRNew):
        return f"{disasm.type_to_haxe(disasm.type_name(code, call.get_type()))}.new"
    if (
        isinstance(call, IRCall)
        and isinstance(call.target, IRConst)
        and isinstance(call.target.value, Function)
        and call.call_type == IRCall.CallType.FUNC
    ):
        func = call.target.value
        abstract = abstracts.abstract_of_function(code, func)
        if abstract is not None and func.findex.value == abstract.constructor:
            return f"{_abstract_ref(abstract, code, ir_function)}.new"
        if abstract is not None and func.findex.value not in abstract.instance:
            return f"{_abstract_ref(abstract, code, ir_function)}.{code.partial_func_name(func)}"
        if abstract is None and _is_static_function(func, code):
            return _expression_to_haxe(call.target, code, ir_function)
    return None


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
            ir_func._containing_class = containing
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

    # An abstract's methods take `this` as their leading argument, and its
    # constructor is `_new`, every argument of which is a parameter.
    abstract = abstracts.abstract_of_function(code, func_core)
    abstract_constructor = False
    if abstract is not None and not getattr(ir_func, "_force_static", False):
        if func_core.findex.value == abstract.constructor:
            abstract_constructor = True
            func_name_str = "new"
            signature = func_core.type.resolve(code).definition
            if isinstance(signature, Fun):
                _abstract_constructor_body(ir_func, signature)
        elif func_core.findex.value in abstract.instance:
            is_instance = True
            for local in ir_func.all_locals:
                if local.reg_idx == 0:
                    local.name = "this"

    # A better way might be to just call disasm.is_static
    if not is_instance and not abstract_constructor:
        static_kw = "static "
        holder = _method_registry(code).get(func_core.findex.value)
        if (
            holder is not None
            and holder[0].is_static
            and _is_static_dynamic_method(code, holder[0], func_core, holder[1])
        ):
            static_kw = "static dynamic "

    override_kw = ""
    if is_instance and not is_constructor and containing is not None and abstract is None:
        if _method_overrides(func_name_str, containing, code):
            override_kw = "override "
        if _is_dynamic_method(code, containing.dynamic, func_core):
            override_kw += "dynamic "

    params_str_list = []
    return_type_str = "Void"
    variables: Dict[int, int] = {}
    returned_variable: Optional[int] = None
    variable_offset = 0

    core_fun_type_def = func_core.type.resolve(code).definition
    if isinstance(core_fun_type_def, Fun):
        start_arg = 1 if is_instance or is_constructor else 0
        erased, narrowed = (
            _erased_parameters(code, containing.dynamic, func_name_str)
            if is_instance and not is_constructor and containing is not None
            else (set(), {})
        )
        variables, returned_variable = _own_type_variables(
            code, func_core, containing, func_name_str, is_instance
        )
        # Slots the method's first declaring class types with one of its type parameters.
        class_obj = (
            containing.dynamic if is_instance and not is_constructor and containing is not None else None
        )
        class_args = {
            i: text
            for i in range(len(core_fun_type_def.args) - start_arg)
            if (text := _method_slot_text(code, class_obj, func_name_str, i)) is not None
        }
        class_ret = _method_slot_text(code, class_obj, func_name_str)
        variables = {k: v for k, v in variables.items() if k - start_arg not in class_args}
        if class_ret is not None:
            returned_variable = None
        # The method's own type parameters are named past its class's.
        variable_offset = (
            len(class_generics(code).params(containing.dynamic)) if containing is not None else 0
        )
        for i, arg_type_idx in enumerate(core_fun_type_def.args[start_arg:]):
            arg_core_type = arg_type_idx.resolve(code)
            arg_haxe_type_name = (
                narrowed[i]
                if i in narrowed
                else "Dynamic"
                if i in erased
                else disasm._haxe_annotation(code, arg_core_type)
            )
            if i in class_args:
                arg_haxe_type_name = class_args[i]
            elif start_arg + i in variables:
                variable = _type_variable_name(variables[start_arg + i] + variable_offset)
                arg_haxe_type_name = (
                    variable if arg_core_type.kind.value == Type.Kind.DYN.value else f"Array<{variable}>"
                )
            elif i not in erased and i not in narrowed:
                arg_haxe_type_name = mapargs.refine(
                    arg_haxe_type_name,
                    mapargs.value_type(code, ("r", func_core.findex.value, start_arg + i)),
                )
                arg_haxe_type_name = ifacenames.refine(
                    arg_haxe_type_name, code, ("r", func_core.findex.value, start_arg + i)
                )
                if (
                    arg_haxe_type_name == "Dynamic"
                    and disasm.type_name(code, arg_core_type) == "hl.BaseType"
                    and enumparams.is_enum_parameter(code, func_core.findex.value, start_arg + i)
                ):
                    arg_haxe_type_name = "Enum<Dynamic>"

            param_name = f"arg{i}"
            local_idx = start_arg + i
            if local_idx < len(ir_func.locals):
                # Use the reg's entry-point local, not a later split (e.g. param reused for super()).
                param_local = next(
                    (lc for lc in ir_func.all_locals if lc.reg_idx == local_idx), ir_func.locals[local_idx]
                )
                candidate = param_local.name
                if candidate and candidate != "this":
                    param_name = candidate
                elif candidate == "this" and getattr(ir_func, "_force_static", False):
                    # Lifted closure: rewrite all "this" locals for this reg to the new param name.
                    for loc in ir_func.all_locals:
                        if loc.reg_idx == local_idx and loc.name == "this":
                            loc.name = param_name
                # If the param's IRLocal has a recovered array element type,
                # render Array<T> instead of the erased Array<Dynamic>.
                if (
                    arg_haxe_type_name == "Array<Dynamic>"
                    and ir_func.locals[local_idx].array_elem_type is not None
                ):
                    elem_type = ir_func.locals[local_idx].array_elem_type
                    assert elem_type is not None  # narrowed by the guard above
                    elem_haxe = disasm._haxe_annotation(code, elem_type)
                    arg_haxe_type_name = f"Array<{elem_haxe}>"
            elif func_core.has_debug and func_core.assigns:
                # Fallback to raw debug assigns if locals aren't available.
                arg_assigns = [a for a in func_core.assigns if a[1].value <= 0]
                if i < len(arg_assigns):
                    param_name = arg_assigns[i][0].resolve(code)

            if id(core_fun_type_def) in disasm._trace_signature_types(code)[1] and local_idx == 1:
                param_name = "?" + param_name
            elif (
                i + start_arg == len(core_fun_type_def.args) - 1
                and not param_name.startswith("?")
                and disasm._is_pos_infos(code, arg_core_type.definition)
            ):
                # The compiler fills a `haxe.PosInfos` parameter in at each call, so it is optional.
                param_name = "?" + param_name
            param_type_decl = f": {arg_haxe_type_name}" if arg_haxe_type_name else ""
            default = ir_func.default_args.get(local_idx)
            if default is not None:
                value, const = default
                value_type = disasm._haxe_annotation(code, value.get_type())
                param_type_decl = f": {value_type} = {_expression_to_haxe(const, code, ir_func)}"
            elif (inherited := overriding_default_arg_regs(code, func_core).get(local_idx)) is not None:
                impl, load = inherited
                value_type = disasm._haxe_annotation(code, impl.regs[load.df["dst"].value].resolve(code))
                default_value = _expression_to_haxe(default_arg_value(code, load), code, ir_func)
                param_type_decl = f": {value_type} = {default_value}"
            params_str_list.append(f"{param_name}{param_type_decl}")

        ret_core_type = core_fun_type_def.ret.resolve(code)
        return_type_str = ifacenames.refine(
            mapargs.refine(
                _return_annotation(code, func_core, ret_core_type),
                mapargs.value_type(code, ("ret", func_core.findex.value)),
            ),
            code,
            ("ret", func_core.findex.value),
        )
        if class_ret is not None:
            return_type_str = class_ret
        elif returned_variable is not None:
            return_type_str = _type_variable_name(returned_variable + variable_offset)
            # No parameter has the variable's type: what is returned is converted to it.
            setattr(ir_func, "_free_return", returned_variable not in variables.values())

    # Constructors do not declare a return type in Haxe.
    if is_constructor or abstract_constructor:
        return_type_str = ""

    params_joined_str = ", ".join(_param_def(p, ir_func) for p in params_str_list)
    ret_decl = f": {return_type_str}" if return_type_str else ""
    constraints = generics.constraints(code, func_core) if variables else {}
    type_params = (
        "<"
        + ", ".join(
            _type_variable_name(n + variable_offset) + _constraint_text(code, constraints.get(n))
            for n in sorted(
                {*variables.values(), *([] if returned_variable is None else [returned_variable])}
            )
        )
        + ">"
        if isinstance(core_fun_type_def, Fun) and (variables or returned_variable is not None)
        else ""
    )
    access_kw = "public "
    # A `dynamic` function is rebound at run time, so Haxe refuses to also inline it.
    is_dynamic = "dynamic" in static_kw or "dynamic" in override_kw
    inline_kw = (
        "inline " if containing is not None and not is_dynamic and is_inline_template(code, func_core) else ""
    )
    member_meta = (
        _rtti_member_meta(code, getattr(containing, "dynamic", None), func_name_str, "static" in static_kw)
        if containing is not None
        else ""
    )
    func_header = f"{member_meta}{access_kw}{static_kw}{override_kw}{inline_kw}function {mark(func_name_str, SymbolRef.function(func_core.findex.value), True)}{type_params}({params_joined_str}){ret_decl} {{"
    output_lines.append(func_header)

    initial_declared_vars = {p.split(":")[0].strip().lstrip("?") for p in params_str_list}
    # For instance methods and constructors, register 0 is `this` — skip it.
    if (is_instance or is_constructor) and ir_func.locals:
        initial_declared_vars.add(ir_func.locals[0].name)
    if abstract_constructor:
        initial_declared_vars.add("this")

    # Classify locals: those with an unconditional first assignment can be declared
    # inline at that assignment site (`var x = expr;`); those without must be
    # pre-declared at the top of the function to avoid Haxe block-scoping errors
    # (the variable would otherwise be undefined at the point of first *use*).
    local_types = _collect_locals(ir_func.block)
    unused_static_aliases = _unused_static_aliases(ir_func.block, code)
    for name in unused_static_aliases:
        local_types.pop(name, None)
    _tag_map_allocations(ir_func.block, code, func_core.findex.value, ir_func.all_locals)
    literal_arrays = _literal_array_types(ir_func.block, code)
    interfaces: Dict[str, Set[Optional[str]]] = {}
    map_values: Dict[str, Optional[str]] = {}
    defs_of_web: Dict[int, List[int]] = {}
    for index, web in getattr(ir_func, "_web_of_def", {}).items():
        defs_of_web.setdefault(web, []).append(index)
    for local in ir_func.all_locals:
        if local.name in local_types and local.reg_idx is not None:
            node = ("r", func_core.findex.value, local.reg_idx)
            local_types[local.name] = mapargs.refine(local_types[local.name], mapargs.value_type(code, node))
            map_values.setdefault(local.name, mapargs.value_type(code, node))
            local_types[local.name] = arrayelems.refine(
                local_types[local.name], arrayelems.element_type(code, func_core, local.reg_idx)
            )
            if local.name in literal_arrays:
                local_types[local.name] = arrayelems.refine(
                    local_types[local.name], literal_arrays[local.name][len("Array<") : -1]
                )
            regs = func_core.regs
            if local.reg_idx >= len(regs) or regs[local.reg_idx].resolve(code) is not local.get_type():
                interfaces.setdefault(local.name, set()).add(None)
                continue
            defs = defs_of_web.get(local.web, []) if local.web is not None else None
            interface = ifacenames.local(code, func_core.findex.value, local.reg_idx, defs)
            interfaces.setdefault(local.name, set()).add(interface.name if interface is not None else None)
    for name, found in interfaces.items():
        # A name several registers share is declared once: only as what they all are.
        only = next(iter(found))
        if len(found) == 1 and only is not None:
            local_types[name] = mapargs.refine(disasm.type_to_haxe(only), map_values.get(name))
    receiver_types = _virtual_receiver_static_types(ir_func, code)
    for name, haxe_type in receiver_types.items():
        if name in local_types:
            local_types[name] = haxe_type
    for name in getattr(ir_func, "_unboxed_captures", ()):
        boxed = re.fullmatch(r"Array<(.+)>", local_types.get(name, ""))
        if boxed is not None:
            local_types[name] = boxed.group(1)
    catch_locals = _collect_catch_local_names(ir_func.block)
    foreach_elem_names = _collect_foreach_elem_names(ir_func.block)
    inline_declarations: Dict[IRStatement, Tuple[str, str]] = {}  # stmt → (name, type_str)
    with _memoized_local_reads():
        _plan_declarations(
            ir_func,
            local_types,
            initial_declared_vars,
            catch_locals,
            foreach_elem_names,
            inline_declarations,
            output_lines,
        )
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
        unused_static_aliases=unused_static_aliases,
    )
    # Suppress trailing bare `return;` for Void functions and constructors — it's implicit.
    is_void_return = return_type_str in ("Void", "void") or is_constructor or abstract_constructor
    if is_void_return and body_lines and body_lines[-1].strip() == "return;":
        body_lines = body_lines[:-1]
    output_lines.extend(body_lines)

    output_lines.append("}")

    return disasm.source_paths("\n".join(output_lines)), op_to_line


def _render_string_concat(expr: IRCall, code: Bytecode, ir_function: Optional[IRFunction]) -> Optional[str]:
    """Render a String.__add__ chain as Haxe.

    Dense chains (with several interpolated values) become single-quote string
    interpolation; otherwise a flat `a + b + c` without redundant parentheses.
    """
    operands = _flatten_string_concat(expr, code)
    if operands is None or len(operands) < 2:
        return None

    # Classify each operand as a string literal or a value to interpolate.
    # `+` and interpolation both stringify their operands, so the explicit
    # conversion HL inserted is noise — as long as one operand still makes
    # the expression a string concatenation rather than arithmetic.
    anchored = any(isinstance(operand, IRConst) and isinstance(operand.value, str) for operand in operands)
    # A non-conversion operand also types the chain as a string concatenation.
    typed_concat = anchored or any(not isinstance(operand, IRStringConvert) for operand in operands)
    parts: List[Tuple[str, Any]] = []  # (kind, payload); kind in {"lit", "val"}
    interp_count = 0
    # A leading int constant must stay a literal: `1 + 2 + ""` is arithmetic in Haxe. Once a
    # string literal precedes it, a bare int is stringified by the chain itself.
    started = False
    for index, operand in enumerate(operands):
        if isinstance(operand, IRConst) and isinstance(operand.value, str):
            parts.append(("lit", operand.value))
            started = True
            continue
        if typed_concat and isinstance(operand, IRStringConvert):
            operand = operand.value
        if (
            anchored
            and not started
            and isinstance(operand, IRConst)
            and not isinstance(operand.value, str)
            # A float prints differently in source (`0.0`) and as text (`0`).
            and operand.get_type().kind.value not in (Type.Kind.F32.value, Type.Kind.F64.value)
        ):
            text = _expression_to_haxe(operand, code, ir_function)
            following = operands[index + 1] if index + 1 < len(operands) else None
            if isinstance(following, IRConst) and isinstance(following.value, str):
                # `3 + ""` stringifies the int itself; quoting it would fold into a literal.
                parts.append(("val", (operand, text)))
                interp_count += 1
                continue
            parts.append(("lit", text))
            started = True
            continue
        simple = _expression_to_haxe(operand, code, ir_function)
        if isinstance(operand, (IRArithmetic, IRBoolExpr)):
            simple = f"({simple})"
        parts.append(("val", (operand, simple)))
        interp_count += 1

    # Use interpolation only for dense chains (multiple interpolated values) that start with
    # literal text. Haxe lowers `'${a} ...'` to `"" + a + ...`, so a leading value would add
    # an empty-string concat the original chain never had.
    starts_with_literal = parts[0][0] == "lit"
    if interp_count >= 2 and starts_with_literal:
        return _render_interpolated(parts)

    # Otherwise: flat `a + b + c`, no redundant wrapping parentheses.
    rendered = []
    for kind, payload in parts:
        if kind == "lit":
            rendered.append('"' + disasm._escape_str(payload, '"') + '"')
        else:
            rendered.append(payload[1])
    return " + ".join(rendered)


def _enum_pattern_to_haxe(pattern: IREnumPattern, code: Bytecode, qualified: bool = False) -> str:
    enum = cast(Enum, pattern.enum_type.resolve(code).definition)
    construct = enum.constructs[pattern.constructor_index]
    name = disasm.enum_construct_name(code, enum, pattern.constructor_index)
    if enum.name.value == 0:
        name = f"{disasm._enum_name(code, enum)}.{name}"
    elif qualified:
        name = f"{destaticify(disasm._enum_name(code, enum))}.{name}"
    params = []
    for index in range(len(construct.params)):
        slot = pattern.slots.get(index)
        if isinstance(slot, IRConst):
            literal = _expression_to_haxe(slot, code, None)
            if (
                slot.const_type == IRConst.ConstType.FLOAT
                and construct.params[index].resolve(code).kind.value == Type.Kind.DYN.value
                and re.fullmatch(r"-?\d{1,9}\.0", strip(literal))
            ):
                literal = strip(literal)[
                    :-2
                ]  # a Dynamic payload compared with a whole number: the Int literal
            params.append(literal)
            continue
        params.append(
            _enum_pattern_to_haxe(slot, code, qualified)
            if isinstance(slot, IREnumPattern)
            else slot.name
            if isinstance(slot, IRLocal)
            else "_"
        )
    return f"{name}({', '.join(params)})" if params else name


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
            name = disasm.enum_construct_name(code, enum_type, idx)
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


def _rewrite_constructor_call(
    call: IRCall, code: Bytecode, ir_function: Optional[IRFunction]
) -> Optional[str]:
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

    if isinstance(arg, IRLocal) and ir_function is not None:
        # The receiver is a local defined by New earlier in the same block
        # (not inlined, e.g. because it's used again later). The New's own
        # rendering already reads as `new X(...)`, so this call is a
        # redundant second invocation of the constructor; drop it.
        defining = _find_defining_assignment(arg.name, ir_function.block)
        if isinstance(defining, IRAssign) and isinstance(defining.expr, IRNew):
            new_type_name = destaticify(disasm.type_name(code, defining.expr.get_type()))
            if new_type_name == ctor_class_name:
                return ""

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
                        rest_args = ", ".join(
                            _expression_to_haxe(a, code, ir_function) for a in call.args[1:]
                        )
                        return f"super({rest_args})"
        return ""

    return None


def _try_instance_method_call(
    func: "Function",
    first_arg: IRExpression,
    code: Bytecode,
    ir_function: Optional[IRFunction] = None,
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
    raw_owner = (code.full_func_name(func) or "").rsplit(".", 1)[0].rsplit(".", 1)[-1]
    if raw_owner.startswith("$") and not _is_std_function(func, code):
        # A user static that happens to take its own class first is not a method.
        return None
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

    arg_expr_str = _expression_to_haxe(first_arg, code, ir_function)
    if (
        isinstance(first_arg, IRCast)
        and first_arg.expr.get_type().kind.value == Type.Kind.DYN.value
        and isinstance(first_arg.get_type().definition, Obj)
    ):
        # A dynamic value (`Any`) has no fields to call; name the class it is used as.
        annotation = disasm._haxe_annotation(code, first_arg.get_type())
        arg_expr_str = f"({arg_expr_str} : {mapargs.refine(annotation, first_arg.map_value)})"
    elif _needs_receiver_parens(arg_expr_str):
        arg_expr_str = f"({arg_expr_str})"
    return f"{arg_expr_str}.{method_name}"


def _render_abstract_call(
    expr: IRCall,
    func: "Function",
    abstract: abstracts.Abstract,
    code: Bytecode,
    ir_function: Optional[IRFunction],
) -> str:
    """`_render_abstract_call_raw`, typed as the class the call is erased to: a std
    abstract's member that returns a class returns the abstract, which doesn't unify with
    its underlying class (`UInt8Array` into the `ArrayBufferViewImpl` a local holds)."""
    rendered = _render_abstract_call_raw(expr, func, abstract, code, ir_function)
    signature = func.type.resolve(code).definition
    if abstract.std and isinstance(signature, Fun) and func.findex.value != abstract.constructor:
        ret = signature.ret.resolve(code)
        if isinstance(ret.definition, Obj):
            return f"(cast ({rendered}) : {disasm._haxe_annotation(code, ret)})"
    return rendered


def _render_abstract_call_raw(
    expr: IRCall,
    func: "Function",
    abstract: abstracts.Abstract,
    code: Bytecode,
    ir_function: Optional[IRFunction],
) -> str:
    """A call to a member of an abstract, as source writes it: `new Name(..)`,
    `Name.member(..)`, or on a value `(value : Name).member(..)` / `.property`."""
    findex = func.findex.value
    args = [_expression_to_haxe(arg, code, ir_function) for arg in expr.args]
    method = code.partial_func_name(func)
    ref = _abstract_ref(abstract, code, ir_function)
    if findex == abstract.constructor:
        return f"new {ref}({', '.join(args)})"
    if findex not in abstract.instance or not expr.args:
        return f"{ref}.{method}({', '.join(args)})"
    accessor = abstract.accessor(findex)
    member = accessor[0].name if accessor is not None else method
    receiver = _abstract_receiver(expr.args[0], args[0], member, abstract, code, ir_function)
    if accessor is None:
        return f"{receiver}{method}({', '.join(args[1:])})"
    if accessor[1]:
        return f"{receiver}{member} = {args[1]}"
    return f"{receiver}{member}"


def _abstract_receiver(
    value: IRExpression,
    rendered: str,
    member: str,
    abstract: abstracts.Abstract,
    code: Bytecode,
    ir_function: Optional[IRFunction],
) -> str:
    """What goes before `member` to reach it on `value`, dot included. The value has
    the underlying type, so it's checked as the abstract (`(v : Name).`), a cast that
    compiles to nothing; inside the abstract's own methods, `this` needs no prefix
    unless a local shadows the member."""
    if (
        isinstance(value, IRLocal)
        and value.name == "this"
        and ir_function is not None
        and isinstance(ir_function.func, Function)
        and abstracts.abstract_of_function(code, ir_function.func) is abstract
        and not any(local.name == member for local in ir_function.all_locals)
    ):
        return ""
    if (
        isinstance(value, IRCall)
        and isinstance(value.target, IRConst)
        and isinstance(value.target.value, Function)
        and value.target.value.findex.value == abstract.constructor
    ):
        return f"{rendered}."
    public = _PRIVATE_STD_ABSTRACT_PROPERTIES.get(abstract.path)
    if public is not None:
        owner, prop = public
        return f"new {owner}({rendered}).{prop}."
    type_args = abstract.type_args
    if type_args == "<Dynamic>":
        # A one-parameter std abstract over an array (`Rest<T>`) takes its element type
        # from the array: `Rest<Dynamic>` would read a typed array as an `Array<Dynamic>`.
        element = value
        while isinstance(element, IRCast):
            element = element.expr
        match = re.fullmatch(r"Array<(.+)>", disasm._haxe_annotation(code, element.get_type()))
        if match:
            type_args = f"<{match.group(1)}>"
            rendered = _expression_to_haxe(element, code, ir_function)
    return f"({rendered} : {_abstract_ref(abstract, code, ir_function)}{type_args})."


def _needs_receiver_parens(text: str) -> bool:
    """Whether `text` has an operator outside brackets and strings, so `text.member` would bind to
    its last operand (`"a" + "b".indexOf(..)`)."""
    text = strip(text)  # a decision only: span markers are neither operators nor operands
    if re.match(r"\s*(?:[-!~]|cast\b|new\b)", text):
        return True
    depth = 0
    plain = []
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif depth == 0:
            plain.append(ch)
    outside = "".join(plain)
    outside = re.sub(r"\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'", "", outside)
    return bool(re.search(r"\s(?:[-+*/%<>=!&|^?:]+|->|is)\s", outside))


def _wrap_receiver(text: str) -> str:
    """Parenthesise a rendered receiver unless it's a plain name or member chain."""
    return text if re.fullmatch(r"[\w.]+", strip(text)) else f"({text})"
