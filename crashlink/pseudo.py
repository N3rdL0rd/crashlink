"""
Pseudocode generation routines to create a Haxe representation of the decompiled IR.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional, List

from .core import Bytecode, Obj, Type, Function, Fun, Native, destaticify
from . import disasm
from .decomp import (
    IRBreak,
    IRContinue,
    IRCast,
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
    IRBoolExpr,
    IRCall,
    IRConditional,
    IRTrace,
    IRTryCatch,
    IRUnliftedOpcode,
    IRArrayAccess,
    IRRef,
    IREnumConstruct,
    IREnumIndex,
    IREnumField,
    IRWhileLoop,
    IRPrimitiveLoop,
    IRReturn,
    IRPrimitiveJump,
    IRSwitch,
    _get_type_in_code,
)


def _indent_str(level: int) -> str:
    return "    " * level  # 4 spaces for indentation


def _collect_assigned_names(stmts: List[IRStatement]) -> set[str]:
    names: set[str] = set()
    for s in stmts:
        if isinstance(s, IRAssign) and isinstance(s.target, IRLocal):
            names.add(s.target.name)
    return names


def _expression_to_haxe(expr: Optional[IRStatement], code: Bytecode, ir_function: IRFunction) -> str:
    assert expr is not None, "Found empty statement!"

    if isinstance(expr, IRLocal):
        return expr.name

    elif isinstance(expr, IRConst):
        if isinstance(expr.value, Function):  # crashlink.core.Function
            # For function constants, use their partial name or findex
            return code.partial_func_name(expr.value) or f"f@{expr.value.findex.value}"
        elif isinstance(expr.value, str):
            # Basic string quoting, may need more sophisticated escaping for real Haxe
            return '"' + expr.value.replace('"', '\\"') + '"'
        elif isinstance(expr.value, bool):
            return "true" if expr.value else "false"
        elif expr.value is None:  # For IRConst.ConstType.NULL
            return "null"
        elif isinstance(expr.value, Type) and isinstance(expr.value.definition, Obj):
            return destaticify(expr.value.definition.name.resolve(code))
        elif isinstance(expr.value, Native):
            return f"<native:{expr.value.name}>"
        elif expr.const_type == IRConst.ConstType.INT:
            val = expr.value.value if hasattr(expr.value, "value") else expr.value
            val = int(val)
            if val >= 0x80000000:
                val = val - 0x100000000
            return str(val)
        return str(expr.value)

    elif isinstance(expr, IRArithmetic):
        left = _expression_to_haxe(expr.left, code, ir_function)
        right = _expression_to_haxe(expr.right, code, ir_function)
        # Add parentheses for potentially ambiguous operations if needed for clarity
        # e.g., if expr.op.value in ["*", "/"] and (isinstance(expr.left, IRArithmetic) or isinstance(expr.right, IRArithmetic)):
        # For pseudocode, direct representation is often fine.
        return f"{left} {expr.op.value} {right}"

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
        target_str = _expression_to_haxe(expr.target, code, ir_function)
        return f"{target_str}.{expr.field_name}"

    elif isinstance(expr, IRArrayAccess):
        arr_str = _expression_to_haxe(expr.array, code, ir_function)
        idx_str = _expression_to_haxe(expr.index, code, ir_function)
        return f"{arr_str}[{idx_str}]"

    elif isinstance(expr, IRRef):
        inner = _expression_to_haxe(expr.target, code, ir_function)
        return f"&{inner}"

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
        return f"{inner}.{expr.field_name}"

    elif isinstance(expr, IRCall):
        callee_str: str
        if expr.call_type == IRCall.CallType.THIS and expr.target is None:
            # This assumes the method name is somehow retrievable or you have a convention
            # For now, let's assume a placeholder if the method name isn't directly in IRCall
            # You might need to pass the Opcode field for 'CallThis' to get the field name.
            callee_str = "this.unknownMethod"  # Placeholder
        elif expr.target:
            callee_str = _expression_to_haxe(expr.target, code, ir_function)
        else:  # Should have a target or be THIS
            raise ValueError(f"IRCall missing target or unhandled type: {expr.call_type}")

        args_str = ", ".join(_expression_to_haxe(arg, code, ir_function) for arg in expr.args)
        return f"{callee_str}({args_str})"

    elif isinstance(expr, IRUnliftedOpcode):
        return f"/* UNLIFTED OPCODE: {expr.op.op} {disasm.pseudo_from_op(expr.op, 0, ir_function.func.regs, code, terse=True)} */"

    elif isinstance(expr, IRNew):
        type_name = disasm.type_name(code, expr.get_type())
        if type_name == "DynObj":
            return "{}"
        else:
            args_str = ", ".join(_expression_to_haxe(a, code, ir_function) for a in expr.constructor_args)
            return f"new {disasm.type_to_haxe(type_name)}({args_str})"

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


def _generate_statements(
    statements: List[IRStatement],
    code: Bytecode,
    ir_function: IRFunction,
    indent_level: int,
    # Track declared variables in the current scope to decide between "var x =" and "x ="
    # This is a simplification; a proper symbol table would be more robust.
    declared_vars_in_scope: set[str],
) -> List[str]:
    output_lines: List[str] = []
    indent = _indent_str(indent_level)

    for stmt in statements:
        if isinstance(stmt, IRBlock):  # Nested block, usually from if/else/loop bodies
            # HaxeBlock's content is generated by recursively calling _generate_statements
            # The parent (if/while) handles the "{" and "}"
            output_lines.extend(
                _generate_statements(
                    stmt.statements,
                    code,
                    ir_function,
                    indent_level,
                    declared_vars_in_scope.copy(),
                )
            )
        elif isinstance(stmt, IRAssign):
            target_str = _expression_to_haxe(stmt.target, code, ir_function)
            already_declared = isinstance(stmt.target, IRLocal) and stmt.target.name in declared_vars_in_scope

            _is_self_ref_arith = (
                isinstance(stmt.target, IRLocal)
                and isinstance(stmt.expr, IRArithmetic)
                and isinstance(stmt.expr.left, IRLocal)
                and stmt.expr.left == stmt.target
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
            if (
                (already_declared or _is_self_ref_arith)
                and isinstance(stmt.target, IRLocal)
                and isinstance(stmt.expr, IRArithmetic)
                and isinstance(stmt.expr.left, IRLocal)
                and stmt.expr.left == stmt.target
                and isinstance(stmt.expr.right, IRConst)
                and stmt.expr.right.value == 1
                and stmt.expr.op in (IRArithmetic.ArithmeticType.ADD, IRArithmetic.ArithmeticType.SUB)
            ):
                op_sym = "++" if stmt.expr.op == IRArithmetic.ArithmeticType.ADD else "--"
                output_lines.append(f"{indent}{target_str}{op_sym};")
                declared_vars_in_scope.add(stmt.target.name)
            # Detect x += y patterns: target = target op expr
            elif (
                (already_declared or _is_self_ref_arith)
                and isinstance(stmt.target, IRLocal)
                and isinstance(stmt.expr, IRArithmetic)
                and isinstance(stmt.expr.left, IRLocal)
                and stmt.expr.left == stmt.target
                and stmt.expr.op in _compound_ops
            ):
                rhs_str = _expression_to_haxe(stmt.expr.right, code, ir_function)
                output_lines.append(f"{indent}{target_str} {_compound_ops[stmt.expr.op]} {rhs_str};")
                declared_vars_in_scope.add(stmt.target.name)
            elif isinstance(stmt.target, IRLocal) and not already_declared:
                type_name = disasm.type_to_haxe(disasm.type_name(code, stmt.target.get_type()))
                type_decl = f": {type_name}" if type_name and type_name != "Dynamic" and type_name != "Void" else ""
                value_str = _expression_to_haxe(stmt.expr, code, ir_function)
                output_lines.append(f"{indent}var {target_str}{type_decl} = {value_str};")
                declared_vars_in_scope.add(stmt.target.name)
            else:
                value_str = _expression_to_haxe(stmt.expr, code, ir_function)
                output_lines.append(f"{indent}{target_str} = {value_str};")

        elif isinstance(stmt, IRTrace):
            msg_str = _expression_to_haxe(stmt.msg, code, ir_function)
            pos_info_str = ", ".join(f"{k}: {v!r}" for k, v in stmt.pos_info.items())
            output_lines.append(f"{indent}trace({msg_str}); // {{ {pos_info_str} }}")

        elif isinstance(stmt, IRUnliftedOpcode):
            output_lines.append(
                f"{indent}// UNLIFTED OPCODE: {disasm.pseudo_from_op(stmt.op, 0, ir_function.func.regs, code, terse=True)}"
            )

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
                output_lines.append(f"{indent}if ({inv_cond}) {{")
                output_lines.extend(
                    _generate_statements(
                        false_stmts, code, ir_function, indent_level + 1, declared_vars_in_scope.copy()
                    )
                )
                output_lines.append(f"{indent}}}")
                declared_vars_in_scope.update(_collect_assigned_names(false_stmts))
            else:
                cond_str = _expression_to_haxe(stmt.condition, code, ir_function)
                output_lines.append(f"{indent}if ({cond_str}) {{")
                output_lines.extend(
                    _generate_statements(true_stmts, code, ir_function, indent_level + 1, declared_vars_in_scope.copy())
                )
                # If the true block ends with a control-flow statement, the else is unnecessary.
                true_ends_with_cf = bool(true_stmts) and isinstance(true_stmts[-1], (IRBreak, IRContinue, IRReturn))
                if false_stmts and not true_ends_with_cf:
                    output_lines.append(f"{indent}}} else {{")
                    output_lines.extend(
                        _generate_statements(
                            false_stmts, code, ir_function, indent_level + 1, declared_vars_in_scope.copy()
                        )
                    )
                    output_lines.append(f"{indent}}}")
                elif false_stmts and true_ends_with_cf:
                    output_lines.append(f"{indent}}}")
                    # Render former else block as plain statements (no else keyword needed)
                    output_lines.extend(
                        _generate_statements(
                            false_stmts, code, ir_function, indent_level, declared_vars_in_scope.copy()
                        )
                    )
                else:
                    output_lines.append(f"{indent}}}")
                declared_vars_in_scope.update(_collect_assigned_names(true_stmts))
                declared_vars_in_scope.update(_collect_assigned_names(false_stmts))

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
                    output_lines.extend(
                        _generate_statements(
                            stmt.body.statements[:-1],
                            code,
                            ir_function,
                            indent_level + 1,
                            declared_vars_in_scope.copy(),
                        )
                    )
                    cond_str = _inverted_bool_expr_to_haxe(last_stmt.condition, code, ir_function)
                    output_lines.append(f"{indent}}} while ({cond_str});")
                    rendered_as_do_while = True

            if not rendered_as_do_while:
                cond_str = _expression_to_haxe(stmt.condition, code, ir_function)
                output_lines.append(f"{indent}while ({cond_str}) {{")
                output_lines.extend(
                    _generate_statements(
                        stmt.body.statements,
                        code,
                        ir_function,
                        indent_level + 1,
                        declared_vars_in_scope.copy(),
                    )
                )
                output_lines.append(f"{indent}}}")

        elif isinstance(stmt, IRPrimitiveLoop):  # Fallback if not optimized to IRWhileLoop
            output_lines.append(f"{indent}// Primitive Loop (condition first, then body)")
            output_lines.append(f"{indent}{{ // Condition Block")
            output_lines.extend(
                _generate_statements(
                    stmt.condition.statements,
                    code,
                    ir_function,
                    indent_level + 1,
                    declared_vars_in_scope.copy(),
                )
            )
            output_lines.append(f"{indent}}}")
            output_lines.append(f"{indent}{{ // Body Block")
            output_lines.extend(
                _generate_statements(
                    stmt.body.statements,
                    code,
                    ir_function,
                    indent_level + 1,
                    declared_vars_in_scope.copy(),
                )
            )
            output_lines.append(f"{indent}}}")

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

        elif isinstance(stmt, IRSwitch):
            value_str = _expression_to_haxe(stmt.value, code, ir_function)
            output_lines.append(f"{indent}switch ({value_str}) {{")
            for case_value, case_block in stmt.cases.items():
                case_str = _expression_to_haxe(case_value, code, ir_function)
                output_lines.append(f"{indent}    case {case_str}:")
                output_lines.extend(
                    _generate_statements(
                        case_block.statements,
                        code,
                        ir_function,
                        indent_level + 2,
                        declared_vars_in_scope.copy(),
                    )
                )
                for s in case_block.statements:
                    if isinstance(s, IRAssign) and isinstance(s.target, IRLocal):
                        declared_vars_in_scope.add(s.target.name)
            if stmt.default and stmt.default.statements:
                output_lines.append(f"{indent}    default:")
                output_lines.extend(
                    _generate_statements(
                        stmt.default.statements,
                        code,
                        ir_function,
                        indent_level + 2,
                        declared_vars_in_scope.copy(),
                    )
                )
                for s in stmt.default.statements:
                    if isinstance(s, IRAssign) and isinstance(s.target, IRLocal):
                        declared_vars_in_scope.add(s.target.name)
            output_lines.append(f"{indent}}}")

        elif isinstance(stmt, IRTryCatch):
            catch_name = "e"
            catch_type = "Dynamic"
            if stmt.catch_local and stmt.catch_local.name and not stmt.catch_local.name.startswith("var"):
                catch_name = stmt.catch_local.name
            if stmt.catch_local:
                t = disasm.type_name(code, stmt.catch_local.get_type())
                if t and t != "Dyn":
                    catch_type = disasm.type_to_haxe(t)
            output_lines.append(f"{indent}try {{")
            output_lines.extend(
                _generate_statements(
                    stmt.try_block.statements,
                    code,
                    ir_function,
                    indent_level + 1,
                    declared_vars_in_scope.copy(),
                )
            )
            output_lines.append(f"{indent}}} catch ({catch_name}:{catch_type}) {{")
            output_lines.extend(
                _generate_statements(
                    stmt.catch_block.statements,
                    code,
                    ir_function,
                    indent_level + 1,
                    declared_vars_in_scope.copy(),
                )
            )
            output_lines.append(f"{indent}}}")

        elif isinstance(stmt, IRBreak):
            output_lines.append(f"{indent}break;")

        elif isinstance(stmt, IRContinue):
            output_lines.append(f"{indent}continue;")

        elif isinstance(stmt, IRExpression):  # e.g. a standalone IRCall not assigned
            expr_str = _expression_to_haxe(stmt, code, ir_function)
            output_lines.append(f"{indent}{expr_str};")

        else:
            output_lines.append(f"{indent}// <Unhandled IRStatement: {type(stmt).__name__}> {str(stmt)[:50]}...")

        if stmt.comment:
            # Add comment at the end of the line or on a new line
            if output_lines:
                output_lines[-1] += f" // {stmt.comment}"
            else:  # Should not happen if statement generated something
                output_lines.append(f"{indent}// {stmt.comment}")

    return output_lines


def _generate_function_pseudo(ir_func: IRFunction) -> str:
    """Generates the Haxe pseudocode for a single function, without the class wrapper."""
    code: Bytecode = ir_func.code
    func_core: Function = ir_func.func

    output_lines: List[str] = []
    base_indent = 0

    func_name_str = code.partial_func_name(func_core) or f"f{func_core.findex.value}"
    static_kw = ""

    # A better way might be to just call disasm.is_static
    if disasm.is_static(code, func_core):
        static_kw = "static "

    if not func_name_str or func_name_str == "<none>":
        return f"// Could not determine name for f@{func_core.findex.value}"

    params_str_list = []
    return_type_str = "Void"

    core_fun_type_def = func_core.type.resolve(code).definition
    if isinstance(core_fun_type_def, Fun):
        for i, arg_type_idx in enumerate(core_fun_type_def.args):
            arg_core_type = arg_type_idx.resolve(code)
            arg_haxe_type_name = disasm.type_to_haxe(disasm.type_name(code, arg_core_type))

            param_name = f"arg{i}"
            if func_core.has_debug and func_core.assigns:
                arg_assigns = [a for a in func_core.assigns if a[1].value <= 0]
                if i < len(arg_assigns):
                    param_name = arg_assigns[i][0].resolve(code)

            param_type_decl = (
                f": {arg_haxe_type_name}" if arg_haxe_type_name and arg_haxe_type_name != "Dynamic" else ""
            )
            params_str_list.append(f"{param_name}{param_type_decl}")

        ret_core_type = core_fun_type_def.ret.resolve(code)
        return_type_str = disasm.type_to_haxe(disasm.type_name(code, ret_core_type))

    params_joined_str = ", ".join(params_str_list)
    func_header = f"{static_kw}function {func_name_str}({params_joined_str}): {return_type_str} {{"
    output_lines.append(func_header)

    initial_declared_vars = {p.split(":")[0].strip() for p in params_str_list}

    body_lines = _generate_statements(ir_func.block.statements, code, ir_func, base_indent + 1, initial_declared_vars)
    # Suppress trailing bare `return;` for Void functions — it's implicit.
    if return_type_str in ("Void", "void") and body_lines and body_lines[-1].strip() == "return;":
        body_lines = body_lines[:-1]
    output_lines.extend(body_lines)

    output_lines.append("}")

    return "\n".join(output_lines)


def pseudo(ir_func: IRFunction) -> str:
    """
    Generates Haxe pseudocode from a given IRFunction, wrapped in a class for context.
    """
    function_body_str = _generate_function_pseudo(ir_func)

    full_name = ir_func.code.full_func_name(ir_func.func)
    class_name_suggestion = "DecompiledClass"
    if "." in full_name and full_name != "<none>.<none>":
        class_name_part = full_name.split(".")[0]
        if class_name_part and class_name_part != "<none>":
            class_name_suggestion = class_name_part.lstrip("$").replace(".", "_")

    final_output = [f"class {class_name_suggestion} {{"]
    final_output.extend(["    " + line for line in function_body_str.split("\n")])
    final_output.append("}")

    return "\n".join(final_output)


def class_pseudo(ir_class: "IRClass") -> str:
    """
    Generates Haxe pseudocode for an entire IRClass.
    """
    code: Bytecode = ir_class.code

    primary_obj = ir_class.dynamic if ir_class.dynamic else ir_class.static
    if not primary_obj:
        return "// Error: IRClass contains no valid Obj definitions."

    output_lines: List[str] = []
    indent_str = _indent_str(1)

    class_name = destaticify(primary_obj.name.resolve(code))
    header = f"class {class_name}"
    if ir_class.dynamic and ir_class.dynamic.super and ir_class.dynamic.super.value > 0:
        super_type = ir_class.dynamic.super.resolve(code)
        if isinstance(super_type.definition, Obj):
            super_name = destaticify(super_type.definition.name.resolve(code))
            header += f" extends {super_name}"
    header += " {"
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
        # A bit of a hack to give the generator context about where the function came from
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

    if output_lines and output_lines[-1] == "":
        output_lines.pop()

    output_lines.append("}")
    return "\n".join(output_lines)
