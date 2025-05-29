"""
Pseudocode generation routines to create a Haxe representation of the decompiled IR.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional, List

from .core import Bytecode, Type, Function, Fun
from . import disasm
from .decomp import (
    IRBreak,
    IRFunction,
    IRBlock,
    IRStatement,
    IRExpression,
    IRAssign,
    IRLocal,
    IRConst,
    IRArithmetic,
    IRBoolExpr,
    IRCall,
    IRConditional,
    IRWhileLoop,
    IRPrimitiveLoop,
    IRReturn,
    IRPrimitiveJump,
    _get_type_in_code,
)


def _indent_str(level: int) -> str:
    return "    " * level  # 4 spaces for indentation


def _expression_to_haxe(expr: Optional[IRStatement], code: Bytecode, ir_function: IRFunction) -> str:
    assert expr is not None, "Found empty statement!"
    if isinstance(expr, IRLocal):
        return expr.name
    elif isinstance(expr, IRConst):
        if isinstance(expr.value, Function):  # crashlink.core.Function
            # For function constants, use their partial name or findex
            return disasm.partial_func_name(code, expr.value) or f"f@{expr.value.findex.value}"
        elif isinstance(expr.value, str):
            # Basic string quoting, may need more sophisticated escaping for real Haxe
            return '"' + expr.value.replace('"', '\\"') + '"'
        elif isinstance(expr.value, bool):
            return "true" if expr.value else "false"
        elif expr.value is None:  # For IRConst.ConstType.NULL
            return "null"
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
        if expr.op == IRBoolExpr.CompareType.NULL:
            return f"{_expression_to_haxe(expr.left, code, ir_function)} == null"
        elif expr.op == IRBoolExpr.CompareType.NOT_NULL:
            return f"{_expression_to_haxe(expr.left, code, ir_function)} != null"
        elif expr.op == IRBoolExpr.CompareType.ISTRUE:
            # For Haxe, (expr) or (expr == true)
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
            left = _expression_to_haxe(expr.left, code, ir_function)
            right = _expression_to_haxe(expr.right, code, ir_function)
            return f"{left} {op_map[expr.op]} {right}"
        elif expr.left:  # Unary boolean expressions like NOT handled above
            raise NotImplementedError(f"Unhandled unary IRBoolExpr op: {expr.op} on {expr.left}")
        else:
            raise NotImplementedError(f"Unhandled IRBoolExpr: {expr}")

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
    elif isinstance(expr, IRPrimitiveJump):  # Should be gone, but as a fallback
        return f"/* GOTO_LIKE({expr.op.op}) */"

    # Fallback for unknown expressions
    return f"/* <UnknownExpr: {type(expr).__name__}> */"


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
            value_str = _expression_to_haxe(stmt.expr, code, ir_function)

            # Simple check for declaration: if target is an IRLocal and not yet declared
            if isinstance(stmt.target, IRLocal) and stmt.target.name not in declared_vars_in_scope:
                type_name = disasm.type_to_haxe(disasm.type_name(code, stmt.target.get_type()))
                type_decl = f":{type_name}" if type_name and type_name != "Dynamic" and type_name != "Void" else ""
                output_lines.append(f"{indent}var {target_str}{type_decl} = {value_str};")
                declared_vars_in_scope.add(stmt.target.name)
            else:
                output_lines.append(f"{indent}{target_str} = {value_str};")

        elif isinstance(stmt, IRConditional):
            cond_str = _expression_to_haxe(stmt.condition, code, ir_function)
            output_lines.append(f"{indent}if ({cond_str}) {{")
            output_lines.extend(
                _generate_statements(
                    stmt.true_block.statements,
                    code,
                    ir_function,
                    indent_level + 1,
                    declared_vars_in_scope.copy(),
                )
            )
            if stmt.false_block and stmt.false_block.statements:
                output_lines.append(f"{indent}}} else {{")
                output_lines.extend(
                    _generate_statements(
                        stmt.false_block.statements,
                        code,
                        ir_function,
                        indent_level + 1,
                        declared_vars_in_scope.copy(),
                    )
                )
                output_lines.append(f"{indent}}}")
            else:
                output_lines.append(f"{indent}}}")

        elif isinstance(stmt, IRWhileLoop):
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
        
        elif isinstance(stmt, IRBreak):
            output_lines.append(f"{indent}break;")

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


def pseudo(ir_func: IRFunction) -> str:
    """
    Generates Haxe pseudocode from a given IRFunction.
    """
    code: Bytecode = ir_func.code
    func_core: Function = ir_func.func  # crashlink.core.Function

    output_lines: List[str] = []
    base_indent = 0

    # Function Signature
    func_name_str = disasm.partial_func_name(code, func_core) or f"f{func_core.findex.value}"
    static_kw = "static " if disasm.is_static(code, func_core) else ""

    params_str_list = []
    return_type_str = "Void"  # Default

    core_fun_type_def = func_core.type.resolve(code).definition
    if isinstance(core_fun_type_def, Fun):  # crashlink.core.Fun
        for i, arg_type_idx in enumerate(core_fun_type_def.args):
            arg_core_type = arg_type_idx.resolve(code)
            arg_haxe_type_name = disasm.type_to_haxe(disasm.type_name(code, arg_core_type))

            param_name = f"arg{i}"  # Default name
            # Try to get actual param name from debug assigns (op index < 0)
            if func_core.has_debug and func_core.assigns:
                arg_assigns = [a for a in func_core.assigns if a[1].value < 0]
                if i < len(arg_assigns):
                    param_name = arg_assigns[i][0].resolve(code)

            param_type_decl = f":{arg_haxe_type_name}" if arg_haxe_type_name and arg_haxe_type_name != "Dynamic" else ""
            params_str_list.append(f"{param_name}{param_type_decl}")

        ret_core_type = core_fun_type_def.ret.resolve(code)
        return_type_str = disasm.type_to_haxe(disasm.type_name(code, ret_core_type))

    params_joined_str = ", ".join(params_str_list)
    func_header = (
        f"{_indent_str(base_indent)}{static_kw}function {func_name_str}({params_joined_str}):{return_type_str} {{"
    )
    output_lines.append(func_header)

    # Function Body
    # Initialize declared_vars with function parameters
    initial_declared_vars = {p_name.split(":")[0] for p_name in params_str_list}

    body_lines = _generate_statements(ir_func.block.statements, code, ir_func, base_indent + 1, initial_declared_vars)
    output_lines.extend(body_lines)

    output_lines.append(f"{_indent_str(base_indent)}}}")

    # Attempt to wrap in a class for context if class name can be derived
    full_name = disasm.full_func_name(code, func_core)
    class_name_suggestion = "DecompiledClass"
    if "." in full_name:
        class_name_part = full_name.split(".")[0]
        if class_name_part and class_name_part != "<none>":
            class_name_suggestion = class_name_part.replace("$", "_")  # Handle Haxe internal names

    final_output = [f"class {class_name_suggestion} {{"]
    final_output.extend(["  " + line for line in output_lines])  # Indent function within class
    final_output.append("}")

    return "\n".join(final_output)
