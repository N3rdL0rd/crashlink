"""
Inlining and copy-propagation optimizers.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Dict, List, Optional, Set, Tuple, Union, cast

if TYPE_CHECKING:
    from ..function import IRFunction

from ...core import (
    Opcode,
    Type,
)
from ...globals import DEBUG, dbg_print
from ..ir import (
    IRStatement,
    IRExpression,
    IRBlock,
    IRLocal,
    IRArithmetic,
    IRNeg,
    IRNot,
    IRTypeOf,
    IRTypeKind,
    IRAssign,
    IRCall,
    IRBoolExpr,
    IRConst,
    IRConditional,
    IRPrimitiveLoop,
    IRReturn,
    IRThrow,
    IRTrace,
    IRSwitch,
    IRPrimitiveJump,
    IRWhileLoop,
    IRForEachLoop,
    IRIntRangeLoop,
    IRField,
    IRNew,
    IRNativeArrayNew,
    IRCast,
    IRArrayLiteral,
    IRArrayAccess,
    IRRef,
    IRRefNew,
    IRRefGet,
    IRRefSet,
    IREnumConstruct,
    IREnumIndex,
    IREnumField,
)
from . import (
    TraversingIROptimizer,
)


class IRPrimitiveJumpLifter(TraversingIROptimizer):
    """
    Lifts an IRPrimitiveJump at the end of an IRPrimitiveLoop's condition block
    into an IRBoolExpr. This IRBoolExpr then becomes the new last statement
    of the condition block.

    This pass makes it easier for subsequent optimizers like IRConditionInliner
    to operate on the boolean logic.
    """

    def visit_primitive_loop(self, loop: IRPrimitiveLoop) -> None:
        """
        Focus on the condition block of the primitive loop.
        """
        if not loop.condition.statements:
            return  # Nothing to do

        last_cond_stmt = loop.condition.statements[-1]
        if not isinstance(last_cond_stmt, IRPrimitiveJump):
            # dbg_print(f"IRPrimitiveJumpLifter: Loop cond for {loop} does not end with IRPrimitiveJump. Skipping.")
            return

        primitive_jump: IRPrimitiveJump = last_cond_stmt
        original_jump_op: Opcode = primitive_jump.op

        # Map bytecode jump opcodes to IRBoolExpr.CompareType
        # This jump condition means "IF THIS EXPRESSION IS TRUE, THEN JUMP (conditionally exit/continue loop based on CFG)"
        # For a loop, the PrimitiveJump in the condition block usually signifies "if true, EXIT loop".
        # So, the IRBoolExpr we create here represents the EXIT condition.
        jump_to_bool_expr_map: Dict[str, IRBoolExpr.CompareType] = {
            "JTrue": IRBoolExpr.CompareType.ISTRUE,
            "JFalse": IRBoolExpr.CompareType.ISFALSE,
            "JNull": IRBoolExpr.CompareType.NULL,
            "JNotNull": IRBoolExpr.CompareType.NOT_NULL,
            "JSLt": IRBoolExpr.CompareType.LT,
            "JSGte": IRBoolExpr.CompareType.GTE,
            "JSGt": IRBoolExpr.CompareType.GT,
            "JSLte": IRBoolExpr.CompareType.LTE,
            "JULt": IRBoolExpr.CompareType.LT,
            "JUGte": IRBoolExpr.CompareType.GTE,
            "JNotLt": IRBoolExpr.CompareType.GTE,
            "JNotGte": IRBoolExpr.CompareType.LT,
            "JEq": IRBoolExpr.CompareType.EQ,
            "JNotEq": IRBoolExpr.CompareType.NEQ,
        }

        if original_jump_op.op not in jump_to_bool_expr_map:
            dbg_print(f"IRPrimitiveJumpLifter: Jump op {original_jump_op.op} not supported for BoolExpr conversion.")
            return

        condition_type = jump_to_bool_expr_map[original_jump_op.op]

        # Create the IRBoolExpr using operands from the original jump Opcode
        # These operands will be IRLocals.
        op_df = original_jump_op.df
        left_expr: Optional[IRExpression] = None
        right_expr: Optional[IRExpression] = None
        cond_operand_expr: Optional[IRExpression] = None

        # Helper to get operand as IRLocal. Prefer operands captured at lift time
        # so that later local-name splits do not change which value the jump was
        # testing (e.g. String.split's empty-delimiter loop bound).
        def resolve_operand(key_name: str) -> Optional[IRLocal]:
            stored: Optional[IRLocal] = None
            _attr = getattr(primitive_jump, key_name, None)
            if isinstance(_attr, IRLocal):
                stored = _attr
            if stored is not None:
                return stored
            if key_name not in op_df:
                return None
            try:
                reg_idx = op_df[key_name].value
                assert isinstance(reg_idx, int), "this should literally never happen!"
                local = self.func.locals[reg_idx]
                return local if isinstance(local, IRLocal) else None
            except (AttributeError, IndexError, KeyError):
                dbg_print(f"IRPrimitiveJumpLifter: Could not resolve local for key {key_name} in {original_jump_op}")
                return None

        if condition_type in [
            IRBoolExpr.CompareType.ISTRUE,
            IRBoolExpr.CompareType.ISFALSE,
        ]:
            cond_operand_expr = resolve_operand("cond") if primitive_jump.cond is None else primitive_jump.cond
            if not cond_operand_expr:
                return  # Failed to create
        elif condition_type in [
            IRBoolExpr.CompareType.NULL,
            IRBoolExpr.CompareType.NOT_NULL,
        ]:
            cond_operand_expr = resolve_operand("reg") if primitive_jump.cond is None else primitive_jump.cond
            if not cond_operand_expr:
                return
        else:  # Two-operand comparisons
            left_expr = primitive_jump.left if primitive_jump.left is not None else resolve_operand("a")
            right_expr = primitive_jump.right if primitive_jump.right is not None else resolve_operand("b")
            if not left_expr or not right_expr:
                dbg_print(f"IRPrimitiveJumpLifter: Missing operands for binary jump {original_jump_op.op}")
                return

        if cond_operand_expr:
            bool_condition_expr = IRBoolExpr(loop.code, condition_type, left=cond_operand_expr)
        else:
            bool_condition_expr = IRBoolExpr(loop.code, condition_type, left=left_expr, right=right_expr)

        # Replace the last statement (IRPrimitiveJump) with the new IRBoolExpr
        bool_condition_expr.adopt(last_cond_stmt)
        loop.condition.statements[-1] = bool_condition_expr
        dbg_print(f"IRPrimitiveJumpLifter: Lifted jump to {bool_condition_expr}")


class IRConditionInliner(TraversingIROptimizer):
    """
    Optimizes IR by inlining expressions (especially IRConst or IRBoolExpr)
    that are assigned to a temporary local and then immediately used in a
    conditional statement (IRConditional, IRWhileLoop) or another expression.

    This helps simplify conditions and expressions before other optimization passes.
    """

    def __init__(self, function: "IRFunction"):
        super().__init__(function)
        self._user_variable_names: Set[str] = set()
        self._user_reg_indices: Set[int] = set()
        if self.func.func.has_debug and self.func.func.assigns:
            for name_ref, op_idx in self.func.func.assigns:
                self._user_variable_names.add(name_ref.resolve(self.func.code))
                val = op_idx.value - 1
                if val >= 0 and val < len(self.func.ops):
                    op = self.func.ops[val]
                    try:
                        self._user_reg_indices.add(op.df["dst"].value)
                    except KeyError:
                        pass

    def _is_user_local(self, local: IRLocal) -> bool:
        if local.name in self._user_variable_names:
            return True
        if local.name.startswith("var"):
            try:
                idx = int(local.name[3:])
                if idx in self._user_reg_indices:
                    return True
            except ValueError:
                pass
        return False

    def _expr_contains_local(self, expr: Optional[IRExpression], local: IRLocal) -> bool:
        if expr is None:
            return False
        if expr == local:
            return True
        for child in expr.get_children():
            if isinstance(child, IRExpression) and self._expr_contains_local(child, local):
                return True
        return False

    def _stmt_contains_local(self, stmt: IRStatement, local: IRLocal) -> bool:
        if isinstance(stmt, IRAssign):
            if isinstance(stmt.target, IRExpression) and self._expr_contains_local(stmt.target, local):
                return True
            if self._expr_contains_local(stmt.expr, local):
                return True
        elif isinstance(stmt, IRExpression):
            if self._expr_contains_local(stmt, local):
                return True
        elif isinstance(stmt, IRReturn):
            if stmt.value is not None and self._expr_contains_local(stmt.value, local):
                return True
        elif isinstance(stmt, IRConditional):
            if self._expr_contains_local(stmt.condition, local):
                return True
        elif isinstance(stmt, IRWhileLoop):
            if self._expr_contains_local(stmt.condition, local):
                return True
        for child in stmt.get_children():
            if child is not stmt and self._stmt_contains_local(child, local):
                return True
        return False

    def _is_safe_to_duplicate(self, expr: IRExpression) -> bool:
        """Return True for side-effect-free expressions that can be duplicated
        without changing program behavior. Calls and allocations are excluded."""
        if isinstance(expr, (IRConst, IRLocal)):
            return True
        if isinstance(expr, (IRField, IRCast, IRNeg, IRNot, IRTypeKind)):
            for child in expr.get_children():
                if isinstance(child, IRExpression) and not self._is_safe_to_duplicate(child):
                    return False
            return True
        if isinstance(expr, (IRArithmetic, IRBoolExpr)):
            return (expr.left is not None and self._is_safe_to_duplicate(expr.left)) and (
                expr.right is not None and self._is_safe_to_duplicate(expr.right)
            )
        return False

    def _stmt_contains_local_read(self, stmt: IRStatement, local: IRLocal) -> bool:
        """Like _stmt_contains_local but ignoring assignment targets (redefinitions)."""
        if isinstance(stmt, IRAssign):
            if self._expr_contains_local(stmt.expr, local):
                return True
            # A compound target (`obj.field = ...`) still reads `local` to
            # compute the field's containing object — only a bare local
            # target (`local = ...`) is a pure redefinition with no read of
            # the old value. (Deliberately narrower than IRField: treating
            # an IRArrayAccess target's index as a "read" here blocks the
            # generic IRAssign-pair fold below from ever reaching it, since
            # that fold only substitutes into the *value* side, not the
            # target — see the dedicated IRArrayAccess substitution path
            # there instead.)
            if isinstance(stmt.target, IRField) and self._expr_contains_local(stmt.target, local):
                return True
            return False
        if isinstance(stmt, IRExpression):
            return self._expr_contains_local(stmt, local)
        if isinstance(stmt, IRReturn):
            if stmt.value is not None and self._expr_contains_local(stmt.value, local):
                return True
        elif isinstance(stmt, IRConditional):
            if self._expr_contains_local(stmt.condition, local):
                return True
        elif isinstance(stmt, IRWhileLoop):
            if self._expr_contains_local(stmt.condition, local):
                return True
        for child in stmt.get_children():
            if child is not stmt and self._stmt_contains_local_read(child, local):
                return True
        return False

    def _local_used_outside_condition(
        self,
        local: IRLocal,
        conditional_stmt: Union[IRConditional, IRWhileLoop],
        later_statements: List[IRStatement],
    ) -> bool:
        """Return True if `local` is read in the branches/body of a conditional or after it."""
        if isinstance(conditional_stmt, IRConditional):
            blocks = [conditional_stmt.true_block]
            if conditional_stmt.false_block:
                blocks.append(conditional_stmt.false_block)
        else:
            blocks = [conditional_stmt.body]
        for blk in blocks:
            for s in blk.statements:
                if self._stmt_contains_local_read(s, local):
                    return True
        for s in later_statements:
            if self._stmt_contains_local_read(s, local):
                return True
            # a top-level reassignment kills the value; later reads don't count
            if isinstance(s, IRAssign) and isinstance(s.target, IRLocal) and s.target.name == local.name:
                break
        return False

    def visit_block(self, block: IRBlock) -> None:
        """
        Iterates through statements to find inlining opportunities.
        """
        self._visit_block_pass(block)

    def _visit_block_pass(self, block: IRBlock) -> bool:
        new_statements: List[IRStatement] = []
        changed = False

        i = 0
        while i < len(block.statements):
            current_stmt = block.statements[i]
            inlined_something = False

            if isinstance(current_stmt, IRAssign) and isinstance(current_stmt.expr, IRExpression):
                assigned_local: IRLocal | IRField | IRArrayAccess = cast(
                    "IRLocal | IRField | IRArrayAccess", current_stmt.target
                )
                expr_to_inline: IRExpression = current_stmt.expr

                if isinstance(assigned_local, IRLocal) and self._is_user_local(assigned_local):
                    new_statements.append(current_stmt)
                    i += 1
                    continue

                if i + 1 < len(block.statements):
                    next_stmt = block.statements[i + 1]

                    if isinstance(next_stmt, IRConditional):
                        conditional_stmt: IRConditional = next_stmt
                        used_outside = isinstance(assigned_local, IRLocal) and self._local_used_outside_condition(
                            assigned_local, conditional_stmt, block.statements[i + 2 :]
                        )
                        if conditional_stmt.condition == assigned_local:
                            if used_outside and not self._is_safe_to_duplicate(expr_to_inline):
                                new_statements.append(current_stmt)
                                i += 1
                                continue
                            dbg_print(
                                f"IRCondInliner: Inlining {expr_to_inline} into IRConditional condition (direct) for {assigned_local}"
                            )
                            conditional_stmt.condition = expr_to_inline
                            if used_outside:
                                new_statements.append(current_stmt)
                            else:
                                conditional_stmt.adopt(current_stmt)  # current_stmt's opcode is dropped
                            new_statements.append(next_stmt)
                            i += 2
                            inlined_something = True
                        elif isinstance(conditional_stmt.condition, IRBoolExpr):
                            if used_outside and not self._is_safe_to_duplicate(expr_to_inline):
                                new_statements.append(current_stmt)
                                i += 1
                                continue
                            modified_bool_expr = self._try_inline_into_boolexpr(
                                conditional_stmt.condition,
                                assigned_local,
                                expr_to_inline,
                            )
                            if modified_bool_expr:
                                dbg_print(
                                    f"IRCondInliner: Inlining {expr_to_inline} into IRBoolExpr within IRConditional for {assigned_local}"
                                )
                                conditional_stmt.condition = modified_bool_expr
                                if used_outside:
                                    new_statements.append(current_stmt)
                                else:
                                    conditional_stmt.adopt(current_stmt)  # current_stmt's opcode is dropped
                                new_statements.append(next_stmt)
                                i += 2
                                inlined_something = True

                    elif not inlined_something and isinstance(next_stmt, IRWhileLoop):
                        while_loop_stmt: IRWhileLoop = next_stmt
                        used_outside = isinstance(assigned_local, IRLocal) and self._local_used_outside_condition(
                            assigned_local, while_loop_stmt, block.statements[i + 2 :]
                        )
                        if while_loop_stmt.condition == assigned_local:
                            if used_outside and not self._is_safe_to_duplicate(expr_to_inline):
                                new_statements.append(current_stmt)
                                i += 1
                                continue
                            dbg_print(
                                f"IRCondInliner: Inlining {expr_to_inline} into IRWhileLoop condition (direct) for {assigned_local}"
                            )
                            while_loop_stmt.condition = expr_to_inline
                            if used_outside:
                                new_statements.append(current_stmt)
                            else:
                                while_loop_stmt.adopt(current_stmt)  # current_stmt's opcode is dropped
                            new_statements.append(next_stmt)
                            i += 2
                            inlined_something = True
                        elif isinstance(while_loop_stmt.condition, IRBoolExpr):
                            if used_outside and not self._is_safe_to_duplicate(expr_to_inline):
                                new_statements.append(current_stmt)
                                i += 1
                                continue
                            modified_bool_expr = self._try_inline_into_boolexpr(
                                while_loop_stmt.condition,
                                assigned_local,
                                expr_to_inline,
                            )
                            if modified_bool_expr:
                                dbg_print(
                                    f"IRCondInliner: Inlining {expr_to_inline} into IRBoolExpr within IRWhileLoop for {assigned_local}"
                                )
                                while_loop_stmt.condition = modified_bool_expr
                                if used_outside:
                                    new_statements.append(current_stmt)
                                else:
                                    while_loop_stmt.adopt(current_stmt)  # current_stmt's opcode is dropped
                                new_statements.append(next_stmt)
                                i += 2
                                inlined_something = True

                    elif (
                        not inlined_something
                        and isinstance(next_stmt, IRAssign)
                        and isinstance(next_stmt.expr, IRExpression)
                    ):
                        assign_next_stmt: IRAssign = next_stmt
                        # If the assigned local is read later, inlining it away here
                        # would disconnect that later use from its definition. Keep
                        # the original assignment when the expression is safe to
                        # duplicate; otherwise leave both statements untouched.
                        # Registers get reused for unrelated values throughout a
                        # function, so a later statement reassigning this same
                        # local name ends the lookahead: reads after that point
                        # belong to that new value, not the one being inlined here
                        # (keeping current_stmt around just to feed a read that's
                        # actually unrelated would also leave its now-inlined value
                        # double-applied wherever next_stmt's substitution put it).
                        used_outside = False
                        if isinstance(assigned_local, IRLocal):
                            for s in block.statements[i + 2 :]:
                                if self._stmt_contains_local_read(s, assigned_local):
                                    used_outside = True
                                    break
                                if (
                                    isinstance(s, IRAssign)
                                    and isinstance(s.target, IRLocal)
                                    and s.target.name == assigned_local.name
                                ):
                                    break
                        if used_outside and not self._is_safe_to_duplicate(expr_to_inline):
                            new_statements.append(current_stmt)
                            i += 1
                            continue
                        modified_rhs_expr = self._try_inline_into_generic_expr(
                            assign_next_stmt.expr, assigned_local, expr_to_inline
                        )
                        if modified_rhs_expr:
                            if DEBUG:
                                dbg_print(
                                    f"IRCondInliner: Inlining {expr_to_inline} into IRAssign RHS for {assigned_local}"
                                )
                            assign_next_stmt.expr = modified_rhs_expr
                            if used_outside:
                                new_statements.append(current_stmt)
                            else:
                                assign_next_stmt.adopt(current_stmt)  # current_stmt's opcode is dropped
                            new_statements.append(assign_next_stmt)
                            i += 2
                            inlined_something = True

                    elif not inlined_something and isinstance(next_stmt, IRReturn):
                        return_stmt: IRReturn = next_stmt
                        if return_stmt.value == assigned_local:
                            dbg_print(
                                f"IRCondInliner: Inlining {expr_to_inline} into IRReturn value (direct) for {assigned_local}"
                            )
                            return_stmt.value = expr_to_inline
                            return_stmt.adopt(current_stmt)  # current_stmt's opcode is dropped
                            new_statements.append(next_stmt)
                            i += 2
                            inlined_something = True
                        elif isinstance(return_stmt.value, IRExpression):
                            modified_ret_val = self._try_inline_into_generic_expr(
                                return_stmt.value, assigned_local, expr_to_inline
                            )
                            if modified_ret_val:
                                dbg_print(
                                    f"IRCondInliner: Inlining {expr_to_inline} into IRReturn expression for {assigned_local}"
                                )
                                return_stmt.value = modified_ret_val
                                return_stmt.adopt(current_stmt)  # current_stmt's opcode is dropped
                                new_statements.append(next_stmt)
                                i += 2
                                inlined_something = True

                    elif not inlined_something and isinstance(next_stmt, IRExpression):
                        modified_next_expr = self._try_inline_into_generic_expr(
                            next_stmt, assigned_local, expr_to_inline
                        )
                        if modified_next_expr:
                            dbg_print(
                                f"IRCondInliner: Inlining {expr_to_inline} into IRExpression statement {next_stmt} (now {modified_next_expr}) for {assigned_local}"
                            )
                            # modified_next_expr may be a brand-new node replacing next_stmt
                            # outright, so both original opcodes need to be carried forward.
                            modified_next_expr.adopt(current_stmt, next_stmt)
                            new_statements.append(modified_next_expr)
                            i += 2
                            inlined_something = True

            if not inlined_something:
                new_statements.append(current_stmt)
                i += 1
            else:
                changed = True

        block.statements = new_statements
        return changed

    def _try_inline_into_boolexpr(
        self,
        bool_expr: IRBoolExpr,
        target: IRLocal | IRField | IRArrayAccess,
        expr_to_inline: IRExpression,
    ) -> Optional[IRBoolExpr]:
        modified = False
        new_left = bool_expr.left
        new_right = bool_expr.right

        if bool_expr.left == target:
            new_left = expr_to_inline
            modified = True
        elif isinstance(bool_expr.left, IRExpression):
            inlined_nested_left = self._try_inline_into_generic_expr(bool_expr.left, target, expr_to_inline)
            if inlined_nested_left:
                new_left = inlined_nested_left
                modified = True

        if bool_expr.right == target:
            new_right = expr_to_inline
            modified = True
        elif isinstance(bool_expr.right, IRExpression):
            inlined_nested_right = self._try_inline_into_generic_expr(bool_expr.right, target, expr_to_inline)
            if inlined_nested_right:
                new_right = inlined_nested_right
                modified = True

        if modified:
            bool_expr.left = new_left
            bool_expr.right = new_right
            return bool_expr
        return None

    def _try_inline_into_generic_expr(
        self,
        current_expr: IRExpression,
        target: IRLocal | IRField | IRArrayAccess,
        expr_to_inline: IRExpression,
    ) -> Optional[IRExpression]:
        if current_expr == target:
            return expr_to_inline

        if isinstance(current_expr, IRArithmetic):
            arith_expr: IRArithmetic = current_expr
            modified_left = arith_expr.left
            modified_right = arith_expr.right
            made_change = False

            inlined_left_child = self._try_inline_into_generic_expr(arith_expr.left, target, expr_to_inline)
            if inlined_left_child:
                modified_left = inlined_left_child
                made_change = True

            inlined_right_child = self._try_inline_into_generic_expr(arith_expr.right, target, expr_to_inline)
            if inlined_right_child:
                modified_right = inlined_right_child
                made_change = True

            if made_change:
                arith_expr.left = modified_left
                arith_expr.right = modified_right
                return arith_expr
            return None

        elif isinstance(current_expr, IRBoolExpr):
            return self._try_inline_into_boolexpr(current_expr, target, expr_to_inline)

        elif isinstance(current_expr, IRCall):
            call_expr: IRCall = current_expr
            made_change = False
            new_args = list(call_expr.args)

            for i, arg_expr in enumerate(call_expr.args):
                inlined_arg = self._try_inline_into_generic_expr(arg_expr, target, expr_to_inline)
                if inlined_arg:
                    new_args[i] = inlined_arg
                    made_change = True

            if isinstance(call_expr.target, IRExpression):
                inlined_target_expr = self._try_inline_into_generic_expr(call_expr.target, target, expr_to_inline)
                if inlined_target_expr:
                    if isinstance(inlined_target_expr, (IRConst, IRLocal, IRField, type(None))):
                        call_expr.target = inlined_target_expr
                        made_change = True

            if made_change:
                call_expr.args = new_args
                return call_expr
            return None

        elif isinstance(current_expr, IRCast):
            cast_expr: IRCast = current_expr
            inlined_inner = self._try_inline_into_generic_expr(cast_expr.expr, target, expr_to_inline)
            if inlined_inner:
                cast_expr.expr = inlined_inner
                return cast_expr
            return None

        elif isinstance(current_expr, IRField):
            field_expr: IRField = current_expr
            inlined_target = self._try_inline_into_generic_expr(field_expr.target, target, expr_to_inline)
            if inlined_target:
                field_expr.target = inlined_target
                return field_expr
            return None

        return None


class IRTempAssignmentInliner(TraversingIROptimizer):
    """
    Optimizes IR by inlining temporary variable assignments.
    This optimizer has two modes, controlled by the `aggressive` flag.

    Crucially, this optimizer will NOT inline any assignment to a variable
    that has an explicit name in the Haxe source code's debug information.
    It only targets compiler-generated temporary variables.

    - Conservative Mode (aggressive=False, default): Only inlines an assignment
      `temp = expr` if `temp` is used in the immediately following statement.

    - Aggressive Mode (aggressive=True): Inlines "safe" expressions (like constants)
      into all subsequent uses of a temporary variable, as long as that variable
      is not redefined.
    """

    def __init__(self, function: "IRFunction", aggressive: bool = False, past_kills: bool = False):
        super().__init__(function)
        self.aggressive = aggressive
        # past_kills: a later redefinition bounds the substitution range instead of blocking inlining
        self.past_kills = past_kills

        # --- NEW: Pre-calculate the set of all user-named variables ---
        self._user_variable_names: Set[str] = set()
        self._user_reg_indices: Set[int] = set()
        if self.func.func.has_debug and self.func.func.assigns:
            for name_ref, op_idx in self.func.func.assigns:
                self._user_variable_names.add(name_ref.resolve(self.func.code))
                val = op_idx.value - 1
                if val >= 0 and val < len(self.func.ops):
                    op = self.func.ops[val]
                    try:
                        reg = op.df["dst"].value
                        self._user_reg_indices.add(reg)
                    except KeyError:
                        pass
        dbg_print(f"IRTempAssignmentInliner: Protecting user variables: {self._user_variable_names}")
        dbg_print(f"IRTempAssignmentInliner: Protecting user reg indices: {self._user_reg_indices}")

    def _is_user_local(self, local: IRLocal) -> bool:
        return local.name in self._user_variable_names

    def _substitute_in_expr(
        self, expr: IRExpression, target: IRLocal, replacement: IRExpression
    ) -> Tuple[IRExpression, bool]:
        """Recursively substitutes a local with an expression within another expression."""
        if expr == target:
            return replacement, True

        made_change = False
        if isinstance(expr, (IRArithmetic, IRBoolExpr)):
            if expr.left:
                expr.left, changed = self._substitute_in_expr(expr.left, target, replacement)
                made_change = made_change or changed
            if expr.right:
                expr.right, changed = self._substitute_in_expr(expr.right, target, replacement)
                made_change = made_change or changed
        elif isinstance(expr, IRCall):
            if expr.target is not None:
                new_target, changed = self._substitute_in_expr(expr.target, target, replacement)
                expr.target = cast(Union[IRConst, IRLocal, IRField], new_target)
                made_change = made_change or changed
            new_args = []
            for arg in expr.args:
                new_arg, changed = self._substitute_in_expr(arg, target, replacement)
                new_args.append(new_arg)
                made_change = made_change or changed
            expr.args = new_args
        elif isinstance(expr, IRField):
            expr.target, changed = self._substitute_in_expr(expr.target, target, replacement)
            made_change = made_change or changed
        elif isinstance(expr, IRCast):
            expr.expr, changed = self._substitute_in_expr(expr.expr, target, replacement)
            made_change = made_change or changed
        elif isinstance(expr, IRArrayAccess):
            expr.array, changed = self._substitute_in_expr(expr.array, target, replacement)
            made_change = made_change or changed
            expr.index, changed = self._substitute_in_expr(expr.index, target, replacement)
            made_change = made_change or changed
        elif isinstance(expr, IRNew):
            new_args = []
            for arg in expr.constructor_args:
                new_arg, changed = self._substitute_in_expr(arg, target, replacement)
                new_args.append(new_arg)
                made_change = made_change or changed
            expr.constructor_args = new_args
        elif isinstance(expr, IRRef):
            expr.target, changed = self._substitute_in_expr(expr.target, target, replacement)
            made_change = made_change or changed
        elif isinstance(expr, IRRefNew):
            expr.target, changed = self._substitute_in_expr(expr.target, target, replacement)
            made_change = made_change or changed
        elif isinstance(expr, IRRefGet):
            expr.ref, changed = self._substitute_in_expr(expr.ref, target, replacement)
            made_change = made_change or changed
        elif isinstance(expr, IREnumConstruct):
            new_args = []
            for arg in expr.args:
                new_arg, changed = self._substitute_in_expr(arg, target, replacement)
                new_args.append(new_arg)
                made_change = made_change or changed
            expr.args = new_args
        elif isinstance(expr, IREnumIndex):
            expr.value, changed = self._substitute_in_expr(expr.value, target, replacement)
            made_change = made_change or changed
        elif isinstance(expr, IREnumField):
            expr.value, changed = self._substitute_in_expr(expr.value, target, replacement)
            made_change = made_change or changed
        elif isinstance(expr, (IRNeg, IRNot, IRTypeOf, IRTypeKind)):
            expr.expr, changed = self._substitute_in_expr(expr.expr, target, replacement)
            made_change = made_change or changed
        elif isinstance(expr, IRArrayLiteral):
            new_elements = []
            for element in expr.elements:
                new_element, changed = self._substitute_in_expr(element, target, replacement)
                new_elements.append(new_element)
                made_change = made_change or changed
            expr.elements = new_elements
        elif isinstance(expr, IRNativeArrayNew):
            expr.size, changed = self._substitute_in_expr(expr.size, target, replacement)
            made_change = made_change or changed

        return expr, made_change

    def _expr_contains_local(self, expr: IRExpression, local: IRLocal) -> bool:
        if expr == local:
            return True
        if isinstance(expr, (IRArithmetic, IRBoolExpr)):
            if expr.left and self._expr_contains_local(expr.left, local):
                return True
            if expr.right and self._expr_contains_local(expr.right, local):
                return True
        elif isinstance(expr, IRCall):
            if expr.target is not None and self._expr_contains_local(expr.target, local):
                return True
            for arg in expr.args:
                if self._expr_contains_local(arg, local):
                    return True
        elif isinstance(expr, IRField):
            if self._expr_contains_local(expr.target, local):
                return True
        elif isinstance(expr, IRCast):
            if self._expr_contains_local(expr.expr, local):
                return True
        elif isinstance(expr, IRArrayAccess):
            if self._expr_contains_local(expr.array, local):
                return True
            if self._expr_contains_local(expr.index, local):
                return True
        elif isinstance(expr, IRRef):
            if self._expr_contains_local(expr.target, local):
                return True
        elif isinstance(expr, IREnumConstruct):
            for arg in expr.args:
                if self._expr_contains_local(arg, local):
                    return True
        elif isinstance(expr, IREnumIndex):
            if self._expr_contains_local(expr.value, local):
                return True
        elif isinstance(expr, IREnumField):
            if self._expr_contains_local(expr.value, local):
                return True
        for child in expr.get_children():
            if isinstance(child, IRExpression) and self._expr_contains_local(child, local):
                return True
        return False

    def _substitute_in_statement(
        self,
        stmt: IRStatement,
        target: IRLocal,
        replacement: IRExpression,
        _visited: Optional[Set[int]] = None,
    ) -> bool:
        """
        Recursively traverses a statement to perform substitutions.
        Returns True if a substitution was made, False otherwise.
        """
        # The lifted IR is a DAG (shared continuation blocks). Mutating a shared
        # node once applies along every path that references it, so prune already
        # visited nodes to avoid exponential re-walks of converging control flow.
        if _visited is None:
            _visited = set()
        if id(stmt) in _visited:
            return False
        _visited.add(id(stmt))

        made_change = False

        if isinstance(stmt, IRAssign):
            if stmt.target != target and isinstance(stmt.target, IRExpression):
                _, changed = self._substitute_in_expr(stmt.target, target, replacement)
                made_change = made_change or changed
            if isinstance(stmt.expr, IRExpression):
                stmt.expr, changed = self._substitute_in_expr(stmt.expr, target, replacement)
                made_change = made_change or changed
        elif isinstance(stmt, IRExpression):
            # a root-equal match can't be replaced in place; don't report a phantom change
            if stmt != target:
                _, changed = self._substitute_in_expr(stmt, target, replacement)
                made_change = made_change or changed
        elif isinstance(stmt, IRReturn):
            if stmt.value:
                stmt.value, changed = self._substitute_in_expr(stmt.value, target, replacement)
                made_change = made_change or changed
        elif isinstance(stmt, IRTrace):
            stmt.msg, changed = self._substitute_in_expr(stmt.msg, target, replacement)
            made_change = made_change or changed
            return made_change

        for child in stmt.get_children():
            if child is not stmt:
                if isinstance(child, IRBlock):
                    # Don't substitute past a direct reassignment of `target`
                    # inside a sub-block: reads after that point belong to the
                    # new value, not the one being inlined.
                    if id(child) in _visited:
                        continue
                    _visited.add(id(child))
                    for sub_stmt in child.statements:
                        if id(sub_stmt) in _visited:
                            continue
                        if self._substitute_in_statement(sub_stmt, target, replacement, _visited):
                            made_change = True
                        if (
                            isinstance(sub_stmt, IRAssign)
                            and isinstance(sub_stmt.target, IRLocal)
                            and (sub_stmt.target == target or sub_stmt.target.same_register(target))
                        ):
                            break
                elif self._substitute_in_statement(child, target, replacement, _visited):
                    made_change = True

        return made_change

    def _substitute_shallow(self, stmt: IRStatement, target: IRLocal, replacement: IRExpression) -> bool:
        """Substitute only at the top level of a statement, not recursing into child blocks."""
        made_change = False
        if isinstance(stmt, IRAssign):
            if stmt.target != target and isinstance(stmt.target, IRExpression):
                _, changed = self._substitute_in_expr(stmt.target, target, replacement)
                made_change = made_change or changed
            if isinstance(stmt.expr, IRExpression):
                stmt.expr, changed = self._substitute_in_expr(stmt.expr, target, replacement)
                made_change = made_change or changed
        elif isinstance(stmt, IRExpression):
            _, changed = self._substitute_in_expr(stmt, target, replacement)
            made_change = made_change or changed
        elif isinstance(stmt, IRReturn):
            if stmt.value:
                stmt.value, changed = self._substitute_in_expr(stmt.value, target, replacement)
                made_change = made_change or changed
        elif isinstance(stmt, IRRefSet):
            stmt.ref, changed = self._substitute_in_expr(stmt.ref, target, replacement)
            made_change = made_change or changed
            stmt.value, changed = self._substitute_in_expr(stmt.value, target, replacement)
            made_change = made_change or changed
        elif isinstance(stmt, IRConditional):
            stmt.condition, changed = self._substitute_in_expr(stmt.condition, target, replacement)
            made_change = made_change or changed
        elif isinstance(stmt, IRWhileLoop):
            # Unlike a one-shot IRConditional, a while-loop's condition re-evaluates
            # on every iteration. If `target` is reassigned inside the body, the
            # condition needs that live value each time — substituting in the value
            # from before the loop would freeze it to a stale snapshot (e.g. turning
            # `idx = 0; while (idx < n)` into the loop-invariant `while (0 < n)`).
            if not self._is_local_redefined(target, stmt.body.statements):
                stmt.condition, changed = self._substitute_in_expr(stmt.condition, target, replacement)
                made_change = made_change or changed
        return made_change

    def _is_local_redefined(self, local_to_check: IRLocal, statements: List[IRStatement]) -> bool:
        """Checks if a local is the target of an assignment in a list of statements."""
        return self._is_local_redefined_walk(local_to_check, statements, set())

    def _is_local_redefined_walk(
        self, local_to_check: IRLocal, statements: List[IRStatement], visited: Set[int]
    ) -> bool:
        # The lifted IR is a DAG: shared continuation blocks are reachable from
        # many parents, so prune already-scanned nodes. Whether a local is
        # redefined inside a subtree is path-independent, so visiting it once is
        # correct and avoids exponential re-walks of converging control flow.
        for stmt in statements:
            if id(stmt) in visited:
                continue
            visited.add(id(stmt))
            if isinstance(stmt, IRAssign) and stmt.target == local_to_check:
                return True
            if (
                isinstance(stmt, IRAssign)
                and isinstance(stmt.target, IRLocal)
                and stmt.target.same_register(local_to_check)
            ):
                return True
            for child in stmt.get_children():
                child_stmts = child.statements if isinstance(child, IRBlock) else [child]
                if self._is_local_redefined_walk(local_to_check, child_stmts, visited):
                    return True
        return False

    def _collect_free_locals(self, expr: IRStatement) -> Set[str]:
        """Collect the names of all locals read within an expression.

        IR expression nodes do not implement get_children(), so traverse the
        known expression shapes explicitly (mirroring _expr_contains_local).
        """
        names: Set[str] = set()

        def walk(e: Optional[IRStatement]) -> None:
            if e is None:
                return
            if isinstance(e, IRLocal):
                names.add(e.name)
            elif isinstance(e, (IRArithmetic, IRBoolExpr)):
                walk(e.left)
                walk(e.right)
            elif isinstance(e, IRCall):
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
            elif isinstance(e, IRRef):
                walk(e.target)
            elif isinstance(e, IREnumConstruct):
                for arg in e.args:
                    walk(arg)
            elif isinstance(e, (IREnumIndex, IREnumField)):
                walk(e.value)
            elif isinstance(e, IRNew):
                for arg in e.constructor_args:
                    walk(arg)

        walk(expr)
        return names

    def _stmt_reassigns_any(self, stmt: IRStatement, names: Set[str]) -> bool:
        """Return True if `stmt` (or any nested statement) assigns to a local in `names`."""
        if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal) and stmt.target.name in names:
            return True
        for child in stmt.get_children():
            if child is not stmt and self._stmt_reassigns_any(child, names):
                return True
        return False

    def is_safe_to_inline_aggressively(self, expr: IRExpression) -> bool:
        """
        Determines if an expression can be safely copied multiple times
        without changing the program's semantics.
        """
        if isinstance(expr, (IRConst, IRLocal)):
            return True
        if isinstance(expr, IRField):
            return self.is_safe_to_inline_aggressively(expr.target)
        if isinstance(expr, IRCast):
            return self.is_safe_to_inline_aggressively(expr.expr)
        if isinstance(expr, (IRTypeOf, IRTypeKind)):
            return self.is_safe_to_inline_aggressively(expr.expr)
        if isinstance(expr, IRArrayAccess):
            return self.is_safe_to_inline_aggressively(expr.array) and self.is_safe_to_inline_aggressively(expr.index)
        if isinstance(expr, IRRef):
            return False
        if isinstance(expr, IREnumConstruct):
            # An EnumAlloc produces an empty-args IREnumConstruct that represents
            # a mutable allocation site (subsequent SetEnumField writes mutate it).
            # Do not inline it, or each use site would get a distinct value.
            return bool(expr.args) and all(self.is_safe_to_inline_aggressively(a) for a in expr.args)
        if isinstance(expr, IREnumIndex):
            return self.is_safe_to_inline_aggressively(expr.value)
        if isinstance(expr, IREnumField):
            return self.is_safe_to_inline_aggressively(expr.value)
        if isinstance(expr, IRArithmetic):
            return self.is_safe_to_inline_aggressively(expr.left) and self.is_safe_to_inline_aggressively(expr.right)
        return False

    def is_safe_to_inline_conservatively(self, expr: IRExpression) -> bool:
        # Avoid inlining calls in conservative mode: they can have side effects
        # and removing the assignment eliminates evidence needed by pattern
        # optimizers (e.g. alloc_bytes for array literals).
        if isinstance(expr, IRCall):
            return False
        if isinstance(expr, IRArrayLiteral):
            return True
        if isinstance(expr, (IRConst, IRLocal)):
            return True
        if isinstance(expr, IRCast):
            return self.is_safe_to_inline_conservatively(expr.expr)
        # Allow flat arithmetic (both operands are leaves) to enable compound assignment detection.
        # Nested arithmetic is excluded to prevent exponential chaining.
        if isinstance(expr, IRArithmetic):
            return isinstance(expr.left, (IRConst, IRLocal)) and isinstance(expr.right, (IRConst, IRLocal))
        # A read with simple (non-side-effecting) array/index operands is moved, not
        # duplicated, by inlining into its sole immediately-following use, so it's
        # still evaluated exactly once: safe even though it can in principle throw.
        if isinstance(expr, IRArrayAccess):
            return isinstance(expr.array, (IRConst, IRLocal)) and isinstance(expr.index, (IRConst, IRLocal))
        # Same reasoning as IRArrayAccess: an `arr.length` read on a simple target
        # is moved, not duplicated, by this inliner. This matters for recovering
        # for-loops: `len = arr.length;` immediately followed by `while (idx < len)`
        # needs to fold into `while (idx < arr.length)` for IRForEachLoopOptimizer's
        # pattern match to fire. Deliberately narrow to the Array kind (not e.g.
        # String, whose `.length` IRStringSwitchOptimizer expects to find un-inlined
        # in its own specific shape) — array length is a plain struct read with no
        # room for that kind of downstream pattern dependency.
        if (
            isinstance(expr, IRField)
            and expr.field_name == "length"
            and isinstance(expr.target, (IRConst, IRLocal))
            and expr.target.get_type().kind.value == Type.Kind.ARRAY.value
        ):
            return True
        return False

    def _call_move_ok(self, stmt: IRStatement, temp: IRLocal) -> bool:
        """True if `stmt` is a local assignment reading `temp` exactly once in an
        expression built only from consts, locals, and arithmetic — so moving a
        call into it preserves evaluation order and count."""
        if not (isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal)):
            return False

        count = 0

        def walk(e: Optional[IRExpression]) -> bool:
            nonlocal count
            if e is None:
                return True
            if e == temp:
                count += 1
                return True
            if isinstance(e, IRConst):
                return True
            if isinstance(e, IRLocal):
                return True
            if isinstance(e, IRArithmetic):
                return walk(e.left) and walk(e.right)
            if isinstance(e, IRCast):
                return walk(e.expr)
            if isinstance(e, IRNativeArrayNew):
                return walk(e.size)
            return False

        return walk(stmt.expr) and count == 1

    def visit_block(self, block: IRBlock) -> None:
        if self.aggressive:
            self._visit_block_aggressive(block)
        else:
            self._visit_block_conservative(block)

    def _stmt_contains_local(self, stmt: IRStatement, local: IRLocal) -> bool:
        """Return True if `stmt` (recursively into child blocks/expressions) reads `local`."""
        if isinstance(stmt, IRAssign):
            if isinstance(stmt.target, IRExpression) and self._expr_contains_local(stmt.target, local):
                return True
            if isinstance(stmt.expr, IRExpression) and self._expr_contains_local(stmt.expr, local):
                return True
        elif isinstance(stmt, IRExpression):
            if self._expr_contains_local(stmt, local):
                return True
        elif isinstance(stmt, IRReturn):
            if stmt.value is not None and self._expr_contains_local(stmt.value, local):
                return True
        elif isinstance(stmt, IRConditional):
            if self._expr_contains_local(stmt.condition, local):
                return True
        elif isinstance(stmt, IRWhileLoop):
            if self._expr_contains_local(stmt.condition, local):
                return True
        elif isinstance(stmt, IRSwitch):
            if self._expr_contains_local(stmt.value, local):
                return True

        for child in stmt.get_children():
            if child is not stmt and self._stmt_contains_local(child, local):
                return True
        return False

    def _is_loop_body_block(self, parent: IRStatement, child: IRStatement) -> bool:
        """Return True if `child` is the body block of a loop statement."""
        return (
            isinstance(parent, (IRWhileLoop, IRPrimitiveLoop, IRForEachLoop, IRIntRangeLoop))
            and getattr(parent, "body", None) is child
        )

    def _flatten_stmts(self, stmts: List[IRStatement]) -> List[IRStatement]:
        """Document-order flattening of a statement list and their nested blocks."""
        out: List[IRStatement] = []
        for s in stmts:
            out.append(s)
            for child in s.get_children():
                if isinstance(child, IRBlock):
                    out.extend(self._flatten_stmts(child.statements))
        return out

    def _local_read_in_continuation(self, continuation: List[IRStatement], local: IRLocal) -> bool:
        """Whether `local` is read anywhere in `continuation` (what executes after
        the current block, e.g. code following the enclosing if/loop). Unlike a
        whole-function scan, this only looks at statements actually reachable after
        the current point — it deliberately excludes sibling branches (e.g. the
        `else` of the `if` we're inside), which are mutually exclusive with us and
        would otherwise cause false "still read" positives for register reuse
        across branches.
        """
        return any(self._stmt_contains_local(s, local) for s in self._flatten_stmts(continuation))

    def _visit_block_conservative(
        self,
        block: IRBlock,
        inside_loop_body: bool = False,
        continuation: Optional[List[IRStatement]] = None,
    ) -> None:
        """Only inlines an assignment if it is used in the very next statement.

        Inside a loop body we still perform the inline substitution, but we keep
        the original assignment. Removing it would destroy the loop-carried value
        that is live after the loop (e.g. String.indexOf's search result).
        """
        if continuation is None:
            continuation = []
        if not block.statements:
            return

        new_statements: List[IRStatement] = []
        i = 0
        statements = block.statements
        while i < len(statements):
            current_stmt = statements[i]
            inlined = False

            if isinstance(current_stmt, IRAssign) and isinstance(current_stmt.target, IRLocal):
                temp_local = current_stmt.target

                # A debug-named register can still be reused by the compiler for an
                # unrelated, short-lived value (e.g. a string literal fed straight
                # into the next call) after the named variable's real last read has
                # already happened. Allow folding that case too, but only when the
                # value is consumed by the very next statement, nothing else in this
                # block follows, we're not inside a loop body (which needs the
                # variable to stay live past the loop), and the whole rest of the
                # function never reads it again — i.e. it's truly dead, not just
                # locally dead within this block. Excluding a bare-IRLocal RHS keeps
                # `s = var1; return s.bytes;` copy-propagation renames intact: that
                # pattern intentionally gives a synthetic temp a readable name, and
                # folding it back would just undo the rename.
                _reuse_expr = current_stmt.expr
                while isinstance(_reuse_expr, IRCast):
                    _reuse_expr = _reuse_expr.expr
                user_local_reuse = (
                    self._is_user_local(temp_local)
                    and not isinstance(_reuse_expr, IRLocal)
                    and not inside_loop_body
                    and i + 2 == len(statements)
                )

                if not self._is_user_local(temp_local) or (
                    user_local_reuse
                    and i + 1 < len(statements)
                    and not getattr(statements[i + 1], "_no_user_inline", False)
                ):
                    expr_to_inline = current_stmt.expr
                    if not self.is_safe_to_inline_conservatively(expr_to_inline):
                        # A call can still be moved (not duplicated) into an adjacent
                        # single use whose other operands are just consts/locals —
                        # locals can't be mutated by the call, so order is preserved.
                        # Only when the assignment gets dropped (never inside a loop
                        # body, where it is kept and the call would run twice).
                        if not (
                            isinstance(expr_to_inline, IRCall)
                            and not inside_loop_body
                            and i + 1 < len(statements)
                            and self._call_move_ok(statements[i + 1], temp_local)
                        ):
                            new_statements.append(current_stmt)
                            i += 1
                            continue
                    if isinstance(expr_to_inline, IRExpression) and self._expr_contains_local(
                        expr_to_inline, temp_local
                    ):
                        new_statements.append(current_stmt)
                        i += 1
                        continue
                    if i + 1 < len(statements):
                        next_stmt = statements[i + 1]
                        if self._stmt_contains_local(next_stmt, temp_local) and not self._is_local_redefined(
                            temp_local, [next_stmt]
                        ):
                            # Reads after a top-level reassignment belong to the new value.
                            later_uses = False
                            for s in statements[i + 2 :]:
                                if (
                                    isinstance(s, IRAssign)
                                    and isinstance(s.target, IRLocal)
                                    and (s.target == temp_local or s.target.same_register(temp_local))
                                ):
                                    # the kill's own RHS may still read the old value
                                    if isinstance(s.expr, IRExpression) and self._expr_contains_local(
                                        s.expr, temp_local
                                    ):
                                        later_uses = True
                                    break
                                if self._stmt_contains_local(s, temp_local):
                                    later_uses = True
                                    break
                            if (
                                not later_uses
                                and user_local_reuse
                                and self._local_read_in_continuation(continuation, temp_local)
                            ):
                                later_uses = True
                            if not later_uses:
                                substituted = self._substitute_in_statement(next_stmt, temp_local, expr_to_inline)
                                if substituted:
                                    dbg_print(f"Conservatively inlining assignment for temporary '{temp_local.name}'.")
                                    if inside_loop_body:
                                        new_statements.append(current_stmt)
                                    else:
                                        next_stmt.adopt(current_stmt)  # current_stmt is dropped
                                        # If this inline merged a user variable into a conditional,
                                        # the resulting statement is a synthetic merge — don't let it
                                        # become a target for further user-var inlining.
                                        if self._is_user_local(temp_local):
                                            next_stmt._no_user_inline = True
                                    new_statements.append(next_stmt)
                                    i += 2
                                    inlined = True

            if not inlined:
                new_statements.append(current_stmt)
                i += 1

        block.statements = new_statements

        for idx, stmt in enumerate(block.statements):
            child_continuation = block.statements[idx + 1 :] + continuation
            for child in stmt.get_children():
                if isinstance(child, IRBlock):
                    self._visit_block_conservative(
                        child,
                        inside_loop_body=inside_loop_body or self._is_loop_body_block(stmt, child),
                        continuation=child_continuation,
                    )

    def _visit_block_aggressive(self, block: IRBlock, inside_loop_body: bool = False) -> None:
        """Inlines safe expressions everywhere they are used, until no more changes can be made.

        As in conservative mode, assignments inside a loop body are preserved so
        loop-carried values remain live after the loop.
        """
        made_change_in_pass = True
        while made_change_in_pass:
            made_change_in_pass = False
            statements_to_remove: List[IRStatement] = []

            for i, stmt in enumerate(block.statements):
                if not (isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal)):
                    continue

                temp_local = stmt.target

                if self._is_user_local(temp_local):
                    continue

                expr_to_inline = stmt.expr

                if not isinstance(expr_to_inline, IRExpression) or not self.is_safe_to_inline_aggressively(
                    expr_to_inline
                ):
                    continue
                if self._expr_contains_local(expr_to_inline, temp_local):
                    continue

                remaining_statements = block.statements[i + 1 :]
                must_keep_assign = False
                boundary_stmt: Optional[IRStatement] = None
                if self.past_kills:
                    # A top-level reassign is a guaranteed kill: substitute up to and
                    # including it (its RHS still reads the old value). A nested
                    # redefinition only kills on some paths, so stop before it and
                    # keep the assignment.
                    for j, s in enumerate(remaining_statements):
                        if self._is_local_redefined(temp_local, [s]):
                            is_top_level_kill = (
                                isinstance(s, IRAssign)
                                and isinstance(s.target, IRLocal)
                                and (s.target == temp_local or s.target.same_register(temp_local))
                            )
                            if is_top_level_kill:
                                remaining_statements = remaining_statements[: j + 1]
                            else:
                                remaining_statements = remaining_statements[:j]
                                must_keep_assign = True
                                # A conditional/switch subject is evaluated before any
                                # branch can redefine the temp, so it can still be
                                # substituted into even though the branches can't.
                                if isinstance(s, (IRConditional, IRSwitch)):
                                    boundary_stmt = s
                            break
                elif self._is_local_redefined(temp_local, remaining_statements):
                    continue

                # The inlined expression reads other locals (its free variables).
                # If one of them is reassigned at a later statement, the value of
                # `expr_to_inline` there differs from its value at the definition
                # site, so we must not substitute past that point.
                free_vars = self._collect_free_locals(expr_to_inline)
                free_vars.discard(temp_local.name)

                # Find every remaining statement that reads `temp_local` before it
                # is redefined. If a free variable referenced by expr_to_inline
                # gets reassigned anywhere between the definition and a given
                # use (not just by the use statement itself — an unrelated
                # statement in between counts too), substituting the captured
                # expression there would silently start reading the *new* value
                # of that free variable instead of the one live when temp_local
                # was actually computed. Keep the temp and let copy propagation
                # clean up the simple copy instead.
                use_indices = [
                    j for j, s in enumerate(remaining_statements) if self._stmt_contains_local(s, temp_local)
                ]
                boundary_subject: Optional[IRExpression] = None
                if boundary_stmt is not None:
                    subject = (
                        boundary_stmt.condition
                        if isinstance(boundary_stmt, IRConditional)
                        else cast(IRSwitch, boundary_stmt).value
                    )
                    if self._expr_contains_local(subject, temp_local) and not (
                        free_vars and any(self._stmt_reassigns_any(s, free_vars) for s in remaining_statements)
                    ):
                        boundary_subject = subject
                if not use_indices and boundary_subject is None:
                    continue
                blocked = False
                if free_vars:
                    for ui in use_indices:
                        if any(self._stmt_reassigns_any(remaining_statements[k], free_vars) for k in range(ui)):
                            blocked = True
                            break
                if blocked:
                    continue

                any_substituted = False
                substituted_into: List[IRStatement] = []
                for subsequent_stmt in remaining_statements:
                    if self._substitute_in_statement(subsequent_stmt, temp_local, expr_to_inline):
                        any_substituted = True
                        substituted_into.append(subsequent_stmt)

                if boundary_subject is not None and boundary_stmt is not None:
                    new_subject, changed = self._substitute_in_expr(boundary_subject, temp_local, expr_to_inline)
                    if changed:
                        if isinstance(boundary_stmt, IRConditional):
                            boundary_stmt.condition = new_subject
                        else:
                            cast(IRSwitch, boundary_stmt).value = new_subject
                        any_substituted = True
                        substituted_into.append(boundary_stmt)

                if not any_substituted:
                    continue

                dbg_print(f"Aggressively inlining safe expression from temporary '{temp_local.name}'.")
                if not inside_loop_body and not must_keep_assign:
                    # stmt is dropped below; every site the expression got inlined
                    # into inherits its opcode (setdefault means whichever renders
                    # first in output wins, so adopting onto all of them is safe).
                    for target_stmt in substituted_into:
                        target_stmt.adopt(stmt)
                    statements_to_remove.append(stmt)
                made_change_in_pass = True
                break

            if statements_to_remove:
                block.statements = [s for s in block.statements if s not in statements_to_remove]

        for stmt in block.statements:
            for child in stmt.get_children():
                if isinstance(child, IRBlock):
                    self._visit_block_aggressive(
                        child,
                        inside_loop_body=inside_loop_body or self._is_loop_body_block(stmt, child),
                    )


class IRTerminalValueInliner(TraversingIROptimizer):
    """
    Folds `temp = expr; return temp` / `throw temp` into `return expr` / `throw expr`
    for compiler temporaries. Because the use is adjacent and terminal, the
    expression is moved (not duplicated), so even calls are safe to inline here.
    """

    def __init__(self, function: "IRFunction"):
        super().__init__(function)
        self._user_variable_names: Set[str] = set()
        if self.func.func.has_debug and self.func.func.assigns:
            for name_ref, _ in self.func.func.assigns:
                self._user_variable_names.add(name_ref.resolve(self.func.code))

    def visit_block(self, block: IRBlock) -> None:
        changed = True
        while changed:
            changed = False
            for i in range(len(block.statements) - 1):
                stmt = block.statements[i]
                nxt = block.statements[i + 1]
                if not (isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal)):
                    continue
                if stmt.target.name in self._user_variable_names:
                    continue
                if not isinstance(nxt, (IRReturn, IRThrow)) or nxt.value is None:
                    continue
                if not isinstance(stmt.expr, IRExpression):
                    continue
                if nxt.value == stmt.target:
                    nxt.value = stmt.expr
                elif not self._subst_leftmost(nxt, stmt.target, stmt.expr):
                    continue
                nxt.adopt(stmt)
                del block.statements[i]
                changed = True
                break

    def _count_reads(self, expr: Optional[IRExpression], local: IRLocal) -> int:
        if expr is None:
            return 0
        if expr == local:
            return 1
        n = 0
        # expression nodes don't expose operands via get_children()
        if isinstance(expr, (IRArithmetic, IRBoolExpr)):
            n += self._count_reads(expr.left, local) + self._count_reads(expr.right, local)
        elif isinstance(expr, IRCall):
            if isinstance(expr.target, IRExpression):
                n += self._count_reads(expr.target, local)
            for arg in expr.args:
                n += self._count_reads(arg, local)
        elif isinstance(expr, IRField):
            n += self._count_reads(expr.target, local)
        elif isinstance(expr, IRCast):
            n += self._count_reads(expr.expr, local)
        elif isinstance(expr, IRArrayAccess):
            n += self._count_reads(expr.array, local) + self._count_reads(expr.index, local)
        else:
            for child in expr.get_children():
                if isinstance(child, IRExpression):
                    n += self._count_reads(child, local)
        return n

    def _subst_leftmost(self, stmt: Union[IRReturn, IRThrow], local: IRLocal, replacement: IRExpression) -> bool:
        # Only fold into the leftmost operand of an arithmetic chain: it is
        # evaluated first, so moving a (possibly side-effecting) expression
        # there preserves evaluation order.
        if self._count_reads(stmt.value, local) != 1:
            return False
        # Descend to the first-evaluated leaf: left of arithmetic, or arg 0 of a
        # const-target call (args evaluate left-to-right).
        node: Optional[IRExpression] = stmt.value
        while True:
            if isinstance(node, IRArithmetic):
                if node.left == local:
                    node.left = replacement
                    return True
                node = node.left
            elif isinstance(node, IRCall) and node.args and isinstance(node.target, IRConst):
                if node.args[0] == local:
                    node.args[0] = replacement
                    return True
                node = node.args[0]
            else:
                return False


class IRCopyPropOptimizer(TraversingIROptimizer):
    """
    Propagates copies of user-named locals introduced by switch/conditional branches.

    If every branch of an IRConditional or IRSwitch ends with the same
    `user_local = temp` assignment, then after the construct `temp` is equivalent
    to `user_local`. We can replace subsequent reads of `temp` with `user_local`
    until `temp` is redefined.
    """

    def visit_block(self, block: IRBlock) -> None:
        new_statements: List[IRStatement] = []
        for stmt in block.statements:
            replacement = self._propagate(stmt, block)
            if replacement is not None:
                new_statements.append(replacement)
            else:
                new_statements.append(stmt)
        block.statements = new_statements

    def _propagate(self, stmt: IRStatement, block: IRBlock) -> Optional[IRStatement]:
        # Branch-level copy propagation for switch/conditional merge temps.
        if isinstance(stmt, (IRConditional, IRSwitch)):
            copy = self._common_copy(stmt)
            if copy is not None:
                temp_local, user_local = copy
                if block is not None:
                    idx = block.statements.index(stmt)
                    for later in block.statements[idx + 1 :]:
                        if (
                            isinstance(later, IRAssign)
                            and isinstance(later.target, IRLocal)
                            and later.target == temp_local
                        ):
                            break
                        self._replace_local_shallow(later, temp_local, user_local)
                return None

            # A branch's `temp = expr; user = temp` can get folded to `user = expr`
            # at lift time, leaving a dangling read of `temp` elsewhere (e.g. a
            # later switch's subject). Every branch set `user` to that value, so
            # an unreassigned read of another local right after must be it too.
            user_local_opt = self._common_user_assign_target(stmt)
            if user_local_opt is not None and block is not None:
                user_local = user_local_opt
                idx = block.statements.index(stmt)
                reassigned: Set[IRLocal] = set()
                for later in block.statements[idx + 1 :]:
                    for phantom in self._phantom_reads(later):
                        if phantom == user_local or phantom in reassigned:
                            continue
                        # Match by name pattern (not _is_user_local): the same
                        # register can be debug-named later in the function while
                        # still anonymous here.
                        if not self._is_synthetic_temp(phantom):
                            continue
                        self._replace_local_shallow(later, phantom, user_local)
                        self._replace_in_branches(later, phantom, user_local)
                    if isinstance(later, IRAssign) and isinstance(later.target, IRLocal):
                        if later.target == user_local:
                            break
                        reassigned.add(later.target)
            return None

        # Simple sequential copy propagation: after `user = temp`, replace reads
        # of `temp` with `user` until `temp` (or `user`) is redefined.
        #
        # `temp` qualifies if it is a non-user local, or a syntactic `varN`
        # compiler temp. The latter matters when a register is later reused for
        # a user variable (so the reg-based _is_user_local check returns True)
        # but the assignment is still really `user = <synthetic temp>`.
        if (
            isinstance(stmt, IRAssign)
            and isinstance(stmt.target, IRLocal)
            and isinstance(stmt.expr, IRLocal)
            and self._is_user_local(stmt.target)
            and (not self._is_user_local(stmt.expr) or self._is_synthetic_temp(stmt.expr))
        ):
            user_local = stmt.target
            temp_local = stmt.expr
            if block is not None:
                idx = block.statements.index(stmt)
                for later in block.statements[idx + 1 :]:
                    # Stop once either name is reassigned: after that point the
                    # two are no longer guaranteed equal.
                    if (
                        isinstance(later, IRAssign)
                        and isinstance(later.target, IRLocal)
                        and (later.target == temp_local or later.target == user_local)
                    ):
                        break
                    self._replace_local_shallow(later, temp_local, user_local)
        return None

    def _replace_in_branches(self, stmt: IRStatement, temp: IRLocal, user: IRLocal) -> None:
        """Replace reads of `temp` with `user` inside a switch/conditional's branch
        bodies, stopping at (but still substituting into the RHS of) a statement
        that reassigns `temp` — reads past that point belong to the new value."""
        branches: List[IRBlock] = []
        if isinstance(stmt, IRConditional):
            branches.append(stmt.true_block)
            if stmt.false_block:
                branches.append(stmt.false_block)
        elif isinstance(stmt, IRSwitch):
            branches.extend(stmt.cases.values())
            if stmt.default:
                branches.append(stmt.default)
        for branch in branches:
            for s in branch.statements:
                self._replace_local_shallow(s, temp, user)
                if isinstance(s, IRAssign) and isinstance(s.target, IRLocal) and s.target == temp:
                    break

    @staticmethod
    def _is_synthetic_temp(local: IRLocal) -> bool:
        """Return True for compiler-generated `varN` temporaries (no debug name)."""
        return bool(re.fullmatch(r"var\d+", local.name))

    def _common_copy(self, stmt: IRStatement) -> Optional[Tuple[IRLocal, IRLocal]]:
        """Return (temp_local, user_local) if all branches end with user_local = temp_local."""
        branches: List[IRBlock] = []
        if isinstance(stmt, IRConditional):
            branches.append(stmt.true_block)
            if stmt.false_block:
                branches.append(stmt.false_block)
        elif isinstance(stmt, IRSwitch):
            branches.extend(stmt.cases.values())
            if stmt.default:
                branches.append(stmt.default)
        else:
            return None

        copy: Optional[Tuple[IRLocal, IRLocal]] = None
        for branch in branches:
            last = self._last_significant_statement(branch)
            if not isinstance(last, IRAssign):
                return None
            if not isinstance(last.target, IRLocal) or not isinstance(last.expr, IRLocal):
                return None
            user, temp = last.target, last.expr
            # The assignment direction must be user_local = temp (temp is the switch value).
            if self._is_user_local(user) and not self._is_user_local(temp):
                current = (temp, user)
            elif self._is_user_local(temp) and not self._is_user_local(user):
                current = (user, temp)
            else:
                return None
            if copy is None:
                copy = current
            elif copy != current:
                return None
        return copy

    def _common_user_assign_target(self, stmt: IRStatement) -> Optional[IRLocal]:
        """Return the user-named local every branch's last statement assigns to, if it's the same one."""
        branches: List[IRBlock] = []
        if isinstance(stmt, IRConditional):
            branches.append(stmt.true_block)
            if stmt.false_block:
                branches.append(stmt.false_block)
        elif isinstance(stmt, IRSwitch):
            branches.extend(stmt.cases.values())
            if stmt.default:
                branches.append(stmt.default)
        else:
            return None

        user_local: Optional[IRLocal] = None
        for branch in branches:
            last = self._last_significant_statement(branch)
            if not isinstance(last, IRAssign) or not isinstance(last.target, IRLocal):
                return None
            if not self._is_user_local(last.target):
                return None
            if user_local is None:
                user_local = last.target
            elif user_local != last.target:
                return None
        return user_local

    def _phantom_reads(self, stmt: IRStatement) -> List[IRLocal]:
        """Top-level local(s) read directly as a switch's value or a conditional's condition."""
        if isinstance(stmt, IRSwitch) and isinstance(stmt.value, IRLocal):
            return [stmt.value]
        if isinstance(stmt, IRConditional) and isinstance(stmt.condition, IRBoolExpr):
            found = []
            if isinstance(stmt.condition.left, IRLocal):
                found.append(stmt.condition.left)
            if isinstance(stmt.condition.right, IRLocal):
                found.append(stmt.condition.right)
            return found
        return []

    def _last_significant_statement(self, block: IRBlock) -> Optional[IRStatement]:
        """Return the last non-IRReturn statement in a block, or None."""
        for s in reversed(block.statements):
            if not isinstance(s, IRReturn):
                return s
        return None

    def _replace_local_shallow(self, stmt: IRStatement, target: IRLocal, replacement: IRLocal) -> bool:
        """Replace reads of target with replacement only at the top level of stmt."""
        made_change = False
        if isinstance(stmt, IRAssign):
            if isinstance(stmt.target, IRExpression) and stmt.target != target:
                _, changed = self._replace_local_in_expr(stmt.target, target, replacement)
                made_change = made_change or changed
            if isinstance(stmt.expr, IRExpression):
                stmt.expr, changed = self._replace_local_in_expr(stmt.expr, target, replacement)
                made_change = made_change or changed
        elif isinstance(stmt, IRExpression):
            _, changed = self._replace_local_in_expr(stmt, target, replacement)
            made_change = made_change or changed
        elif isinstance(stmt, IRReturn):
            if stmt.value:
                stmt.value, changed = self._replace_local_in_expr(stmt.value, target, replacement)
                made_change = made_change or changed
        elif isinstance(stmt, IRConditional):
            stmt.condition, changed = self._replace_local_in_expr(stmt.condition, target, replacement)
            made_change = made_change or changed
        elif isinstance(stmt, IRWhileLoop):
            stmt.condition, changed = self._replace_local_in_expr(stmt.condition, target, replacement)
            made_change = made_change or changed
        elif isinstance(stmt, IRSwitch):
            stmt.value, changed = self._replace_local_in_expr(stmt.value, target, replacement)
            made_change = made_change or changed
        return made_change

    def _replace_local_in_statement(self, stmt: IRStatement, target: IRLocal, replacement: IRLocal) -> bool:
        made_change = False
        if isinstance(stmt, IRAssign):
            if isinstance(stmt.target, IRExpression) and stmt.target != target:
                _, changed = self._replace_local_in_expr(stmt.target, target, replacement)
                made_change = made_change or changed
            if isinstance(stmt.expr, IRExpression):
                stmt.expr, changed = self._replace_local_in_expr(stmt.expr, target, replacement)
                made_change = made_change or changed
        elif isinstance(stmt, IRExpression):
            _, changed = self._replace_local_in_expr(stmt, target, replacement)
            made_change = made_change or changed
        elif isinstance(stmt, IRReturn):
            if stmt.value:
                stmt.value, changed = self._replace_local_in_expr(stmt.value, target, replacement)
                made_change = made_change or changed
        elif isinstance(stmt, IRConditional):
            stmt.condition, changed = self._replace_local_in_expr(stmt.condition, target, replacement)
            made_change = made_change or changed
        elif isinstance(stmt, IRWhileLoop):
            stmt.condition, changed = self._replace_local_in_expr(stmt.condition, target, replacement)
            made_change = made_change or changed

        for child in stmt.get_children():
            if child is not stmt and isinstance(child, IRStatement):
                if self._replace_local_in_statement(child, target, replacement):
                    made_change = True
        return made_change

    def _replace_local_in_expr(
        self, expr: IRExpression, target: IRLocal, replacement: IRLocal
    ) -> Tuple[IRExpression, bool]:
        if expr == target:
            return replacement, True
        made_change = False
        if isinstance(expr, (IRArithmetic, IRBoolExpr)):
            if expr.left is not None:
                expr.left, changed = self._replace_local_in_expr(expr.left, target, replacement)
                made_change = made_change or changed
            if expr.right is not None:
                expr.right, changed = self._replace_local_in_expr(expr.right, target, replacement)
                made_change = made_change or changed
        elif isinstance(expr, IRCall):
            for i, arg in enumerate(expr.args):
                expr.args[i], changed = self._replace_local_in_expr(arg, target, replacement)
                made_change = made_change or changed
        elif isinstance(expr, IRField):
            expr.target, changed = self._replace_local_in_expr(expr.target, target, replacement)
            made_change = made_change or changed
        elif isinstance(expr, IRCast):
            expr.expr, changed = self._replace_local_in_expr(expr.expr, target, replacement)
            made_change = made_change or changed
        elif isinstance(expr, (IREnumIndex, IREnumField)):
            expr.value, changed = self._replace_local_in_expr(expr.value, target, replacement)
            made_change = made_change or changed
        elif isinstance(expr, IRArrayAccess):
            expr.array, changed = self._replace_local_in_expr(expr.array, target, replacement)
            made_change = made_change or changed
            expr.index, changed = self._replace_local_in_expr(expr.index, target, replacement)
            made_change = made_change or changed
        elif isinstance(expr, IREnumConstruct):
            for i, arg in enumerate(expr.args):
                expr.args[i], changed = self._replace_local_in_expr(arg, target, replacement)
                made_change = made_change or changed
        return expr, made_change

    def _is_user_local(self, local: IRLocal) -> bool:
        if not self.func.func.has_debug or not self.func.func.assigns:
            return False
        user_names = {name_ref.resolve(self.func.code) for name_ref, _ in self.func.func.assigns}
        if local.name in user_names:
            return True
        if local.name.startswith("var"):
            try:
                idx = int(local.name[3:])
            except ValueError:
                return False
            for _, op_idx in self.func.func.assigns:
                val = op_idx.value - 1
                if 0 <= val < len(self.func.ops):
                    op = self.func.ops[val]
                    if "dst" in op.df and op.df["dst"].value == idx:
                        return True
        return False
