"""
Structural cleanup and dead-code elimination optimizers.
"""

from __future__ import annotations

import copy
import re
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple, Union, cast

if TYPE_CHECKING:
    from ..function import IRFunction

from ...core import (
    Bytecode,
    DynObj,
    Enum,
    Fun,
    Function,
    Native,
    Obj,
    Opcode,
    Ref,
    ResolvableVarInt,
    Type,
    TypeDef,
    Virtual,
    Void,
    fieldRef,
    gIndex,
    tIndex,
)
from ...errors import DecompError
from ...globals import DEBUG, dbg_print
from ... import disasm
from ...opcodes import arithmetic, conditionals, terminal, simple_calls
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
    IRBreak,
    IRContinue,
    IRReturn,
    IRThrow,
    IRTrace,
    IRTryCatch,
    IRSwitch,
    IRPrimitiveJump,
    IRWhileLoop,
    IRForEachLoop,
    IRIntRangeLoop,
    IRField,
    IRNew,
    IRNativeArrayNew,
    IRNativeMapNew,
    IRCast,
    IRArrayLiteral,
    IRArrayAccess,
    IRRef,
    IRRefNew,
    IRRefSet,
    IREnumConstruct,
    IREnumIndex,
    IREnumField,
    IRUnliftedOpcode,
    IRNativeStub,
    _get_type_in_code,
    _strip_ansi,
)

from ..cfg import CFNode, CFGraph, IsolatedCFGraph, _find_jumps_to_label
from . import (
    IROptimizer,
    TraversingIROptimizer,
    _ir_structurally_equal,
    _structurally_equal,
    _stmt_lists_structurally_equal,
    _bytes_mem_kind,
    _int_const_value,
    _signed_i32,
)


class IRLoopConditionOptimizer(TraversingIROptimizer):
    """
    Optimizes IRPrimitiveLoop structures into IRWhileLoop.
    It expects the IRPrimitiveLoop's condition block to end with an IRBoolExpr
    (which would typically have been lifted from a jump by IRPrimitiveJumpLifter).
    This IRBoolExpr determines the loop *exit* condition.

    The optimizer inverts this exit condition to get the 'while' *continuation* condition.
    Any statements from the original condition block preceding the final IRBoolExpr
    are prepended to the new IRWhileLoop's body.
    """

    def _clone_bool_expr(self, expr: IRBoolExpr) -> IRBoolExpr:
        return cast(IRBoolExpr, IRBoolExpr(expr.code, expr.op, expr.left, expr.right).adopt(expr))

    def _inline_into_boolexpr(
        self, bool_expr: IRBoolExpr, target: IRLocal | IRField | IRArrayAccess, expr_to_inline: IRExpression
    ) -> Optional[IRBoolExpr]:
        modified = False
        new_left = bool_expr.left
        new_right = bool_expr.right

        if bool_expr.left == target:
            new_left = expr_to_inline
            modified = True
        if bool_expr.right == target:
            new_right = expr_to_inline
            modified = True

        if modified:
            bool_expr.left = new_left
            bool_expr.right = new_right
            return bool_expr
        return None

    def _statement_reads_target(self, statement: IRStatement, target: IRLocal | IRField | IRArrayAccess) -> bool:
        if statement == target:
            return True
        if isinstance(statement, IRAssign):
            return self._statement_reads_target(statement.expr, target)
        if isinstance(statement, IRBoolExpr):
            return (statement.left is not None and self._statement_reads_target(statement.left, target)) or (
                statement.right is not None and self._statement_reads_target(statement.right, target)
            )
        return any(self._statement_reads_target(child, target) for child in statement.get_children())

    def _convert_to_while_true_break(
        self,
        loop: IRPrimitiveLoop,
        setup_statements: List[IRStatement],
        exit_condition_expr: IRBoolExpr,
    ) -> IRWhileLoop:
        true_loop_condition = IRBoolExpr(loop.code, IRBoolExpr.CompareType.TRUE)
        break_block = IRBlock(loop.code)
        break_block.statements.append(IRBreak(loop.code))
        if_break_stmt = IRConditional(loop.code, exit_condition_expr, break_block, IRBlock(loop.code))

        new_body_block = IRBlock(loop.code)
        new_body_block.statements = setup_statements + [if_break_stmt] + list(loop.body.statements)

        new_while_loop = IRWhileLoop(loop.code, true_loop_condition, new_body_block)
        new_while_loop.comment = loop.comment
        new_while_loop.adopt(loop, exit_condition_expr)
        return new_while_loop

    def visit_block(self, block: IRBlock) -> None:
        new_statements: List[IRStatement] = []
        for stmt in block.statements:
            if isinstance(stmt, IRPrimitiveLoop):
                converted_loop = self._try_convert_to_while(stmt)
                new_statements.append(converted_loop if converted_loop else stmt)
            else:
                new_statements.append(stmt)
        block.statements = new_statements

    def _try_convert_to_while(self, loop: IRPrimitiveLoop) -> Optional[IRWhileLoop]:
        if not loop.condition.statements:
            dbg_print(f"IRLoopCondOpt: PrimitiveLoop at {loop} has empty condition block. Cannot convert.")
            return None

        last_cond_stmt = loop.condition.statements[-1]

        if not isinstance(last_cond_stmt, IRBoolExpr):
            dbg_print(
                f"IRLoopCondOpt: PrimitiveLoop at {loop} condition does not end with IRBoolExpr. Ends with {type(last_cond_stmt).__name__}. Cannot convert."
            )
            return None

        setup_statements_for_body = loop.condition.statements[:-1]
        working_exit_condition = self._clone_bool_expr(last_cond_stmt)
        remaining_setup: List[IRStatement] = []

        for i, stmt in enumerate(setup_statements_for_body):
            if (
                isinstance(stmt, IRAssign)
                and isinstance(stmt.expr, IRExpression)
                and isinstance(stmt.target, (IRLocal, IRField, IRArrayAccess))
            ):
                later_statements = list(setup_statements_for_body[i + 1 :]) + list(loop.body.statements)
                reads_later = any(
                    self._statement_reads_target(later_stmt, stmt.target) for later_stmt in later_statements
                )
                reads_in_condition = self._statement_reads_target(working_exit_condition, stmt.target)
                if reads_later or reads_in_condition:
                    remaining_setup.append(stmt)
                    continue

                inlined = self._inline_into_boolexpr(working_exit_condition, stmt.target, stmt.expr)
                if inlined:
                    working_exit_condition.adopt(stmt)  # stmt itself is dropped below
                    continue
            remaining_setup.append(stmt)

        if remaining_setup:
            dbg_print(
                "IRLoopCondOpt: Condition setup must execute each iteration; converting to while(true)+break form."
            )
            return self._convert_to_while_true_break(loop, remaining_setup, working_exit_condition)

        loop_continuation_expr = self._clone_bool_expr(working_exit_condition)
        loop_continuation_expr.invert()

        new_body_statements = list(loop.body.statements)
        new_body_block = IRBlock(loop.code)
        new_body_block.statements = new_body_statements

        new_while_loop = IRWhileLoop(loop.code, loop_continuation_expr, new_body_block)

        new_while_loop.comment = loop.comment
        new_while_loop.adopt(loop, loop_continuation_expr)

        dbg_print(f"IRLoopCondOpt: Converted IRPrimitiveLoop to IRWhileLoop. While condition: {loop_continuation_expr}")
        return new_while_loop


class IRSelfAssignOptimizer(TraversingIROptimizer):
    """
    Optimizes away redundant assignments like `x = x`.
    """

    def visit_block(self, block: IRBlock) -> None:
        new_statements = []

        for stmt in block.statements:
            if isinstance(stmt, IRAssign):
                if isinstance(stmt.target, IRLocal) and stmt.target == stmt.expr:
                    if DEBUG:
                        dbg_print(f"IRSelfAssignOptimizer: Removing redundant assignment: {stmt}")
                    continue
            new_statements.append(stmt)

        block.statements = new_statements


class IRBoolMaterializationCollapser(TraversingIROptimizer):
    """
    Collapses `if (cond) { t = true; } else { t = false; }` into `t = cond`,
    the inverted constant pair into `t = !cond`, and unwraps double negation.
    """

    @staticmethod
    def _negated_operand(expr: IRExpression) -> Optional[IRExpression]:
        if isinstance(expr, IRNot):
            return expr.expr
        if (
            isinstance(expr, IRBoolExpr)
            and expr.op in (IRBoolExpr.CompareType.ISFALSE, IRBoolExpr.CompareType.NOT)
            and expr.left is not None
        ):
            return expr.left
        return None

    @staticmethod
    def _strip_istrue(expr: IRExpression) -> IRExpression:
        while (
            isinstance(expr, IRBoolExpr) and expr.op == IRBoolExpr.CompareType.ISTRUE and expr.left is not None
        ):
            expr = expr.left
        return expr

    @classmethod
    def _unwrap_double_not(cls, expr: IRExpression) -> IRExpression:
        inner = cls._negated_operand(cls._strip_istrue(expr))
        if inner is None:
            return expr
        inner2 = cls._negated_operand(cls._strip_istrue(inner))
        if inner2 is None:
            return expr
        return cls._unwrap_double_not(inner2)

    @staticmethod
    def _branch_bool_assign(block: Optional[IRBlock]) -> Optional[Tuple[IRLocal, bool]]:
        if block is None or len(block.statements) != 1:
            return None
        stmt = block.statements[0]
        if (
            isinstance(stmt, IRAssign)
            and isinstance(stmt.target, IRLocal)
            and isinstance(stmt.expr, IRConst)
            and stmt.expr.const_type == IRConst.ConstType.BOOL
        ):
            return stmt.target, bool(stmt.expr.value)
        return None

    def visit_block(self, block: IRBlock) -> None:
        new_statements: List[IRStatement] = []
        for stmt in block.statements:
            if isinstance(stmt, IRAssign) and isinstance(stmt.expr, IRExpression):
                stmt.expr = self._unwrap_double_not(stmt.expr)
            elif isinstance(stmt, IRConditional):
                stmt.condition = self._unwrap_double_not(stmt.condition)
            elif isinstance(stmt, IRWhileLoop):
                stmt.condition = self._unwrap_double_not(stmt.condition)
            elif isinstance(stmt, IRReturn) and stmt.value is not None:
                stmt.value = self._unwrap_double_not(stmt.value)
            if isinstance(stmt, IRConditional):
                true_assign = self._branch_bool_assign(stmt.true_block)
                false_assign = self._branch_bool_assign(stmt.false_block)
                if (
                    true_assign is not None
                    and false_assign is not None
                    and true_assign[0] == false_assign[0]
                    and true_assign[1] != false_assign[1]
                    and not (
                        isinstance(true_assign[0], IRLocal)
                        and re.match(r"^var\d+$", true_assign[0].name)
                    )
                ):
                    target = true_assign[0]
                    cond = stmt.condition
                    if not true_assign[1]:
                        # Negate: prefer inverting a comparison in-place over
                        # wrapping in IRNot to avoid `!(a >= b)` → `a < b`.
                        if isinstance(cond, IRBoolExpr) and cond.op in (
                            IRBoolExpr.CompareType.LT,
                            IRBoolExpr.CompareType.LTE,
                            IRBoolExpr.CompareType.GT,
                            IRBoolExpr.CompareType.GTE,
                            IRBoolExpr.CompareType.EQ,
                            IRBoolExpr.CompareType.NEQ,
                        ):
                            cond = copy.copy(cond)
                            cond.invert()
                        else:
                            cond = cond.expr if isinstance(cond, IRNot) else IRNot(self.func.code, cond)
                    assign = IRAssign(self.func.code, target, cond)
                    assign.adopt(stmt)
                    # The collapsed `t = cond` is a synthetic merge of the original
                    # branch — folding constants into it would lose the branch
                    # structure on recompile (e.g. `cond = 4 != 3` → `Bool True`).
                    assign._no_user_inline = True
                    dbg_print(f"IRBoolMaterializationCollapser: {stmt} -> {assign}")
                    new_statements.append(assign)
                    continue
            new_statements.append(stmt)
        block.statements = new_statements


class IRArrayGrowGuardEliminator(TraversingIROptimizer):
    """
    Removes `if (idx >= arr.length) arr.__expand(idx);` guards.

    HL's compiler emits this guard in front of *every* bracket write to a
    typed array (`arr[idx] = value;`), growing the backing storage first if
    needed. `__expand` isn't a real method of `Array<T>` though — it only
    exists on the internal ArrayBytes_T/ArrayObj implementation classes —
    so rendering this guard literally produces Haxe that doesn't compile.
    Since the guard is implied by (and always paired with) an ordinary
    bracket write, it's safe to drop unconditionally rather than try to
    render it.
    """

    def visit_block(self, block: IRBlock) -> None:
        new_statements = []

        for stmt in block.statements:
            if isinstance(stmt, IRConditional) and not (stmt.false_block and stmt.false_block.statements):
                true_stmts = stmt.true_block.statements if stmt.true_block else []
                if (
                    len(true_stmts) == 1
                    and isinstance(true_stmts[0], IRCall)
                    and isinstance(true_stmts[0].target, IRConst)
                    and isinstance(true_stmts[0].target.value, Function)
                    and self.func.code.partial_func_name(true_stmts[0].target.value) == "__expand"
                    # Keep the guard when __expand is called on `this`: that's the
                    # array impl class's own setDyn body (real source), not a
                    # compiler-inserted guard fronting a user's `arr[i] = v`.
                    and not (
                        true_stmts[0].args
                        and isinstance(true_stmts[0].args[0], IRLocal)
                        and true_stmts[0].args[0].name == "this"
                    )
                ):
                    if DEBUG:
                        dbg_print(f"IRArrayGrowGuardEliminator: Removing __expand guard: {stmt}")
                    continue
            new_statements.append(stmt)

        block.statements = new_statements


class IRRedundantRecomputeEliminator(TraversingIROptimizer):
    """
    Rewrites `t1 = E; t2 = E;` (the same expression recomputed verbatim in the
    very next statement) into `t1 = E; t2 = t1;`.

    This undoes copy-propagation's effect on a `temp = expr; user = temp;`
    pattern when it inlined `expr` into the second assignment instead of
    leaving a plain copy: HashLink's own compiler always lowers compound
    assignment (`x += n`) to exactly that compute-then-copy shape (`Add`
    then `Mov`), so re-expanding the second assignment into a fresh `Add`
    produces extra opcodes that don't exist in the original bytecode.
    """

    def visit_block(self, block: IRBlock) -> None:
        new_statements: List[IRStatement] = []
        i = 0
        stmts = block.statements
        while i < len(stmts):
            stmt = stmts[i]
            nxt = stmts[i + 1] if i + 1 < len(stmts) else None
            if (
                nxt is not None
                and isinstance(stmt, IRAssign)
                and isinstance(stmt.target, IRLocal)
                and isinstance(nxt, IRAssign)
                and isinstance(nxt.target, IRLocal)
                and nxt.target != stmt.target
                and not isinstance(stmt.expr, (IRLocal, IRConst))
                and _structurally_equal(stmt.expr, nxt.expr)
            ):
                new_statements.append(stmt)
                new_statements.append(IRAssign(self.func.code, nxt.target, stmt.target).adopt(nxt))
                i += 2
                continue
            # `t = E; return E;` (or throw) — the terminator re-evaluates E
            # independently rather than reading t (e.g. left over from a
            # condition check that reused the checked value), so t's
            # assignment is pure overhead. Safe regardless of whether t is
            # used elsewhere: a return ends this path, so nothing after it
            # on this path could have read t anyway.
            if (
                nxt is not None
                and isinstance(stmt, IRAssign)
                and isinstance(stmt.target, IRLocal)
                and not isinstance(stmt.expr, (IRLocal, IRConst))
                and isinstance(nxt, (IRReturn, IRThrow))
                and nxt.value is not None
                and _structurally_equal(stmt.expr, nxt.value)
            ):
                nxt.adopt(stmt)  # stmt is dropped; nxt (return/throw) is kept as-is below
                i += 1
                continue
            new_statements.append(stmt)
            i += 1
        block.statements = new_statements


class IRBlockFlattener(TraversingIROptimizer):
    """
    Flattens nested IRBlock structures. For example, an IRBlock child of another IRBlock
    will have its statements merged into the parent IRBlock. This simplifies the IR by
    removing unnecessary layers of blocks.

    This optimizer works by ensuring that any IRBlock child of a currently visited IRBlock
    is itself visited (and thus potentially flattened internally) before its statements
    are pulled up into the parent.
    """

    def visit_block(self, block: IRBlock) -> None:
        original_statements = list(block.statements)
        new_statements: List[IRStatement] = []

        made_structural_change = False

        for stmt in original_statements:
            if isinstance(stmt, IRBlock):
                self.visit(stmt)

                new_statements.extend(stmt.statements)
                made_structural_change = True
            else:
                new_statements.append(stmt)

        if made_structural_change or new_statements != original_statements:
            block.statements = new_statements
            dbg_print(
                f"IRBlockFlattener: Processed block. Original item count: {len(original_statements)}, New item count: {len(new_statements)}"
            )


class IRCommonBlockMerger(TraversingIROptimizer):
    """
    Finds IRConditional statements where both the true and false blocks end
    with the same sequence of statements. It "hoists" this common suffix out
    of the conditional and places it after the if/else block.

    For example:
        if (cond) {
            do_a();
            common_code();
        } else {
            do_b();
            common_code();
        }

    Becomes:
        if (cond) {
            do_a();
        } else {
            do_b();
        }
        common_code();
    """

    def visit_block(self, block: IRBlock) -> None:
        made_change = False
        new_statements: List[IRStatement] = []

        for stmt in block.statements:
            if isinstance(stmt, IRConditional):
                # We can only merge if there is an 'else' block
                if not stmt.false_block or not stmt.false_block.statements:
                    new_statements.append(stmt)
                    continue

                true_stmts = stmt.true_block.statements
                false_stmts = stmt.false_block.statements

                common_suffix: List[IRStatement] = []
                # Compare statements from the end of each block
                t_idx, f_idx = len(true_stmts) - 1, len(false_stmts) - 1
                while t_idx >= 0 and f_idx >= 0:
                    # Cheap type check first: a mismatch here means the repr()s can never
                    # be equal, so we skip fully rendering large nested subtrees (e.g. a
                    # branch ending in a deeply nested IRConditional from a cascading
                    # if/elif chain) just to find out they differ.
                    if type(true_stmts[t_idx]) is not type(false_stmts[f_idx]):
                        break
                    # Structural comparison without rendering: repr()/pformat on
                    # the IR DAG re-expands shared continuation blocks and is
                    # exponential for branchy code. _ir_structurally_equal walks
                    # the pair in lockstep with memoization instead.
                    if _ir_structurally_equal(true_stmts[t_idx], false_stmts[f_idx]):
                        # Prepend to keep the order correct
                        common_suffix.insert(0, true_stmts[t_idx])
                        t_idx -= 1
                        f_idx -= 1
                    else:
                        break

                if common_suffix:
                    dbg_print(f"IRCommonBlockMerger: Found {len(common_suffix)} common statements to merge.")
                    made_change = True

                    # Truncate the original blocks
                    stmt.true_block.statements = true_stmts[: t_idx + 1]
                    stmt.false_block.statements = false_stmts[: f_idx + 1]

                    # Add the modified conditional, then the common code after it.
                    new_statements.append(stmt)
                    new_statements.extend(common_suffix)
                else:
                    new_statements.append(stmt)
            else:
                new_statements.append(stmt)

        if made_change:
            block.statements = new_statements


class IRRedundantContinueEliminator(TraversingIROptimizer):
    """
    Removes redundant `else { continue; }` blocks that are the last statement
    of a loop body. After the if-block, control naturally falls through to the
    end of the loop body, which is equivalent to continuing the loop, so the
    explicit else-continue is just noise.
    """

    def __init__(self, function: "IRFunction") -> None:
        super().__init__(function)
        self._loop_depth = 0

    def before_visit_statement(self, statement: IRStatement) -> None:
        if isinstance(statement, (IRWhileLoop, IRPrimitiveLoop)):
            self._loop_depth += 1

    def after_visit_statement(self, statement: IRStatement) -> None:
        if isinstance(statement, (IRWhileLoop, IRPrimitiveLoop)):
            self._loop_depth -= 1

    def visit_block(self, block: IRBlock) -> None:
        if self._loop_depth == 0 or not block.statements:
            super().visit_block(block)
            return

        last = block.statements[-1]
        if isinstance(last, IRConditional) and last.false_block is not None:
            false_stmts = [s for s in last.false_block.statements if not isinstance(s, IRReturn)]
            if len(false_stmts) == 1 and isinstance(false_stmts[0], IRContinue):
                dbg_print("IRRedundantContinueEliminator: removing trailing else { continue; }")
                last.false_block = IRBlock(self.func.code)
                last.false_block.statements = []

        super().visit_block(block)


class IRVoidAssignOptimizer(TraversingIROptimizer):
    """
    Removes assignments to IRLocals of type Void, keeping the expression
    for its side effects and annotating the discard.
    E.g., `var_void_local:Void = some_call();` becomes `some_call();`
    """

    def visit_block(self, block: IRBlock) -> None:
        new_statements: List[IRStatement] = []
        made_change_this_pass = False

        for stmt in block.statements:
            if isinstance(stmt, IRAssign):
                target = stmt.target
                if isinstance(target, IRLocal):
                    target_type_resolved = target.type.resolve(self.func.code)
                    if target_type_resolved.kind.value == Type.Kind.VOID.value:
                        if DEBUG:
                            dbg_print(
                                f"IRVoidAssignOptimizer: Removing void assignment: {stmt} (target: {target.name})"
                            )

                        expr_being_kept = stmt.expr
                        expr_being_kept.adopt(stmt)  # opcode was tagged on the assign, not its expr
                        new_statements.append(expr_being_kept)
                        made_change_this_pass = True
                        continue
            new_statements.append(stmt)

        if made_change_this_pass:
            block.statements = new_statements


class IRDeadTempEliminator(IROptimizer):
    """Removes assignments to compiler-generated temp variables that are never read."""

    def optimize(self) -> None:
        if not hasattr(self.func, "block"):
            return
        user_names = self._collect_user_names()
        user_regs = self._collect_user_reg_indices()
        globally_used = self._collect_all_used_names(self.func.block)
        self._remove_dead(self.func.block, user_names, user_regs, globally_used)

    def _collect_user_names(self) -> Set[str]:
        names: Set[str] = set()
        if self.func.func.has_debug and self.func.func.assigns:
            for name_ref, _ in self.func.func.assigns:
                names.add(name_ref.resolve(self.func.code))
        return names

    def _collect_user_reg_indices(self) -> Set[int]:
        indices: Set[int] = set()
        if self.func.func.has_debug and self.func.func.assigns:
            for _, op_idx in self.func.func.assigns:
                val = op_idx.value - 1
                if val >= 0 and val < len(self.func.ops):
                    op = self.func.ops[val]
                    try:
                        indices.add(op.df["dst"].value)
                    except KeyError:
                        pass
        return indices

    def _is_user_local(self, local: IRLocal, user_names: Set[str], user_regs: Set[int]) -> bool:
        if local.name in user_names:
            return True
        # Preserve names like `b1` that were generated to disambiguate two
        # user-named locals with different types.
        for name in user_names:
            if local.name.startswith(name) and local.name[len(name) :].isdigit():
                return True
        if local.name.startswith("var"):
            try:
                idx = int(local.name[3:])
                if idx in user_regs:
                    return True
            except ValueError:
                pass
        return False

    def _is_dead_removable(self, local: IRLocal, user_names: Set[str], user_regs: Set[int]) -> bool:
        """Return True if an unread assignment to `local` is safe to delete.

        Non-user locals are always removable. A purely synthetic `varN` temp is
        also removable even when its register index is reused by a user variable:
        the caller has already confirmed the name is never read anywhere, so the
        register-reuse protection (meant to keep live SSA-split user values) does
        not apply. User-named locals (real names, or `nameN` disambiguations) are
        never removed here.
        """
        if not self._is_user_local(local, user_names, user_regs):
            return True
        if local.name in user_names:
            return False
        for name in user_names:
            if local.name.startswith(name) and local.name[len(name) :].isdigit():
                return False
        # Only reached for `varN` names kept alive solely by register reuse.
        return bool(re.fullmatch(r"var\d+", local.name))

    def _collect_all_used_names(self, block: IRBlock, _visited: Optional[Set[int]] = None) -> Set[str]:
        # DAG-aware: shared continuation blocks are reachable from many parents,
        # so prune already-visited blocks to avoid exponential re-walks.
        if _visited is None:
            _visited = set()
        used: Set[str] = set()
        if id(block) in _visited:
            return used
        _visited.add(id(block))
        for stmt in block.statements:
            self._collect_used_in_stmt(stmt, used)
            for child in stmt.get_children():
                if isinstance(child, IRBlock):
                    used.update(self._collect_all_used_names(child, _visited))
        return used

    def _collect_used_in_stmt(self, stmt: IRStatement, used: Set[str]) -> None:
        if isinstance(stmt, IRAssign):
            self._collect_used_in_expr(stmt.expr, used)
            # For array-element assignments, the array/index expressions are still reads.
            if isinstance(stmt.target, IRArrayAccess):
                self._collect_used_in_expr(stmt.target.array, used)
                self._collect_used_in_expr(stmt.target.index, used)
        elif isinstance(stmt, IRReturn) and stmt.value:
            self._collect_used_in_expr(stmt.value, used)
        elif isinstance(stmt, IRThrow):
            self._collect_used_in_expr(stmt.value, used)
        elif isinstance(stmt, IRCall):
            self._collect_used_in_expr(stmt.target, used)
            for arg in stmt.args:
                self._collect_used_in_expr(arg, used)
        elif isinstance(stmt, IRTrace):
            self._collect_used_in_expr(stmt.msg, used)
        elif isinstance(stmt, IRConditional):
            self._collect_used_in_expr(stmt.condition, used)
        elif isinstance(stmt, IRWhileLoop):
            self._collect_used_in_expr(stmt.condition, used)
        elif isinstance(stmt, IRPrimitiveLoop):
            used.update(self._collect_all_used_names(stmt.condition))
        elif isinstance(stmt, IRSwitch):
            self._collect_used_in_expr(stmt.value, used)
        else:
            # Generic fallback (e.g. IRRefSet): treat any expression child as a
            # read, so a missing case can't delete a still-needed assignment.
            for child in stmt.get_children():
                if isinstance(child, IRExpression):
                    self._collect_used_in_expr(child, used)

    def _collect_used_in_expr(self, expr: Optional[IRExpression], used: Set[str]) -> None:
        if expr is None:
            return
        if isinstance(expr, IRLocal):
            used.add(expr.name)
        elif isinstance(expr, IRArithmetic):
            self._collect_used_in_expr(expr.left, used)
            self._collect_used_in_expr(expr.right, used)
        elif isinstance(expr, IRArrayAccess):
            self._collect_used_in_expr(expr.array, used)
            self._collect_used_in_expr(expr.index, used)
        elif isinstance(expr, IRArrayLiteral):
            for element in expr.elements:
                self._collect_used_in_expr(element, used)
        elif isinstance(expr, IRBoolExpr):
            self._collect_used_in_expr(expr.left, used)
            self._collect_used_in_expr(expr.right, used)
        elif isinstance(expr, IRCast):
            self._collect_used_in_expr(expr.expr, used)
        elif isinstance(expr, IRCall):
            self._collect_used_in_expr(expr.target, used)
            for arg in expr.args:
                self._collect_used_in_expr(arg, used)
        elif isinstance(expr, IREnumConstruct):
            for arg in expr.args:
                self._collect_used_in_expr(arg, used)
        elif isinstance(expr, IREnumField):
            self._collect_used_in_expr(expr.value, used)
        elif isinstance(expr, IREnumIndex):
            self._collect_used_in_expr(expr.value, used)
        elif isinstance(expr, IRField):
            self._collect_used_in_expr(expr.target, used)
        elif isinstance(expr, IRNew):
            for arg in expr.constructor_args:
                self._collect_used_in_expr(arg, used)
        elif isinstance(expr, IRRef):
            self._collect_used_in_expr(expr.target, used)
        else:
            # Fall back to generic traversal for any expression type not
            # explicitly listed above (e.g. IRNativeArrayNew/IRNativeMapNew),
            # so a missing case here can't silently treat a real read as
            # absent and delete a still-needed assignment as dead.
            for child in expr.get_children():
                if isinstance(child, IRExpression):
                    self._collect_used_in_expr(child, used)

    def _remove_dead(
        self,
        block: IRBlock,
        user_names: Set[str],
        user_regs: Set[int],
        globally_used: Set[str],
        _visited: Optional[Set[int]] = None,
    ) -> None:
        # DAG-aware: prune already-processed shared blocks. Removing a dead temp
        # in a shared block once applies to every path that references it.
        if _visited is None:
            _visited = set()
        if id(block) in _visited:
            return
        _visited.add(id(block))
        new_stmts: List[IRStatement] = []
        for stmt in block.statements:
            if (
                isinstance(stmt, IRAssign)
                and isinstance(stmt.target, IRLocal)
                and stmt.target.name not in globally_used
                and self._is_dead_removable(stmt.target, user_names, user_regs)
            ):
                dbg_print(f"Removing dead temp assignment '{stmt.target.name}'.")
                # Preserve user-visible function calls as bare statements (side effects).
                # Native calls (itos, ftos, alloc_array, etc.) can be dropped entirely
                # when their result is dead — they have no user-visible side effects beyond
                # writing through a ref argument that is itself dead.
                if (
                    isinstance(stmt.expr, IRCall)
                    and isinstance(stmt.expr.target, IRConst)
                    and isinstance(stmt.expr.target.value, Function)
                ):
                    stmt.expr.adopt(stmt)  # opcode was tagged on the assign, not its expr
                    new_stmts.append(stmt.expr)
                continue
            new_stmts.append(stmt)
        block.statements = new_stmts
        for stmt in block.statements:
            for child in stmt.get_children():
                if isinstance(child, IRBlock):
                    self._remove_dead(child, user_names, user_regs, globally_used, _visited)


class IRDeadCodeEliminator(TraversingIROptimizer):
    """Removes statements after terminators (return, break, continue) within the same block."""

    def _body_has_break(self, block: IRBlock) -> bool:
        """Return True if the block (recursively) contains an IRBreak."""
        for stmt in block.statements:
            if isinstance(stmt, IRBreak):
                return True
            for child in stmt.get_children():
                if isinstance(child, IRBlock) and self._body_has_break(child):
                    return True
        return False

    def _is_infinite_loop(self, stmt: IRStatement) -> bool:
        if not isinstance(stmt, IRWhileLoop):
            return False
        cond = stmt.condition
        if isinstance(cond, IRBoolExpr):
            if cond.op == IRBoolExpr.CompareType.TRUE:
                return True
            if cond.op == IRBoolExpr.CompareType.ISTRUE and isinstance(cond.left, IRConst) and cond.left.value is True:
                return True
        return False

    def visit_block(self, block: IRBlock) -> None:
        new_stmts: List[IRStatement] = []
        terminated = False
        for stmt in block.statements:
            if terminated:
                continue
            new_stmts.append(stmt)
            if isinstance(stmt, (IRReturn, IRBreak, IRContinue, IRThrow)):
                terminated = True
            elif (
                self._is_infinite_loop(stmt)
                and isinstance(stmt, IRPrimitiveLoop)
                and not self._body_has_break(stmt.body)
            ):
                terminated = True
        block.statements = new_stmts
        for stmt in block.statements:
            for child in stmt.get_children():
                if isinstance(child, IRBlock):
                    self.visit_block(child)


class IRDeadStoreEliminator(TraversingIROptimizer):
    """Removes local assignments that are overwritten before being read within a block."""

    def visit_block(self, block: IRBlock) -> None:
        def _locals_in_expr(expr: Optional[IRExpression]) -> Set[IRLocal]:
            found: Set[IRLocal] = set()
            if expr is None:
                return found
            if isinstance(expr, IRLocal):
                found.add(expr)
            elif isinstance(expr, (IRArithmetic, IRBoolExpr)):
                found.update(_locals_in_expr(expr.left))
                found.update(_locals_in_expr(expr.right))
            elif isinstance(expr, IRArrayAccess):
                found.update(_locals_in_expr(expr.array))
                found.update(_locals_in_expr(expr.index))
            elif isinstance(expr, (IRField, IRCast, IRNeg, IRNot, IRTypeOf, IRTypeKind, IREnumIndex)):
                target = getattr(expr, "target", getattr(expr, "expr", getattr(expr, "value", None)))
                found.update(_locals_in_expr(target))
            elif isinstance(expr, IRCall):
                if expr.target is not None:
                    found.update(_locals_in_expr(expr.target))
                for arg in expr.args:
                    found.update(_locals_in_expr(arg))
            elif isinstance(expr, IRNew):
                for arg in expr.constructor_args:
                    found.update(_locals_in_expr(arg))
            elif isinstance(expr, IRArrayLiteral):
                for element in expr.elements:
                    found.update(_locals_in_expr(element))
            elif isinstance(expr, IREnumConstruct):
                for arg in expr.args:
                    found.update(_locals_in_expr(arg))
            elif isinstance(expr, IREnumField):
                found.update(_locals_in_expr(expr.value))
            elif isinstance(expr, IRRef):
                found.update(_locals_in_expr(expr.target))
            else:
                # Fall back to generic traversal for any expression type not
                # explicitly listed above (e.g. IRNativeArrayNew/IRNativeMapNew)
                # so a missing case here can't silently treat a real read as
                # absent and prune a still-needed assignment as dead.
                for child in expr.get_children():
                    if isinstance(child, IRExpression):
                        found.update(_locals_in_expr(child))
            return found

        def _has_side_effects(expr: Optional[IRExpression]) -> bool:
            if expr is None:
                return False
            if isinstance(expr, (IRCall, IRNew)):
                return True
            if isinstance(expr, IREnumConstruct):
                return any(_has_side_effects(arg) for arg in expr.args)
            if isinstance(expr, (IRArithmetic, IRBoolExpr)):
                return _has_side_effects(expr.left) or _has_side_effects(expr.right)
            if isinstance(expr, (IRField, IRCast, IRNeg, IRNot, IRTypeOf, IRTypeKind, IREnumIndex)):
                target = getattr(expr, "target", getattr(expr, "expr", getattr(expr, "value", None)))
                return _has_side_effects(target)
            if isinstance(expr, IRArrayAccess):
                return _has_side_effects(expr.array) or _has_side_effects(expr.index)
            if isinstance(expr, IRArrayLiteral):
                return any(_has_side_effects(e) for e in expr.elements)
            if isinstance(expr, IREnumField):
                return _has_side_effects(expr.value)
            if isinstance(expr, IRRef):
                return _has_side_effects(expr.target)
            return False

        def _reads_in_stmt(stmt: IRStatement) -> Set[IRLocal]:
            reads: Set[IRLocal] = set()
            if isinstance(stmt, IRAssign):
                reads.update(_locals_in_expr(stmt.expr))
                if isinstance(stmt.target, IRArrayAccess):
                    reads.update(_locals_in_expr(stmt.target.array))
                    reads.update(_locals_in_expr(stmt.target.index))
                elif isinstance(stmt.target, IRField):
                    reads.update(_locals_in_expr(stmt.target.target))
            elif isinstance(stmt, (IRReturn, IRThrow)) and stmt.value is not None:
                reads.update(_locals_in_expr(stmt.value))
            elif isinstance(stmt, IRCall):
                if stmt.target is not None:
                    reads.update(_locals_in_expr(stmt.target))
                for arg in stmt.args:
                    reads.update(_locals_in_expr(arg))
            elif isinstance(stmt, IRTrace):
                reads.update(_locals_in_expr(stmt.msg))
            elif isinstance(stmt, IRConditional):
                reads.update(_locals_in_expr(stmt.condition))
            elif isinstance(stmt, IRWhileLoop):
                reads.update(_locals_in_expr(stmt.condition))
            elif isinstance(stmt, IRSwitch):
                reads.update(_locals_in_expr(stmt.value))
            return reads

        def _written_local(stmt: IRStatement) -> Optional[IRLocal]:
            if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal):
                return stmt.target
            return None

        # First use of `local` along every path through a statement:
        # "read" (value needed), "kill" (dead on all paths: overwritten before
        # any read, or the path terminates), or "none" (untouched).
        def _first_use(stmt: IRStatement, local: IRLocal, _visited: Optional[Set[int]] = None) -> str:
            if _visited is None:
                _visited = set()
            if id(stmt) in _visited:
                return "none"
            _visited.add(id(stmt))

            if isinstance(stmt, IRAssign):
                if _reads_in_stmt(stmt) & {local}:
                    return "read"
                if isinstance(stmt.target, IRLocal) and (
                    stmt.target == local or stmt.target.same_register(local)
                ):
                    return "kill"
                return "none"
            if isinstance(stmt, (IRBreak, IRContinue)):
                # jumps to a continuation this block-level scan can't see
                return "read"
            if isinstance(stmt, (IRReturn, IRThrow)):
                if _reads_in_stmt(stmt) & {local}:
                    return "read"
                return "kill"
            if isinstance(stmt, IRConditional):
                if _locals_in_expr(stmt.condition) & {local}:
                    return "read"
                branches = [stmt.true_block.statements]
                branches.append(stmt.false_block.statements if stmt.false_block else [])
                results = [_first_use_in_list(b, local, _visited) for b in branches]
                if "read" in results:
                    return "read"
                if all(r == "kill" for r in results):
                    return "kill"
                return "none"
            if isinstance(stmt, IRSwitch):
                if _locals_in_expr(stmt.value) & {local}:
                    return "read"
                branches = [c.statements for c in stmt.cases.values()]
                branches.append(stmt.default.statements if stmt.default else [])
                results = [_first_use_in_list(b, local, _visited) for b in branches]
                if "read" in results:
                    return "read"
                if all(r == "kill" for r in results):
                    return "kill"
                return "none"
            if isinstance(stmt, IRExpression):
                return "read" if local in _locals_in_expr(stmt) else "none"
            # Loops, try/catch and anything else with nested blocks: any
            # occurrence at all is conservatively a read.
            if _reads_in_stmt(stmt) & {local}:
                return "read"
            for child in stmt.get_children():
                child_stmts = child.statements if isinstance(child, IRBlock) else [child]
                for s in child_stmts:
                    if _first_use(s, local, set()) != "none":
                        return "read"
            return "none"

        def _first_use_in_list(stmts: List[IRStatement], local: IRLocal, _visited: Set[int]) -> str:
            for s in stmts:
                r = _first_use(s, local, _visited)
                if r != "none":
                    return r
            return "none"

        user_names = self._collect_user_names()
        user_regs = self._collect_user_reg_indices()

        new_stmts = []
        for i, stmt in enumerate(block.statements):
            target = _written_local(stmt)
            if (
                target is not None
                and isinstance(stmt, IRAssign)
                and not _has_side_effects(stmt.expr)
                and _first_use_in_list(block.statements[i + 1 :], target, set()) == "kill"
                and not self._is_user_local(target, user_names, user_regs)
            ):
                if DEBUG:
                    dbg_print(f"IRDeadStoreEliminator: removing dead store {stmt}")
                continue
            new_stmts.append(stmt)

        block.statements = new_stmts
        for stmt in block.statements:
            for child in stmt.get_children():
                if isinstance(child, IRBlock):
                    self.visit_block(child)



    def _collect_user_names(self) -> Set[str]:
        names: Set[str] = set()
        if self.func.func.has_debug and self.func.func.assigns:
            for name_ref, _ in self.func.func.assigns:
                names.add(name_ref.resolve(self.func.code))
        return names

    def _collect_user_reg_indices(self) -> Set[int]:
        indices: Set[int] = set()
        if self.func.func.has_debug and self.func.func.assigns:
            for _, op_idx in self.func.func.assigns:
                val = op_idx.value - 1
                if val >= 0 and val < len(self.func.ops):
                    op = self.func.ops[val]
                    try:
                        indices.add(op.df["dst"].value)
                    except KeyError:
                        pass
        return indices

    def _is_user_local(self, local: IRLocal, user_names: Set[str], user_regs: Set[int]) -> bool:
        if local.name in user_names:
            return True
        for name in user_names:
            if local.name.startswith(name) and local.name[len(name):].isdigit():
                return True
        if local.name.startswith("var"):
            try:
                idx = int(local.name[3:])
                if idx in user_regs:
                    return True
            except ValueError:
                pass
        return False

class IRSequentialTempFolder(TraversingIROptimizer):
    """Folds a simple local assignment into the very next assignment to the same local.

    Patterns like `var1 = this.bytes; var1 = Native.f(var1, ...)` are simplified
    to `var1 = Native.f(this.bytes, ...)` and the first assignment is dropped.
    The source expression must be side-effect free and must not reference the
    target local.
    """

    def visit_block(self, block: IRBlock) -> None:
        changed = True
        while changed:
            changed = False
            i = 0
            while i < len(block.statements) - 1:
                stmt = block.statements[i]
                nxt = block.statements[i + 1]
                if not (
                    isinstance(stmt, IRAssign)
                    and isinstance(stmt.target, IRLocal)
                    and self._is_simple_expr(stmt.expr)
                    and not self._expr_uses_local(stmt.expr, stmt.target)
                    and isinstance(nxt, IRAssign)
                    and isinstance(nxt.target, IRLocal)
                    and nxt.target == stmt.target
                ):
                    i += 1
                    continue
                replaced = self._replace_local_in_expr(nxt.expr, stmt.target, stmt.expr)
                if not replaced:
                    # The next RHS may also use the local through its target (e.g. array index).
                    if isinstance(nxt.target, IRArrayAccess):
                        replaced |= self._replace_local_in_expr(nxt.target.array, stmt.target, stmt.expr)
                        replaced |= self._replace_local_in_expr(nxt.target.index, stmt.target, stmt.expr)
                    if not replaced:
                        i += 1
                        continue
                nxt.adopt(stmt)  # stmt is dropped, folded into nxt's RHS
                block.statements.pop(i)
                changed = True
        for stmt in block.statements:
            for child in stmt.get_children():
                if isinstance(child, IRBlock):
                    self.visit_block(child)

    def _is_simple_expr(self, expr: IRExpression) -> bool:
        if isinstance(expr, (IRCall, IRNew)):
            return False
        for child in expr.get_children():
            if isinstance(child, IRExpression) and not self._is_simple_expr(child):
                return False
        return True

    def _expr_uses_local(self, expr: IRExpression, local: IRLocal) -> bool:
        if expr == local:
            return True
        return any(
            self._expr_uses_local(child, local) for child in expr.get_children() if isinstance(child, IRExpression)
        )

    def _replace_local_in_expr(self, expr: IRExpression, local: IRLocal, replacement: IRExpression) -> bool:
        if expr == local:
            return True
        made_change = False
        # get_children returns a list of child statements/expressions.  We only
        # mutate expression children.
        children = expr.get_children()
        for i, child in enumerate(children):
            if not isinstance(child, IRExpression):
                continue
            if child == local:
                # Use the type-specific setter to keep the IR node intact.
                if self._set_child(expr, i, replacement):
                    made_change = True
                continue
            if self._replace_local_in_expr(child, local, replacement):
                made_change = True
        return made_change

    def _set_child(self, parent: IRExpression, index: int, value: IRExpression) -> bool:
        children = parent.get_children()
        if index >= len(children):
            return False
        child = children[index]
        if isinstance(parent, (IRArithmetic, IRBoolExpr)):
            if child is parent.left:
                parent.left = value
                return True
            if child is parent.right:
                parent.right = value
                return True
        elif isinstance(parent, IRCall):
            for j, arg in enumerate(parent.args):
                if arg is child:
                    parent.args[j] = value
                    return True
        elif isinstance(parent, IRField):
            if child is parent.target:
                parent.target = value
                return True
        elif isinstance(parent, IRCast):
            if child is parent.expr:
                parent.expr = value
                return True
        elif isinstance(parent, (IRNeg, IRNot, IRTypeOf, IRTypeKind, IREnumIndex)):
            attr = "expr" if hasattr(parent, "expr") else "value"
            if getattr(parent, attr) is child:
                setattr(parent, attr, value)
                return True
        elif isinstance(parent, IRArrayAccess):
            if child is parent.array:
                parent.array = value
                return True
            if child is parent.index:
                parent.index = value
                return True
        elif isinstance(parent, IREnumConstruct):
            for j, arg in enumerate(parent.args):
                if arg is child:
                    parent.args[j] = value
                    return True
        elif isinstance(parent, IREnumField):
            if child is parent.value:
                parent.value = value
                return True
        elif isinstance(parent, IRRef):
            if child is parent.target:
                parent.target = value
                return True
        elif isinstance(parent, IRArrayLiteral):
            for j, element in enumerate(parent.elements):
                if element is child:
                    parent.elements[j] = value
                    return True
        elif isinstance(parent, IRNativeArrayNew):
            if child is parent.size:
                parent.size = value
                return True
        elif isinstance(parent, IRNew):
            for j, arg in enumerate(parent.constructor_args):
                if arg is child:
                    parent.constructor_args[j] = value
                    return True
        return False


class IRDeadAssignmentEliminator(TraversingIROptimizer):
    """Removes assignments to locals that are never read before being redefined.

    Performs a structured backward liveness sweep keyed by local *name* (HL IR
    may split a single local into several objects).  Each block is processed
    with a live-out set so that assignments feeding into later statements,
    sibling branches, loop conditions, or code after a loop are never dropped.
    """

    def optimize(self) -> None:
        if not hasattr(self.func, "block"):
            return
        self._block_live: Dict[int, Tuple[Set[str], Set[str]]] = {}
        self._process_block(self.func.block, set())

    def _local_name(self, local: IRLocal) -> str:
        return local.name

    def _process_block(self, block: IRBlock, live_out: Set[str], mutate: bool = True) -> Set[str]:
        block_id = id(block)
        if mutate:
            cached = self._block_live.get(block_id)
            if cached is not None:
                cached_out, cached_in = cached
                if live_out.issubset(cached_out):
                    return cached_in
                live_out = cached_out | live_out

        live: Set[str] = set(live_out)
        new_stmts: List[IRStatement] = []

        for stmt in reversed(block.statements):
            uses, defs = self._stmt_uses_and_defs(stmt, live, mutate=mutate)
            if (
                mutate
                and isinstance(stmt, IRAssign)
                and isinstance(stmt.target, IRLocal)
                and self._local_name(stmt.target) not in live
            ):
                if self._is_user_local_name(self._local_name(stmt.target)):
                    # Preserve dead stores to user-named locals so the source
                    # round-trip stays faithful to the original bytecode.
                    new_stmts.append(stmt)
                elif self._has_side_effects(stmt.expr):
                    # Keep the side effects as a bare expression statement.
                    stmt.expr.adopt(stmt)  # opcode was tagged on the assign, not its expr
                    new_stmts.append(stmt.expr)
                # else: drop the dead assignment entirely for compiler temps.
                # For kept statements, still update liveness; dropped ones don't.
                live.difference_update(defs)
                live.update(uses)
                continue
            if mutate:
                new_stmts.append(stmt)
            live.difference_update(defs)
            live.update(uses)

        if mutate:
            block.statements = list(reversed(new_stmts))
            self._block_live[block_id] = (live_out, live)
        return live

    def _stmt_uses_and_defs(
        self, stmt: IRStatement, live_after_stmt: Set[str], mutate: bool = True
    ) -> Tuple[Set[str], Set[str]]:
        uses: Set[str] = set()
        defs: Set[str] = set()

        if isinstance(stmt, IRAssign):
            uses.update(self._locals_in_expr(stmt.expr))
            if isinstance(stmt.target, IRArrayAccess):
                uses.update(self._locals_in_expr(stmt.target.array))
                uses.update(self._locals_in_expr(stmt.target.index))
            elif isinstance(stmt.target, IRField):
                uses.update(self._locals_in_expr(stmt.target.target))
            elif isinstance(stmt.target, IRLocal):
                defs.add(self._local_name(stmt.target))
        elif isinstance(stmt, (IRReturn, IRThrow)) and stmt.value is not None:
            uses.update(self._locals_in_expr(stmt.value))
        elif isinstance(stmt, IRCall):
            if stmt.target is not None:
                uses.update(self._locals_in_expr(stmt.target))
            for arg in stmt.args:
                uses.update(self._locals_in_expr(arg))
        elif isinstance(stmt, IRTrace):
            uses.update(self._locals_in_expr(stmt.msg))
        elif isinstance(stmt, (IRConditional, IRWhileLoop)):
            uses.update(self._locals_in_expr(stmt.condition))
        elif isinstance(stmt, IRSwitch):
            uses.update(self._locals_in_expr(stmt.value))
        else:
            # Generic fallback (e.g. IRRefSet): expression children are reads.
            for child in stmt.get_children():
                if isinstance(child, IRExpression):
                    uses.update(self._locals_in_expr(child))

        # Recursively process nested blocks with the correct live-out sets.
        if isinstance(stmt, IRConditional):
            child_out = set(live_after_stmt)
            true_in = self._process_block(stmt.true_block, child_out, mutate=mutate) if stmt.true_block else set()
            false_in = self._process_block(stmt.false_block, child_out, mutate=mutate) if stmt.false_block else set()
            uses.update(true_in)
            uses.update(false_in)
        elif isinstance(stmt, IRWhileLoop):
            body_in = self._process_loop_body(
                stmt.body, live_after_stmt, self._locals_in_expr(stmt.condition), mutate=mutate
            )
            uses.update(body_in)
        elif isinstance(stmt, IRPrimitiveLoop):
            cond_uses: Set[str] = set()
            body_in = self._process_loop_body(stmt.body, live_after_stmt, cond_uses, mutate=mutate)
            uses.update(body_in)
            uses.update(cond_uses)
        elif isinstance(stmt, IRForEachLoop):
            array_uses = self._locals_in_expr(stmt.array) if hasattr(stmt, "array") else set()
            body_in = self._process_loop_body(stmt.body, live_after_stmt, array_uses, mutate=mutate)
            uses.update(body_in)
            uses.update(array_uses)
        elif isinstance(stmt, IRIntRangeLoop):
            header_uses = self._locals_in_expr(stmt.start) | self._locals_in_expr(stmt.end)
            body_in = self._process_loop_body(stmt.body, live_after_stmt, header_uses, mutate=mutate)
            uses.update(body_in)
            uses.update(header_uses)
        elif isinstance(stmt, IRSwitch):
            child_out = set(live_after_stmt)
            for case_block in stmt.cases.values():
                uses.update(self._process_block(case_block, child_out, mutate=mutate))
            if stmt.default is not None:
                uses.update(self._process_block(stmt.default, child_out, mutate=mutate))
        elif isinstance(stmt, IRTryCatch):
            child_out = set(live_after_stmt)
            try_in = self._process_block(stmt.try_block, child_out, mutate=mutate)
            catch_in = self._process_block(stmt.catch_block, child_out, mutate=mutate)
            uses.update(try_in)
            uses.update(catch_in)

        return uses, defs

    def _process_loop_body(
        self, body: IRBlock, live_after: Set[str], header_uses: Set[str], mutate: bool = True
    ) -> Set[str]:
        """Process a loop body to a fixed point so loop-carried assignments live.

        We must not mutate ``body`` until the live-in set stabilises, because the
        first backward pass would otherwise drop loop-carried assignments whose
        uses appear earlier in the source order (later in reverse).
        """
        if not mutate:
            return self._compute_block_live_in(body, live_after | header_uses)

        child_out = live_after | header_uses
        while True:
            body_in = self._compute_block_live_in(body, child_out)
            next_out = live_after | header_uses | body_in
            if next_out == child_out:
                break
            child_out = next_out
        return self._process_block(body, child_out)

    def _compute_block_live_in(self, block: IRBlock, live_out: Set[str]) -> Set[str]:
        """Return the live-in set for ``block`` without mutating it."""
        live: Set[str] = set(live_out)
        for stmt in reversed(block.statements):
            uses, defs = self._stmt_uses_and_defs(stmt, live, mutate=False)
            live.difference_update(defs)
            live.update(uses)
        return live

    def _is_user_local_name(self, name: str) -> bool:
        if not self.func.func.has_debug or not self.func.func.assigns:
            return False
        user_names = {name_ref.resolve(self.func.code) for name_ref, _ in self.func.func.assigns}
        if name in user_names:
            return True
        for un in user_names:
            if name.startswith(un) and name[len(un):].isdigit():
                return True
        return False

    def _locals_in_expr(self, expr: Optional[IRExpression]) -> Set[str]:
        found: Set[str] = set()
        if expr is None:
            return found
        if isinstance(expr, IRLocal):
            found.add(self._local_name(expr))
        elif isinstance(expr, (IRArithmetic, IRBoolExpr)):
            found.update(self._locals_in_expr(expr.left))
            found.update(self._locals_in_expr(expr.right))
        elif isinstance(expr, IRArrayAccess):
            found.update(self._locals_in_expr(expr.array))
            found.update(self._locals_in_expr(expr.index))
        elif isinstance(expr, (IRField, IRCast, IRNeg, IRNot, IRTypeOf, IRTypeKind, IREnumIndex)):
            target = getattr(expr, "target", getattr(expr, "expr", getattr(expr, "value", None)))
            found.update(self._locals_in_expr(target))
        elif isinstance(expr, IRCall):
            if expr.target is not None:
                found.update(self._locals_in_expr(expr.target))
            for arg in expr.args:
                found.update(self._locals_in_expr(arg))
        elif isinstance(expr, IRNew):
            for arg in expr.constructor_args:
                found.update(self._locals_in_expr(arg))
        elif isinstance(expr, IRArrayLiteral):
            for element in expr.elements:
                found.update(self._locals_in_expr(element))
        elif isinstance(expr, IREnumConstruct):
            for arg in expr.args:
                found.update(self._locals_in_expr(arg))
        elif isinstance(expr, IREnumField):
            found.update(self._locals_in_expr(expr.value))
        elif isinstance(expr, IRRef):
            found.update(self._locals_in_expr(expr.target))
        elif isinstance(expr, IRRefNew):
            found.update(self._locals_in_expr(expr.target))
        else:
            # Generic fallback (e.g. IRNativeArrayNew, IRRefGet): a missing case
            # here must not hide a read and let a live assignment be dropped.
            for child in expr.get_children():
                if isinstance(child, IRExpression):
                    found.update(self._locals_in_expr(child))
        return found

    def _has_side_effects(self, expr: Optional[IRExpression]) -> bool:
        if expr is None:
            return False
        if isinstance(expr, IRNew):
            return True
        if isinstance(expr, IRCall):
            # Keep side effects for calls whose result is discarded.  Pure-ish
            # stdlib helpers (String.substr, indexOf, etc.) can be dropped safely.
            return not self._is_pure_call(expr)
        if isinstance(expr, IREnumConstruct):
            return any(self._has_side_effects(arg) for arg in expr.args)
        if isinstance(expr, (IRArithmetic, IRBoolExpr)):
            return self._has_side_effects(expr.left) or self._has_side_effects(expr.right)
        if isinstance(expr, (IRField, IRCast, IRNeg, IRNot, IRTypeOf, IRTypeKind, IREnumIndex)):
            target = getattr(expr, "target", getattr(expr, "expr", getattr(expr, "value", None)))
            return self._has_side_effects(target)
        if isinstance(expr, IRArrayAccess):
            return self._has_side_effects(expr.array) or self._has_side_effects(expr.index)
        if isinstance(expr, IRArrayLiteral):
            return any(self._has_side_effects(e) for e in expr.elements)
        if isinstance(expr, IREnumField):
            return self._has_side_effects(expr.value)
        if isinstance(expr, IRRef):
            return self._has_side_effects(expr.target)
        return False

    def _is_pure_call(self, call: IRCall) -> bool:
        """True for calls that are safe to drop when their result is unused."""
        target = call.target
        if not isinstance(target, IRConst) or not isinstance(target.value, Function):
            return False
        code = self.func.code
        name = code.full_func_name(target.value) or code.partial_func_name(target.value) or ""
        # Array read-only inspectors.
        if any(s in name for s in ("ArrayAccess.getDyn", "ArrayAccess.get_length", "ArrayBase.indexOf")):
            return True
        # String read-only inspectors / factories whose result is unused.
        if any(
            s in name
            for s in (
                "String.substr",
                "String.substring",
                "String.charAt",
                "String.charCodeAt",
                "String.indexOf",
                "String.lastIndexOf",
                "String.findChar",
                "String.toUpperCase",
                "String.toLowerCase",
                "String.toString",
                "String.__alloc__",
                "$String.__alloc__",
            )
        ):
            return True
        # Byte/string comparison/search helpers.
        if any(s in name for s in ("bytes_find", "bytes_compare", "ucs2_length", "ucs2_upper", "ucs2_lower")):
            return True
        return False


class IRConstructorFolder(TraversingIROptimizer):
    """Folds `new X; __constructor__(x, args...)` into `new X(args...)`."""

    TARGET_OPCODES = {"New"}

    def visit_block(self, block: IRBlock) -> None:
        made_change = True
        while made_change:
            made_change = False
            new_statements: List[IRStatement] = []
            i = 0
            while i < len(block.statements):
                stmt = block.statements[i]
                if (
                    isinstance(stmt, IRAssign)
                    and isinstance(stmt.target, IRLocal)
                    and isinstance(stmt.expr, IRNew)
                    and not stmt.expr.constructor_args
                ):
                    folded = False
                    for j in range(i + 1, len(block.statements)):
                        next_stmt = block.statements[j]
                        ctor_args = self._match_constructor_call(next_stmt, stmt.target)
                        if ctor_args is not None:
                            # Keep any statements between the allocation and the
                            # constructor call (e.g. initializers for constructor
                            # arguments), and place the folded `new` after them.
                            stmt.expr.constructor_args = ctor_args
                            stmt.adopt(next_stmt)  # constructor-call opcode is dropped below
                            new_statements.extend(block.statements[i + 1 : j])
                            new_statements.append(stmt)
                            i = j + 1
                            made_change = True
                            folded = True
                            break
                        # We can only fold across statements that don't touch the
                        # freshly allocated instance.
                        if self._statement_uses_local(next_stmt, stmt.target):
                            break
                    if folded:
                        continue
                new_statements.append(stmt)
                i += 1
            block.statements = new_statements
        for stmt in block.statements:
            for child in stmt.get_children():
                if isinstance(child, IRBlock):
                    self.visit_block(child)

    def _match_constructor_call(self, stmt: IRStatement, instance_local: IRLocal) -> Optional[List[IRExpression]]:
        if not isinstance(stmt, IRCall):
            return None
        if stmt.call_type != IRCall.CallType.FUNC:
            return None
        if not stmt.args:
            return None
        first_arg = stmt.args[0]
        if not (isinstance(first_arg, IRLocal) and first_arg == instance_local):
            return None
        fun_const = stmt.target
        if not isinstance(fun_const, IRConst):
            return None
        if not isinstance(fun_const.value, Function):
            return None
        func_name = self.func.code.partial_func_name(fun_const.value)
        if func_name and "__constructor__" in func_name:
            return list(stmt.args[1:])
        return None

    def _statement_uses_local(self, stmt: IRStatement, local: IRLocal) -> bool:
        """Return True if stmt reads or writes the given local."""
        if isinstance(stmt, IRAssign):
            if stmt.target == local:
                return True
            return self._expr_uses_local(stmt.expr, local)
        if isinstance(stmt, IRExpression):
            return self._expr_uses_local(stmt, local)
        if isinstance(stmt, IRReturn):
            return stmt.value is not None and self._expr_uses_local(stmt.value, local)
        return False

    def _expr_uses_local(self, expr: IRStatement, local: IRLocal) -> bool:
        if expr == local:
            return True
        return any(self._expr_uses_local(child, local) for child in expr.get_children())


class IRAnonObjectLiteralOptimizer(TraversingIROptimizer):
    """
    Folds `temp = {}; temp.f1 = e1; temp.f2 = e2; ...; use(temp)` into
    `use({f1: e1, f2: e2, ...})`, wherever the anonymous object has exactly
    one further reference and it's the very next statement.

    HashLink lowers every Haxe anonymous-object literal to a `{}` allocation
    followed by one field-assignment per key. `IRTraceOptimizer` already
    special-cases this for `trace()`'s implicit position argument; this pass
    generalizes it to any consumer — most notably the same `?pos:haxe.
    PosInfos` argument the compiler silently attaches to any function that
    declares one (e.g. every `haxe.PosException` subclass constructor),
    which otherwise bloats a two-line `throw new SomeException();` into six
    lines of DynObj scaffolding.
    """

    TARGET_OPCODES = {"New"}

    def visit_block(self, block: IRBlock) -> None:
        made_change = True
        while made_change:
            made_change = False
            new_statements: List[IRStatement] = []
            i = 0
            while i < len(block.statements):
                match = self._try_fold(block.statements, i)
                if match is not None:
                    consumer, consumed = match
                    new_statements.append(consumer)
                    i += consumed
                    made_change = True
                    continue
                new_statements.append(block.statements[i])
                i += 1
            block.statements = new_statements
        for stmt in block.statements:
            for child in stmt.get_children():
                if isinstance(child, IRBlock):
                    self.visit_block(child)

    def _try_fold(self, stmts: List[IRStatement], start: int) -> Optional[Tuple[IRStatement, int]]:
        stmt = stmts[start]
        if not isinstance(stmt, IRAssign) or not isinstance(stmt.target, IRLocal):
            return None
        if not isinstance(stmt.expr, IRNew) or stmt.expr.constructor_args:
            return None
        # Anonymous-object allocations show up as either a generic DynObj or,
        # when the compiler can infer the exact field set statically (as it
        # always can for the fixed fileName/lineNumber/className/methodName
        # shape of `?pos:haxe.PosInfos`), a structural Virtual type. A real
        # `new SomeClass()` allocation is always an Obj, never either of these.
        alloc_defn = stmt.expr.get_type().definition
        if not isinstance(alloc_defn, (DynObj, Virtual)):
            return None
        temp = stmt.target

        fields: List[Tuple[str, IRExpression]] = []
        j = start + 1
        while j < len(stmts):
            s = stmts[j]
            if (
                isinstance(s, IRAssign)
                and isinstance(s.target, IRField)
                and s.target.target == temp
                and isinstance(s.expr, IRExpression)
                and not self._expr_uses_local(s.expr, temp)
            ):
                fields.append((s.target.field_name, s.expr))
                j += 1
                continue
            break

        if not fields or j >= len(stmts):
            return None

        use_stmt = stmts[j]
        if self._count_local_refs(use_stmt, temp) != 1:
            return None
        for later in stmts[j + 1 :]:
            if self._stmt_uses_local(later, temp):
                return None

        literal = IRObjectLiteral(self.func.code, fields)
        if not self._substitute_use(use_stmt, temp, literal):
            return None
        use_stmt.adopt(*stmts[start:j])  # the alloc + field-assign statements are dropped
        return use_stmt, j - start + 1

    def _substitute_use(self, stmt: IRStatement, local: IRLocal, replacement: IRExpression) -> bool:
        if isinstance(stmt, IRAssign):
            changed = False
            if stmt.expr == local:
                stmt.expr = replacement
                changed = True
            elif isinstance(stmt.expr, IRExpression) and self._replace_in_expr(stmt.expr, local, replacement):
                changed = True
            if isinstance(stmt.target, IRExpression) and stmt.target != local:
                if self._replace_in_expr(stmt.target, local, replacement):
                    changed = True
            return changed
        if isinstance(stmt, (IRReturn, IRThrow)):
            if stmt.value == local:
                stmt.value = replacement
                return True
            if stmt.value is not None:
                return self._replace_in_expr(stmt.value, local, replacement)
            return False
        if isinstance(stmt, IRExpression):
            return self._replace_in_expr(stmt, local, replacement)
        return False

    def _replace_in_expr(self, expr: IRExpression, local: IRLocal, replacement: IRExpression) -> bool:
        made_change = False
        for i, child in enumerate(expr.get_children()):
            if not isinstance(child, IRExpression):
                continue
            if child == local:
                if self._set_child(expr, i, replacement):
                    made_change = True
                continue
            if self._replace_in_expr(child, local, replacement):
                made_change = True
        return made_change

    def _set_child(self, parent: IRExpression, index: int, value: IRExpression) -> bool:
        children = parent.get_children()
        if index >= len(children):
            return False
        child = children[index]
        if isinstance(parent, (IRArithmetic, IRBoolExpr)):
            if child is parent.left:
                parent.left = value
                return True
            if child is parent.right:
                parent.right = value
                return True
        elif isinstance(parent, IRCall):
            if parent.target is child:
                parent.target = cast(Any, value)
                return True
            for j, arg in enumerate(parent.args):
                if arg is child:
                    parent.args[j] = value
                    return True
        elif isinstance(parent, IRField):
            if child is parent.target:
                parent.target = value
                return True
        elif isinstance(parent, IRCast):
            if child is parent.expr:
                parent.expr = value
                return True
        elif isinstance(parent, IRArrayAccess):
            if child is parent.array:
                parent.array = value
                return True
            if child is parent.index:
                parent.index = value
                return True
        elif isinstance(parent, IRNew):
            for j, arg in enumerate(parent.constructor_args):
                if arg is child:
                    parent.constructor_args[j] = value
                    return True
        elif isinstance(parent, IREnumConstruct):
            for j, arg in enumerate(parent.args):
                if arg is child:
                    parent.args[j] = value
                    return True
        elif isinstance(parent, IREnumField):
            if child is parent.value:
                parent.value = value
                return True
        elif isinstance(parent, IRArrayLiteral):
            for j, element in enumerate(parent.elements):
                if element is child:
                    parent.elements[j] = value
                    return True
        elif isinstance(parent, IRRef):
            if child is parent.target:
                parent.target = value
                return True
        return False

    def _count_local_refs(self, stmt: IRStatement, local: IRLocal) -> int:
        if stmt == local:
            return 1
        return sum(self._count_local_refs(child, local) for child in stmt.get_children())

    def _stmt_uses_local(self, stmt: IRStatement, local: IRLocal) -> bool:
        return self._count_local_refs(stmt, local) > 0

    def _expr_uses_local(self, expr: IRExpression, local: IRLocal) -> bool:
        return self._count_local_refs(expr, local) > 0


class IRShiftConstantOptimizer(TraversingIROptimizer):
    """
    Replaces shift-amount locals with their constant values when the local is
    assigned a constant and not yet redefined. This cleans up bytecode patterns
    like `var n = 1; x = y << n` without the broader risks of full copy
    propagation.
    """

    def _replace_shift_const(self, expr: IRExpression, const_map: Dict[IRLocal, IRConst]) -> bool:
        if isinstance(expr, IRArithmetic) and expr.op.value in ("<<", ">>", ">>>"):
            if isinstance(expr.right, IRLocal) and expr.right in const_map:
                expr.right = const_map[expr.right]
                return True
        made_change = False
        if isinstance(expr, (IRArithmetic, IRBoolExpr)):
            if expr.left is not None and self._replace_shift_const(expr.left, const_map):
                made_change = True
            if expr.right is not None and self._replace_shift_const(expr.right, const_map):
                made_change = True
        elif isinstance(expr, IRCall):
            if expr.target is not None and self._replace_shift_const(expr.target, const_map):
                made_change = True
            for arg in expr.args:
                if self._replace_shift_const(arg, const_map):
                    made_change = True
        elif isinstance(expr, IRCast):
            if self._replace_shift_const(expr.expr, const_map):
                made_change = True
        elif isinstance(expr, IRField):
            if self._replace_shift_const(expr.target, const_map):
                made_change = True
        elif isinstance(expr, IRArrayAccess):
            if self._replace_shift_const(expr.array, const_map):
                made_change = True
            if self._replace_shift_const(expr.index, const_map):
                made_change = True
        return made_change

    def _apply_to_statement(self, stmt: IRStatement, const_map: Dict[IRLocal, IRConst]) -> None:
        if isinstance(stmt, IRAssign):
            self._replace_shift_const(stmt.expr, const_map)
        elif isinstance(stmt, IRReturn):
            if stmt.value is not None:
                self._replace_shift_const(stmt.value, const_map)
        elif isinstance(stmt, IRConditional):
            self._replace_shift_const(stmt.condition, const_map)
        elif isinstance(stmt, IRPrimitiveJump):
            for attr in ("left", "right", "cond"):
                val = getattr(stmt, attr, None)
                if val is not None:
                    self._replace_shift_const(val, const_map)
        elif isinstance(stmt, IRSwitch):
            self._replace_shift_const(stmt.value, const_map)

    def visit_block(self, block: IRBlock) -> None:
        const_map: Dict[IRLocal, IRConst] = {}
        for stmt in block.statements:
            # Apply current constant mappings before updating them, so the
            # definition site itself is not rewritten.
            self._apply_to_statement(stmt, const_map)

            if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal):
                target_local = stmt.target
                const_map.pop(target_local, None)
                # Only substitute compiler-generated temporaries (`varN`):
                # user-named shift-amount variables (e.g. `x << n`) are
                # meaningful source identifiers and substituting their value
                # in destroys the symbolic shift the user actually wrote,
                # even though the bytecode result is equivalent.
                if isinstance(stmt.expr, IRConst) and re.fullmatch(r"var\d+", target_local.name):
                    const_map[target_local] = stmt.expr


class IRGuardOrMerger(TraversingIROptimizer):
    """Merge `if (A) { T } else { if (B) { T } else { W } } }` into a single
    `if (A || B) { T } else { W }` when both `T` branches perform the exact
    same action.

    This is the inverse of how Haxe's `||`/`&&` short-circuiting lowers to
    bytecode: `if (A || B) X; else Y;` compiles to a nested guard where the
    "taken" branch is reachable from two jump targets. Without this merge,
    the decompiled source duplicates the action under two separate branches,
    which recompiles to different (larger) bytecode than the original.
    """

    def visit_block(self, block: IRBlock) -> None:
        new_statements: List[IRStatement] = []
        i = 0
        stmts = block.statements
        while i < len(stmts):
            stmt = stmts[i]
            if isinstance(stmt, IRConditional):
                merged = self._try_merge_else(stmt)
                if merged is not None:
                    new_statements.append(merged)
                    i += 1
                    continue
                merged2 = self._try_merge_sibling(stmt, stmts[i + 1 :])
                if merged2 is not None:
                    new_cond, consumed_siblings = merged2
                    new_statements.append(new_cond)
                    i += 1 + consumed_siblings
                    continue
                merged3 = self._try_merge_sibling_and(stmt, stmts[i + 1 :])
                if merged3 is not None:
                    new_cond, consumed_siblings = merged3
                    new_statements.append(new_cond)
                    i += 1 + consumed_siblings
                    continue
            new_statements.append(stmt)
            i += 1
        block.statements = new_statements

    def _try_merge_else(self, stmt: IRConditional) -> Optional[IRConditional]:
        """if (A) { T } else { if (B) { T } else { W } } -> if (A || B) { T } else { W }"""
        outer_true = stmt.true_block.statements
        false_stmts = stmt.false_block.statements
        if not outer_true or len(false_stmts) != 1:
            return None
        inner = false_stmts[0]
        if not isinstance(inner, IRConditional):
            return None
        if _stmt_lists_structurally_equal(outer_true, inner.true_block.statements):
            or_cond = IRBoolExpr(self.func.code, IRBoolExpr.CompareType.OR, stmt.condition, inner.condition)
            merged = IRConditional(self.func.code, or_cond, inner.true_block, inner.false_block)
            merged.adopt(stmt, inner)
            return merged
        return None

    def _try_merge_sibling(
        self, stmt: IRConditional, following: List[IRStatement]
    ) -> Optional[Tuple[IRConditional, int]]:
        """if (A) { if (B) { T } REST } (empty else), followed in the parent
        block by T as the fallthrough-when-!A path -> if (!A || B) { T } { REST },
        consuming T's statements from the parent block."""
        outer_true = stmt.true_block.statements
        if stmt.false_block.statements or not outer_true:
            return None
        inner = outer_true[0]
        if not isinstance(inner, IRConditional) or inner.false_block.statements:
            return None
        inner_true = inner.true_block.statements
        if not inner_true or len(following) < len(inner_true):
            return None
        if not _stmt_lists_structurally_equal(inner_true, following[: len(inner_true)]):
            return None
        not_a = self._invert(stmt.condition)
        or_cond = IRBoolExpr(self.func.code, IRBoolExpr.CompareType.OR, not_a, inner.condition)
        rest_block = IRBlock(self.func.code)
        rest_block.statements = outer_true[1:]
        merged = IRConditional(self.func.code, or_cond, inner.true_block, rest_block)
        # The consumed parent-block siblings duplicate inner_true's *content*
        # (that's the merge precondition) but are distinct compiled copies with
        # their own opcodes, same as stmt/inner themselves being replaced.
        merged.adopt(stmt, inner, *following[: len(inner_true)])
        return merged, len(inner_true)

    def _try_merge_sibling_and(
        self, stmt: IRConditional, following: List[IRStatement]
    ) -> Optional[Tuple[IRConditional, int]]:
        """if (A) { if (B) { X } else { Y } TAIL } (empty else), followed in
        the parent block by Y then TAIL again (the fallthrough-when-!A path
        repeats the else-action and shared tail-code) -> if (A && B) { X }
        else { Y } TAIL, consuming Y+TAIL's statements from the parent block.
        """
        outer_true = stmt.true_block.statements
        if stmt.false_block.statements or not outer_true:
            return None
        inner = outer_true[0]
        if not isinstance(inner, IRConditional) or not inner.false_block.statements:
            return None
        tail = outer_true[1:]
        inner_false = inner.false_block.statements
        wanted = inner_false + tail
        if not wanted or len(following) < len(wanted):
            return None
        if not _stmt_lists_structurally_equal(wanted, following[: len(wanted)]):
            return None
        and_cond = IRBoolExpr(self.func.code, IRBoolExpr.CompareType.AND, stmt.condition, inner.condition)
        merged = IRConditional(self.func.code, and_cond, inner.true_block, inner.false_block)
        merged.adopt(stmt, inner, *following[: len(wanted)])
        return merged, len(inner_false)

    def _invert(self, cond: IRExpression) -> IRExpression:
        """Return a negated copy of a boolean expression. Flips simple
        comparisons (>= becomes <, etc.) in place on a shallow copy rather
        than wrapping with a unary NOT, which existing code doesn't expect
        to need parenthesizing."""
        if isinstance(cond, IRBoolExpr) and cond.op not in (
            IRBoolExpr.CompareType.OR,
            IRBoolExpr.CompareType.AND,
            IRBoolExpr.CompareType.NOT,
        ):
            inverted = copy.copy(cond)
            try:
                inverted.invert()
                return inverted
            except DecompError:
                pass
        return IRBoolExpr(self.func.code, IRBoolExpr.CompareType.NOT, cond)
