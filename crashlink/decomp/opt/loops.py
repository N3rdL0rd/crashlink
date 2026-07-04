"""
Loop-reroll and loop-lifting optimizers.
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


class IRLoopRerollOptimizer(TraversingIROptimizer):
    """
    Recover Haxe for-each loops from bytecode that the compiler unrolled.

    This is intentionally conservative: it only matches consecutive iterations of
    the form::

        elem = c0
        <body using elem>
        elem = c1
        <identical body using elem>
        ...

    where c0, c1, ... are consecutive integers.  The matched run is replaced
    with `for (elem in [c0, c1, ...]) { body }`.
    """

    def visit_block(self, block: IRBlock) -> None:
        if not block.statements:
            return
        new_statements: List[IRStatement] = []
        i = 0
        while i < len(block.statements):
            reroll = self._try_reroll(block.statements, i)
            if reroll is not None:
                loop, consumed = reroll
                new_statements.append(loop)
                i += consumed
                continue
            new_statements.append(block.statements[i])
            i += 1
        block.statements = new_statements

    def _try_reroll(self, stmts: List[IRStatement], start: int) -> Optional[Tuple[IRForEachLoop, int]]:
        header = self._header_assign(stmts[start])
        if header is None:
            return None
        elem_local, start_value = header

        # Find the second iteration header so we can determine the body length.
        h1 = self._find_next_header(stmts, start + 1, elem_local, start_value + 1)
        if h1 is None:
            return None

        body = stmts[start + 1 : h1]
        if not body:
            return None
        if not self._body_is_simple(body, elem_local):
            return None

        body_len = len(body)
        headers = [start, h1]
        # Expect further headers at regular intervals with consecutive constants.
        while True:
            expected_idx = headers[-1] + 1 + body_len
            expected_value = start_value + len(headers)
            if expected_idx >= len(stmts):
                break
            if not self._is_header(stmts[expected_idx], elem_local, expected_value):
                break
            next_body = stmts[headers[-1] + 1 : expected_idx]
            if not self._bodies_equal(body, next_body):
                break
            headers.append(expected_idx)

        if len(headers) < 2:
            return None

        last_header = headers[-1]
        run_end = last_header + 1 + body_len
        # Verify the final body segment too (it may not have a trailing header).
        final_body = stmts[last_header + 1 : run_end]
        if len(final_body) != body_len or not self._bodies_equal(body, final_body):
            return None

        values: List[IRExpression] = [
            IRConst(self.func.code, IRConst.ConstType.INT, value=start_value + k) for k in range(len(headers))
        ]
        array_literal = IRArrayLiteral(self.func.code, values)
        new_body = IRBlock(self.func.code)
        new_body.statements = list(body)
        loop = IRForEachLoop(self.func.code, elem_local, array_literal, new_body)
        # Only the first iteration's header+body statements survive as objects
        # (reused for new_body above, keeping their own src_op_idxs intact);
        # every other iteration's header/body copy is discarded here, so adopt
        # those onto the loop itself rather than double-claiming the first one's.
        loop.adopt(stmts[start], *stmts[h1:run_end])
        return loop, run_end - start

    def _header_assign(self, stmt: IRStatement) -> Optional[Tuple[IRLocal, int]]:
        if not isinstance(stmt, IRAssign) or not isinstance(stmt.target, IRLocal):
            return None
        expr = stmt.expr
        if isinstance(expr, IRCast):
            expr = expr.expr
        if not isinstance(expr, IRConst) or expr.const_type != IRConst.ConstType.INT:
            return None
        value = _int_const_value(expr)
        if value is None:
            return None
        return stmt.target, value

    def _is_header(self, stmt: IRStatement, elem: IRLocal, value: int) -> bool:
        header = self._header_assign(stmt)
        if header is None:
            return False
        return header[0] == elem and header[1] == value

    def _find_next_header(self, stmts: List[IRStatement], start: int, elem: IRLocal, value: int) -> Optional[int]:
        for i in range(start, len(stmts)):
            if self._is_header(stmts[i], elem, value):
                return i
        return None

    def _body_is_simple(self, body: List[IRStatement], elem: IRLocal) -> bool:
        # Conservative: only allow assignments and expression statements; no
        # nested control flow. Also require the body to actually use the element.
        uses_elem = False
        for stmt in body:
            if isinstance(stmt, IRAssign):
                if isinstance(stmt.target, IRLocal) and stmt.target == elem:
                    return False
                if self._expr_reads_local(stmt.expr, elem):
                    uses_elem = True
                if isinstance(stmt.target, IRArrayAccess):
                    if self._expr_reads_local(stmt.target.array, elem) or self._expr_reads_local(
                        stmt.target.index, elem
                    ):
                        uses_elem = True
            elif isinstance(stmt, (IRTrace, IRCall, IRReturn)):
                if self._expr_reads_local(
                    stmt.msg
                    if isinstance(stmt, IRTrace)
                    else stmt.value
                    if isinstance(stmt, IRReturn)
                    else stmt.target,
                    elem,
                ):
                    uses_elem = True
                for arg in getattr(stmt, "args", []):
                    if self._expr_reads_local(arg, elem):
                        uses_elem = True
            else:
                return False
        return uses_elem

    def _bodies_equal(self, a: List[IRStatement], b: List[IRStatement]) -> bool:
        if len(a) != len(b):
            return False
        for s1, s2 in zip(a, b):
            if not self._stmts_equal(s1, s2):
                return False
        return True

    def _stmts_equal(self, a: IRStatement, b: IRStatement) -> bool:
        if type(a) is not type(b):
            return False
        if isinstance(a, IRAssign) and isinstance(b, IRAssign):
            return self._exprs_equal(a.target, b.target) and self._exprs_equal(a.expr, b.expr)
        if isinstance(a, IRTrace) and isinstance(b, IRTrace):
            return self._exprs_equal(a.msg, b.msg)
        if isinstance(a, IRReturn) and isinstance(b, IRReturn):
            return self._exprs_equal(a.value, b.value)
        if isinstance(a, IRCall) and isinstance(b, IRCall):
            return (
                self._exprs_equal(a.target, b.target)
                and len(a.args) == len(b.args)
                and all(self._exprs_equal(x, y) for x, y in zip(a.args, b.args))
            )
        return False

    def _exprs_equal(self, a: Optional[IRExpression], b: Optional[IRExpression]) -> bool:
        if a is None or b is None:
            return a is b
        if type(a) is not type(b):
            return False
        if isinstance(a, IRConst) and isinstance(b, IRConst):
            return a.const_type == b.const_type and a.value == b.value
        if isinstance(a, IRLocal) and isinstance(b, IRLocal):
            return a == b
        if isinstance(a, (IRArithmetic, IRBoolExpr)) and isinstance(b, (IRArithmetic, IRBoolExpr)):
            return a.op == b.op and self._exprs_equal(a.left, b.left) and self._exprs_equal(a.right, b.right)
        if isinstance(a, IRArrayAccess) and isinstance(b, IRArrayAccess):
            return self._exprs_equal(a.array, b.array) and self._exprs_equal(a.index, b.index)
        if isinstance(a, IRField) and isinstance(b, IRField):
            return a.field_name == b.field_name and self._exprs_equal(a.target, b.target)
        if isinstance(a, IRCast) and isinstance(b, IRCast):
            return self._exprs_equal(a.expr, b.expr)
        if isinstance(a, IRCall) and isinstance(b, IRCall):
            return (
                self._exprs_equal(a.target, b.target)
                and len(a.args) == len(b.args)
                and all(self._exprs_equal(x, y) for x, y in zip(a.args, b.args))
            )
        if isinstance(a, IRNew) and isinstance(b, IRNew):
            return (
                a.alloc_type_idx == b.alloc_type_idx
                and len(a.constructor_args) == len(b.constructor_args)
                and all(self._exprs_equal(x, y) for x, y in zip(a.constructor_args, b.constructor_args))
            )
        if isinstance(a, IRRef) and isinstance(b, IRRef):
            return self._exprs_equal(a.target, b.target)
        return False

    def _expr_reads_local(self, expr: Optional[IRExpression], local: IRLocal) -> bool:
        if expr is None:
            return False
        if expr == local:
            return True
        if isinstance(expr, (IRArithmetic, IRBoolExpr)):
            return self._expr_reads_local(expr.left, local) or self._expr_reads_local(expr.right, local)
        if isinstance(expr, IRCall):
            if self._expr_reads_local(expr.target, local):
                return True
            return any(self._expr_reads_local(arg, local) for arg in expr.args)
        if isinstance(expr, IRField):
            return self._expr_reads_local(expr.target, local)
        if isinstance(expr, IRCast):
            return self._expr_reads_local(expr.expr, local)
        if isinstance(expr, IRArrayAccess):
            return self._expr_reads_local(expr.array, local) or self._expr_reads_local(expr.index, local)
        if isinstance(expr, IRArrayLiteral):
            return any(self._expr_reads_local(e, local) for e in expr.elements)
        if isinstance(expr, IRNew):
            return any(self._expr_reads_local(arg, local) for arg in expr.constructor_args)
        if isinstance(expr, IRRef):
            return self._expr_reads_local(expr.target, local)
        return False


class IRForEachLoopOptimizer(TraversingIROptimizer):
    """
    Recover Haxe for-each loops from the manual index-while lowering.

    HashLink compiles `for (elem in array) { body }` as:
        idx = 0
        while (idx < array.length) {
            elem = array[idx]
            idx++
            body
        }

    This pass recognises that pattern and raises it back, but only when the
    index temporary is compiler-generated (no debug assign).  User-written
    `while (idx < arr.length)` loops keep their explicit index.
    """

    def _is_user_local(self, local: IRLocal) -> bool:
        if not self.func.func.has_debug or not self.func.func.assigns:
            return False
        user_regs: Set[int] = set()
        for _, op_idx in self.func.func.assigns:
            val = op_idx.value - 1
            if 0 <= val < len(self.func.ops):
                op = self.func.ops[val]
                if "dst" in op.df:
                    user_regs.add(op.df["dst"].value)
        if local.name.startswith("var"):
            try:
                return int(local.name[3:]) in user_regs
            except ValueError:
                pass
        return True

    def _expr_reads_local(self, expr: Optional[IRExpression], local: IRLocal) -> bool:
        if expr is None:
            return False
        if expr == local:
            return True
        if isinstance(expr, (IRArithmetic, IRBoolExpr)):
            return self._expr_reads_local(expr.left, local) or self._expr_reads_local(expr.right, local)
        if isinstance(expr, IRCall):
            if expr.target is not None and self._expr_reads_local(expr.target, local):
                return True
            return any(self._expr_reads_local(arg, local) for arg in expr.args)
        if isinstance(expr, IRField):
            return self._expr_reads_local(expr.target, local)
        if isinstance(expr, IRCast):
            return self._expr_reads_local(expr.expr, local)
        if isinstance(expr, IRArrayAccess):
            return self._expr_reads_local(expr.array, local) or self._expr_reads_local(expr.index, local)
        if isinstance(expr, IRArrayLiteral):
            return any(self._expr_reads_local(e, local) for e in expr.elements)
        if isinstance(expr, (IREnumIndex, IREnumField)):
            return self._expr_reads_local(expr.value, local)
        if isinstance(expr, IRNew):
            return any(self._expr_reads_local(arg, local) for arg in expr.constructor_args)
        return False

    def _stmt_reads_local(self, stmt: IRStatement, local: IRLocal) -> bool:
        if isinstance(stmt, IRLocal):
            return stmt == local
        if isinstance(stmt, IRAssign):
            if self._expr_reads_local(stmt.expr, local):
                return True
            if isinstance(stmt.target, IRArrayAccess):
                return self._expr_reads_local(stmt.target.array, local) or self._expr_reads_local(
                    stmt.target.index, local
                )
            return False
        if isinstance(stmt, IRReturn):
            return stmt.value is not None and self._expr_reads_local(stmt.value, local)
        if isinstance(stmt, IRCall):
            if stmt.target is not None and self._expr_reads_local(stmt.target, local):
                return True
            return any(self._expr_reads_local(arg, local) for arg in stmt.args)
        if isinstance(stmt, IRConditional):
            if self._expr_reads_local(stmt.condition, local):
                return True
            return any(self._stmt_reads_local(s, local) for s in stmt.true_block.statements) or any(
                self._stmt_reads_local(s, local) for s in stmt.false_block.statements
            )
        if isinstance(stmt, IRWhileLoop):
            if self._expr_reads_local(stmt.condition, local):
                return True
            return any(self._stmt_reads_local(s, local) for s in stmt.body.statements)
        if isinstance(stmt, IRForEachLoop):
            if self._expr_reads_local(stmt.array, local):
                return True
            return any(self._stmt_reads_local(s, local) for s in stmt.body.statements)
        if isinstance(stmt, IRPrimitiveLoop):
            return any(self._stmt_reads_local(s, local) for s in stmt.condition.statements) or any(
                self._stmt_reads_local(s, local) for s in stmt.body.statements
            )
        if isinstance(stmt, IRSwitch):
            if self._expr_reads_local(stmt.value, local):
                return True
            for case_block in stmt.cases.values():
                if any(self._stmt_reads_local(s, local) for s in case_block.statements):
                    return True
            if stmt.default and any(self._stmt_reads_local(s, local) for s in stmt.default.statements):
                return True
        if isinstance(stmt, IRTrace):
            return self._expr_reads_local(stmt.msg, local)
        return False

    def _stmt_assigns_local(self, stmt: IRStatement, local: IRExpression) -> bool:
        if isinstance(stmt, IRAssign) and stmt.target == local:
            return True
        for child in stmt.get_children():
            if isinstance(child, IRBlock):
                if any(self._stmt_assigns_local(s, local) for s in child.statements):
                    return True
            elif self._stmt_assigns_local(child, local):
                return True
        return False

    def _is_index_increment(self, stmt: IRStatement, idx: IRLocal) -> bool:
        if not isinstance(stmt, IRAssign) or stmt.target != idx:
            return False
        expr = stmt.expr
        if isinstance(expr, IRCast):
            expr = expr.expr
        if not isinstance(expr, IRArithmetic) or expr.op != IRArithmetic.ArithmeticType.ADD:
            return False
        if expr.left != idx:
            return False
        if not isinstance(expr.right, IRConst) or expr.right.const_type != IRConst.ConstType.INT:
            return False
        val = _int_const_value(expr.right)
        return val == 1

    def _try_convert(self, loop: IRWhileLoop) -> Optional[Tuple[IRForEachLoop, IRLocal]]:
        cond = loop.condition
        if not isinstance(cond, IRBoolExpr):
            return None
        idx: Optional[IRLocal] = None
        arr: Optional[IRExpression] = None
        if cond.op == IRBoolExpr.CompareType.LT:
            if isinstance(cond.left, IRLocal) and isinstance(cond.right, IRField) and cond.right.field_name == "length":
                idx = cond.left
                arr = cond.right.target
        elif cond.op == IRBoolExpr.CompareType.GT:
            if isinstance(cond.right, IRLocal) and isinstance(cond.left, IRField) and cond.left.field_name == "length":
                idx = cond.right
                arr = cond.left.target
        if idx is None or arr is None:
            return None
        if self._is_user_local(idx):
            return None
        body = loop.body
        if len(body.statements) < 2:
            return None
        first = body.statements[0]
        if not isinstance(first, IRAssign) or not isinstance(first.target, IRLocal):
            return None
        if not isinstance(first.expr, IRArrayAccess):
            return None
        if first.expr.array != arr or first.expr.index != idx:
            return None
        elem = first.target
        if not self._is_index_increment(body.statements[1], idx):
            return None
        rest = body.statements[2:]
        for s in rest:
            if self._stmt_reads_local(s, idx):
                return None
            if self._stmt_assigns_local(s, elem):
                return None
        for s in body.statements:
            if self._stmt_assigns_local(s, arr):
                return None
        new_body = IRBlock(loop.code)
        new_body.statements = list(rest)
        foreach = IRForEachLoop(loop.code, elem, arr, new_body)
        # `loop` (the while) and the two discarded body statements (array-index
        # read + idx++) are dropped in favor of `foreach` and `rest` above.
        foreach.adopt(loop, first, body.statements[1])
        return foreach, idx

    def visit_block(self, block: IRBlock) -> None:
        made_change = True
        while made_change:
            made_change = False
            new_statements: List[IRStatement] = []
            i = 0
            while i < len(block.statements):
                stmt = block.statements[i]
                converted: Optional[Tuple[IRForEachLoop, IRLocal]] = None
                if isinstance(stmt, IRWhileLoop):
                    converted = self._try_convert(stmt)
                if converted is not None:
                    foreach_loop, idx = converted
                    # The index temporary's `idx = 0` initializer may have been
                    # hoisted several statements before the loop (e.g. because
                    # the array expression was lifted into a temp).  Find the
                    # closest preceding safe assignment to the index and remove
                    # it, but only if nothing between it and the loop touches
                    # the index.
                    for j in range(len(new_statements) - 1, -1, -1):
                        prev = new_statements[j]
                        if isinstance(prev, IRAssign) and prev.target == idx:
                            if isinstance(prev.expr, IRConst) and not self._expr_reads_local(prev.expr, idx):
                                foreach_loop.adopt(prev)
                                del new_statements[j]
                            break
                        if self._stmt_reads_local(prev, idx):
                            break

                    # If the iterable was lifted into a compiler temp that is
                    # only used by this loop, inline it into the `for (...)`
                    # header.  This recovers `for (i in foo())` instead of
                    # leaving a separate `var arr = foo();` declaration.
                    if isinstance(foreach_loop.array, IRLocal):
                        arr_local = foreach_loop.array
                        for j in range(len(new_statements) - 1, -1, -1):
                            prev = new_statements[j]
                            if not (
                                isinstance(prev, IRAssign)
                                and prev.target == arr_local
                                and not self._is_user_local(arr_local)
                            ):
                                continue
                            # Ensure nothing else reads or redefines the temp
                            # between the assignment and the loop.
                            intervening = new_statements[j + 1 :]
                            if any(self._stmt_reads_local(s, arr_local) for s in intervening):
                                break
                            if any(self._stmt_assigns_local(s, arr_local) for s in intervening):
                                break
                            if self._stmt_reads_local(foreach_loop.body, arr_local):
                                break
                            if self._stmt_assigns_local(foreach_loop.body, arr_local):
                                break
                            foreach_loop.array = prev.expr
                            foreach_loop.adopt(prev)
                            del new_statements[j]
                            break

                    new_statements.append(foreach_loop)
                    i += 1
                    made_change = True
                    continue
                new_statements.append(stmt)
                i += 1
            block.statements = new_statements
        for stmt in block.statements:
            self._cow_children(stmt)
            for child in stmt.get_children():
                if isinstance(child, IRBlock):
                    self.visit_block(child)


class IRIntRangeLoopOptimizer(TraversingIROptimizer):
    """
    Recover Haxe int-range for loops from the manual index-while lowering.

    HashLink compiles `for (elem in start...end) { body }` as:
        idx = start
        while (idx < end) {
            elem = idx
            idx++
            body
        }

    This is the same index-while shape IRForEachLoopOptimizer targets, but the
    loop variable is a copy of the index itself (`elem = idx`) rather than an
    array element (`elem = array[idx]`) — i.e. the source iterates over a range
    of integers, not an array's contents.
    """

    def _is_user_local(self, local: IRLocal) -> bool:
        if not self.func.func.has_debug or not self.func.func.assigns:
            return False
        user_regs: Set[int] = set()
        for _, op_idx in self.func.func.assigns:
            val = op_idx.value - 1
            if 0 <= val < len(self.func.ops):
                op = self.func.ops[val]
                if "dst" in op.df:
                    user_regs.add(op.df["dst"].value)
        if local.name.startswith("var"):
            try:
                return int(local.name[3:]) in user_regs
            except ValueError:
                pass
        return True

    def _expr_reads_local(self, expr: Optional[IRExpression], local: IRLocal) -> bool:
        if expr is None:
            return False
        if expr == local:
            return True
        if isinstance(expr, (IRArithmetic, IRBoolExpr)):
            return self._expr_reads_local(expr.left, local) or self._expr_reads_local(expr.right, local)
        if isinstance(expr, IRCall):
            if expr.target is not None and self._expr_reads_local(expr.target, local):
                return True
            return any(self._expr_reads_local(arg, local) for arg in expr.args)
        if isinstance(expr, IRField):
            return self._expr_reads_local(expr.target, local)
        if isinstance(expr, IRCast):
            return self._expr_reads_local(expr.expr, local)
        if isinstance(expr, IRArrayAccess):
            return self._expr_reads_local(expr.array, local) or self._expr_reads_local(expr.index, local)
        return False

    def _stmt_reads_local(self, stmt: IRStatement, local: IRLocal) -> bool:
        if isinstance(stmt, IRLocal):
            return stmt == local
        if isinstance(stmt, IRAssign):
            if self._expr_reads_local(stmt.expr, local):
                return True
            if isinstance(stmt.target, IRArrayAccess):
                return self._expr_reads_local(stmt.target.array, local) or self._expr_reads_local(
                    stmt.target.index, local
                )
            return False
        if isinstance(stmt, IRReturn):
            return stmt.value is not None and self._expr_reads_local(stmt.value, local)
        if isinstance(stmt, IRCall):
            if stmt.target is not None and self._expr_reads_local(stmt.target, local):
                return True
            return any(self._expr_reads_local(arg, local) for arg in stmt.args)
        if isinstance(stmt, IRTrace):
            return self._expr_reads_local(stmt.msg, local)
        return False

    def _stmt_assigns_local(self, stmt: IRStatement, local: IRExpression) -> bool:
        if isinstance(stmt, IRAssign) and stmt.target == local:
            return True
        for child in stmt.get_children():
            if isinstance(child, IRBlock):
                if any(self._stmt_assigns_local(s, local) for s in child.statements):
                    return True
            elif self._stmt_assigns_local(child, local):
                return True
        return False

    def _is_index_increment(self, stmt: IRStatement, idx: IRLocal) -> bool:
        if not isinstance(stmt, IRAssign) or stmt.target != idx:
            return False
        expr = stmt.expr
        if isinstance(expr, IRCast):
            expr = expr.expr
        if not isinstance(expr, IRArithmetic) or expr.op != IRArithmetic.ArithmeticType.ADD:
            return False
        if expr.left != idx:
            return False
        if not isinstance(expr.right, IRConst) or expr.right.const_type != IRConst.ConstType.INT:
            return False
        val = _int_const_value(expr.right)
        return val == 1

    def _try_convert(self, loop: IRWhileLoop) -> Optional[Tuple[IRIntRangeLoop, IRLocal]]:
        cond = loop.condition
        if not isinstance(cond, IRBoolExpr):
            return None
        idx: Optional[IRLocal] = None
        end_expr: Optional[IRExpression] = None
        if cond.op == IRBoolExpr.CompareType.LT and isinstance(cond.left, IRLocal):
            idx = cond.left
            end_expr = cond.right
        elif cond.op == IRBoolExpr.CompareType.GT and isinstance(cond.right, IRLocal):
            idx = cond.right
            end_expr = cond.left
        if idx is None or end_expr is None:
            return None
        if self._is_user_local(idx):
            return None
        body = loop.body
        if len(body.statements) < 2:
            return None
        first = body.statements[0]
        if not isinstance(first, IRAssign) or not isinstance(first.target, IRLocal):
            return None
        # The loop variable must be a plain copy of the index, not e.g. an
        # array element — that pattern belongs to IRForEachLoopOptimizer.
        if first.expr != idx:
            return None
        elem = first.target
        if elem == idx:
            return None
        if not self._is_index_increment(body.statements[1], idx):
            return None
        rest = body.statements[2:]
        for s in rest:
            if self._stmt_reads_local(s, idx):
                return None
            if self._stmt_assigns_local(s, elem):
                return None
        # The bound must be loop-invariant: nothing in the body may redefine
        # whatever it reads from (e.g. reassigning the array behind `a.length`).
        for s in body.statements:
            if isinstance(end_expr, IRLocal) and self._stmt_assigns_local(s, end_expr):
                return None
            if isinstance(end_expr, IRField) and isinstance(end_expr.target, IRLocal):
                if self._stmt_assigns_local(s, end_expr.target):
                    return None
        new_body = IRBlock(loop.code)
        new_body.statements = list(rest)
        range_loop = IRIntRangeLoop(loop.code, elem, idx, end_expr, new_body)
        # `loop` (the while) and the two discarded body statements (elem = idx,
        # idx++) are dropped in favor of `range_loop` and `rest` above.
        range_loop.adopt(loop, first, body.statements[1])
        return range_loop, idx

    def visit_block(self, block: IRBlock) -> None:
        made_change = True
        while made_change:
            made_change = False
            new_statements: List[IRStatement] = []
            i = 0
            while i < len(block.statements):
                stmt = block.statements[i]
                converted: Optional[Tuple[IRIntRangeLoop, IRLocal]] = None
                if isinstance(stmt, IRWhileLoop):
                    converted = self._try_convert(stmt)
                if converted is not None:
                    range_loop, idx = converted
                    # The index temporary's `idx = start` initializer may have been
                    # hoisted several statements before the loop. Find the closest
                    # preceding safe assignment to the index, use its expression as
                    # the range's start, and remove it, but only if nothing between
                    # it and the loop touches the index.
                    for j in range(len(new_statements) - 1, -1, -1):
                        prev = new_statements[j]
                        if isinstance(prev, IRAssign) and prev.target == idx:
                            if not self._expr_reads_local(prev.expr, idx):
                                range_loop.start = prev.expr
                                range_loop.adopt(prev)
                                del new_statements[j]
                            break
                        if self._stmt_reads_local(prev, idx):
                            break

                    new_statements.append(range_loop)
                    i += 1
                    made_change = True
                    continue
                new_statements.append(stmt)
                i += 1
            block.statements = new_statements
        for stmt in block.statements:
            self._cow_children(stmt)
            for child in stmt.get_children():
                if isinstance(child, IRBlock):
                    self.visit_block(child)
