"""
Fold String.__alloc__ calls into their use sites.

HL lowers every string conversion to `String.__alloc__(bytes, length)`. The
result is a pure value: it allocates and initializes, but never reads external
state, so a temp that exists only to hold it can be inlined.
"""

from __future__ import annotations

from typing import Optional, Tuple

from ...core import Function
from ..ir import (
    IRAssign,
    IRBlock,
    IRCall,
    IRConst,
    IRExpression,
    IRLocal,
    IRReturn,
    IRStatement,
    IRTrace,
)
from . import TraversingIROptimizer


class IRStringAllocInliner(TraversingIROptimizer):
    """Inline a single-use String.__alloc__ result into its consumer."""

    TARGET_OPCODES = {"Call1", "Call2", "Call3", "Call4", "CallN"}

    def visit_block(self, block: IRBlock) -> None:
        made_change = True
        while made_change:
            made_change = False
            new_statements = []
            i = 0
            while i < len(block.statements):
                fold = self._try_fold(block.statements, i)
                if fold is not None:
                    stmt, consumed = fold
                    new_statements.append(stmt)
                    i += consumed
                    made_change = True
                    continue
                new_statements.append(block.statements[i])
                i += 1
            block.statements = new_statements

    def _try_fold(self, statements: list, start: int) -> Optional[Tuple[IRStatement, int]]:
        if start + 1 >= len(statements):
            return None
        assign = statements[start]
        if not (
            isinstance(assign, IRAssign)
            and isinstance(assign.target, IRLocal)
            and self._is_alloc_call(assign.expr)
        ):
            return None
        temp = assign.target
        use = statements[start + 1]
        if not self._reads_local(use, temp):
            return None
        # The temp must be dead after the use: nothing else reads it.
        if self._read_after(statements, start + 1, temp):
            return None
        # Inline the call into the use.
        return self._substitute(use, temp, assign.expr), 2

    def _is_alloc_call(self, expr: IRExpression) -> bool:
        if not isinstance(expr, IRCall) or expr.call_type != IRCall.CallType.FUNC:
            return False
        target = expr.target
        if not (isinstance(target, IRConst) and isinstance(target.value, Function)):
            return False
        name = self.func.code.partial_func_name(target.value) or ""
        return name == "__alloc__"

    def _reads_local(self, stmt: IRStatement, local: IRLocal) -> bool:
        if isinstance(stmt, IRAssign):
            if isinstance(stmt.target, IRExpression) and self._expr_contains(stmt.target, local):
                return True
            if stmt.expr is not None and self._expr_contains(stmt.expr, local):
                return True
        elif isinstance(stmt, IRReturn):
            if stmt.value is not None and self._expr_contains(stmt.value, local):
                return True
        elif isinstance(stmt, IRCall):
            if stmt.target is not None and self._expr_contains(stmt.target, local):
                return True
            for arg in stmt.args:
                if self._expr_contains(arg, local):
                    return True
        elif isinstance(stmt, IRTrace):
            if self._expr_contains(stmt.msg, local):
                return True
        return False

    def _expr_contains(self, expr: IRExpression, local: IRLocal) -> bool:
        if expr == local:
            return True
        return any(
            self._expr_contains(child, local)
            for child in expr.get_children()
            if isinstance(child, IRExpression)
        )

    def _read_after(self, statements: list, idx: int, local: IRLocal) -> bool:
        for stmt in statements[idx + 1 :]:
            if self._reads_local(stmt, local):
                return True
            if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal) and stmt.target == local:
                return False
        return False

    def _substitute(self, stmt: IRStatement, local: IRLocal, value: IRExpression) -> IRStatement:
        def replace(expr: IRExpression) -> IRExpression:
            if expr == local:
                return value
            if isinstance(expr, IRCall):
                return IRCall(expr.code, expr.call_type, expr.target, [replace(arg) for arg in expr.args])
            return expr

        if isinstance(stmt, IRAssign):
            return IRAssign(stmt.code, stmt.target, replace(stmt.expr))
        if isinstance(stmt, IRReturn):
            if stmt.value is None:
                return stmt
            return IRReturn(stmt.code, replace(stmt.value))
        if isinstance(stmt, IRTrace):
            return IRTrace(stmt.code, replace(stmt.msg), stmt.pos_info, stmt.extra_args)
        if isinstance(stmt, IRCall):
            return replace(stmt)
        return stmt
