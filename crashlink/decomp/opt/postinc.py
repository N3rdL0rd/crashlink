"""`a[pos++]`: a field read, bumped by one, whose old value is used by the next statement."""

from __future__ import annotations

import re
from typing import Iterator, List, Optional

from ..ir import (
    IRArithmetic,
    IRArrayAccess,
    IRAssign,
    IRBlock,
    IRCall,
    IRCast,
    IRConst,
    IRExpression,
    IRField,
    IRLocal,
    IRPostIncrement,
    IRReturn,
    IRStatement,
)
from .inliner import _ReferenceAwareOptimizer


def _is_one(const: IRConst) -> bool:
    value = const.value
    return getattr(value, "value", value) == 1


def _same_field(a: IRExpression, b: IRExpression) -> bool:
    return (
        isinstance(a, IRField)
        and isinstance(b, IRField)
        and a.field_name == b.field_name
        and isinstance(a.target, IRLocal)
        and a.target == b.target
    )


def _walk(node: IRStatement) -> Iterator[IRStatement]:
    yield node
    if isinstance(node, IRBlock):
        for stmt in node.statements:
            yield from _walk(stmt)
    else:
        for child in node.get_children():
            yield from _walk(child)


class IRPostIncrementRecovery(_ReferenceAwareOptimizer):
    """Folds `t = this.pos; this.pos = t + 1; ... t ...` into `... this.pos++ ...`.

    The compiler lowers `a[pos++]` to a read of `pos`, the store of the bumped value, and then
    the access that uses the old value; written out as three statements the index is computed
    before the receiver is checked for null, which is a different order than the source's.
    Only the statement right after the store may use the old value, exactly once, and nothing
    else in it may read or write the field, so evaluating the increment in place cannot change
    what anything sees.

    It runs last: the optimizers before it treat the increment as the plain reads and writes it is.
    """

    def visit_block(self, block: IRBlock) -> None:
        statements = block.statements
        i = 0
        while i + 2 < len(statements):
            if self._fold(statements, i):
                continue
            i += 1

    def _fold(self, statements: List[IRStatement], start: int) -> bool:
        read = statements[start]
        if not (
            isinstance(read, IRAssign)
            and isinstance(read.target, IRLocal)
            and re.fullmatch(r"var\d+", read.target.name)
            and isinstance(read.expr, IRField)
        ):
            return False
        temp, field = read.target, read.expr
        if temp.name in self._address_names:
            return False
        # The compiler keeps a copy of the old value for the use: `t2 = t; field = t + 1; ... t2 ...`.
        position = start + 1
        old = temp
        copy = statements[position] if position < len(statements) else None
        if (
            isinstance(copy, IRAssign)
            and isinstance(copy.target, IRLocal)
            and re.fullmatch(r"var\d+", copy.target.name)
            and copy.expr == temp
            and copy.target.name not in self._address_names
        ):
            old = copy.target
            position += 1
        if position + 1 >= len(statements):
            return False
        store, user = statements[position], statements[position + 1]
        if not (
            isinstance(store, IRAssign)
            and _same_field(store.target, field)
            and isinstance(store.expr, IRArithmetic)
            and store.expr.op in (IRArithmetic.ArithmeticType.ADD, IRArithmetic.ArithmeticType.SUB)
            and store.expr.left == temp
            and isinstance(store.expr.right, IRConst)
            and _is_one(store.expr.right)
        ):
            return False
        # The old value is used exactly once, by the very next statement, and by nothing after it.
        rest = statements[position + 1 :]
        uses = [n for stmt in rest for n in _walk(stmt) if isinstance(n, IRLocal) and n == old]
        in_user = [n for n in _walk(user) if isinstance(n, IRLocal) and n == old]
        if len(uses) != 1 or len(in_user) != 1:
            return False
        if old is not temp and any(
            isinstance(n, IRLocal) and n == temp for stmt in rest for n in _walk(stmt)
        ):
            return False
        if not self._order_free(user, old, field):
            return False
        delta = 1 if store.expr.op == IRArithmetic.ArithmeticType.ADD else -1
        replacement = IRPostIncrement(self.func.code, field, delta)
        if not self._replace(user, old, replacement):
            return False
        del statements[start : position + 1]
        return True

    def _order_free(self, user: IRStatement, temp: IRLocal, field: IRField) -> bool:
        """Nothing in `user` besides the use of `temp` observes or changes the field, or does
        anything whose order against the increment could show."""
        stack: List[IRStatement] = [user]
        while stack:
            node = stack.pop()
            if node is temp or (isinstance(node, IRLocal) and node == temp):
                continue
            if isinstance(node, IRReturn):
                if node.value is None:
                    return False
            elif isinstance(node, IRAssign):
                if _same_field(node.target, field) or not isinstance(node.target, (IRLocal, IRField)):
                    return False
            elif isinstance(node, IRField):
                if node.field_name == field.field_name:
                    return False
            elif isinstance(node, IRCall):
                # an element read of an array (`a.getDyn(i)`), which only looks at `a` and the index
                callee = node.target
                if not (
                    isinstance(callee, IRField)
                    and callee.field_name in ("getDyn", "get")
                    and isinstance(callee.target, IRLocal)
                    and len(node.args) == 1
                ):
                    return False
                stack.extend(node.args)
                continue
            elif not isinstance(node, (IRLocal, IRConst, IRArrayAccess, IRArithmetic, IRCast)):
                return False
            stack.extend(node.get_children())
        return True

    def _replace(self, node: IRStatement, temp: IRLocal, replacement: IRPostIncrement) -> bool:
        """Substitute `replacement` for the one use of `temp` below `node`."""
        if isinstance(node, IRReturn):
            if node.value == temp:
                node.value = replacement
                return True
            return isinstance(node.value, IRExpression) and self._replace_in(node.value, temp, replacement)
        if isinstance(node, IRAssign):
            if node.expr == temp:
                node.expr = replacement
                return True
            return self._replace_in(node.expr, temp, replacement)
        return False

    def _replace_in(self, expr: Optional[IRStatement], temp: IRLocal, replacement: IRPostIncrement) -> bool:
        if isinstance(expr, IRArrayAccess):
            if expr.index == temp:
                expr.index = replacement
                return True
            return self._replace_in(expr.array, temp, replacement) or self._replace_in(
                expr.index, temp, replacement
            )
        if isinstance(expr, IRArithmetic):
            if expr.left == temp:
                expr.left = replacement
                return True
            if expr.right == temp:
                expr.right = replacement
                return True
            return self._replace_in(expr.left, temp, replacement) or self._replace_in(
                expr.right, temp, replacement
            )
        if isinstance(expr, IRCall):
            for position, arg in enumerate(expr.args):
                if arg == temp:
                    expr.args[position] = replacement
                    return True
            return False
        if isinstance(expr, IRCast):
            if expr.expr == temp:
                expr.expr = replacement
                return True
            return self._replace_in(expr.expr, temp, replacement)
        return False
