"""`cast(value, SomeClass)`: a class check followed by `throw "Cast error"`."""

from __future__ import annotations

import re
from typing import Iterator, List, Optional

from ..ir import (
    IRAssign,
    IRBlock,
    IRBoolExpr,
    IRCall,
    IRCast,
    IRClassCast,
    IRConditional,
    IRConst,
    IRExpression,
    IRLocal,
    IRPosInfos,
    IRStatement,
    IRThrow,
)
from .inliner import _ReferenceAwareOptimizer


def _walk(node: IRStatement) -> Iterator[IRStatement]:
    yield node
    if isinstance(node, IRBlock):
        for stmt in node.statements:
            yield from _walk(stmt)
    else:
        for child in node.get_children():
            yield from _walk(child)


class IRCastCheckRecovery(_ReferenceAwareOptimizer):
    """Folds `v = e; if (!check(Class, v) && v != null) throw "Cast error"; use(v)` back into
    `use(cast(e, Class))`.

    HashLink has no cast opcode for a class or interface: the compiler writes the type test and
    the throw out. Spelled out again in source it compiles to the same test through the
    `Std.isOfType` inline instead of `hl.BaseType.check`, so the cast is written as a cast. The
    value is evaluated at its use, so everything evaluated before it in that statement must be
    unable to observe the difference.
    """

    def visit_block(self, block: IRBlock) -> None:
        statements = block.statements
        i = 0
        while i + 2 < len(statements):
            if self._fold(statements, i):
                continue
            i += 1

    def _fold(self, statements: List[IRStatement], start: int) -> bool:
        assign, check, user = statements[start], statements[start + 1], statements[start + 2]
        if not (
            isinstance(assign, IRAssign)
            and isinstance(assign.target, IRLocal)
            and re.fullmatch(r"var\d+", assign.target.name)
            and assign.target.name not in self._address_names
            and isinstance(assign.expr, IRExpression)
            and isinstance(check, IRConditional)
            and not check.false_block.statements
        ):
            return False
        temp = assign.target
        class_ref = self._checked_class(check, temp)
        if class_ref is None:
            return False
        uses = [
            n for stmt in statements[start + 2 :] for n in _walk(stmt) if isinstance(n, IRLocal) and n == temp
        ]
        in_user = [n for n in _walk(user) if isinstance(n, IRLocal) and n == temp]
        if len(uses) != 1 or len(in_user) != 1:
            return False
        call = user.expr if isinstance(user, IRAssign) else user
        if not isinstance(call, IRCall):
            return False
        replacement = IRClassCast(self.func.code, assign.expr, class_ref)
        for position, arg in enumerate(call.args):
            wrapper: Optional[IRCast] = None
            inner: IRStatement = arg
            if isinstance(arg, IRCast):
                wrapper, inner = arg, arg.expr
            if inner != temp:
                continue
            if not all(
                isinstance(earlier, (IRConst, IRLocal, IRPosInfos)) for earlier in call.args[:position]
            ):
                return False
            if call.target is not None and not isinstance(call.target, (IRConst, IRLocal)):
                return False
            if wrapper is not None:
                wrapper.expr = replacement
            else:
                call.args[position] = replacement
            del statements[start : start + 2]
            return True
        return False

    @staticmethod
    def _checked_class(check: IRConditional, temp: IRLocal) -> Optional[IRConst]:
        """The class constant when `check` is `if (!type.check(Class, temp) && temp != null) throw "Cast error"`."""
        cond = check.condition
        body = check.true_block.statements
        if not (
            isinstance(cond, IRBoolExpr)
            and cond.op == IRBoolExpr.CompareType.AND
            and len(body) == 1
            and isinstance(body[0], IRThrow)
            and isinstance(body[0].value, IRConst)
            and body[0].value.value == "Cast error"
        ):
            return None
        left, right = cond.left, cond.right
        if not (
            isinstance(left, IRBoolExpr)
            and left.op == IRBoolExpr.CompareType.ISFALSE
            and isinstance(left.left, IRCall)
            and isinstance(right, IRBoolExpr)
            and right.op == IRBoolExpr.CompareType.NOT_NULL
            and right.left == temp
        ):
            return None
        test = left.left
        if len(test.args) != 2 or test.args[1] != temp or not isinstance(test.args[0], IRConst):
            return None
        callee = test.target
        if not (isinstance(callee, IRConst) and "BaseType.check" in str(callee)):
            return None
        return test.args[0]
