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
    IRDowncast,
    IRExpression,
    IRLocal,
    IRPosInfos,
    IRReturn,
    IRStatement,
    IRThrow,
)
from . import TraversingIROptimizer
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
        while i + 1 < len(statements):
            if self._fold(statements, i):
                continue
            i += 1

    def _fold_in_place(self, statements: List[IRStatement], start: int) -> bool:
        """`if (!check(Class, v) && v != null) throw "Cast error"` where `v` is a variable that lives
        on: the check is `cast(v, Class)` at its one value use, a following `(T)v` argument or
        initializer, or a statement of its own when nothing follows."""
        check = statements[start]
        if not (isinstance(check, IRConditional) and not check.false_block.statements):
            return False
        test = check.condition
        if not (
            isinstance(test, IRBoolExpr)
            and isinstance(test.right, IRBoolExpr)
            and test.right.left is not None
        ):
            return False
        value = test.right.left
        if not isinstance(value, IRLocal) or value.name in self._address_names:
            return False
        class_ref = self._checked_class(check, value)
        if class_ref is None:
            return False
        replacement = IRClassCast(self.func.code, value, class_ref)
        tail = statements[start + 1 :]
        if all(
            (isinstance(t, IRReturn) and t.value is None) or (isinstance(t, IRCast) and t.expr == value)
            for t in tail
        ):
            replacement.adopt(check)
            statements[start:] = [replacement] + [t for t in tail if isinstance(t, IRReturn)]
            return True
        user = statements[start + 1]
        if isinstance(user, IRAssign):
            inner = user.expr.expr if isinstance(user.expr, IRCast) else user.expr
            if inner == value:
                if isinstance(user.expr, IRCast):
                    user.expr.expr = replacement
                else:
                    user.expr = replacement
                del statements[start]
                return True
        call = user.expr if isinstance(user, IRAssign) else user
        if not isinstance(call, IRCall):
            return False
        if call.target is not None and not isinstance(call.target, (IRConst, IRLocal)):
            return False
        for position, arg in enumerate(call.args):
            if isinstance(arg, IRCast) and arg.expr == value:
                if not all(
                    isinstance(earlier, (IRConst, IRLocal, IRPosInfos)) for earlier in call.args[:position]
                ):
                    return False
                arg.expr = replacement
                del statements[start]
                return True
        return False

    def _fold(self, statements: List[IRStatement], start: int) -> bool:
        if self._fold_in_place(statements, start):
            return True
        if start + 2 >= len(statements):
            return False
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


class IRDowncastRecovery(TraversingIROptimizer):
    """`if (check(Class, v)) { x = v; } else { x = null; }` is `x = Std.downcast(v, Class)`.

    The compiler writes `Std.downcast` out as the `hl.BaseType.check` test selecting the value or
    null. Spelled out again in source the test goes through the `Std.isOfType` call instead.
    """

    def visit_block(self, block: IRBlock) -> None:
        for index, stmt in enumerate(block.statements):
            replaced = self._recover(stmt)
            if replaced is not None:
                block.statements[index] = replaced

    def _recover(self, stmt: IRStatement) -> Optional[IRStatement]:
        if not isinstance(stmt, IRConditional):
            return None
        test = stmt.condition
        if not (
            isinstance(test, IRBoolExpr)
            and test.op in (IRBoolExpr.CompareType.ISTRUE, IRBoolExpr.CompareType.ISFALSE)
            and isinstance(test.left, IRCall)
        ):
            return None
        call = test.left
        callee = call.target
        if not (
            isinstance(callee, IRConst)
            and "BaseType.check" in str(callee)
            and len(call.args) == 2
            and isinstance(call.args[0], IRConst)
        ):
            return None
        selected, rejected = stmt.true_block.statements, stmt.false_block.statements
        if test.op == IRBoolExpr.CompareType.ISFALSE:
            selected, rejected = rejected, selected
        if len(selected) != 1 or len(rejected) != 1:
            return None
        yes, no = selected[0], rejected[0]
        if not (isinstance(yes, IRAssign) and isinstance(no, IRAssign) and yes.target == no.target):
            return None
        if not (isinstance(no.expr, IRConst) and no.expr.value is None):
            return None
        picked = yes.expr.expr if isinstance(yes.expr, IRCast) else yes.expr
        value = call.args[1]
        if not (isinstance(value, IRLocal) and picked == value):
            return None
        out = IRAssign(self.func.code, yes.target, IRDowncast(self.func.code, value, call.args[0]))
        out.adopt(stmt)
        out._no_user_inline = True
        return out
