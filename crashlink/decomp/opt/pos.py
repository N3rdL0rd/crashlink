"""Mark the compiler-supplied `?pos:haxe.PosInfos` argument of calls.

A function with a `?pos:haxe.PosInfos` parameter gets its position filled in at every call
site, as a literal of the call's own file, line, class and method. Source leaves it out, and
writing the literal explicitly compiles to different code (a dynamic object instead of the
typed structure). `IRPosInfos` tags such an argument so the renderer can omit it, keeping the
position as a comment.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from ... import disasm
from ...core import Bytecode, Fun, Function, Virtual
from ..ir import (
    IRAssign,
    IRBlock,
    IRCall,
    IRCast,
    IRConst,
    IRExpression,
    IRLocal,
    IRObjectLiteral,
    IRPosInfos,
    IRStatement,
)
from . import TraversingIROptimizer

_AUTO_FIELDS = {"fileName", "lineNumber", "className", "methodName"}


class IRPosInfosFolder(TraversingIROptimizer):
    """Replace an auto-filled position argument by an `IRPosInfos`."""

    def _literal(self, expr: IRStatement) -> Optional[Tuple[IRObjectLiteral, IRExpression]]:
        node = expr
        while isinstance(node, IRCast):
            node = node.expr
        if (
            isinstance(node, IRObjectLiteral)
            and {name for name, _ in node.fields} == _AUTO_FIELDS
            and len(node.fields) == len(_AUTO_FIELDS)
            and all(isinstance(value, IRConst) for _, value in node.fields)
        ):
            return node, cast_expr(expr)
        return None

    def _position_param(self, call: IRCall) -> bool:
        """Whether the call's last argument is passed for a `haxe.PosInfos` parameter."""
        if call.target is None:
            return False
        signature = call.target.get_type().definition
        if not isinstance(signature, Fun) or not call.args or len(signature.args) != len(call.args):
            return False
        last = signature.args[-1].resolve(self.func.code).definition
        return isinstance(last, Virtual) and disasm._is_pos_infos(self.func.code, last)

    def _tag(self, call: IRCall, arg: IRExpression) -> bool:
        found = self._literal(arg)
        if found is None or not self._position_param(call) or position_observed(self.func.code, call):
            return False
        literal, original = found
        call.args[-1] = IRPosInfos(self.func.code, literal.fields, original, arg.get_type())
        return True

    def before_visit_statement(self, statement: IRStatement) -> None:
        if isinstance(statement, IRCall) and self._position_param(statement):
            self._tag(statement, statement.args[-1])

    def visit_block(self, block: IRBlock) -> None:
        """`pos = {..}; f(a, pos)`: fold the literal into the one call that reads it."""
        stmts = block.statements
        i = 0
        while i < len(stmts):
            stmt = stmts[i]
            if (
                isinstance(stmt, IRAssign)
                and isinstance(stmt.target, IRLocal)
                and isinstance(stmt.expr, IRExpression)
                and self._literal(stmt.expr) is not None
                and self._mentions(stmt.target) == 2
            ):
                call = next(
                    (c for c in self._calls(stmts[i + 1 :]) if c.args and c.args[-1] == stmt.target), None
                )
                if call is not None and self._position_param(call):
                    self._tag(call, stmt.expr)
                    call.adopt(stmt)  # the assignment's opcodes go with it
                    del stmts[i]
                    continue
            i += 1

    def _calls(self, statements: List[IRStatement]) -> List[IRCall]:
        found: List[IRCall] = []
        pending: List[IRStatement] = list(statements)
        while pending:
            node = pending.pop(0)
            if isinstance(node, IRCall):
                found.append(node)
            pending.extend(node.get_children())
        return found

    def _mentions(self, local: IRLocal) -> int:
        count = 0
        pending: List[IRStatement] = [self.func.block]
        seen = set()
        while pending:
            node = pending.pop()
            if id(node) in seen:
                continue
            seen.add(id(node))
            if isinstance(node, IRLocal) and node.name == local.name:
                count += 1
            pending.extend(node.get_children())
        return count


def cast_expr(expr: IRStatement) -> IRExpression:
    assert isinstance(expr, IRExpression)
    return expr


_observed_cache: Dict[Tuple[int, int], bool] = {}


def position_observed(code: Bytecode, call: IRCall, depth: int = 0) -> bool:
    """Whether the function `call` reaches reads its position argument.

    The recompiled program has its own layout, so a position that is read (printed, compared)
    must stay as written; one that is only passed along, or ignored, can be left to the
    compiler. Anything that cannot be followed counts as read."""
    target = call.target
    if not (isinstance(target, IRConst) and isinstance(target.value, Function)) or depth > 4:
        return True
    return _function_reads_position(code, target.value, depth)


def _function_reads_position(code: Bytecode, func: Function, depth: int) -> bool:
    key = (id(code), func.findex.value)
    if key in _observed_cache:
        return _observed_cache[key]
    _observed_cache[key] = True  # a recursive function that forwards its position reads nothing new
    from ..function import IRFunction

    signature = func.type.resolve(code).definition
    if not isinstance(signature, Fun) or not signature.args:
        return True
    try:
        ir = IRFunction(code, func)
    except Exception:
        return True
    reg = len(signature.args) - 1
    names = {local.name for local in ir.all_locals if local.reg_idx == reg}
    observed = False

    def walk(node: IRStatement, parent: Optional[IRStatement]) -> None:
        nonlocal observed
        if observed:
            return
        if isinstance(node, IRLocal) and node.name in names:
            if not (
                isinstance(parent, IRCall)
                and parent.args
                and parent.args[-1] is node
                and not position_observed(code, parent, depth + 1)
            ):
                observed = True
            return
        for child in node.get_children():
            walk(child, node)

    walk(ir.block, None)
    _observed_cache[key] = observed
    return observed
