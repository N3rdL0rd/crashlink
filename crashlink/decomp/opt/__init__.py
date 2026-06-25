"""
Base optimizer infrastructure and shared helpers.
"""
from __future__ import annotations

import copy
import re
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set, Tuple, Union, cast

from ...core import (
    Bytecode, DynObj, Enum, Fun, Function, Native, Obj, Opcode, Ref,
    ResolvableVarInt, Type, TypeDef, Virtual, Void, fieldRef, gIndex, tIndex,
)
from ...errors import DecompError
from ...globals import DEBUG, dbg_print
from ... import disasm
from ...opcodes import arithmetic, conditionals, terminal, simple_calls
from ..ir import (
    IRStatement, IRExpression, IRBlock, IRLocal, IRArithmetic, IRNeg, IRNot,
    IRTypeOf, IRTypeKind, IRAssign, IRCall, IRBoolExpr, IRConst, IRConditional,
    IRPrimitiveLoop, IRBreak, IRContinue, IRReturn, IRThrow, IRTrace, IRTryCatch,
    IRSwitch, IRPrimitiveJump, IRWhileLoop, IRForEachLoop, IRIntRangeLoop,
    IRField, IRNew, IRNativeArrayNew, IRNativeMapNew, IRCast, IRArrayLiteral,
    IRArrayAccess, IRRef, IREnumConstruct, IREnumIndex, IREnumField,
    IRUnliftedOpcode, IRNativeStub, _get_type_in_code, _strip_ansi,
)
from ..cfg import CFNode, CFGraph, IsolatedCFGraph, _find_jumps_to_label


class IROptimizer(ABC):
    """
    Base class for intermediate representation optimization routines.
    """

    #: Opcodes that must appear somewhere in the function for this optimizer to
    #: possibly do anything. None means "can't tell from opcodes alone, always run".
    TARGET_OPCODES: Optional[Set[str]] = None

    def __init__(self, function: "IRFunction"):
        self.func = function

    def should_run(self) -> bool:
        """Cheap pre-check: skip optimize() if none of TARGET_OPCODES are present."""
        if self.TARGET_OPCODES is None:
            return True
        return any(op.op in self.TARGET_OPCODES for op in self.func.ops)

    @abstractmethod
    def optimize(self) -> None:
        pass


class TraversingIROptimizer(IROptimizer):
    """
    Base class for intermediate representation optimization routines that recursively travel through the decompilation.
    """

    def optimize(self) -> None:
        """Start the optimization by traversing the root IR block."""
        if hasattr(self.func, "block"):
            self._visited_ids: Set[int] = set()
            self.visit(self.func.block)

    def visit(self, statement: IRStatement) -> None:
        """
        Recursively visit an IR statement and its children.

        The traversal performs a pre-order visit (parent first, then children):
        1. Call before_visit_statement for the current statement
        2. Handle specific statement type with visit_X methods
        3. Visit all children recursively
        4. Call after_visit_statement for the current statement

        IRFunction._lift_block memoizes shared continuation points, so the same
        IRBlock/IRStatement object can be reachable from multiple parents (a DAG,
        not a tree). Skip a node already visited in this pass: it denotes the
        exact same content, so revisiting would just redundantly (but harmlessly,
        since mutating it once already applies everywhere it's referenced) re-walk
        an already-processed subtree, which is exponential for deeply nested,
        heavily-converging control flow.
        """
        if id(statement) in self._visited_ids:
            return
        self._visited_ids.add(id(statement))

        self.before_visit_statement(statement)

        if isinstance(statement, IRBlock):
            self.visit_block(statement)
        elif isinstance(statement, IRAssign):
            self.visit_assign(statement)
        elif isinstance(statement, IRConditional):
            self.visit_conditional(statement)
        elif isinstance(statement, IRPrimitiveLoop):
            self.visit_primitive_loop(statement)
        elif isinstance(statement, IRSwitch):
            self.visit_switch(statement)
        elif isinstance(statement, IRReturn):
            self.visit_return(statement)
        elif isinstance(statement, IRTryCatch):
            self.visit_try_catch(statement)
        elif isinstance(statement, IRBreak):
            self.visit_break(statement)
        elif isinstance(statement, IRContinue):
            self.visit_continue(statement)
        elif isinstance(statement, IRExpression):
            self.visit_expression(statement)

        for child in statement.get_children():
            self.visit(child)

        self.after_visit_statement(statement)

    def before_visit_statement(self, statement: IRStatement) -> None:
        """Called before visiting a statement. Override in subclasses for custom behavior."""
        pass

    def after_visit_statement(self, statement: IRStatement) -> None:
        """Called after visiting a statement and all its children. Override in subclasses for custom behavior."""
        pass

    def visit_block(self, block: IRBlock) -> None:
        """Visit an IRBlock. Override in subclasses for custom behavior."""
        pass

    def visit_assign(self, assign: IRAssign) -> None:
        """Visit an IRAssign. Override in subclasses for custom behavior."""
        pass

    def visit_conditional(self, conditional: IRConditional) -> None:
        """Visit an IRConditional. Override in subclasses for custom behavior."""
        pass

    def visit_primitive_loop(self, loop: IRPrimitiveLoop) -> None:
        """Visit an IRPrimitiveLoop. Override in subclasses for custom behavior."""
        pass

    def visit_switch(self, switch: IRSwitch) -> None:
        """Visit an IRSwitch. Override in subclasses for custom behavior."""
        pass

    def visit_return(self, ret: IRReturn) -> None:
        """Visit an IRReturn. Override in subclasses for custom behavior."""

    def visit_try_catch(self, try_catch: IRTryCatch) -> None:
        """Visit an IRTryCatch. Override in subclasses for custom behavior."""
        pass

    def visit_break(self, brk: IRBreak) -> None:
        """Visit an IRBreak. Override in subclasses for custom behavior."""
        pass

    def visit_continue(self, cont: IRContinue) -> None:
        """Visit an IRContinue. Override in subclasses for custom behavior."""
        pass

    def visit_expression(self, expr: IRExpression) -> None:
        """Visit an IRExpression. Override in subclasses for custom behavior."""
        pass
def _ir_structurally_equal(a: Any, b: Any, memo: Optional[Set[Tuple[int, int]]] = None) -> bool:
    """Deep structural equality for IR nodes that is safe and fast on the IR DAG.

    The IR shares continuation blocks between parents (it is a DAG, not a tree),
    so rendering nodes with ``repr()`` to compare them is exponential — pprint
    re-expands every shared subtree. This walks both trees in lockstep instead,
    memoizing visited ``(id(a), id(b))`` pairs so each shared node pair is only
    compared once, which keeps the comparison linear and also tolerates cycles.
    """
    if a is b:
        return True
    if type(a) is not type(b):
        return False

    if memo is None:
        memo = set()
    key = (id(a), id(b))
    if key in memo:
        return True
    memo.add(key)

    if isinstance(a, (IRStatement, IRExpression)):
        a_fields = vars(a)
        b_fields = vars(b)
        if a_fields.keys() != b_fields.keys():
            return False
        for name, av in a_fields.items():
            # `code` is the shared Bytecode; comparing it adds nothing and would
            # recurse into the whole program.
            if name == "code":
                continue
            if not _ir_structurally_equal(av, b_fields[name], memo):
                return False
        return True

    if isinstance(a, (list, tuple)):
        if len(a) != len(b):
            return False
        return all(_ir_structurally_equal(x, y, memo) for x, y in zip(a, b))

    # ResolvableVarInt and friends carry a plain `.value`; compare it directly to
    # avoid depending on their __eq__ (which may need a Bytecode context).
    if hasattr(a, "value") and not isinstance(a, (str, int, float, bytes, bool)):
        return bool(a.value == b.value)

    return bool(a == b)


def _structurally_equal(a: Any, b: Any) -> bool:
    """Deep structural equality for IR statements/expressions.

    Used by IRGuardOrMerger to detect when two branches perform the exact
    same action (e.g. an identical `throw`), so they can be merged into a
    single branch with an `||`/`&&` condition. Conservative: returns False
    for any shape it doesn't specifically recognize rather than guessing.
    """
    if a is b:
        return True
    if type(a) is not type(b):
        return False
    if isinstance(a, IRLocal):
        return a == b
    if isinstance(a, IRConst):
        if a.const_type != b.const_type:
            return False
        if a.const_type == IRConst.ConstType.INT:
            return _int_const_value(a) == _int_const_value(b)
        return a.value == b.value
    if isinstance(a, IRArithmetic):
        return a.op == b.op and _structurally_equal(a.left, b.left) and _structurally_equal(a.right, b.right)
    if isinstance(a, IRBoolExpr):
        return a.op == b.op and _structurally_equal(a.left, b.left) and _structurally_equal(a.right, b.right)
    if isinstance(a, IRField):
        return a.field_name == b.field_name and _structurally_equal(a.target, b.target)
    if isinstance(a, IRArrayAccess):
        return _structurally_equal(a.array, b.array) and _structurally_equal(a.index, b.index)
    if isinstance(a, IRCall):
        if a.call_type != b.call_type or len(a.args) != len(b.args):
            return False
        if not _structurally_equal(a.target, b.target):
            return False
        return all(_structurally_equal(x, y) for x, y in zip(a.args, b.args))
    if isinstance(a, IRCast):
        return _structurally_equal(a.expr, b.expr)
    if isinstance(a, (IRNeg, IRNot)):
        return _structurally_equal(a.expr, b.expr)
    if isinstance(a, IRAssign):
        return _structurally_equal(a.target, b.target) and _structurally_equal(a.expr, b.expr)
    if isinstance(a, IRThrow):
        return _structurally_equal(a.value, b.value)
    if isinstance(a, IRReturn):
        return _structurally_equal(a.value, b.value)
    if a is None and b is None:
        return True
    return False


def _stmt_lists_structurally_equal(a: List[IRStatement], b: List[IRStatement]) -> bool:
    return len(a) == len(b) and all(_structurally_equal(x, y) for x, y in zip(a, b))

def _bytes_mem_kind(code: Bytecode, reg_type: tIndex) -> Optional[str]:
    """Map a GetMem/SetMem operand's register type to the matching hl.Bytes
    accessor suffix ("I32", "F32", or "F64"). GetMem/SetMem are used for any
    element width from 4 bytes up; unlike GetI16/GetI8, the opcode itself
    doesn't distinguish 4-byte int vs 4-byte float, so this only works
    because the *register's own type* (Int vs Single vs Float) does.
    """
    typedef = type(reg_type.resolve(code).definition)
    if typedef.__name__ == "I32":
        return "I32"
    if typedef.__name__ == "F32":
        return "F32"
    if typedef.__name__ == "F64":
        return "F64"
    return None


def _int_const_value(c: IRConst) -> Optional[int]:
    """Return the integer value of an IRConst INT, handling intRef objects."""
    if c.const_type != IRConst.ConstType.INT:
        return None
    val = c.value.value if hasattr(c.value, "value") else c.value
    return int(val)


def _signed_i32(val: int) -> int:
    """Convert an unsigned 32-bit constant back to signed when needed."""
    if val >= 0x80000000:
        return val - 0x100000000
    return val
