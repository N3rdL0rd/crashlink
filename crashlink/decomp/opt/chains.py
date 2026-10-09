"""Chained assignments: `a = b = value`."""

from __future__ import annotations

import re
from typing import List, Optional, Set, Tuple

from ..ir import (
    IRAssign,
    IRBlock,
    IRCall,
    IRConst,
    IRExpression,
    IRField,
    IRLocal,
    IRStatement,
    IRStoreExpr,
)
from .inliner import _ReferenceAwareOptimizer


class IRChainAssignFolder(_ReferenceAwareOptimizer):
    """Folds one register stored to several places back into a chained assignment.

    `a = b = c = 42` evaluates `42` once into a register that is stored to `c`, `b` and
    `a` in turn (and `i = j = 1` stores it to `j`, then hands it to the setter of `i`).
    The register is a compiler temp read once per store; written as separate statements,
    each store would load its own constant, so the chain is rebuilt as nested
    assignment expressions while the register's reads are still visible, before the
    constant is copied into each of them.
    """

    def visit_block(self, block: IRBlock) -> None:
        statements = block.statements
        i = 0
        while i < len(statements):
            folded = self._try_fold(statements, i)
            if folded is None:
                i += 1
                continue
            replacement, consumed = folded
            statements[i : i + consumed] = replacement
            i += len(replacement)

    def _try_fold(self, statements: List[IRStatement], start: int) -> Optional[Tuple[List[IRStatement], int]]:
        first = statements[start]
        if not (
            isinstance(first, IRAssign)
            and isinstance(first.target, IRLocal)
            and re.fullmatch(r"var\d+", first.target.name)
            and isinstance(first.expr, IRExpression)
            and first.target.name not in self._address_names
            and not self._reads_address_taken(first.expr)
        ):
            return None
        temp = first.target
        stores: List[IRAssign] = []
        loads: List[IRAssign] = []  # class references the stores' receivers are loaded from
        j = start + 1
        while j < len(statements):
            candidate = statements[j]
            following = statements[j + 1] if j + 1 < len(statements) else None
            if (
                isinstance(candidate, IRAssign)
                and isinstance(candidate.target, IRLocal)
                and re.fullmatch(r"var\d+", candidate.target.name)
                and isinstance(candidate.expr, IRConst)
                and isinstance(following, IRAssign)
                and isinstance(following.target, IRField)
                and following.target.target == candidate.target
            ):
                loads.append(candidate)
                j += 1
                continue
            if not (
                isinstance(candidate, IRAssign)
                and candidate.expr == temp
                and self._store_target_ok(candidate.target, temp)
            ):
                break
            stores.append(candidate)
            j += 1
        if not stores:
            return None

        consumer: Optional[IRStatement] = None
        if len(stores) == 1:
            consumer = statements[j] if j < len(statements) else None
            if consumer is None or not self._consumer_ok(consumer, temp):
                return None
        # The register must not be read anywhere else: every other read would have to see the value.
        expected = len(stores) + (1 if consumer is not None else 0)
        if self._count_refs(self.func.block, temp.name) != expected + 1:
            return None

        chain: IRExpression = first.expr
        inner = stores if consumer is not None else stores[:-1]
        for store in inner:
            chain = IRStoreExpr(self.func.code, IRAssign(self.func.code, store.target, chain))
        if consumer is None:
            last = stores[-1]
            replacement: IRStatement = IRAssign(self.func.code, last.target, chain)
            replacement.adopt(first, *stores)
            return [*loads, replacement], 1 + len(loads) + len(stores)
        assert isinstance(consumer, (IRCall, IRAssign))
        call = consumer if isinstance(consumer, IRCall) else consumer.expr
        assert isinstance(call, IRCall)
        call.args = [chain if arg == temp else arg for arg in call.args]
        consumer.adopt(first, *stores)
        return [*loads, consumer], 2 + len(loads) + len(stores)

    def _store_target_ok(self, target: IRExpression, temp: IRLocal) -> bool:
        """A field of a local or of a class, whose receiver evaluates the same whenever it is read."""
        if not isinstance(target, IRField) or target == temp:
            return False
        receiver = target.target
        if isinstance(receiver, IRConst):
            return receiver.const_type == IRConst.ConstType.GLOBAL_OBJ
        return isinstance(receiver, IRLocal) and receiver != temp and receiver.name not in self._address_names

    def _consumer_ok(self, consumer: IRStatement, temp: IRLocal) -> bool:
        """A call (statement, or its result stored) that takes the register as an argument, with
        nothing but locals and constants evaluated before it."""
        if isinstance(consumer, IRAssign):
            if not isinstance(consumer.target, IRLocal) or not isinstance(consumer.expr, IRCall):
                return False
            call = consumer.expr
        elif isinstance(consumer, IRCall):
            call = consumer
        else:
            return False
        if call.target is not None and not isinstance(call.target, (IRConst, IRLocal)):
            return False
        if call.target == temp:
            return False
        if sum(1 for arg in call.args if arg == temp) != 1:
            return False
        return all(isinstance(arg, (IRConst, IRLocal)) for arg in call.args)

    def _count_refs(self, root: IRStatement, name: str) -> int:
        count = 0
        pending: List[IRStatement] = [root]
        visited: Set[int] = set()
        while pending:
            node = pending.pop()
            if isinstance(node, IRBlock):
                # Shared continuation blocks are reachable from several parents.
                if id(node) in visited:
                    continue
                visited.add(id(node))
            if isinstance(node, IRLocal) and node.name == name:
                count += 1
            pending.extend(node.get_children())
        return count
