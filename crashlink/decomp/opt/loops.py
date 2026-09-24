"""
Loop-reroll and loop-lifting optimizers.
"""

from __future__ import annotations

import copy
from typing import Dict, List, Optional, Set, Tuple, cast


from ...core import tIndex
from ..ir import (
    IRStatement,
    IRExpression,
    IRBlock,
    IRLocal,
    IRArithmetic,
    IRAssign,
    IRCall,
    IRBoolExpr,
    IRConst,
    IRConditional,
    IRPrimitiveLoop,
    IRReturn,
    IRTrace,
    IRSwitch,
    IRWhileLoop,
    IRForEachLoop,
    IRIntRangeLoop,
    IRField,
    IRNew,
    IRCast,
    IRArrayLiteral,
    IRArrayAccess,
    IRRef,
    IREnumIndex,
    IREnumField,
    IRStringConvert,
    _get_type_in_code,
)
from . import (
    TraversingIROptimizer,
    _int_const_value,
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

    def _find_next_header(
        self, stmts: List[IRStatement], start: int, elem: IRLocal, value: int
    ) -> Optional[int]:
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


class IRUnrolledLoopRerollOptimizer(TraversingIROptimizer):
    """
    Rebuild a `for (i in a...b)` loop the Haxe compiler unrolled.

    A constant-bounds loop can be emitted as N copies of its body, each copy
    differing only in the values derived from the iteration index. This pass
    finds a run of structurally identical copies whose differing integer
    constants advance by a fixed step, and rewrites the run as a loop whose
    body recomputes those constants from the induction variable.

    Only exact arithmetic progressions over at least three copies qualify: two
    copies fit any step, and a non-uniform difference means the copies are not
    iterations of one loop.
    """

    #: Enough to cover a realistic unrolled body without scanning quadratically.
    _MAX_PERIOD = 64
    _MIN_COPIES = 3
    #: An unrolled loop and a handful of similar source statements compile to
    #: the same bytecode, so only collapse a run big enough that a loop is the
    #: better reading of it.
    _MIN_STATEMENTS = 8

    #: Nodes whose children this pass can enumerate and rebuild.
    _CHILD_ATTRS: dict = {
        IRAssign: ("target", "expr"),
        IRConditional: ("condition", "true_block", "false_block"),
        IRReturn: ("value",),
        IRTrace: ("msg",),
        IRCall: ("target", "args"),
        IRArithmetic: ("left", "right"),
        IRBoolExpr: ("left", "right"),
        IRCast: ("expr",),
        IRField: ("target",),
        IRArrayAccess: ("array", "index"),
        IRArrayLiteral: ("elements",),
        IRNew: ("constructor_args",),
        IRRef: ("target",),
        IRStringConvert: ("value",),
        IRConst: (),
        IRLocal: (),
    }

    #: Induction variable names, tried in order (then `i1`, `j1`, ...).
    _INDUCTION_NAMES = ("i", "j", "k")

    def optimize(self) -> None:
        # A rebuilt loop's variable must not shadow a local of the function or the
        # variable of a rebuilt loop around it, so every one gets a name nothing uses.
        self._used_names: Set[str] = {local.name for local in getattr(self.func, "locals", ())}
        pending: List[IRStatement] = [self.func.block] if hasattr(self.func, "block") else []
        seen: Set[int] = set()
        while pending:
            node = pending.pop()
            if id(node) in seen:
                continue
            seen.add(id(node))
            if isinstance(node, IRLocal):
                self._used_names.add(node.name)
            pending.extend(node.get_children())
        super().optimize()

    def _fresh_induction_name(self) -> str:
        suffix = 0
        while True:
            for base in self._INDUCTION_NAMES:
                name = f"{base}{suffix}" if suffix else base
                if name not in self._used_names:
                    self._used_names.add(name)
                    return name
            suffix += 1

    def visit_block(self, block: IRBlock) -> None:
        statements = block.statements
        # Each statement's shape, computed once: recomputing the shapes of everything
        # after every start position made long blocks quadratic.
        shapes: List[Optional[str]] = [self._shape(stmt) for stmt in statements]
        runs = self._run_lengths(shapes)
        start = 0
        while start < len(statements):
            rerolled = self._try_reroll(statements, start, shapes, runs[start])
            if rerolled is not None:
                # The loop has no shape, so it ends every run that reached it: positions
                # before it can't start matching now, and scanning just moves on.
                loop, consumed = rerolled
                statements = statements[:start] + [loop] + statements[start + consumed :]
                shapes = shapes[:start] + [None] + shapes[start + consumed :]
                runs = self._run_lengths(shapes)
            start += 1
        block.statements = statements

    @staticmethod
    def _run_lengths(shapes: List[Optional[str]]) -> List[int]:
        """For each position, how many shaped statements follow it (itself included)
        before one without a shape."""
        runs = [0] * (len(shapes) + 1)
        for i in range(len(shapes) - 1, -1, -1):
            runs[i] = runs[i + 1] + 1 if shapes[i] is not None else 0
        return runs

    def _try_reroll(
        self,
        statements: List[IRStatement],
        start: int,
        all_shapes: Optional[List[Optional[str]]] = None,
        run: Optional[int] = None,
    ) -> Optional[Tuple[IRIntRangeLoop, int]]:
        available = len(statements) - start
        if available < self._MIN_COPIES:
            return None
        shapes = all_shapes if all_shapes is not None else [self._shape(stmt) for stmt in statements]
        if run is None:
            run = self._run_lengths(shapes[start:])[0]
        if run < self._MIN_COPIES:
            return None

        for period in range(1, min(self._MAX_PERIOD, run // self._MIN_COPIES) + 1):
            copies = 1
            while (copies + 1) * period <= run and shapes[
                start + (copies - 1) * period : start + copies * period
            ] == shapes[start + copies * period : start + (copies + 1) * period]:
                copies += 1
            if copies < self._MIN_COPIES:
                continue
            if period * copies < self._MIN_STATEMENTS:
                continue
            if not self._copies_share_source_lines(statements, start, period, copies):
                continue
            loop = self._build_loop(statements, start, period, copies)
            if loop is not None:
                return loop, period * copies
        return None

    def _build_loop(
        self, statements: List[IRStatement], start: int, period: int, copies: int
    ) -> Optional[IRIntRangeLoop]:
        groups = [statements[start + k * period : start + (k + 1) * period] for k in range(copies)]
        constant_lists = [self._constants(group) for group in groups]
        first = constant_lists[0]
        if any(len(other) != len(first) for other in constant_lists[1:]):
            return None

        steps: List[int] = []
        for position, node in enumerate(first):
            values = [_int_const_value(consts[position]) for consts in constant_lists]
            if any(value is None for value in values):
                return None
            base = cast(int, values[0])
            step = cast(int, values[1]) - base
            if any(cast(int, values[k]) - base != step * k for k in range(copies)):
                return None
            steps.append(step)
        if not any(steps):
            # Nothing advances: these are repeated statements, not iterations.
            return None

        int_type = _get_type_in_code(self.func.code, "I32")
        elem = IRLocal(
            self._fresh_induction_name(), tIndex(self.func.code.types.index(int_type)), self.func.code
        )
        replacements = {
            id(node): self._induction_expr(elem, cast(int, _int_const_value(node)), step)
            for node, step in zip(first, steps)
            if step
        }
        body = IRBlock(self.func.code)
        body.statements = [self._rebuild(stmt, replacements) for stmt in groups[0]]
        loop = IRIntRangeLoop(
            self.func.code,
            elem,
            IRConst(self.func.code, IRConst.ConstType.INT, value=0),
            IRConst(self.func.code, IRConst.ConstType.INT, value=copies),
            body,
        )
        loop.adopt(*[stmt for group in groups for stmt in group])
        return loop

    def _copies_share_source_lines(
        self, statements: List[IRStatement], start: int, period: int, copies: int
    ) -> bool:
        """Every iteration of one loop comes from the same source lines.

        Repeated but distinct source statements carry distinct line numbers,
        which is the only evidence that separates them from an unrolled body.
        """
        lines = self._source_lines()
        if lines is None:
            return False
        signatures = []
        for k in range(copies):
            group = statements[start + k * period : start + (k + 1) * period]
            signature: List[int] = []
            for stmt in group:
                signature.extend(sorted(lines.get(idx, -1) for idx in stmt.src_op_idxs))
            signatures.append(signature)
        return all(signature == signatures[0] for signature in signatures[1:])

    def _source_lines(self) -> Optional[Dict[int, int]]:
        func = self.func.func
        debug = getattr(func, "debuginfo", None)
        if not getattr(func, "has_debug", False) or debug is None:
            return None
        return {index: ref.line for index, ref in enumerate(debug.value)}

    def _induction_expr(self, elem: IRLocal, base: int, step: int) -> IRExpression:
        term: IRExpression = elem
        if step != 1:
            term = IRArithmetic(
                self.func.code,
                elem,
                IRConst(self.func.code, IRConst.ConstType.INT, value=step),
                IRArithmetic.ArithmeticType.MUL,
            )
        if base:
            term = IRArithmetic(
                self.func.code,
                term,
                IRConst(self.func.code, IRConst.ConstType.INT, value=base),
                IRArithmetic.ArithmeticType.ADD,
            )
        return term

    def _shape(self, node: Optional[IRStatement]) -> Optional[str]:
        """A structural key that ignores integer constant values."""
        if node is None:
            return "-"
        if isinstance(node, IRBlock):
            parts = [self._shape(child) for child in node.statements]
            if any(part is None for part in parts):
                return None
            return "block(" + ",".join(cast(List[str], parts)) + ")"
        attrs = self._CHILD_ATTRS.get(type(node))
        if attrs is None:
            return None
        if isinstance(node, IRConst):
            if _int_const_value(node) is not None:
                return "int#"
            return f"const({node.const_type},{node.value!r})"
        if isinstance(node, IRLocal):
            return f"local({node.name})"
        parts = []
        for attr in attrs:
            value = getattr(node, attr, None)
            if isinstance(value, list):
                for item in value:
                    parts.append(self._shape(item))
            else:
                parts.append(self._shape(value))
        if any(part is None for part in parts):
            return None
        extra = ""
        if isinstance(node, IRField):
            extra = node.field_name
        elif isinstance(node, (IRArithmetic, IRBoolExpr)):
            extra = str(node.op)
        return f"{type(node).__name__}[{extra}](" + ",".join(cast(List[str], parts)) + ")"

    def _constants(self, nodes: List[IRStatement]) -> List[IRConst]:
        found: List[IRConst] = []

        def walk(node: Optional[IRStatement]) -> None:
            if node is None:
                return
            if isinstance(node, IRConst):
                if _int_const_value(node) is not None:
                    found.append(node)
                return
            if isinstance(node, IRBlock):
                for child in node.statements:
                    walk(child)
                return
            for attr in self._CHILD_ATTRS.get(type(node), ()):
                value = getattr(node, attr, None)
                if isinstance(value, list):
                    for item in value:
                        walk(item)
                else:
                    walk(value)

        for node in nodes:
            walk(node)
        return found

    def _rebuild(self, node: IRStatement, replacements: dict) -> IRStatement:
        if isinstance(node, IRConst) and id(node) in replacements:
            return replacements[id(node)]
        if isinstance(node, IRBlock):
            rebuilt_block = IRBlock(self.func.code)
            rebuilt_block.statements = [self._rebuild(child, replacements) for child in node.statements]
            return rebuilt_block
        attrs = self._CHILD_ATTRS.get(type(node), ())
        if not attrs:
            return node
        rebuilt = copy.copy(node)
        for attr in attrs:
            value = getattr(node, attr, None)
            if isinstance(value, list):
                setattr(rebuilt, attr, [self._rebuild(item, replacements) for item in value])
            elif value is not None:
                setattr(rebuilt, attr, self._rebuild(value, replacements))
        return rebuilt


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
        return not local.name.startswith("var")

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
            if (
                isinstance(cond.left, IRLocal)
                and isinstance(cond.right, IRField)
                and cond.right.field_name == "length"
            ):
                idx = cond.left
                arr = cond.right.target
        elif cond.op == IRBoolExpr.CompareType.GT:
            if (
                isinstance(cond.right, IRLocal)
                and isinstance(cond.left, IRField)
                and cond.left.field_name == "length"
            ):
                idx = cond.right
                arr = cond.left.target
        if idx is None or arr is None:
            return None
        if self._is_user_local(idx):
            return None
        body = loop.body
        if len(body.statements) < 2:
            return None

        # Two lowerings show up in practice. Plain: `elem = arr[idx]; idx++;`.
        # Snapshot: `snap = idx; idx++; elem = arr[snap];` - some compiler
        # versions save the pre-increment index into a second compiler temp
        # first, so the array access (which comes after the increment) can
        # still read the old value. Peel off a leading snapshot+increment
        # pair before falling through to the shared access-statement check.
        access_index = idx
        discarded: List[IRStatement] = []
        snapshot = body.statements[0]
        if (
            len(body.statements) >= 3
            and isinstance(snapshot, IRAssign)
            and isinstance(snapshot.target, IRLocal)
            and snapshot.target != idx
            and snapshot.expr == idx
            and not self._is_user_local(snapshot.target)
            and self._is_index_increment(body.statements[1], idx)
        ):
            access_index = snapshot.target
            discarded = [snapshot, body.statements[1]]
            access_stmt = body.statements[2]
            rest = body.statements[3:]
        else:
            access_stmt = body.statements[0]
            if not self._is_index_increment(body.statements[1], idx):
                return None
            discarded = [body.statements[1]]
            rest = body.statements[2:]

        if not isinstance(access_stmt, IRAssign) or not isinstance(access_stmt.target, IRLocal):
            return None
        if not isinstance(access_stmt.expr, IRArrayAccess):
            return None
        if access_stmt.expr.array != arr or access_stmt.expr.index != access_index:
            return None
        elem = access_stmt.target
        discarded.append(access_stmt)

        for s in rest:
            if self._stmt_reads_local(s, idx):
                return None
            if access_index != idx and self._stmt_reads_local(s, access_index):
                return None
            if self._stmt_assigns_local(s, elem):
                return None
        for s in body.statements:
            if self._stmt_assigns_local(s, arr):
                return None
        new_body = IRBlock(loop.code)
        new_body.statements = list(rest)
        foreach = IRForEachLoop(loop.code, elem, arr, new_body)
        # `loop` (the while) and the discarded body statements (index
        # snapshot if present, idx++, and the array-index read) are dropped
        # in favor of `foreach` and `rest` above.
        foreach.adopt(loop, *discarded)
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
        return not local.name.startswith("var")

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
            for child in stmt.get_children():
                if isinstance(child, IRBlock):
                    self.visit_block(child)
