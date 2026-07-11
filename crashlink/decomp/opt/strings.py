"""
String-related IR optimizers.
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


class IRGlobalStringOptimizer(TraversingIROptimizer):
    """
    Optimizes `GetGlobal` operations that resolve to constant strings.
    It replaces an assignment from a global `String` object with a direct
    assignment of a new IRConst type that holds the string value.

    This transforms:
        reg = <IRConst type=OBJ, value=<Obj: ...>>
    into:
        reg = <IRConst type=GLOBAL_STRING, value="the actual string">
    """

    TARGET_OPCODES = {"GetGlobal"}

    def visit_block(self, block: IRBlock) -> None:
        for stmt in block.statements:
            if not isinstance(stmt, IRAssign):
                continue

            assign_stmt = stmt
            expr = assign_stmt.expr

            if not (isinstance(expr, IRConst) and expr.const_type == IRConst.ConstType.GLOBAL_OBJ):
                continue

            if not (expr.original_index and isinstance(expr.original_index, gIndex)):
                continue

            global_idx = expr.original_index.value
            try:
                string_value = self.func.code.const_str(global_idx)

                dbg_print(f"IRGlobalStringOptimizer: Optimizing GetGlobal for string '{string_value}'")

                new_string_const = IRConst(self.func.code, IRConst.ConstType.GLOBAL_STRING, value=string_value)

                assign_stmt.expr = new_string_const

            except (ValueError, TypeError):
                pass


class IRStringIntConcatOptimizer(TraversingIROptimizer):
    """
    Collapses the HashLink string+int lowering pattern at the IR level.

    HashLink compiles `str + int` as:
        var_bytes = itos(int_local, ref(int_local))
        var_str   = String.__alloc__(var_bytes, int_local)  [or inline itos]
        result    = String.__add__(left, var_str)

    Does a single forward pass tracking the most-recent assignment for each
    local so that reused registers (same var7 for multiple conversions) are
    resolved correctly.  Both top-level __alloc__ assignments and __alloc__
    nested inside __add__ are collapsed to the plain integer local.
    """

    def _check_conversion_call(self, expr: IRExpression) -> Optional[Tuple["IRLocal", "IRLocal"]]:
        """
        If `expr` is itos(val, ref) or ftos(val, ref), return (value_local, count_ref_local).
        For itos, HashLink uses the same variable as both value and ref storage.
        For ftos, a separate int variable stores the byte count.
        """
        if not (
            isinstance(expr, IRCall) and isinstance(expr.target, IRConst) and isinstance(expr.target.value, Native)
        ):
            return None
        func_name = expr.target.value.name.resolve(self.func.code)
        if func_name not in ("itos", "ftos"):
            return None
        if len(expr.args) < 2:
            return None
        if not isinstance(expr.args[0], IRLocal):
            return None
        # arg1 is the ref where byte count is stored back (IRLocal, IRRef, or IRRefNew wrapping one)
        count_ref: Optional[IRLocal] = None
        arg1 = expr.args[1]
        if isinstance(arg1, IRLocal):
            count_ref = arg1
        elif isinstance(arg1, (IRRef, IRRefNew)) and isinstance(arg1.target, IRLocal):
            count_ref = arg1.target
        if count_ref is None:
            return None
        return expr.args[0], count_ref

    def _try_collapse_alloc(self, expr: IRExpression, current_assigns: Dict[str, "IRAssign"]) -> Optional[IRLocal]:
        """
        If `expr` is __alloc__(itos/ftos_bytes, count_ref) with matching count_ref, return
        the value local (int for itos, float for ftos). `current_assigns` maps local names
        to their most-recent assignments seen so far.
        """
        if not isinstance(expr, IRCall):
            return None
        if not (isinstance(expr.target, IRConst) and isinstance(expr.target.value, Function)):
            return None
        if self.func.code.partial_func_name(expr.target.value) != "__alloc__":
            return None
        if len(expr.args) != 2:
            return None

        bytes_arg, int_arg = expr.args[0], expr.args[1]
        if not isinstance(int_arg, IRLocal):
            return None

        value_local: Optional[IRLocal] = None
        count_ref_local: Optional[IRLocal] = None
        consumed_stmt: Optional[IRAssign] = None
        if isinstance(bytes_arg, IRCall):
            result = self._check_conversion_call(bytes_arg)
            if result:
                value_local, count_ref_local = result
        elif isinstance(bytes_arg, IRLocal) and bytes_arg.name in current_assigns:
            defn = current_assigns[bytes_arg.name]
            if isinstance(defn.expr, IRCall):
                result = self._check_conversion_call(defn.expr)
                if result:
                    value_local, count_ref_local = result
                    consumed_stmt = defn

        if value_local is None or count_ref_local is None:
            return None

        # Direct match: count_ref is the same local as int_arg
        if count_ref_local.name == int_arg.name:
            if consumed_stmt is not None:
                self._consumed.add(id(consumed_stmt))
                self._target_stmt.adopt(consumed_stmt)
            return value_local

        # Indirect match: count_ref = &int_arg (before IRConditionInliner runs, the Ref
        # is a separate local var6 = &var13; we need to look through it)
        if count_ref_local.name in current_assigns:
            ref_defn = current_assigns[count_ref_local.name]
            if isinstance(ref_defn.expr, (IRRef, IRRefNew)) and isinstance(ref_defn.expr.target, IRLocal):
                if ref_defn.expr.target.name == int_arg.name:
                    if consumed_stmt is not None:
                        self._consumed.add(id(consumed_stmt))
                        self._target_stmt.adopt(consumed_stmt)
                    return value_local

        return None

    def _rewrite_expr(self, expr: IRExpression, current_assigns: Dict[str, "IRAssign"]) -> IRExpression:
        """Recursively collapse __alloc__ within an expression."""
        collapsed = self._try_collapse_alloc(expr, current_assigns)
        if collapsed is not None:
            dbg_print(f"IRStringIntConcatOptimizer: collapsing __alloc__(...,{collapsed.name}) → {collapsed.name}")
            return collapsed
        if isinstance(expr, IRCall):
            expr.args = [self._rewrite_expr(a, current_assigns) for a in expr.args]
        return expr

    def visit_block(self, block: IRBlock) -> None:
        current_assigns: Dict[str, IRAssign] = {}
        self._consumed: Set[int] = getattr(self, "_consumed", set())
        for stmt in block.statements:
            if isinstance(stmt, IRAssign):
                if isinstance(stmt.target, IRLocal):
                    current_assigns[stmt.target.name] = stmt
                if isinstance(stmt.expr, IRExpression):
                    self._target_stmt = stmt
                    stmt.expr = self._rewrite_expr(stmt.expr, current_assigns)

        # A bytes-temp assignment fully consumed by a collapse above is now
        # dead — its only use (the __alloc__ call) no longer reads it — but
        # the register it occupies is frequently reused later in the same
        # block for an unrelated value, so leaving the statement in place
        # would have a later, completely unrelated assignment's debug name
        # misleadingly attached to this stale `itos`/`ftos` call.
        if self._consumed:
            block.statements = [s for s in block.statements if id(s) not in self._consumed]
            self._consumed = set()


class IRStringAllocOptimizer(TraversingIROptimizer):
    """
    Folds the inlined body of `String.__alloc__(bytes, length)` back into a call.

    Because `__alloc__` is an inline static method, call sites lower to:
        var s = new String();
        s.bytes = bytesExpr;
        s.length = lengthExpr;
    This optimizer recognises that sequence and replaces it with
    `String.__alloc__(bytesExpr, lengthExpr)`, which pseudo can render as the
    source idiom `__alloc__(bytes, length)` inside the String class.
    """

    TARGET_OPCODES = {"New"}

    def __init__(self, function: "IRFunction"):
        super().__init__(function)
        self.alloc_func: Optional[Function] = self._find_string_alloc()

    def _find_string_alloc(self) -> Optional[Function]:
        for f in self.func.code.functions:
            try:
                path = f.resolve_file(self.func.code).replace("\\", "/")
            except Exception:
                continue
            if "/std/hl/_std/String.hx" not in path:
                continue
            if self.func.code.partial_func_name(f) == "__alloc__":
                return f
        return None

    def _match_new_string(self, stmt: IRStatement) -> Optional[IRLocal]:
        if (
            isinstance(stmt, IRAssign)
            and isinstance(stmt.target, IRLocal)
            and isinstance(stmt.expr, IRNew)
            and not stmt.expr.constructor_args
        ):
            type_name = disasm.type_name(self.func.code, stmt.expr.get_type())
            if type_name == "String":
                return stmt.target
        return None

    def _match_bytes_assign(self, stmt: IRStatement, local: IRLocal) -> Optional[IRExpression]:
        if (
            isinstance(stmt, IRAssign)
            and isinstance(stmt.target, IRField)
            and stmt.target.target == local
            and stmt.target.field_name == "bytes"
        ):
            return stmt.expr
        return None

    def _match_length_assign(self, stmt: IRStatement, local: IRLocal) -> Optional[IRExpression]:
        if (
            isinstance(stmt, IRAssign)
            and isinstance(stmt.target, IRField)
            and stmt.target.target == local
            and stmt.target.field_name == "length"
        ):
            return stmt.expr
        return None

    def _statement_touches_local(self, stmt: IRStatement, local: IRLocal) -> bool:
        """True if stmt reads or writes `local` (including via a field target)."""
        if isinstance(stmt, IRAssign):
            if stmt.target == local or (
                isinstance(stmt.target, IRExpression) and self._expr_uses_local(stmt.target, local)
            ):
                return True
            if stmt.expr is not None and self._expr_uses_local(stmt.expr, local):
                return True
        elif isinstance(stmt, IRReturn):
            if stmt.value is not None and self._expr_uses_local(stmt.value, local):
                return True
        elif isinstance(stmt, IRCall):
            if stmt.target is not None and self._expr_uses_local(stmt.target, local):
                return True
            if any(self._expr_uses_local(a, local) for a in stmt.args):
                return True
        elif isinstance(stmt, IRExpression):
            if self._expr_uses_local(stmt, local):
                return True
        return False

    def _expr_uses_local(self, expr: Optional[IRStatement], local: IRLocal) -> bool:
        if expr is None:
            return False
        if expr == local:
            return True
        for child in expr.get_children():
            if child is not expr and self._expr_uses_local(child, local):
                return True
        return False

    def _collect_free_locals(self, expr: IRExpression) -> Set[str]:
        """Names of all locals read by `expr`."""
        names: Set[str] = set()

        def walk(e: Optional[IRStatement]) -> None:
            if e is None:
                return
            if isinstance(e, IRLocal):
                names.add(e.name)
            for child in e.get_children():
                if child is not e:
                    walk(child)

        walk(expr)
        return names

    def _stmt_reassigns_any(self, stmt: IRStatement, names: Set[str]) -> bool:
        """True if stmt (or any nested statement) assigns to a local in `names`."""
        if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal) and stmt.target.name in names:
            return True
        for child in stmt.get_children():
            if child is not stmt and self._stmt_reassigns_any(child, names):
                return True
        return False

    def visit_block(self, block: IRBlock) -> None:
        if self.alloc_func is None or self.func.func.findex.value == self.alloc_func.findex.value:
            for stmt in block.statements:
                for child in stmt.get_children():
                    if isinstance(child, IRBlock):
                        self.visit_block(child)
            return

        remove: Set[int] = set()
        i = 0
        while i < len(block.statements):
            stmt = block.statements[i]
            local = self._match_new_string(stmt)
            if local is not None:
                bytes_idx: Optional[int] = None
                len_idx: Optional[int] = None
                for j in range(i + 1, len(block.statements)):
                    nxt = block.statements[j]
                    if bytes_idx is None and self._match_bytes_assign(nxt, local) is not None:
                        bytes_idx = j
                        continue
                    if bytes_idx is not None and len_idx is None and self._match_length_assign(nxt, local) is not None:
                        len_idx = j
                        break
                    if self._statement_touches_local(nxt, local):
                        break
                if bytes_idx is not None and len_idx is not None:
                    bytes_expr = cast(IRExpression, self._match_bytes_assign(block.statements[bytes_idx], local))
                    length_expr = cast(IRExpression, self._match_length_assign(block.statements[len_idx], local))
                    # Moving the call to the allocation site evaluates its arguments
                    # earlier. That is only safe if no free variable of the bytes
                    # or length expression is reassigned between the allocation and
                    # the field writes (e.g. String.fromUCS2 computes the length
                    # after creating the empty string).
                    free_names = self._collect_free_locals(bytes_expr) | self._collect_free_locals(length_expr)
                    free_names.discard(local.name)
                    safe = True
                    for k in range(i + 1, len_idx):
                        if self._stmt_reassigns_any(block.statements[k], free_names):
                            safe = False
                            break
                    if safe and isinstance(stmt, IRAssign):
                        target = IRConst(
                            self.func.code,
                            IRConst.ConstType.FUN,
                            idx=self.alloc_func.findex,
                        )
                        stmt.expr = IRCall(
                            self.func.code,
                            IRCall.CallType.FUNC,
                            target,
                            [bytes_expr, length_expr],
                        )
                        stmt.adopt(block.statements[bytes_idx], block.statements[len_idx])
                        remove.add(bytes_idx)
                        remove.add(len_idx)
                        i = len_idx + 1
                        continue
            i += 1

        if remove:
            block.statements = [s for idx, s in enumerate(block.statements) if idx not in remove]

        for stmt in block.statements:
            for child in stmt.get_children():
                if isinstance(child, IRBlock):
                    self.visit_block(child)


class IRTraceOptimizer(TraversingIROptimizer):
    """
    Finds the common `haxe.Log.trace` pattern with an anonymous object for
    position and collapses it into a single IRTrace statement.
    """

    TARGET_OPCODES = {"New"}

    def visit_block(self, block: IRBlock) -> None:
        made_change = True
        while made_change:
            made_change = False
            new_statements: List[IRStatement] = []
            i = 0
            while i < len(block.statements):
                stmt = block.statements[i]
                if DEBUG:
                    dbg_print(f"[TraceOpt] Analyzing statement {i}: {stmt}")

                if isinstance(stmt, IRConditional) and stmt.true_block is not None and stmt.false_block is not None:
                    branched = self._try_branched_trace(stmt, block.statements, i)
                    if branched is not None:
                        true_tail, false_tail, msg_true, msg_false, pos_true, pos_false, consumed_after = branched
                        old_true_stmts = stmt.true_block.statements
                        old_false_stmts = stmt.false_block.statements
                        true_trace = IRTrace(self.func.code, msg_true, pos_true)
                        false_trace = IRTrace(self.func.code, msg_false, pos_false)
                        true_trace.adopt(*old_true_stmts[len(true_tail) :])
                        false_trace.adopt(*old_false_stmts[len(false_tail) :])
                        stmt.true_block.statements = true_tail + [true_trace]
                        stmt.false_block.statements = false_tail + [false_trace]
                        # The shared position-field assigns + hoisted call after the
                        # conditional are dropped outright; fold their opcodes onto
                        # the conditional itself since neither branch alone owns them.
                        stmt.adopt(*block.statements[i + 1 : i + 1 + consumed_after])
                        new_statements.append(stmt)
                        i += 1 + consumed_after
                        made_change = True
                        continue

                temp_local = None
                start_idx = i
                extra_adopt: List[IRStatement] = []

                if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal):
                    if isinstance(stmt.expr, IRNew) and stmt.expr.get_type().definition.__class__ == DynObj:
                        temp_local = stmt.target
                        start_idx = i + 1
                    else:
                        new_statements.append(stmt)
                        i += 1
                        continue
                elif isinstance(stmt, IRAssign) and isinstance(stmt.target, IRField):
                    candidate = stmt.target.target
                    if isinstance(candidate, IRLocal):
                        temp_local = candidate
                        start_idx = i
                    else:
                        new_statements.append(stmt)
                        i += 1
                        continue
                else:
                    new_statements.append(stmt)
                    i += 1
                    continue

                if temp_local is None:
                    new_statements.append(stmt)
                    i += 1
                    continue

                pos_info: Dict[str, Any] = {}
                j = start_idx

                while j < len(block.statements):
                    next_stmt = block.statements[j]
                    if isinstance(next_stmt, IRAssign) and isinstance(next_stmt.target, IRField):
                        field_target = next_stmt.target
                        if field_target.target == temp_local:
                            field_name = field_target.field_name
                            if isinstance(next_stmt.expr, IRConst):
                                pos_info[field_name] = next_stmt.expr.value
                                if DEBUG:
                                    dbg_print(
                                        f"[TraceOpt]  -> Collected const field: {field_name} = {next_stmt.expr.value!r}"
                                    )
                                j += 1
                                continue
                            elif isinstance(next_stmt.expr, IRLocal):
                                pos_info[field_name] = next_stmt.expr
                                if DEBUG:
                                    dbg_print(f"[TraceOpt]  -> Collected local field: {field_name} = {next_stmt.expr}")
                                j += 1
                                continue
                    elif isinstance(next_stmt, IRAssign) and isinstance(next_stmt.target, IRLocal):
                        j += 1
                        continue
                    break

                if j < len(block.statements):
                    call_stmt = block.statements[j]
                    if DEBUG:
                        dbg_print(f"[TraceOpt] Checking statement {j} as potential trace call: {call_stmt}")

                    is_valid_trace_call = False
                    if isinstance(call_stmt, IRCall) and len(call_stmt.args) == 2:
                        last_arg = call_stmt.args[1]

                        is_our_var = (isinstance(last_arg, IRLocal) and last_arg == temp_local) or (
                            isinstance(last_arg, IRCast) and last_arg.expr == temp_local
                        )

                        is_trace_func = False
                        if isinstance(call_stmt.target, IRField) and call_stmt.target.field_name == "trace":
                            if DEBUG:
                                dbg_print("[TraceOpt]  -> Call target is a field named 'trace'.")
                            target_obj = call_stmt.target.target
                            if (
                                isinstance(target_obj, IRConst)
                                and isinstance(target_obj.value, Type)
                                and isinstance(target_obj.value.definition, Obj)
                            ):
                                obj_name = target_obj.value.definition.name.resolve(self.func.code)
                                if "haxe.$Log" in obj_name:
                                    is_trace_func = True

                        if DEBUG:
                            dbg_print(f"[TraceOpt]  -> Is function 'haxe.Log.trace'? {is_trace_func}")

                        if is_our_var and is_trace_func:
                            is_valid_trace_call = True

                    elif DEBUG:
                        dbg_print(f"[TraceOpt]  -> FAILED: Statement is not an IRCall with 2 arguments.")

                    if is_valid_trace_call:
                        assert isinstance(call_stmt, IRCall)
                        msg_expr = call_stmt.args[0]
                        if (
                            isinstance(msg_expr, IRLocal)
                            and msg_expr.reg_idx is not None
                            and msg_expr.reg_idx not in self.func._user_reg_indices
                            and new_statements
                            and isinstance(new_statements[-1], IRAssign)
                            and new_statements[-1].target == msg_expr
                        ):
                            # inline if this is obviously compiler-generated (one use, right before the call, has no user assign)
                            _popped = new_statements.pop()
                            extra_adopt.append(_popped)
                            msg_expr = _popped.expr if isinstance(_popped, IRAssign) else msg_expr
                        resolved_pos: Dict[str, Any] = {}
                        for k, v in pos_info.items():
                            if isinstance(v, IRLocal):
                                for s_idx in range(start_idx, j):
                                    s = block.statements[s_idx]
                                    if isinstance(s, IRAssign) and s.target == v and isinstance(s.expr, IRConst):
                                        try:
                                            resolved_pos[k] = int(
                                                s.expr.value.value if hasattr(s.expr.value, "value") else s.expr.value
                                            )
                                        except (ValueError, TypeError):
                                            resolved_pos[k] = v
                                        break
                                else:
                                    resolved_pos[k] = v
                            else:
                                resolved_pos[k] = v
                        trace_stmt = IRTrace(self.func.code, msg_expr, resolved_pos)
                        trace_stmt.adopt(*block.statements[i : j + 1], *extra_adopt)
                        new_statements.append(trace_stmt)

                        i = j + 1
                        made_change = True
                        continue
                    elif DEBUG:
                        dbg_print(f"[TraceOpt] FAILED: Pattern did not match for trace call.")

                new_statements.append(stmt)
                i += 1

            block.statements = new_statements

    def _match_trace_prep(
        self, stmts: List[IRStatement]
    ) -> Optional[Tuple[List[IRStatement], IRLocal, IRLocal, Dict[str, Any]]]:
        """
        Matches a branch that ends with the `haxe.Log.trace` position-object setup
        (`fun = ...trace; temp = new DynObj; temp.field = const; ...`) but has no
        call of its own — the call was hoisted out to a point after the branches
        converge. Returns (statements before the pattern, fun local, temp local,
        position info) or None if the branch doesn't end in this shape.
        """
        new_idx = None
        temp_local = None
        for k, s in enumerate(stmts):
            if (
                isinstance(s, IRAssign)
                and isinstance(s.target, IRLocal)
                and isinstance(s.expr, IRNew)
                and s.expr.get_type().definition.__class__ == DynObj
            ):
                new_idx = k
                temp_local = s.target
                break
        if new_idx is None or temp_local is None:
            return None

        fun_local = None
        for k in range(new_idx - 1, -1, -1):
            s = stmts[k]
            if isinstance(s, IRAssign) and isinstance(s.target, IRLocal) and isinstance(s.expr, IRField):
                if s.expr.field_name == "trace":
                    fun_local = s.target
                break
        if fun_local is None:
            return None

        pos_info: Dict[str, Any] = {}
        j = new_idx + 1
        while j < len(stmts):
            s = stmts[j]
            if (
                isinstance(s, IRAssign)
                and isinstance(s.target, IRField)
                and s.target.target == temp_local
                and isinstance(s.expr, IRConst)
            ):
                pos_info[s.target.field_name] = s.expr.value
                j += 1
                continue
            break
        if j != len(stmts):
            return None

        return stmts[:new_idx], fun_local, temp_local, pos_info

    def _resolve_local_value(self, stmts: List[IRStatement], local: IRExpression) -> Optional[IRExpression]:
        """Find the most recent assignment to `local` within `stmts`, searching from the end."""
        for s in reversed(stmts):
            if isinstance(s, IRAssign) and isinstance(s.target, IRLocal) and s.target == local:
                return s.expr
        return None

    def _try_branched_trace(
        self, cond: "IRConditional", statements: List[IRStatement], idx: int
    ) -> Optional[
        Tuple[List[IRStatement], List[IRStatement], IRExpression, IRExpression, Dict[str, Any], Dict[str, Any], int]
    ]:
        """
        Matches `trace(msg)` calls that got duplicated into each branch of an
        if/else by the Haxe/HL compiler, then merged back into a single shared
        call after the branches converge (since both calls have the same target
        and arg count, just a different message/line number). Returns the new
        branch tails, per-branch resolved message + position info, and how many
        extra statements after the conditional the merged call consumed.
        """
        true_block = cond.true_block
        false_block = cond.false_block
        if true_block is None or false_block is None:
            return None

        true_match = self._match_trace_prep(true_block.statements)
        false_match = self._match_trace_prep(false_block.statements)
        if true_match is None or false_match is None:
            return None
        true_tail, fun_local_t, temp_local_t, pos_t = true_match
        false_tail, fun_local_f, temp_local_f, pos_f = false_match
        if fun_local_t != fun_local_f or temp_local_t != temp_local_f:
            return None

        j = idx + 1
        shared_pos: Dict[str, Any] = {}
        while j < len(statements):
            s = statements[j]
            if (
                isinstance(s, IRAssign)
                and isinstance(s.target, IRField)
                and s.target.target == temp_local_t
                and isinstance(s.expr, IRConst)
            ):
                shared_pos[s.target.field_name] = s.expr.value
                j += 1
                continue
            break
        if j >= len(statements):
            return None

        call_stmt = statements[j]
        if not (isinstance(call_stmt, IRCall) and len(call_stmt.args) == 2):
            return None
        last_arg = call_stmt.args[1]
        is_our_var = (isinstance(last_arg, IRLocal) and last_arg == temp_local_t) or (
            isinstance(last_arg, IRCast) and last_arg.expr == temp_local_t
        )
        if not is_our_var:
            return None

        is_trace_func = False
        target = call_stmt.target
        if isinstance(target, IRField) and target.field_name == "trace":
            target_obj = target.target
            if (
                isinstance(target_obj, IRConst)
                and isinstance(target_obj.value, Type)
                and isinstance(target_obj.value.definition, Obj)
            ):
                obj_name = target_obj.value.definition.name.resolve(self.func.code)
                if "haxe.$Log" in obj_name:
                    is_trace_func = True
        elif isinstance(target, IRLocal) and target == fun_local_t:
            is_trace_func = True
        if not is_trace_func:
            return None

        msg_arg = call_stmt.args[0]
        msg_true: IRExpression = msg_arg
        msg_false: IRExpression = msg_arg
        if isinstance(msg_arg, IRLocal):
            resolved_true = self._resolve_local_value(true_block.statements, msg_arg)
            resolved_false = self._resolve_local_value(false_block.statements, msg_arg)
            if resolved_true is not None:
                msg_true = resolved_true
            if resolved_false is not None:
                msg_false = resolved_false

        final_pos_t = {**pos_t, **shared_pos}
        final_pos_f = {**pos_f, **shared_pos}
        consumed_after = j - idx
        return true_tail, false_tail, msg_true, msg_false, final_pos_t, final_pos_f, consumed_after


class IRStringConcatFolder(TraversingIROptimizer):
    """
    Folds chained string-concat temporaries into a single inline expression.

    HashLink often lowers `trace("..." + x)` or `var s = "..." + x` to:
        temp = "...";
        temp = String.__add__(temp, x);
        temp = String.__add__(temp, y);
        ... use(temp);

    After dead-temp cleanup the assignments become adjacent.  This pass collapses
    the whole chain into a single String.__add__ expression at the use site, which
    the pseudocode printer then renders with Haxe's `+` operator.
    """

    def visit_block(self, block: IRBlock) -> None:
        made_change = True
        while made_change:
            made_change = False
            new_statements: List[IRStatement] = []
            i = 0
            n = len(block.statements)
            while i < n:
                fold = self._try_fold_concat_temp(block.statements, i)
                if fold is not None:
                    use_stmt, consumed = fold
                    new_statements.append(use_stmt)
                    i += consumed
                    made_change = True
                    continue
                new_statements.append(block.statements[i])
                i += 1
            block.statements = new_statements

    def _try_fold_concat_temp(self, statements: List[IRStatement], start: int) -> Optional[Tuple[IRStatement, int]]:
        # Look for: temp = init_string_expr;
        #           temp = String.__add__(temp, rhs1);
        #           temp = String.__add__(temp, rhs2);
        #           ...
        #           use(temp)   (trace(temp) or target = temp)
        if start >= len(statements):
            return None

        first = statements[start]
        if not (isinstance(first, IRAssign) and isinstance(first.target, IRLocal) and self._is_string_expr(first.expr)):
            return None

        temp = first.target
        init_expr = first.expr

        # Collect a chain of adjacent `temp = String.__add__(temp, rhs)` assignments.
        i = start + 1
        parts: List[IRExpression] = [init_expr]
        while i < len(statements):
            stmt = statements[i]
            if not isinstance(stmt, IRAssign) or stmt.target != temp:
                break
            add_call = stmt.expr
            if not self._is_string_add_with_temp(add_call, temp):
                break
            assert isinstance(add_call, IRCall)
            rhs = add_call.args[1]
            if self._expr_contains_local(rhs, temp):
                break
            parts.append(rhs)
            i += 1

        if len(parts) == 1:
            return None  # No concat happened.

        # Now find the single use of `temp` after the chain.  We allow unrelated
        # statements in between as long as they don't touch `temp`.
        use_idx: Optional[int] = None
        folded_expr_for_use: Optional[IRCall] = None
        for j in range(i, len(statements)):
            stmt = statements[j]
            if self._statement_assigns_local(stmt, temp):
                break
            if self._statement_reads_local(stmt, temp):
                if use_idx is not None:
                    return None
                if isinstance(stmt, IRTrace) and stmt.msg == temp:
                    use_idx = j
                elif isinstance(stmt, IRAssign) and stmt.expr == temp:
                    use_idx = j
                elif isinstance(stmt, IRAssign) and self._is_string_add_with_temp(stmt.expr, temp):
                    use_idx = j
                    folded_expr_for_use = self._fold_concat(parts + [cast(IRCall, stmt.expr).args[1]])
                else:
                    return None

        if use_idx is None:
            return None

        use_stmt = statements[use_idx]
        if folded_expr_for_use is None:
            folded_expr_for_use = self._fold_concat(parts)

        new_use: IRStatement
        if isinstance(use_stmt, IRTrace):
            new_use = IRTrace(
                code=self.func.code,
                msg=folded_expr_for_use,
                pos_info=use_stmt.pos_info,
            )
        elif isinstance(use_stmt, IRAssign):
            new_use = IRAssign(
                code=self.func.code,
                target=use_stmt.target,
                expr=folded_expr_for_use,
            )
        else:
            return None

        new_use.adopt(*statements[start : use_idx + 1])
        return new_use, use_idx - start + 1

    def _is_string_expr(self, expr: IRExpression) -> bool:
        if isinstance(expr, IRConst) and isinstance(expr.value, str):
            return True
        if isinstance(expr, IRLocal):
            return True
        if isinstance(expr, IRCall):
            return self._is_string_add(expr)
        return False

    def _is_string_add(self, expr: IRExpression) -> bool:
        if not isinstance(expr, IRCall):
            return False
        if not (isinstance(expr.target, IRConst) and isinstance(expr.target.value, Function)):
            return False
        return self.func.code.partial_func_name(expr.target.value) == "__add__"

    def _is_string_add_with_temp(self, expr: IRExpression, temp: IRLocal) -> bool:
        if not self._is_string_add(expr):
            return False
        assert isinstance(expr, IRCall)
        return len(expr.args) == 2 and expr.args[0] == temp

    def _fold_concat(self, parts: List[IRExpression]) -> IRCall:
        # Build a left-associative String.__add__ chain from the parts.
        add_func = self._string_add_func()
        result: IRExpression = parts[0]
        for part in parts[1:]:
            result = IRCall(
                code=self.func.code,
                call_type=IRCall.CallType.FUNC,
                target=IRConst(self.func.code, IRConst.ConstType.FUN, idx=add_func.findex),
                args=[result, part],
            )
        assert isinstance(result, IRCall)
        return result

    def _string_add_func(self) -> Function:
        # Locate String.__add__ in the bytecode.  It is needed often enough that
        # caching it avoids creating mismatched call targets.
        for f in self.func.code.functions:
            if self.func.code.partial_func_name(f) == "__add__":
                try:
                    path = f.resolve_file(self.func.code)
                except Exception:
                    continue
                if "String.hx" in path.replace("\\", "/"):
                    return f
        raise DecompError("String.__add__ not found in bytecode")

    def _statement_assigns_local(self, stmt: IRStatement, local: IRLocal) -> bool:
        if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal) and stmt.target == local:
            return True
        for child in stmt.get_children():
            if isinstance(child, IRBlock):
                if any(self._statement_assigns_local(s, local) for s in child.statements):
                    return True
            elif self._statement_assigns_local(child, local):
                return True
        return False

    def _statement_reads_local(self, stmt: IRStatement, local: IRLocal) -> bool:
        if isinstance(stmt, IRAssign):
            if isinstance(stmt.target, IRExpression) and self._expr_contains_local(stmt.target, local):
                return True
            if stmt.expr is not None and self._expr_contains_local(stmt.expr, local):
                return True
        elif isinstance(stmt, IRReturn):
            if stmt.value is not None and self._expr_contains_local(stmt.value, local):
                return True
        elif isinstance(stmt, IRCall):
            if stmt.target is not None and self._expr_contains_local(stmt.target, local):
                return True
            for arg in stmt.args:
                if self._expr_contains_local(arg, local):
                    return True
        elif isinstance(stmt, IRTrace):
            if self._expr_contains_local(stmt.msg, local):
                return True
        elif isinstance(stmt, IRConditional):
            if self._expr_contains_local(stmt.condition, local):
                return True
        elif isinstance(stmt, IRWhileLoop):
            if self._expr_contains_local(stmt.condition, local):
                return True
        elif isinstance(stmt, IRPrimitiveLoop):
            if self._statement_reads_local(stmt.condition, local):
                return True
        elif isinstance(stmt, IRSwitch):
            if self._expr_contains_local(stmt.value, local):
                return True
        return False

    def _expr_contains_local(self, expr: IRExpression, local: IRLocal) -> bool:
        if expr == local:
            return True
        if isinstance(expr, (IRArithmetic, IRBoolExpr)):
            if expr.left is not None and self._expr_contains_local(expr.left, local):
                return True
            if expr.right is not None and self._expr_contains_local(expr.right, local):
                return True
        elif isinstance(expr, IRCall):
            if expr.target is not None and self._expr_contains_local(expr.target, local):
                return True
            for arg in expr.args:
                if self._expr_contains_local(arg, local):
                    return True
        elif isinstance(expr, IRField):
            if self._expr_contains_local(expr.target, local):
                return True
        elif isinstance(expr, IRCast):
            if self._expr_contains_local(expr.expr, local):
                return True
        elif isinstance(expr, IRArrayAccess):
            if self._expr_contains_local(expr.array, local):
                return True
            if self._expr_contains_local(expr.index, local):
                return True
        elif isinstance(expr, IRRef):
            if self._expr_contains_local(expr.target, local):
                return True
        elif isinstance(expr, IREnumConstruct):
            for arg in expr.args:
                if self._expr_contains_local(arg, local):
                    return True
        elif isinstance(expr, (IREnumIndex, IREnumField)):
            if self._expr_contains_local(expr.value, local):
                return True
        elif isinstance(expr, IRNew):
            for arg in expr.constructor_args:
                if self._expr_contains_local(arg, local):
                    return True
        for child in expr.get_children():
            if isinstance(child, IRExpression) and self._expr_contains_local(child, local):
                return True
        return False
