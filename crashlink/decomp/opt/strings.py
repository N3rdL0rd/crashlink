"""
String-related IR optimizers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple, cast

if TYPE_CHECKING:
    from ..function import IRFunction

from ...core import (
    DynObj,
    Function,
    Native,
    Obj,
    Type,
    Virtual,
    gIndex,
)
from ...errors import DecompError
from ...globals import DEBUG, dbg_print
from ... import disasm
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
    IRField,
    IRNew,
    IRCast,
    IRStringConvert,
    IRArrayAccess,
    IRArrayLiteral,
    IRRef,
    IRRefNew,
    IREnumConstruct,
    IREnumIndex,
    IREnumField,
    IRUnliftedOpcode,
)
from . import (
    TraversingIROptimizer,
    _has_observable_effects,
)
from .inliner import _ScopedLocalLifetime


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

                new_string_const = IRConst(
                    self.func.code, IRConst.ConstType.GLOBAL_STRING, value=string_value
                )

                assign_stmt.expr = new_string_const

            except (ValueError, TypeError):
                pass


class IRStringIntConcatOptimizer(TraversingIROptimizer):
    """Recover numeric string conversions without dropping the count write.

    Only an adjacent std conversion / String allocation pair with private
    count and reference storage can be folded. Other uses keep the real native
    calls, including their out-parameter effects.
    """

    def optimize(self) -> None:
        lifetime = _ScopedLocalLifetime(self.func.block)
        candidates = []
        references = []
        pending: List[IRStatement] = [self.func.block]
        seen: Set[int] = set()
        occurrences: Dict[int, int] = {}
        while pending:
            node = pending.pop()
            occurrences[id(node)] = occurrences.get(id(node), 0) + 1
            if id(node) in seen:
                continue
            seen.add(id(node))
            # An unlifted instruction can expose storage without an IRRef node.
            if isinstance(node, IRUnliftedOpcode):
                return
            if isinstance(node, (IRRef, IRRefNew)) and isinstance(node.target, IRLocal):
                references.append(node)
            if isinstance(node, IRBlock):
                candidates.extend(self._candidates(node))
            pending.extend(node.get_children())

        private = []
        for block, index, reference, conversion, allocation in candidates:
            if any(
                occurrences[id(node)] != 1 for node in (reference, conversion, allocation, reference.expr)
            ):
                continue
            scratch = (reference.target, conversion.target, reference.expr.target)
            # Distinct storage is essential: neither the native result nor the
            # recovered string may overwrite its own input/out-parameter cell.
            if any(
                lifetime.aliases(left, right)
                for pos, left in enumerate(scratch)
                for right in (*scratch[pos + 1 :], allocation.target)
            ):
                continue
            if all(lifetime.dead_after(block, index, local) for local in scratch):
                private.append((block, index, reference, conversion, allocation))

        # A prior escaped address can observe later writes, even after the ref
        # register itself is reused. Every address of scratch storage must belong
        # to another proven private conversion; iterate to a fixed point because
        # rejecting one conversion can invalidate another using the same cell.
        while private:
            owned = {id(reference.expr) for _, _, reference, _, _ in private}
            kept = [
                candidate
                for candidate in private
                if not any(
                    id(ref) not in owned and lifetime.aliases(cast(IRLocal, ref.target), local)
                    for local in (candidate[2].target, candidate[3].target, candidate[2].expr.target)
                    for ref in references
                )
            ]
            if len(kept) == len(private):
                break
            private = kept

        removals: Dict[int, Tuple[IRBlock, Set[int]]] = {}
        for block, _, reference, conversion, allocation in private:
            native, alloc = conversion.expr, allocation.expr
            # The input is read once, before the removed native count write.
            allocation.expr = IRStringConvert(self.func.code, native.args[0]).adopt(native, alloc)
            allocation.adopt(reference, conversion)
            if id(block) not in removals:
                removals[id(block)] = (block, set())
            removals[id(block)][1].update((id(reference), id(conversion)))
        for block, removed in removals.values():
            block.statements = [stmt for stmt in block.statements if id(stmt) not in removed]

    def _candidates(self, block: IRBlock):
        statements = block.statements
        i = 2
        while i < len(statements):
            reference, conversion, allocation = statements[i - 2 : i + 1]
            if not (
                isinstance(reference, IRAssign)
                and isinstance(reference.target, IRLocal)
                and isinstance(conversion, IRAssign)
                and isinstance(conversion.target, IRLocal)
                and isinstance(allocation, IRAssign)
                and isinstance(allocation.target, IRLocal)
            ):
                i += 1
                continue
            ref_expr, native, alloc = reference.expr, conversion.expr, allocation.expr
            if not (
                isinstance(ref_expr, (IRRef, IRRefNew))
                and isinstance(ref_expr.target, IRLocal)
                and isinstance(native, IRCall)
                and isinstance(native.target, IRConst)
                and isinstance(native.target.value, Native)
                and native.target.value.lib.resolve(self.func.code) == "std"
                and native.target.value.name.resolve(self.func.code) in ("itos", "ftos")
                and len(native.args) == 2
                and isinstance(native.args[0], IRLocal)
                and native.args[1] is reference.target
                and isinstance(alloc, IRCall)
                and isinstance(alloc.target, IRConst)
                and isinstance(alloc.target.value, Function)
                and self.func.code.full_func_name(alloc.target.value) == "$String.__alloc__"
                and len(alloc.args) == 2
                and alloc.args[0] is conversion.target
                and alloc.args[1] is ref_expr.target
            ):
                i += 1
                continue
            yield block, i, reference, conversion, allocation
            i += 1


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
                    if (
                        bytes_idx is not None
                        and len_idx is None
                        and self._match_length_assign(nxt, local) is not None
                    ):
                        len_idx = j
                        break
                    if self._statement_touches_local(nxt, local):
                        break
                if bytes_idx is not None and len_idx is not None:
                    bytes_expr = cast(
                        IRExpression,
                        self._match_bytes_assign(block.statements[bytes_idx], local),
                    )
                    length_expr = cast(
                        IRExpression,
                        self._match_length_assign(block.statements[len_idx], local),
                    )
                    # Moving the call to the allocation site evaluates its arguments
                    # earlier. That is only safe if no free variable of the bytes
                    # or length expression is reassigned between the allocation and
                    # the field writes (e.g. String.fromUCS2 computes the length
                    # after creating the empty string).
                    free_names = self._collect_free_locals(bytes_expr) | self._collect_free_locals(
                        length_expr
                    )
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
    Collapses HashLink's `haxe.Log.trace` lowering back into a `trace(...)` call.

    Haxe compiles `trace(msg, extra...)` into:

        logClass = haxe.Log;             # class reference
        fn       = logClass.trace;       # trace is a dynamic function: field load
        msgTmp   = cast msg;             # only when the argument needs boxing
        pos      = new DynObj|PosInfos;  # the implicit ?pos argument
        pos.fileName = ...; pos.lineNumber = ...;
        pos.className = ...; pos.methodName = ...;
        posArg   = cast pos;             # DynObj shape only
        pos.customParams = [extra...];   # only with extra trace arguments
        fn(msgTmp, posArg);

    Matching is anchored on the call, because the callee reaches it either
    inlined (`haxe.Log.trace(...)`) or through the temp alias above, and the
    position object reaches it directly or through a cast temp. Only the
    statements actually recognized are consumed; anything else inside the
    window is left alone rather than silently dropped.
    """

    TARGET_OPCODES = {"New"}

    #: Fields of `haxe.PosInfos` that identify a trace position object.
    _REQUIRED_POS_FIELDS = ("fileName", "lineNumber")

    def visit_block(self, block: IRBlock) -> None:
        made_change = True
        while made_change:
            made_change = False
            statements = block.statements
            for idx, stmt in enumerate(statements):
                if (
                    isinstance(stmt, IRConditional)
                    and stmt.true_block is not None
                    and stmt.false_block is not None
                ):
                    if self._collapse_branched(block, idx):
                        made_change = True
                        break
                    continue
                if not isinstance(stmt, IRCall):
                    continue
                match = self._match_trace_call(statements, idx)
                if match is None:
                    continue
                trace_stmt, consumed = match
                trace_stmt.adopt(*(statements[k] for k in sorted(consumed)))
                block.statements = [
                    trace_stmt if k == idx else s
                    for k, s in enumerate(statements)
                    if k == idx or k not in consumed
                ]
                made_change = True
                break

    # -- matching ---------------------------------------------------------

    def _match_trace_call(self, stmts: List[IRStatement], idx: int) -> Optional[Tuple[IRTrace, Set[int]]]:
        """Build the IRTrace for the call at `idx`, plus the indices it consumes."""
        call = stmts[idx]
        if not isinstance(call, IRCall) or len(call.args) != 2:
            return None
        callee_defs = self._trace_callee_defs(stmts, idx, call.target)
        if callee_defs is None:
            return None
        resolved_pos = self._resolve_pos_object(stmts, idx, call.args[1])
        if resolved_pos is None:
            return None
        alloc_idx, pos_targets, alias_defs = resolved_pos
        fields, field_defs = self._collect_pos_fields(stmts, alloc_idx + 1, idx, pos_targets)
        if any(name not in fields for name in self._REQUIRED_POS_FIELDS):
            return None

        consumed = {idx, alloc_idx} | callee_defs | alias_defs | field_defs
        extra_args: List[IRExpression] = []
        custom = fields.pop("customParams", None)
        if custom is not None:
            resolved = self._resolve_custom_params(stmts, alloc_idx, idx, custom)
            if resolved is None:
                # Dropping the extra arguments would change what gets printed.
                return None
            extra_args, custom_defs = resolved
            consumed |= custom_defs
            # The argument array is built from throwaway temporaries (element
            # type marker, reinterpret flag and its reference cell) that now
            # have no reader left.
            self._sweep_dead_scaffold(stmts, alloc_idx, idx, consumed)

        pos_info = {name: self._literal_value(stmts, alloc_idx, idx, value) for name, value in fields.items()}
        msg, msg_def = self._resolve_msg(stmts, idx, call.args[0], consumed)
        if msg_def is not None:
            consumed.add(msg_def)

        # `trace(...)` re-reads `haxe.Log.trace` at the call site, and that
        # field is a reassignable dynamic function: collapsing across a rebind
        # would call the wrong function.
        if any(
            isinstance(stmts[k], IRAssign)
            and isinstance(cast(IRAssign, stmts[k]).target, IRField)
            and cast(IRField, cast(IRAssign, stmts[k]).target).field_name == "trace"
            for k in range(min(consumed), idx)
        ):
            if DEBUG:
                dbg_print(f"[TraceOpt] Refused trace at {idx}: haxe.Log.trace is rebound in the window")
            return None
        # The position object must be dead after the call; a surviving reader
        # would lose the object the collapse deletes.
        if any(
            self._is_live(stmts, idx, target, consumed)
            for target in pos_targets
            if isinstance(target, IRLocal)
        ):
            if DEBUG:
                dbg_print(f"[TraceOpt] Refused trace at {idx}: position object outlives the call")
            return None

        if DEBUG:
            dbg_print(f"[TraceOpt] Collapsed trace at {idx}: msg={msg}, extras={extra_args}, pos={pos_info}")
        return IRTrace(self.func.code, msg, pos_info, extra_args), consumed

    def _is_log_class(self, expr: Optional[IRExpression]) -> bool:
        return (
            isinstance(expr, IRConst)
            and isinstance(expr.value, Type)
            and isinstance(expr.value.definition, Obj)
            and "haxe.$Log" in expr.value.definition.name.resolve(self.func.code)
        )

    def _find_def(self, stmts: List[IRStatement], before: int, local: IRExpression) -> Optional[int]:
        """Index of the nearest assignment to `local` before `before`."""
        for k in range(before - 1, -1, -1):
            s = stmts[k]
            if isinstance(s, IRAssign) and isinstance(s.target, IRLocal) and s.target == local:
                return k
        return None

    def _is_temp(self, local: IRLocal) -> bool:
        """True for a register the compiler introduced, not a source variable.

        Source variables can hold a *snapshot* of the reassignable
        `haxe.Log.trace` field, or a position object the program keeps using,
        so their assignments are never part of a trace lowering to consume.
        """
        return local.reg_idx is not None and local.reg_idx not in self.func._user_reg_indices

    def _trace_callee_defs(
        self, stmts: List[IRStatement], before: int, target: Optional[IRExpression]
    ) -> Optional[Set[int]]:
        """Indices of the statements that materialize `haxe.Log.trace`, or None
        if `target` is not that function."""
        if isinstance(target, IRField) and target.field_name == "trace":
            base = target.target
            if self._is_log_class(base):
                return set()
            if isinstance(base, IRLocal) and self._is_temp(base):
                base_idx = self._find_def(stmts, before, base)
                if base_idx is not None:
                    base_def = stmts[base_idx]
                    if isinstance(base_def, IRAssign) and self._is_log_class(base_def.expr):
                        return {base_idx}
            return None
        if isinstance(target, IRLocal) and self._is_temp(target):
            fn_idx = self._find_def(stmts, before, target)
            if fn_idx is None:
                return None
            fn_def = stmts[fn_idx]
            if not isinstance(fn_def, IRAssign):
                return None
            inner = self._trace_callee_defs(stmts, fn_idx, fn_def.expr)
            if inner is None:
                return None
            return inner | {fn_idx}
        return None

    def _is_pos_alloc(self, expr: IRExpression) -> bool:
        """True for the allocation of trace's implicit position argument, which
        HL emits either as an untyped DynObj or as the PosInfos virtual."""
        if not isinstance(expr, IRNew):
            return False
        definition = expr.get_type().definition
        if isinstance(definition, DynObj):
            return True
        if isinstance(definition, Virtual):
            names = {field.name.resolve(self.func.code) for field in definition.fields}
            return all(name in names for name in self._REQUIRED_POS_FIELDS)
        return False

    def _resolve_pos_object(
        self, stmts: List[IRStatement], before: int, expr: IRExpression
    ) -> Optional[Tuple[int, List[IRExpression], Set[int]]]:
        """Follow the position argument back to its allocation.

        Returns the allocation index, every local the object is reachable
        through (field assignments can target any of them), and the indices of
        the alias assignments walked through.
        """
        alias_defs: Set[int] = set()
        targets: List[IRExpression] = []
        while True:
            if isinstance(expr, IRCast):
                expr = expr.expr
                continue
            if not isinstance(expr, IRLocal) or not self._is_temp(expr):
                return None
            targets.append(expr)
            def_idx = self._find_def(stmts, before, expr)
            if def_idx is None:
                return None
            assign = stmts[def_idx]
            if not isinstance(assign, IRAssign):
                return None
            if self._is_pos_alloc(assign.expr):
                return def_idx, targets, alias_defs
            if isinstance(assign.expr, (IRCast, IRLocal)):
                alias_defs.add(def_idx)
                before = def_idx
                expr = assign.expr
                continue
            return None

    def _collect_pos_fields(
        self, stmts: List[IRStatement], start: int, end: int, targets: List[IRExpression]
    ) -> Tuple[Dict[str, IRExpression], Set[int]]:
        fields: Dict[str, IRExpression] = {}
        defs: Set[int] = set()
        for k in range(start, end):
            s = stmts[k]
            if (
                isinstance(s, IRAssign)
                and isinstance(s.target, IRField)
                and any(s.target.target == target for target in targets)
            ):
                fields[s.target.field_name] = s.expr
                defs.add(k)
        return fields, defs

    def _literal_value(self, stmts: List[IRStatement], start: int, end: int, expr: IRExpression) -> Any:
        """Position metadata is rendered as a comment, so reduce it to plain
        values where possible and keep the expression otherwise."""
        if isinstance(expr, IRConst):
            return expr.value
        if isinstance(expr, IRLocal):
            def_idx = self._find_def(stmts, end, expr)
            if def_idx is not None and def_idx >= start:
                assign = stmts[def_idx]
                if isinstance(assign, IRAssign) and isinstance(assign.expr, IRConst):
                    value = assign.expr.value
                    return value.value if hasattr(value, "value") else value
        return expr

    def _is_array_dyn_alloc(self, expr: IRExpression) -> bool:
        if not isinstance(expr, IRCall) or not expr.args:
            return False
        target = expr.target
        if not (isinstance(target, IRConst) and isinstance(target.value, Function)):
            return False
        name = self.func.code.full_func_name(target.value) or ""
        return name.endswith("ArrayDyn.alloc")

    def _resolve_custom_params(
        self, stmts: List[IRStatement], start: int, end: int, expr: IRExpression
    ) -> Optional[Tuple[List[IRExpression], Set[int]]]:
        """Recover `trace(msg, a, b)`'s extra arguments from the customParams
        array HL builds for them."""
        consumed: Set[int] = set()
        before = end
        while True:
            if isinstance(expr, IRCast):
                expr = expr.expr
                continue
            if isinstance(expr, IRArrayLiteral):
                return list(expr.elements), consumed
            if isinstance(expr, IRLocal):
                def_idx = self._find_def(stmts, before, expr)
                if def_idx is None or def_idx <= start:
                    return None
                assign = stmts[def_idx]
                if not isinstance(assign, IRAssign):
                    return None
                consumed.add(def_idx)
                before = def_idx
                expr = assign.expr
                continue
            if self._is_array_dyn_alloc(expr):
                expr = cast(IRCall, expr).args[0]
                continue
            return None

    #: Expression shapes HL emits while materializing trace's argument array.
    _SCAFFOLD_EXPRS = (IRConst, IRCast, IRLocal, IRRefNew, IRArrayLiteral)

    def _sweep_dead_scaffold(
        self, stmts: List[IRStatement], start: int, end: int, consumed: Set[int]
    ) -> None:
        """Consume window temporaries that no surviving statement reads."""
        # A temp can only be seen dead once its own consumers are consumed, so
        # repeat until the window stops shrinking.
        changed = True
        while changed:
            changed = False
            for k in range(start + 1, end):
                if k in consumed:
                    continue
                assign = stmts[k]
                if not (isinstance(assign, IRAssign) and isinstance(assign.target, IRLocal)):
                    continue
                local = assign.target
                if not self._is_temp(local):
                    continue
                if not isinstance(assign.expr, self._SCAFFOLD_EXPRS):
                    continue
                if self._is_live(stmts, k, local, consumed):
                    continue
                consumed.add(k)
                changed = True

    def _is_live(self, stmts: List[IRStatement], def_idx: int, local: IRLocal, consumed: Set[int]) -> bool:
        """Whether the value assigned at `def_idx` still has a reader.

        Statements this collapse consumes are about to disappear, and nothing
        past a redefinition of the local can observe the old value.
        """
        for k in range(def_idx + 1, len(stmts)):
            if k in consumed:
                continue
            touch = self._scan_local(stmts[k], local)
            if touch is not None:
                return touch
        return False

    def _scan_local(self, stmt: IRStatement, local: IRLocal) -> Optional[bool]:
        """First interaction `stmt` has with `local`, in execution order.

        True: read before any redefinition. False: redefined without being
        read. None: untouched. Compiler temps are recycled aggressively, so
        distinguishing a later *kill* from a later *use* is what lets a trace
        inside a loop be collapsed without disturbing the outer one.
        """
        if isinstance(stmt, IRAssign):
            if self._reads_local(stmt.expr, local):
                return True
            if isinstance(stmt.target, IRLocal):
                return False if stmt.target == local else None
            # Storing through the local (field or element write) reads it.
            return True if self._reads_local(stmt.target, local) else None
        if isinstance(stmt, IRBlock):
            for child in stmt.statements:
                touch = self._scan_local(child, local)
                if touch is not None:
                    return touch
            return None
        if isinstance(stmt, IRConditional):
            if stmt.condition is not None and self._reads_local(stmt.condition, local):
                return True
            branches = [b for b in (stmt.true_block, stmt.false_block) if b is not None]
            touches = [self._scan_local(b, local) for b in branches]
            if any(touch for touch in touches):
                return True
            # Only a redefinition on every path can be relied on.
            if len(touches) == 2 and all(touch is False for touch in touches):
                return False
            return None
        if isinstance(stmt, (IRWhileLoop, IRPrimitiveLoop)):
            condition = getattr(stmt, "condition", None)
            if condition is not None and self._reads_local(condition, local):
                return True
            # A zero-trip loop redefines nothing, so the body can only add reads.
            body = getattr(stmt, "body", None)
            return True if body is not None and self._scan_local(body, local) else None
        nested = [child for child in stmt.get_children() if isinstance(child, IRBlock)]
        if nested:
            # Switches, try/catch and anything else carrying blocks: the parts
            # evaluated before them are reads, and a redefinition inside one
            # arm is not guaranteed to happen, so it never counts as a kill.
            if any(
                self._reads_local(child, local)
                for child in stmt.get_children()
                if not isinstance(child, IRBlock)
            ):
                return True
            return True if any(self._scan_local(block, local) for block in nested) else None
        return True if self._reads_local(stmt, local) else None

    def _reads_local(self, stmt: IRStatement, local: IRLocal) -> bool:
        """Whether `stmt` (or anything nested in it) reads `local`."""
        if isinstance(stmt, IRAssign):
            if self._reads_local(stmt.expr, local):
                return True
            # Writing the local is not a read; reading through it (a field or
            # element store) is.
            return not isinstance(stmt.target, IRLocal) and self._reads_local(stmt.target, local)
        if isinstance(stmt, IRLocal):
            return stmt == local
        return any(self._reads_local(child, local) for child in stmt.get_children())

    def _resolve_msg(
        self, stmts: List[IRStatement], idx: int, msg: IRExpression, consumed: Set[int]
    ) -> Tuple[IRExpression, Optional[int]]:
        """Inline the compiler temp holding the traced value, when its only role
        is to carry that value into the call."""
        if not isinstance(msg, IRLocal):
            return msg, None
        if not self._is_temp(msg):
            return msg, None
        def_idx = self._find_def(stmts, idx, msg)
        if def_idx is None:
            return msg, None
        # Everything between the definition and the call must belong to the
        # trace scaffolding, otherwise moving the value across it is unsound.
        if any(k not in consumed for k in range(def_idx + 1, idx)):
            return msg, None
        assign = stmts[def_idx]
        if not isinstance(assign, IRAssign):
            return msg, None
        return assign.expr, def_idx

    # -- branch-merged calls ----------------------------------------------

    def _collapse_branched(self, block: IRBlock, idx: int) -> bool:
        """Collapse a trace whose call was hoisted out of an if/else."""
        stmt = block.statements[idx]
        if not isinstance(stmt, IRConditional):
            return False
        branched = self._try_branched_trace(stmt, block.statements, idx)
        if branched is None:
            return False
        (
            true_tail,
            false_tail,
            msg_true,
            msg_false,
            pos_true,
            pos_false,
            consumed_after,
        ) = branched
        assert stmt.true_block is not None and stmt.false_block is not None
        old_true_stmts = stmt.true_block.statements
        old_false_stmts = stmt.false_block.statements
        true_trace = IRTrace(self.func.code, msg_true, pos_true)
        false_trace = IRTrace(self.func.code, msg_false, pos_false)
        true_trace.adopt(*old_true_stmts[len(true_tail) :])
        false_trace.adopt(*old_false_stmts[len(false_tail) :])
        stmt.true_block.statements = true_tail + [true_trace]
        stmt.false_block.statements = false_tail + [false_trace]
        # The shared position-field assigns + hoisted call after the
        # conditional are dropped outright; fold their opcodes onto the
        # conditional itself since neither branch alone owns them.
        stmt.adopt(*block.statements[idx + 1 : idx + 1 + consumed_after])
        block.statements = block.statements[: idx + 1] + block.statements[idx + 1 + consumed_after :]
        return True

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
            if isinstance(s, IRAssign) and isinstance(s.target, IRLocal) and self._is_pos_alloc(s.expr):
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
        aliases: List[IRExpression] = [temp_local]
        j = new_idx + 1
        while j < len(stmts):
            s = stmts[j]
            if (
                isinstance(s, IRAssign)
                and isinstance(s.target, IRField)
                and any(s.target.target == alias for alias in aliases)
                and isinstance(s.expr, IRConst)
            ):
                pos_info[s.target.field_name] = s.expr.value
                j += 1
                continue
            # The branch may end by casting the built object into the local the
            # hoisted call reads from.
            if (
                isinstance(s, IRAssign)
                and isinstance(s.target, IRLocal)
                and isinstance(s.expr, IRCast)
                and any(s.expr.expr == alias for alias in aliases)
            ):
                aliases.append(s.target)
                j += 1
                continue
            break
        if j != len(stmts):
            return None

        return stmts[:new_idx], fun_local, cast(IRLocal, aliases[-1]), pos_info

    def _resolve_local_value(self, stmts: List[IRStatement], local: IRExpression) -> Optional[IRExpression]:
        """Find the most recent assignment to `local` within `stmts`, searching from the end."""
        for s in reversed(stmts):
            if isinstance(s, IRAssign) and isinstance(s.target, IRLocal) and s.target == local:
                return s.expr
        return None

    def _try_branched_trace(
        self, cond: "IRConditional", statements: List[IRStatement], idx: int
    ) -> Optional[
        Tuple[
            List[IRStatement],
            List[IRStatement],
            IRExpression,
            IRExpression,
            Dict[str, Any],
            Dict[str, Any],
            int,
        ]
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

        target = call_stmt.target
        if isinstance(target, IRLocal) and target == fun_local_t:
            pass
        elif self._trace_callee_defs(statements, j, target) is None:
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
        return (
            true_tail,
            false_tail,
            msg_true,
            msg_false,
            final_pos_t,
            final_pos_f,
            consumed_after,
        )


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
                    folded, consumed, absorbed = fold
                    if absorbed:
                        # The chain's first value can be computed before the
                        # chain itself starts; that definition is now inlined.
                        new_statements = [s for s in new_statements if id(s) not in absorbed]
                    new_statements.extend(folded)
                    i += consumed
                    made_change = True
                    continue
                new_statements.append(block.statements[i])
                i += 1
            block.statements = new_statements

    def _try_fold_concat_temp(
        self, statements: List[IRStatement], start: int
    ) -> Optional[Tuple[List[IRStatement], int, Set[int]]]:
        # Look for: temp = init_string_expr;
        #           temp = String.__add__(temp, rhs1);
        #           temp = String.__add__(temp, rhs2);
        #           ...
        #           use(temp)   (trace(temp) or target = temp)
        # HL evaluates each interpolated value into its own temp right before
        # appending it, so the links are separated by those definitions; they
        # are folded into the parts rather than treated as chain breaks.
        if start >= len(statements):
            return None

        first = statements[start]
        if not (
            isinstance(first, IRAssign)
            and isinstance(first.target, IRLocal)
            and self._is_string_expr(first.expr)
        ):
            return None

        temp = first.target
        init_expr = first.expr

        # Collect the chain of `temp = String.__add__(temp, rhs)` assignments,
        # stepping over the pure temp definitions that feed them. Each appended
        # value is resolved against the definitions live *at that point*: HL
        # recycles one register for every interpolated value, so reading it
        # later would yield whichever value was appended last.
        i = start + 1
        live: Dict[str, Tuple[int, IRExpression]] = {}
        used_defs: Set[int] = set()
        # The first appended value is computed before the chain opens, so the
        # run of pure temp definitions leading up to it counts as chain input.
        prelude = start - 1
        while prelude >= 0 and self._is_movable(statements[prelude]):
            definition = cast(IRAssign, statements[prelude])
            live.setdefault(cast(IRLocal, definition.target).name, (prelude, definition.expr))
            prelude -= 1
        parts: List[IRExpression] = [self._resolve_part(init_expr, live, used_defs)]
        while i < len(statements):
            stmt = statements[i]
            if isinstance(stmt, IRAssign) and stmt.target == temp:
                add_call = stmt.expr
                if not self._is_string_add_with_temp(add_call, temp):
                    break
                assert isinstance(add_call, IRCall)
                rhs = add_call.args[1]
                if self._expr_contains_local(rhs, temp):
                    break
                parts.append(self._resolve_part(rhs, live, used_defs))
                i += 1
                continue
            if self._statement_reads_local(stmt, temp) or self._statement_assigns_local(stmt, temp):
                break
            # A temp definition feeding the chain is normally required to be
            # side-effect free, since the fold reorders it relative to the
            # values the chain collects. A *read* (field/array access) that can
            # throw is different: its temp is resolved (inlined) into the very
            # next chain link, which evaluates it at exactly the same point —
            # so it may be absorbed rather than treated as a chain break. A def
            # with any other observable effect (a call, allocation) must stay.
            movable = self._is_movable(stmt)
            if not movable:
                if not (
                    isinstance(stmt, IRAssign)
                    and isinstance(stmt.target, IRLocal)
                    and stmt.target.name.startswith("var")
                    and stmt.target.name[3:].isdigit()
                    and self._is_absorbable_read_def(stmt)
                    and self._read_reaches_next_add(statements, i, temp, stmt.target)
                ):
                    break
            assert isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal)
            live[stmt.target.name] = (i, stmt.expr)
            i += 1

        if len(parts) == 1:
            return None  # No concat happened.

        # Now find the single use of `temp` after the chain.  We allow unrelated
        # statements in between as long as they don't touch `temp`.
        use_idx: Optional[int] = None
        tail_part: Optional[IRExpression] = None
        for j in range(i, len(statements)):
            stmt = statements[j]
            # A statement that overwrites the temp without reading its old
            # value ends the chain's lifetime — and HL starts the *next*
            # interpolation by doing exactly that.
            if self._statement_assigns_local(stmt, temp) and not self._value_reads_local(stmt, temp):
                break
            if self._statement_reads_local(stmt, temp):
                if use_idx is not None:
                    return None
                if isinstance(stmt, IRTrace) and stmt.msg == temp:
                    use_idx = j
                elif isinstance(stmt, IRTrace) and self._is_string_add_with_temp(stmt.msg, temp):
                    use_idx = j
                    tail_part = self._resolve_part(cast(IRCall, stmt.msg).args[1], live, used_defs)
                elif isinstance(stmt, IRAssign) and stmt.expr == temp:
                    use_idx = j
                elif isinstance(stmt, IRAssign) and self._is_string_add_with_temp(stmt.expr, temp):
                    use_idx = j
                    tail_part = self._resolve_part(cast(IRCall, stmt.expr).args[1], live, used_defs)
                elif isinstance(stmt, (IRCall, IRReturn, IRAssign, IRTrace)):
                    # Any single consumer works — `Sys.println(s)` and
                    # `return s` end just as many chains as `trace(s)`.
                    use_idx = j
                else:
                    return None
            elif use_idx is None and self._is_movable(stmt):
                assert isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal)
                live[stmt.target.name] = (j, stmt.expr)

        if use_idx is None:
            return None

        use_stmt = statements[use_idx]
        folded_expr_for_use = self._fold_concat(parts + ([tail_part] if tail_part is not None else []))
        # Moving the reads to the use site is only faithful while nothing in
        # the window reassigns what they read.
        if self._window_rebinds_reads(folded_expr_for_use, statements, start, use_idx, used_defs):
            return None

        new_use: IRStatement
        if tail_part is not None:
            if isinstance(use_stmt, IRTrace):
                new_use = IRTrace(
                    code=self.func.code,
                    msg=folded_expr_for_use,
                    pos_info=use_stmt.pos_info,
                    extra_args=use_stmt.extra_args,
                )
            else:
                assert isinstance(use_stmt, IRAssign)
                new_use = IRAssign(
                    code=self.func.code,
                    target=use_stmt.target,
                    expr=folded_expr_for_use,
                )
        else:
            substituted = self._substitute_use(use_stmt, temp, folded_expr_for_use)
            if substituted is None:
                return None
            new_use = substituted

        # Definitions the fold absorbed disappear; the rest keep their order,
        # and only those with a reader left are worth emitting.
        surviving = [
            index
            for index, _ in sorted(live.values())
            if index not in used_defs
            and start <= index < use_idx
            and self._read_after(statements, use_idx, cast(IRAssign, statements[index]).target)
        ]
        absorbed = {id(statements[index]) for index in used_defs if index < start}
        new_use.adopt(*statements[start : use_idx + 1], *(statements[index] for index in used_defs))
        return (
            [statements[index] for index in surviving] + [new_use],
            use_idx - start + 1,
            absorbed,
        )

    def _resolve_part(
        self,
        expr: IRExpression,
        live: Dict[str, Tuple[int, IRExpression]],
        used_defs: Set[int],
    ) -> IRExpression:
        """Substitute the temps an appended value reads with their live values."""
        if isinstance(expr, IRLocal):
            entry = live.get(expr.name)
            if entry is None:
                return expr
            index, value = entry
            used_defs.add(index)
            return self._resolve_part(value, live, used_defs)
        if isinstance(expr, IRCall):
            return IRCall(
                code=self.func.code,
                call_type=expr.call_type,
                target=expr.target,
                args=[self._resolve_part(arg, live, used_defs) for arg in expr.args],
            )
        if isinstance(expr, IRStringConvert):
            return IRStringConvert(self.func.code, self._resolve_part(expr.value, live, used_defs))
        if isinstance(expr, IRCast):
            return IRCast(
                self.func.code, expr.target_type_idx, self._resolve_part(expr.expr, live, used_defs)
            )
        return expr

    def _substitute_use(self, stmt: IRStatement, temp: IRLocal, value: IRExpression) -> Optional[IRStatement]:
        """Rebuild the consuming statement with the folded string in place."""

        def replace(expr: IRExpression) -> IRExpression:
            if isinstance(expr, IRLocal):
                return value if expr == temp else expr
            if isinstance(expr, IRCall):
                return IRCall(
                    code=self.func.code,
                    call_type=expr.call_type,
                    target=expr.target,
                    args=[replace(arg) for arg in expr.args],
                )
            if isinstance(expr, IRStringConvert):
                return IRStringConvert(self.func.code, replace(expr.value))
            if isinstance(expr, IRCast):
                return IRCast(self.func.code, expr.target_type_idx, replace(expr.expr))
            return expr

        if isinstance(stmt, IRTrace):
            if stmt.msg != temp:
                return None
            return IRTrace(self.func.code, value, stmt.pos_info, stmt.extra_args)
        if isinstance(stmt, IRAssign):
            if self._expr_contains_local(stmt.target, temp):
                return None
            return IRAssign(self.func.code, stmt.target, replace(stmt.expr))
        if isinstance(stmt, IRReturn):
            if stmt.value is None:
                return None
            return IRReturn(self.func.code, replace(stmt.value))

        if isinstance(stmt, IRCall):
            rebuilt = replace(stmt)
            return rebuilt if isinstance(rebuilt, IRCall) else None
        return None

    def _value_reads_local(self, stmt: IRStatement, local: IRLocal) -> bool:
        """Whether `stmt` consumes `local`'s current value.

        Distinct from `_statement_reads_local`, which also reports the local
        appearing as an assignment *target*.
        """
        if isinstance(stmt, IRAssign):
            if stmt.expr is not None and self._expr_contains_local(stmt.expr, local):
                return True
            target = stmt.target
            if isinstance(target, IRLocal):
                return False
            return self._expr_contains_local(target, local)
        return self._statement_reads_local(stmt, local)

    def _window_rebinds_reads(
        self,
        expr: IRExpression,
        statements: List[IRStatement],
        start: int,
        use_idx: int,
        used_defs: Set[int],
    ) -> bool:
        locals_read: Set[str] = set()
        self._collect_locals(expr, locals_read)
        for index in range(start, use_idx):
            if index in used_defs:
                continue
            stmt = statements[index]
            if not isinstance(stmt, IRAssign) or not isinstance(stmt.target, IRLocal):
                continue
            if stmt.target.name in locals_read:
                return True
        return False

    def _collect_locals(self, expr: IRStatement, out: Set[str]) -> None:
        if isinstance(expr, IRLocal):
            out.add(expr.name)
        for child in expr.get_children():
            self._collect_locals(child, out)

    def _read_after(self, statements: List[IRStatement], idx: int, local: IRExpression) -> bool:
        """Whether anything past `idx` still consumes `local` before it is reset."""
        if not isinstance(local, IRLocal):
            return True
        for stmt in statements[idx + 1 :]:
            if self._value_reads_local(stmt, local):
                return True
            if self._statement_assigns_local(stmt, local):
                return False
        return False

    def _is_absorbable_read_def(self, stmt: IRAssign) -> bool:
        """Whether `stmt` defines a temp with an expression whose only
        observable behavior is a potentially-throwing read (field/array access)
        over pure operands. Such a value may be inlined into the immediately
        following chain link, which evaluates it at the same point."""
        expr = stmt.expr
        # Unwrap pure wrappers (casts/string-converts of primitives).
        while isinstance(expr, (IRCast, IRStringConvert)):
            expr = expr.expr if isinstance(expr, IRCast) else expr.value
        if isinstance(expr, IRField):
            # A static field read (`SomeType.field`) targets a TYPE constant,
            # which `_has_effects` conservatively flags as a global-object
            # reference. The type object is always live; only the field read
            # itself (which the absorb moves to the same evaluation point) can
            # throw, so the target is effectively pure here.
            if isinstance(expr.target, IRConst) and expr.target.const_type == IRConst.ConstType.GLOBAL_OBJ:
                return True
            return not self._has_effects(expr.target)
        if isinstance(expr, IRArrayAccess):
            return not self._has_effects(expr.array) and not self._has_effects(expr.index)
        return False

    def _read_reaches_next_add(
        self, statements: List[IRStatement], i: int, temp: IRLocal, read_temp: IRLocal
    ) -> bool:
        """Whether the value of `read_temp` reaches the next `temp =
        String.__add__(temp, ...)` link through only pure wrapper defs (casts,
        primitive string-converts) in between — so inlining the read into that
        link evaluates it at exactly the same point as before."""
        # Trace the add's RHS back through the wrapper defs to see whether it
        # ultimately reads `read_temp`, and confirm every statement between the
        # read's def and the add is such a pure wrapper.
        wrappers: Dict[str, IRExpression] = {}
        j = i + 1
        while j < len(statements):
            nxt = statements[j]
            if isinstance(nxt, IRAssign) and nxt.target == temp:
                if not self._is_string_add_with_temp(nxt.expr, temp):
                    return False
                assert isinstance(nxt.expr, IRCall)
                return self._unwrap_reads(nxt.expr.args[1], wrappers, read_temp)
            # An intermediate statement must be a pure wrapper of a temp (its
            # value is resolved through `live` when the add's RHS is folded).
            if not (isinstance(nxt, IRAssign) and isinstance(nxt.target, IRLocal)):
                return False
            if not self._is_pure_wrapper(nxt.expr):
                return False
            wrappers[nxt.target.name] = nxt.expr
            j += 1
        return False

    def _unwrap_reads(self, expr: IRExpression, wrappers: Dict[str, IRExpression], target: IRLocal) -> bool:
        """Whether `expr` reads `target`, resolving wrapper temps via `wrappers`."""
        if self._expr_contains_local(expr, target):
            return True
        # Resolve a wrapper temp to its definition and recurse.
        if isinstance(expr, IRLocal) and expr.name in wrappers:
            return self._unwrap_reads(wrappers[expr.name], wrappers, target)
        for child in expr.get_children():
            if isinstance(child, IRExpression) and self._unwrap_reads(child, wrappers, target):
                return True
        # IRStringConvert/IRCast don't expose their operand via get_children in
        # a uniform way here; unwrap them explicitly.
        inner = None
        if isinstance(expr, IRStringConvert):
            inner = expr.value
        elif isinstance(expr, IRCast):
            inner = expr.expr
        if inner is not None and self._unwrap_reads(inner, wrappers, target):
            return True
        return False

    def _is_pure_wrapper(self, expr: IRExpression) -> bool:
        """Whether `expr` only re-wraps a single temp/local read without doing
        work of its own — a cast or a primitive string-convert."""
        while isinstance(expr, (IRCast, IRStringConvert)):
            expr = expr.expr if isinstance(expr, IRCast) else expr.value
        return isinstance(expr, (IRLocal, IRConst))

    def _is_movable(self, stmt: IRStatement) -> bool:
        """Whether folding may evaluate the chain's parts past `stmt`.

        Only a side-effect-free definition of a compiler temp qualifies:
        anything observable would be reordered against the values the chain
        collects.
        """
        if not (isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal)):
            return False
        # The target must be a compiler temp: an anonymous `varN` name. SSA
        # splitting already gives each distinct temp value its own name, so a
        # register index that is *also* reused by a user variable elsewhere in
        # the function must not disqualify this particular split — only a temp
        # whose name is itself a user variable (or a `nameN` disambiguation of
        # one) is off-limits.
        if not (stmt.target.name.startswith("var") and stmt.target.name[3:].isdigit()):
            return False
        return not self._has_effects(stmt.expr)

    def _has_effects(self, expr: IRExpression) -> bool:
        if isinstance(expr, IRStringConvert):
            # Std.string of a primitive is a pure formatting step; on an object
            # it would run toString().
            kind = expr.value.get_type().kind.value
            primitive = kind in (
                Type.Kind.U8.value,
                Type.Kind.U16.value,
                Type.Kind.I32.value,
                Type.Kind.I64.value,
                Type.Kind.F32.value,
                Type.Kind.F64.value,
                Type.Kind.BOOL.value,
            )
            return not primitive or self._has_effects(expr.value)
        return _has_observable_effects(expr)

    def _is_string_expr(self, expr: IRExpression) -> bool:
        if isinstance(expr, IRConst) and isinstance(expr.value, str):
            return True
        if isinstance(expr, IRLocal):
            return True
        if isinstance(expr, IRStringConvert):
            # `"" + x` opens as a bare conversion of the first value.
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
