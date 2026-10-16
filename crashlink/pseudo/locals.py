"""
Local variable and declaration analysis: reads/writes, assignment planning, capture locals.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Optional, List, Set, Dict, FrozenSet, Tuple, Union, Iterator
from .doc import mark
from .symbols import SymbolRef
from ..core import Bytecode, Obj, Function, is_static_name, gIndex
from .. import disasm
from .. import mapargs
from ..decomp import (
    IRBreak,
    IRContinue,
    IRCast,
    IRNativeStub,
    IRField,
    IRFunction,
    IRBlock,
    IRNew,
    IRStatement,
    IRExpression,
    IRAssign,
    IRLocal,
    IRConst,
    IRArithmetic,
    IRNeg,
    IRNot,
    IRBoolExpr,
    IRCall,
    IRConditional,
    IRTrace,
    IRTryCatch,
    IRUnliftedOpcode,
    IRArrayAccess,
    IRRef,
    IRRefNew,
    IRRefGet,
    IRRefSet,
    IRArrayLiteral,
    IREnumConstruct,
    IREnumIndex,
    IREnumField,
    IRWhileLoop,
    IRForEachLoop,
    IRIntRangeLoop,
    IRPrimitiveLoop,
    IRReturn,
    IRThrow,
    IRPrimitiveJump,
    IRSwitch,
)
from ..decomp.ir import IREnumPattern
from .enums import _is_expression_switch, _detect_enum_value_from_cases, _unbound_reads, _pattern_captures
from .hierarchy import _ancestors


def _collect_assigned_names(stmts: List[IRStatement]) -> set[str]:
    names: set[str] = set()
    for s in stmts:
        if isinstance(s, IRAssign) and isinstance(s.target, IRLocal):
            names.add(s.target.name)
    return names


def _null_guarded_ref_source(local: IRLocal, block: IRBlock) -> Optional[IRExpression]:
    """The nullable value a reference local was made from.

    Passing a `Null<T>` to an optional basic parameter compiles to
    `r = x == null ? null : new hl.Ref(x)`; source just passes `x`."""
    for stmt in block.statements:
        found = _null_guarded_ref_in(local, stmt)
        if found is not None:
            return found
    return None


def _null_guarded_ref_in(local: IRLocal, stmt: IRStatement) -> Optional[IRExpression]:
    if isinstance(stmt, IRConditional):
        condition = stmt.condition
        if (
            isinstance(condition, IRBoolExpr)
            and condition.op in (IRBoolExpr.CompareType.NULL, IRBoolExpr.CompareType.NOT_NULL)
            and isinstance(condition.left, IRLocal)
        ):
            null_branch, make_branch = stmt.true_block, stmt.false_block
            if condition.op == IRBoolExpr.CompareType.NOT_NULL:
                null_branch, make_branch = make_branch, null_branch
            nulls, makes = null_branch.statements, make_branch.statements
            if (
                len(nulls) == 1
                and isinstance(nulls[0], IRAssign)
                and nulls[0].target == local
                and isinstance(nulls[0].expr, IRConst)
                and nulls[0].expr.const_type == IRConst.ConstType.NULL
                and makes
                and isinstance(makes[-1], IRAssign)
                and makes[-1].target == local
                and isinstance(makes[-1].expr, IRRefNew)
            ):
                # The value it holds is the checked one, possibly through a converting copy.
                held = makes[-1].expr.target
                copies = {
                    s.target.name: s.expr
                    for s in makes[:-1]
                    if isinstance(s, IRAssign) and isinstance(s.target, IRLocal)
                }
                while isinstance(held, IRLocal) and held.name in copies:
                    held = copies[held.name]
                    while isinstance(held, IRCast):
                        held = held.expr
                if isinstance(held, IRLocal) and held.name == condition.left.name:
                    return condition.left
    for child in stmt.get_children():
        if isinstance(child, IRBlock):
            found = _null_guarded_ref_source(local, child)
            if found is not None:
                return found
        elif isinstance(child, IRStatement):
            found = _null_guarded_ref_in(local, child)
            if found is not None:
                return found
    return None


def _is_simple_render_expr(expr: IRExpression) -> bool:
    """Expressions safe to substitute into every later use of a local.

    Restricted to bare locals (aliases). Constants are deliberately excluded
    here even though they're "simple": duplicating a constant into multiple
    expressions can let Haxe's own compiler constant-fold arithmetic that the
    original bytecode computed at runtime (e.g. `x << n` becoming `x << 4`),
    which changes the recompiled opcodes. See _is_single_use_render_expr for
    the narrower, single-use-safe variant that does allow constants.
    """
    return isinstance(expr, IRLocal)


def _is_single_use_render_expr(expr: IRExpression) -> bool:
    """Expressions safe to substitute when the local is read exactly once.

    With only one read to satisfy, substituting a constant can't trigger the
    multi-use constant-folding problem _is_simple_render_expr avoids.
    Casts must retain their binding: rendering keeps the original assignment,
    so substituting its RHS would repeat the conversion or lose the target
    type supplied by its declaration. Only IR optimizers may move a conversion
    together with eliminating its original assignment.
    """
    return isinstance(expr, (IRLocal, IRConst))


def _free_locals_in_expr(expr: IRExpression) -> Set[IRLocal]:
    found: Set[IRLocal] = set()

    def walk(e: Optional[IRExpression]) -> None:
        if e is None:
            return
        if isinstance(e, IRLocal):
            found.add(e)
        elif isinstance(e, (IRArithmetic, IRBoolExpr)):
            walk(e.left)
            walk(e.right)
        elif isinstance(e, IRCall):
            if e.target is not None:
                walk(e.target)
            for arg in e.args:
                walk(arg)
        elif isinstance(e, IRField):
            walk(e.target)
        elif isinstance(e, IRCast):
            walk(e.expr)
        elif isinstance(e, IRArrayAccess):
            walk(e.array)
            walk(e.index)

    walk(expr)
    return found


def _source_redefined_before_use(
    root: IRStatement, def_stmt: IRStatement, target_name: str, source_names: Set[str]
) -> bool:
    """True if a local in `source_names` is reassigned after `def_stmt` but before
    the (single, assumed) later read of `target_name`. Guards single-use render
    substitution: `varN = i; ...; i = 1; ...; use(varN)` must not fold to `use(i)`
    since `i`'s value changed between the copy and the use."""
    started = False
    hit = False
    stopped = False

    def walk(s: Optional[IRStatement]) -> None:
        nonlocal started, hit, stopped
        if stopped or s is None:
            return
        if not started:
            if s is def_stmt:
                started = True
                return
            for child in s.get_children():
                if stopped:
                    return
                if isinstance(child, IRBlock):
                    for cs in child.statements:
                        walk(cs)
                else:
                    walk(child)
            return
        if isinstance(s, IRAssign) and isinstance(s.target, IRLocal) and s.target.name in source_names:
            hit = True
            stopped = True
            return
        if isinstance(s, IRLocal) and s.name == target_name:
            stopped = True
            return
        for child in s.get_children():
            if stopped:
                return
            if isinstance(child, IRBlock):
                for cs in child.statements:
                    walk(cs)
            else:
                walk(child)

    walk(root)
    return hit


def _count_local_reads_and_writes(root: IRStatement, name: str) -> Tuple[int, int]:
    """Count read vs write occurrences of a local by name across an IR subtree.

    A write is an IRAssign whose target is exactly that local; every other
    occurrence (including as the array/field base of a write, which is itself
    a read of the base pointer) counts as a read.
    """
    reads = 0
    writes = 0
    seen: Set[int] = set()

    def walk(s: Optional[IRStatement]) -> None:
        nonlocal reads, writes
        if s is None or id(s) in seen:
            return
        seen.add(id(s))
        if isinstance(s, IRAssign) and isinstance(s.target, IRLocal) and s.target.name == name:
            writes += 1
            walk(s.expr)
            return
        if isinstance(s, IRLocal) and s.name == name:
            reads += 1
        # IRArithmetic doesn't expose left/right via get_children (several
        # passes rely on that to avoid auto-recursing into operands), so walk
        # them explicitly here instead.
        if isinstance(s, IRArithmetic):
            walk(s.left)
            walk(s.right)
            return
        for child in s.get_children():
            if isinstance(child, IRBlock):
                for child_stmt in child.statements:
                    walk(child_stmt)
            else:
                walk(child)

    walk(root)
    return reads, writes


def _redefined_locals(stmt: IRStatement) -> Set[IRLocal]:
    found: Set[IRLocal] = set()

    def walk(s: IRStatement) -> None:
        if isinstance(s, IRAssign):
            if isinstance(s.target, IRLocal):
                found.add(s.target)
            # Array/field writes mutate the object referenced by their base local.
            elif isinstance(s.target, IRArrayAccess):
                arr = s.target.array
                if isinstance(arr, IRLocal):
                    found.add(arr)
                elif isinstance(arr, IRField) and isinstance(arr.target, IRLocal):
                    found.add(arr.target)
            elif isinstance(s.target, IRField) and isinstance(s.target.target, IRLocal):
                found.add(s.target.target)
        elif isinstance(s, (IRRef, IRRefNew)) and isinstance(s.target, IRLocal):
            # A reference lets whatever it is handed to write the local.
            found.add(s.target)
        for child in s.get_children():
            if isinstance(child, IRBlock):
                for child_stmt in child.statements:
                    walk(child_stmt)
            else:
                walk(child)

    walk(stmt)
    return found


def _redefined_before_expression(stmt: IRStatement) -> Set[IRLocal]:
    """Locals assigned by `stmt` before its own expression(s) are evaluated.

    Only IRAssignments to a local fall into this category (the RHS is read
    before the target is overwritten).  Array/field writes mutate their base
    object after the index/value expressions are evaluated, so they are not
    included here.
    """
    found: Set[IRLocal] = set()
    if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal):
        found.add(stmt.target)
    return found


def _contains_top_level_call(stmt: IRStatement) -> bool:
    """True if any expression evaluated by `stmt` itself (not nested blocks) is a call."""

    def walk(e: Optional[IRExpression]) -> bool:
        if e is None:
            return False
        if isinstance(e, IRCall):
            return True
        return any(walk(child) for child in e.get_children() if isinstance(child, IRExpression))

    if isinstance(stmt, IRAssign):
        return walk(stmt.expr) or walk(stmt.target)
    if isinstance(stmt, (IRReturn, IRThrow)) and stmt.value is not None:
        return walk(stmt.value)
    if isinstance(stmt, IRTrace):
        return walk(stmt.msg)
    if isinstance(stmt, (IRConditional, IRWhileLoop)) and stmt.condition is not None:
        return walk(stmt.condition)
    if isinstance(stmt, IRSwitch) and stmt.value is not None:
        return walk(stmt.value)
    if isinstance(stmt, IRExpression):
        return walk(stmt)
    return False


def _contains_call(stmt: IRStatement) -> bool:
    """True if a statement contains any IRCall expression (including nested blocks)."""
    found = False

    def walk(e: Optional[IRExpression]) -> None:
        nonlocal found
        if e is None:
            return
        if isinstance(e, IRCall):
            found = True
        for child in e.get_children():
            if isinstance(child, IRExpression):
                walk(child)

    for child in stmt.get_children():
        if isinstance(child, IRExpression):
            walk(child)
        elif isinstance(child, IRBlock):
            for child_stmt in child.statements:
                if isinstance(child_stmt, IRExpression):
                    walk(child_stmt)
    return found


def _contains_loop_continue(stmt: IRStatement) -> bool:
    """Find continues targeting the enclosing loop, not a nested loop."""
    if isinstance(stmt, IRContinue):
        return True
    if isinstance(stmt, (IRWhileLoop, IRPrimitiveLoop, IRForEachLoop, IRIntRangeLoop)):
        return False
    return any(_contains_loop_continue(child) for child in stmt.get_children())


def _unused_static_aliases(root: IRStatement, code: Bytecode) -> Set[str]:
    """Find class-global bindings whose only reads render as qualified fields.

    GetGlobal only reads initialized HL storage; it does not run a lazy class
    initializer. Keep every class referenced by these bindings visible through
    a retained field access so Haxe DCE still preserves its static initializer.
    Any other read or assignment keeps the whole local (including reused names).
    """
    assigned: Dict[str, Set[str]] = {}
    qualified: Dict[str, Set[str]] = {}
    live: Set[str] = set()

    def static_name(expr: IRExpression) -> Optional[str]:
        typ = expr.get_type()
        if isinstance(typ.definition, Obj):
            name = disasm.type_name(code, typ)
            if is_static_name(name):
                return name
        return None

    def visit(stmt: Optional[IRStatement]) -> None:
        if stmt is None:
            return
        if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal):
            value = stmt.expr
            if (
                isinstance(value, IRConst)
                and value.const_type == IRConst.ConstType.GLOBAL_OBJ
                and isinstance(value.original_index, gIndex)
                and (name := static_name(value)) is not None
            ):
                assigned.setdefault(stmt.target.name, set()).add(name)
            else:
                live.add(stmt.target.name)
            visit(value)
            return
        if isinstance(stmt, IRField) and isinstance(stmt.target, IRLocal):
            name = static_name(stmt.target)
            if name is not None:
                qualified.setdefault(stmt.target.name, set()).add(name)
                return
        if isinstance(stmt, IRLocal):
            live.add(stmt.name)
        for child in stmt.get_children():
            visit(child)

    visit(root)
    return {
        local
        for local, classes in assigned.items()
        if local not in live and classes <= qualified.get(local, set())
    }


def _all_statements(node: IRStatement) -> List[IRStatement]:
    found: List[IRStatement] = []
    pending: List[IRStatement] = [node]
    seen: Set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        found.append(current)
        pending.extend(current.get_children())
    return found


def _local_def(name: str, ir_function: Optional[IRFunction]) -> str:
    """`name` as the declaration of that local of `ir_function`."""
    if ir_function is None or name == "this":
        return name
    return mark(name, SymbolRef.local(ir_function.func.findex.value, name), True)


def _param_def(param: str, ir_function: IRFunction) -> str:
    """A rendered parameter (`?name: T = default`) with its name tagged as the declaration."""
    name, colon, rest = param.partition(":")
    bare = name.strip().lstrip("?")
    if not bare or not bare.isidentifier():
        return param
    at = name.index(bare)
    return name[:at] + _local_def(bare, ir_function) + name[at + len(bare) :] + colon + rest


def _plan_declarations(
    ir_func: IRFunction,
    local_types: Dict[str, str],
    initial_declared_vars: Set[str],
    catch_locals: Set[str],
    foreach_elem_names: Set[str],
    inline_declarations: Dict[IRStatement, Tuple[str, str]],
    output_lines: List[str],
) -> None:
    """Decide where each local is declared: inline at its defining statement (recorded in
    `inline_declarations`) or up front (appended to `output_lines`)."""
    for local_name in local_types:
        if local_name in initial_declared_vars or local_name == "this":
            continue
        # Catch-clause locals are declared by the `catch (e:T)` syntax; skip them.
        # But if the same name is also explicitly assigned elsewhere (register
        # reuse for an unrelated local), it still needs a real declaration.
        if local_name in catch_locals and not _has_explicit_assignment(local_name, ir_func.block):
            continue
        # For-each loop variables are declared by the `for (x in y)` syntax - unless
        # the same name is also assigned somewhere else in the function (register
        # reuse), in which case it still needs a real declaration.
        if local_name in foreach_elem_names and not _has_explicit_assignment(local_name, ir_func.block):
            continue
        type_str = local_types[local_name]
        defining_stmt = _find_defining_assignment(local_name, ir_func.block)
        if defining_stmt is not None:
            # If the same local is also assigned inside a compound statement that
            # appears earlier in the block, declaring it at the later assignment
            # site would produce a use-before-declaration.  Fall back to a top-level
            # declaration instead.
            if not _assigned_before_in_block(local_name, ir_func.block, defining_stmt):
                # Emit inline at the assignment site, preserving statement order.
                inline_declarations[defining_stmt] = (local_name, type_str)
                continue
        # If the variable only lives inside a single compound statement, declare
        # it inline there rather than pre-declaring at function level.
        assigned_before_use = _is_definitely_assigned_before_use(local_name, ir_func.block)
        inner_stmt = (
            _find_inner_defining_assignment(local_name, ir_func.block) if assigned_before_use else None
        )
        if inner_stmt is not None:
            inline_declarations[inner_stmt] = (local_name, type_str)
            continue
        # Declaration placement is independent of initialization: omit synthetic
        # defaults only when every reachable read has a preceding assignment.
        if assigned_before_use:
            output_lines.append(f"    var {_local_def(local_name, ir_func)}: {type_str};")
            continue
        default_init = {
            "Int": "0",
            "Float": "0.0",
            "Bool": "false",
            "String": '""',
            "Dynamic": "null",
        }.get(type_str)
        if type_str.startswith("Array<"):
            default_init = "[]"
        init = f" = {default_init}" if default_init is not None else ""
        output_lines.append(f"    var {_local_def(local_name, ir_func)}: {type_str}{init};")


def _has_explicit_assignment(local_name: str, stmt: IRStatement) -> bool:
    """Recursively check for a genuine `IRAssign` to `local_name` anywhere in `stmt`.

    HL bytecode reuses register names, so the same name can be bound as a
    for-loop's element (an implicit binding, no `IRAssign` statement of its own)
    *and* separately reused as an ordinary assigned variable elsewhere in the same
    function. `_collect_foreach_elem_names` alone can't tell those cases apart; this
    catches the "elsewhere" case so that variable still gets a hoisted declaration.
    """
    if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal) and stmt.target.name == local_name:
        return True
    return any(_has_explicit_assignment(local_name, child) for child in stmt.get_children())


def _collect_foreach_elem_names(block: IRBlock) -> Set[str]:
    """Collect names of IRForEachLoop element locals at any depth in block."""
    names: Set[str] = set()
    for stmt in block.statements:
        if isinstance(stmt, (IRForEachLoop, IRIntRangeLoop)):
            if stmt.elem.name:
                names.add(stmt.elem.name)
            names.update(_collect_foreach_elem_names(stmt.body))
        elif isinstance(stmt, IRConditional):
            names.update(_collect_foreach_elem_names(stmt.true_block))
            if stmt.false_block:
                names.update(_collect_foreach_elem_names(stmt.false_block))
        elif isinstance(stmt, (IRWhileLoop, IRPrimitiveLoop)):
            names.update(_collect_foreach_elem_names(stmt.body))
        elif isinstance(stmt, IRTryCatch):
            names.update(_collect_foreach_elem_names(stmt.try_block))
            names.update(_collect_foreach_elem_names(stmt.catch_block))
            for _, extra_block in stmt.extra_catches:
                names.update(_collect_foreach_elem_names(extra_block))
        elif isinstance(stmt, IRSwitch):
            for case_block in stmt.cases.values():
                names.update(_collect_foreach_elem_names(case_block))
            if stmt.default:
                names.update(_collect_foreach_elem_names(stmt.default))
    return names


def _collect_catch_local_names(block: IRBlock) -> Set[str]:
    """Collect names of all catch-clause locals at any depth in block."""
    names: Set[str] = set()
    for stmt in block.statements:
        if isinstance(stmt, IRTryCatch):
            if stmt.catch_local and stmt.catch_local.name:
                names.add(stmt.catch_local.name)
            for extra_local, _ in stmt.extra_catches:
                if extra_local.name:
                    names.add(extra_local.name)
            names.update(_collect_catch_local_names(stmt.try_block))
            names.update(_collect_catch_local_names(stmt.catch_block))
        elif isinstance(stmt, IRConditional):
            names.update(_collect_catch_local_names(stmt.true_block))
            if stmt.false_block:
                names.update(_collect_catch_local_names(stmt.false_block))
        elif isinstance(stmt, (IRWhileLoop, IRPrimitiveLoop)):
            names.update(_collect_catch_local_names(stmt.body))
    return names


def _switch_defines_local(switch_stmt: IRSwitch, local_name: str) -> Optional[IRLocal]:
    """Return the target local if `switch_stmt` is an expression switch that
    unconditionally assigns to `local_name` in every branch."""
    expr_switch = _is_expression_switch(switch_stmt)
    if expr_switch is None:
        return None
    target, case_exprs, default_expr = expr_switch
    if target.name != local_name:
        return None
    sources: Set[str] = set()
    for expr in case_exprs.values():
        sources.update(_collect_local_names(expr))
    if default_expr is not None:
        sources.update(_collect_local_names(default_expr))
    if local_name in sources:
        return None
    return target


def _is_definitely_assigned_before_use(local_name: str, block: IRBlock) -> bool:
    """Prove that removing a hoisted default cannot expose an unassigned read.

    Exit states record definite assignment separately for normal fallthrough,
    break, and continue. Missing exits are unreachable (return/throw), not
    unassigned paths. Assignment is monotone, so checking a loop's first
    iteration with its entry state also covers subsequent iterations; we never
    use a back-edge write to justify a first-iteration read.
    """

    def merge(exits: Dict[str, bool], other: Dict[str, bool]) -> None:
        for kind, assigned in other.items():
            exits[kind] = exits.get(kind, True) and assigned

    def reads_safely(stmt: Optional[IRStatement], assigned: bool) -> bool:
        if stmt is None:
            return True
        # Raw opcodes/jumps can hide register reads from get_children().
        if isinstance(stmt, (IRUnliftedOpcode, IRPrimitiveJump, IRNativeStub)):
            return False
        if isinstance(stmt, IRLocal):
            return assigned or stmt.name != local_name
        return all(reads_safely(child, assigned) for child in stmt.get_children())

    def walk(stmt: Optional[IRStatement], assigned: bool) -> Optional[Dict[str, bool]]:
        if stmt is None:
            return {"normal": assigned}
        if isinstance(stmt, IRBlock):
            exits = {"normal": assigned}
            for child in stmt.statements:
                if "normal" not in exits:
                    break
                child_exits = walk(child, exits.pop("normal"))
                if child_exits is None:
                    return None
                merge(exits, child_exits)
            return exits
        if isinstance(stmt, IRAssign):
            if not reads_safely(stmt.expr, assigned):
                return None
            if isinstance(stmt.target, IRLocal):
                return {"normal": assigned or stmt.target.name == local_name}
            # Storing through a field/array reads its receiver and index.
            return {"normal": assigned} if reads_safely(stmt.target, assigned) else None
        if isinstance(stmt, (IRReturn, IRThrow)):
            return {} if reads_safely(stmt, assigned) else None
        if isinstance(stmt, IRBreak):
            return {"break": assigned}
        if isinstance(stmt, IRContinue):
            return {"continue": assigned}
        if isinstance(stmt, (IRConditional, IRSwitch)):
            condition = stmt.condition if isinstance(stmt, IRConditional) else stmt.value
            if not reads_safely(condition, assigned):
                return None
            branches = (
                [stmt.true_block, stmt.false_block]
                if isinstance(stmt, IRConditional)
                else [*stmt.cases.values(), stmt.default]
            )
            exits: Dict[str, bool] = {}
            for branch in branches:
                branch_exits = walk(branch, assigned)
                if branch_exits is None:
                    return None
                merge(exits, branch_exits)
            return exits
        if isinstance(stmt, (IRWhileLoop, IRForEachLoop, IRIntRangeLoop)):
            if isinstance(stmt, IRWhileLoop):
                inputs = [stmt.condition]
                body_assigned = assigned
            else:
                inputs = [stmt.array] if isinstance(stmt, IRForEachLoop) else [stmt.start, stmt.end]
                body_assigned = assigned or stmt.elem.name == local_name
            if not all(reads_safely(expr, assigned) for expr in inputs):
                return None
            body_exits = walk(stmt.body, body_assigned)
            if body_exits is None:
                return None
            # Haxe's definite-assignment analysis does not reliably propagate
            # assignments out of literal-true loops with break/return exits.
            # Even when every reachable break assigns the local, retain its
            # entry state after the loop so the emitted declaration compiles.
            # The body proof still permits defaults to disappear for loop-local
            # scratch values whose reads follow a write within the iteration.
            return {"normal": assigned}
        if isinstance(stmt, IRTryCatch):
            exits = walk(stmt.try_block, assigned)
            if exits is None:
                return None
            for binding, body in [(stmt.catch_local, stmt.catch_block), *stmt.extra_catches]:
                # An exception can precede any write in the try, including a
                # throwing assignment RHS. Do not borrow its normal exit state.
                shadowed = binding is not None and binding.name == local_name
                catch_exits = walk(body, assigned or shadowed)
                if catch_exits is None:
                    return None
                if shadowed:
                    catch_exits = {kind: assigned for kind in catch_exits}
                merge(exits, catch_exits)
            return exits
        if isinstance(stmt, IRPrimitiveLoop):
            return None  # Unstructured exits cannot support a dominance proof.
        return {"normal": assigned} if reads_safely(stmt, assigned) else None

    exits = walk(block, False)
    return exits is not None and "break" not in exits and "continue" not in exits


def _find_defining_assignment(local_name: str, block: IRBlock) -> Optional[Union[IRAssign, IRSwitch]]:
    """Return the top-level assignment (or expression switch) that defines a local
    if it happens unconditionally before any read of that local.

    The assignment is folded into `var name = ...` at its existing statement
    position, so it is safe as long as the statement itself does not read the
    local being defined.
    """
    for stmt in block.statements:
        if isinstance(stmt, IRAssign):
            if isinstance(stmt.target, IRLocal) and stmt.target.name == local_name:
                if _contains_local_name(local_name, stmt.expr):
                    return None
                return stmt
        elif isinstance(stmt, IRSwitch):
            target = _switch_defines_local(stmt, local_name)
            if target is not None:
                expr_switch = _is_expression_switch(stmt)
                assert expr_switch is not None
                _, case_exprs, default_expr = expr_switch
                sources: Set[str] = set()
                for expr in case_exprs.values():
                    sources.update(_collect_local_names(expr))
                if default_expr is not None:
                    sources.update(_collect_local_names(default_expr))
                if local_name in sources:
                    return None
                return stmt
        if _contains_local_name(local_name, stmt):
            return None
    return None


def _find_inner_defining_assignment(local_name: str, block: IRBlock) -> Optional[Union[IRAssign, IRSwitch]]:
    """If `local_name` is only used inside a single sub-block of a single top-level
    compound statement, return the first assignment to it in that sub-block.

    Safe cases:
    - IRTryCatch: variable only in try_block or only in catch_block (not both).
    - IRConditional: variable only in true_block or only in false_block (not both),
      with no other reads/writes in the function.
    """
    # Ensure the variable doesn't appear in top-level assignments or reads.
    compound_types = (IRTryCatch, IRConditional, IRSwitch, IRWhileLoop, IRPrimitiveLoop)
    compound_stmts = [s for s in block.statements if isinstance(s, compound_types)]
    non_compound = [s for s in block.statements if not isinstance(s, compound_types)]
    if any(
        _contains_local_name(local_name, s) or _find_assignment_recursive(local_name, s) is not None
        for s in non_compound
    ):
        return None
    # Must appear in exactly one compound statement.
    containing = [
        s
        for s in compound_stmts
        if _find_assignment_recursive(local_name, s) is not None or _contains_local_name(local_name, s)
    ]
    if len(containing) != 1:
        return None
    stmt = containing[0]

    if isinstance(stmt, IRTryCatch):
        in_try = _find_assignment_recursive(local_name, stmt.try_block) is not None or _contains_local_name(
            local_name, stmt.try_block
        )
        in_catch = (
            _find_assignment_recursive(local_name, stmt.catch_block) is not None
            or _contains_local_name(local_name, stmt.catch_block)
            or any(
                _find_assignment_recursive(local_name, extra_block) is not None
                or _contains_local_name(local_name, extra_block)
                for _, extra_block in stmt.extra_catches
            )
        )
        if in_try and not in_catch:
            # Use _find_defining_assignment on the sub-block to ensure it's safe.
            return _find_defining_assignment(local_name, stmt.try_block)
        if in_catch and not in_try:
            return _find_defining_assignment(local_name, stmt.catch_block)

    elif isinstance(stmt, IRConditional):
        true_block = stmt.true_block
        false_block = stmt.false_block
        in_true = true_block is not None and (
            _find_assignment_recursive(local_name, true_block) is not None
            or _contains_local_name(local_name, true_block)
        )
        in_false = false_block is not None and (
            _find_assignment_recursive(local_name, false_block) is not None
            or _contains_local_name(local_name, false_block)
        )
        if in_true and not in_false:
            return _find_defining_assignment(local_name, true_block)
        if in_false and not in_true:
            return _find_defining_assignment(local_name, false_block)

    elif isinstance(stmt, IRSwitch):
        candidate_block: Optional[IRBlock] = None
        for case_block in stmt.cases.values():
            if _find_assignment_recursive(local_name, case_block) is not None or _contains_local_name(
                local_name, case_block
            ):
                if candidate_block is not None:
                    return None
                candidate_block = case_block
        if stmt.default and (
            _find_assignment_recursive(local_name, stmt.default) is not None
            or _contains_local_name(local_name, stmt.default)
        ):
            if candidate_block is not None:
                return None
            candidate_block = stmt.default
        if candidate_block is not None:
            return _find_defining_assignment(local_name, candidate_block)

    elif isinstance(stmt, (IRWhileLoop, IRPrimitiveLoop)):
        # The local lives only inside this loop. Declare it inline at its first
        # assignment in the loop body, recursing in case it nests deeper.
        if _contains_local_name(local_name, stmt.condition):
            return None
        # A test at the end of the body becomes the `while` of a do-while, outside the body's scope.
        for tail in stmt.body.statements[-2:]:
            if isinstance(tail, IRConditional) and _contains_local_name(local_name, tail.condition):
                return None
        inner = _find_defining_assignment(local_name, stmt.body)
        if inner is not None:
            return inner
        return _find_inner_defining_assignment(local_name, stmt.body)

    return None


# Memoized read-name sets for `_contains_local_name`, active while declarations are
# planned (read-only analysis of the IR). Thread-local: renders run on worker threads.
_local_reads_state = threading.local()


@contextmanager
def _memoized_local_reads() -> Iterator[None]:
    previous = getattr(_local_reads_state, "reads", None)
    _local_reads_state.reads = {}
    try:
        yield
    finally:
        _local_reads_state.reads = previous


def _read_names(stmt: Optional[IRStatement], memo: Dict[int, FrozenSet[str]]) -> FrozenSet[str]:
    """Every local name `_contains_local_name` would find in `stmt`, memoized by node."""
    if stmt is None:
        return frozenset()
    key = id(stmt)
    found = memo.get(key)
    if found is not None:
        return found
    if isinstance(stmt, IRLocal):
        found = frozenset((stmt.name,))
        memo[key] = found
        return found
    parts: List[Optional[IRStatement]]
    if isinstance(stmt, (IRArithmetic, IRBoolExpr)):
        parts = [stmt.left, stmt.right]
    elif isinstance(stmt, IRCall):
        parts = [stmt.target, *stmt.args]
    elif isinstance(stmt, (IRField, IRRef, IRRefNew)):
        parts = [stmt.target]
    elif isinstance(stmt, IRArrayAccess):
        parts = [stmt.array, stmt.index]
    elif isinstance(stmt, (IRCast, IRNeg, IRNot)):
        parts = [stmt.expr]
    elif isinstance(stmt, IRRefGet):
        parts = [stmt.ref]
    elif isinstance(stmt, IRRefSet):
        parts = [stmt.ref, stmt.value]
    elif isinstance(stmt, IREnumConstruct):
        parts = list(stmt.args)
    elif isinstance(stmt, (IREnumIndex, IREnumField)):
        parts = [stmt.value]
    elif isinstance(stmt, IRNew):
        parts = list(stmt.constructor_args)
    elif isinstance(stmt, IRTrace):
        parts = [stmt.msg]
    elif isinstance(stmt, IRReturn):
        parts = [stmt.value]
    elif isinstance(stmt, IRAssign):
        # A local target is a write; a field/array target reads its receiver/index.
        parts = [stmt.expr] if isinstance(stmt.target, IRLocal) else [stmt.expr, stmt.target]
    elif isinstance(stmt, IRBlock):
        parts = list(stmt.statements)
    elif isinstance(stmt, IRConditional):
        parts = [stmt.condition, stmt.true_block, stmt.false_block]
    elif isinstance(stmt, (IRWhileLoop, IRPrimitiveLoop)):
        parts = [stmt.condition, stmt.body]
    elif isinstance(stmt, IRSwitch):
        parts = [stmt.value, *stmt.cases.values(), stmt.default]
    elif isinstance(stmt, IRTryCatch):
        parts = [
            stmt.try_block,
            stmt.catch_block,
            *(block for _, block in stmt.extra_catches),
            stmt.catch_local,
        ]
    else:
        parts = list(stmt.get_children())
    names: Set[str] = set()
    for part in parts:
        names |= _read_names(part, memo)
    found = frozenset(names)
    memo[key] = found
    return found


def _contains_local_name(local_name: str, stmt: IRStatement) -> bool:
    """Recursively search `stmt` for a read of the named local."""
    memo = getattr(_local_reads_state, "reads", None)
    if memo is not None:
        return local_name in _read_names(stmt, memo)
    return _contains_local_name_walk(local_name, stmt)


def _contains_local_name_walk(local_name: str, stmt: IRStatement) -> bool:
    """`_contains_local_name` without the memo."""
    if isinstance(stmt, IRLocal):
        return stmt.name == local_name
    if isinstance(stmt, IRArithmetic):
        return _contains_local_name_walk(local_name, stmt.left) or _contains_local_name_walk(
            local_name, stmt.right
        )
    if isinstance(stmt, IRBoolExpr):
        return (stmt.left is not None and _contains_local_name_walk(local_name, stmt.left)) or (
            stmt.right is not None and _contains_local_name_walk(local_name, stmt.right)
        )
    if isinstance(stmt, IRCall):
        if stmt.target is not None and _contains_local_name_walk(local_name, stmt.target):
            return True
        return any(_contains_local_name_walk(local_name, arg) for arg in stmt.args)
    if isinstance(stmt, IRField):
        return _contains_local_name_walk(local_name, stmt.target)
    if isinstance(stmt, IRArrayAccess):
        return _contains_local_name_walk(local_name, stmt.array) or _contains_local_name_walk(
            local_name, stmt.index
        )
    if isinstance(stmt, IRCast):
        return _contains_local_name_walk(local_name, stmt.expr)
    if isinstance(stmt, IRNeg):
        return _contains_local_name_walk(local_name, stmt.expr)
    if isinstance(stmt, IRNot):
        return _contains_local_name_walk(local_name, stmt.expr)
    if isinstance(stmt, IRRef):
        return _contains_local_name_walk(local_name, stmt.target)
    if isinstance(stmt, IRRefNew):
        return _contains_local_name_walk(local_name, stmt.target)
    if isinstance(stmt, IRRefGet):
        return _contains_local_name_walk(local_name, stmt.ref)
    if isinstance(stmt, IRRefSet):
        return _contains_local_name_walk(local_name, stmt.ref) or _contains_local_name_walk(
            local_name, stmt.value
        )
    if isinstance(stmt, IREnumConstruct):
        return any(_contains_local_name_walk(local_name, arg) for arg in stmt.args)
    if isinstance(stmt, (IREnumIndex, IREnumField)):
        return _contains_local_name_walk(local_name, stmt.value)
    if isinstance(stmt, IRNew):
        return any(_contains_local_name_walk(local_name, arg) for arg in stmt.constructor_args)
    if isinstance(stmt, IRTrace):
        return _contains_local_name_walk(local_name, stmt.msg)
    if isinstance(stmt, IRReturn):
        return stmt.value is not None and _contains_local_name_walk(local_name, stmt.value)
    if isinstance(stmt, IRAssign):
        # A local target is a write, but a field/array target evaluates its
        # receiver/index before storing and therefore reads those locals.
        return _contains_local_name_walk(local_name, stmt.expr) or (
            not isinstance(stmt.target, IRLocal) and _contains_local_name_walk(local_name, stmt.target)
        )
    if isinstance(stmt, IRBlock):
        return any(_contains_local_name_walk(local_name, child) for child in stmt.statements)
    if isinstance(stmt, IRConditional):
        return (
            _contains_local_name_walk(local_name, stmt.condition)
            or _contains_local_name_walk(local_name, stmt.true_block)
            or _contains_local_name_walk(local_name, stmt.false_block)
        )
    if isinstance(stmt, (IRWhileLoop, IRPrimitiveLoop)):
        return _contains_local_name_walk(local_name, stmt.condition) or _contains_local_name_walk(
            local_name, stmt.body
        )
    if isinstance(stmt, IRSwitch):
        if _contains_local_name_walk(local_name, stmt.value):
            return True
        return any(_contains_local_name_walk(local_name, block) for block in stmt.cases.values()) or (
            stmt.default is not None and _contains_local_name_walk(local_name, stmt.default)
        )
    if isinstance(stmt, IRTryCatch):
        return (
            _contains_local_name_walk(local_name, stmt.try_block)
            or _contains_local_name_walk(local_name, stmt.catch_block)
            or any(
                _contains_local_name_walk(local_name, extra_block) for _, extra_block in stmt.extra_catches
            )
            or (stmt.catch_local is not None and stmt.catch_local.name == local_name)
        )
    return any(_contains_local_name_walk(local_name, child) for child in stmt.get_children())


def _collect_local_names(stmt: IRStatement) -> Set[str]:
    """Recursively collect the names of all `IRLocal` nodes in `stmt`."""
    names: Set[str] = set()
    if isinstance(stmt, IRLocal):
        names.add(stmt.name)
        return names
    for child in stmt.get_children():
        names.update(_collect_local_names(child))
    return names


def _has_multiple_assignments(local_name: str, block: IRBlock) -> bool:
    """Return True if `local_name` is assigned more than once at the top level of `block`."""
    count = 0
    for stmt in block.statements:
        if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal) and stmt.target.name == local_name:
            count += 1
            if count > 1:
                return True
    return False


def _assigned_before_in_block(local_name: str, block: IRBlock, stmt: IRStatement) -> bool:
    """Return True if `local_name` is assigned anywhere inside a statement that
    appears before `stmt` in the block (including nested compound statements).
    """
    for s in block.statements:
        if s is stmt:
            return False
        if _find_assignment_recursive(local_name, s) is not None:
            return True
    return False


def _find_assignment_recursive(local_name: str, stmt: IRStatement) -> Optional[IRAssign]:
    """Recursively search `stmt` for a top-level assignment to `local_name`."""
    if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal) and stmt.target.name == local_name:
        return stmt
    for child in stmt.get_children():
        found = _find_assignment_recursive(local_name, child)
        if found is not None:
            return found
    return None


def _collect_locals(root: IRStatement) -> Dict[str, str]:
    """
    Collect all local variables referenced in an IR tree, mapping name to a
    Haxe type name. This is used to hoist variable declarations to the top of a
    function, avoiding Haxe's block-scoping issues with decompiled output.
    """
    locals: Dict[str, str] = {}
    seen: Set[int] = set()
    pattern_locals: Set[str] = set()
    unbound = _unbound_reads(root)
    catch_bindings: Set[int] = set()

    def collect_pattern(pattern: IREnumPattern) -> None:
        for slot in pattern.slots.values():
            if isinstance(slot, IRLocal):
                pattern_locals.add(slot.name)
            elif isinstance(slot, IREnumPattern):
                collect_pattern(slot)

    def visit(stmt: IRStatement) -> None:
        if id(stmt) in seen:
            return
        seen.add(id(stmt))
        if isinstance(stmt, IRTryCatch):
            # A catch binding is declared by its own `catch (name: T)` clause. Hoisting it
            # would merge it with an unrelated same-named local of another type.
            for binding in [stmt.catch_local, *(local for local, _ in stmt.extra_catches)]:
                if binding is not None:
                    catch_bindings.add(id(binding))
        if isinstance(stmt, IRSwitch):
            for pattern in stmt.enum_patterns.values():
                collect_pattern(pattern)
            if isinstance(stmt.value, IREnumIndex):
                switch_value = stmt.value.value
            else:
                detected = _detect_enum_value_from_cases(stmt)
                switch_value = detected if detected is not None else stmt.value
            for case_value, case_block in stmt.cases.items():
                if case_value in stmt.enum_patterns:
                    continue
                captures = _pattern_captures(case_block, switch_value, unbound)
                if captures:
                    pattern_locals.update(capture for capture, local in captures if local is None)
            if stmt.default is not None:
                captures = _pattern_captures(stmt.default, switch_value, unbound)
                if captures:
                    pattern_locals.update(capture for capture, local in captures if local is None)
        if isinstance(stmt, IRLocal):
            if stmt.name in pattern_locals or id(stmt) in catch_bindings:
                return
            if stmt.native_elem_type is not None:
                elem_haxe_type = disasm._haxe_annotation(stmt.code, stmt.native_elem_type)
                type_name = f"hl.NativeArray<{elem_haxe_type}>"
            elif stmt.native_map_class is not None:
                type_name = stmt.native_map_class
            elif stmt.array_elem_type is not None:
                elem_haxe_type = disasm._haxe_annotation(stmt.code, stmt.array_elem_type)
                type_name = f"Array<{elem_haxe_type}>"
            else:
                local_type = stmt.get_type()
                type_name = disasm._haxe_annotation(stmt.code, local_type)
                if stmt.is_unsigned and type_name == "Int":
                    type_name = "UInt"
            if stmt.name in locals and locals[stmt.name] != type_name:
                locals[stmt.name] = "Dynamic"
            else:
                locals[stmt.name] = type_name
        for child in stmt.get_children():
            visit(child)

    visit(root)

    # Upgrade raw hl.Bytes temporaries that feed ArrayBase.alloc* calls to
    # hl.BytesAccess<T>. This lets the decompiled byte-manipulation pattern
    # recompile as typed array-access stores.
    def _alloc_element_type(func_name: str) -> str:
        if "allocF64" in func_name:
            return "Float"
        if "allocF32" in func_name:
            return "Single"
        if "allocUI16" in func_name:
            return "Int"
        if "allocI32" in func_name:
            return "Int"
        return "Int"

    # A name that's also used as a raw hl.Bytes buffer elsewhere (explicit
    # .setI32()/.getI32()-style accessor calls, rendered whenever an
    # IRArrayAccess carries a bytes_access_kind) must keep the hl.Bytes
    # declaration -- those accessors don't exist on hl.BytesAccess<T>. A
    # register can legitimately feed ArrayBase.alloc* at one point (e.g. an
    # empty-array fast path) and be manually byte-written at another (e.g.
    # building a single-element literal), so the upgrade below can't apply
    # per-name unconditionally.
    raw_bytes_required: Set[str] = set()

    def _collect_raw_bytes_required(stmt: IRStatement, _seen: Set[int]) -> None:
        if id(stmt) in _seen:
            return
        _seen.add(id(stmt))
        if isinstance(stmt, IRArrayAccess) and getattr(stmt, "bytes_access_kind", None):
            if isinstance(stmt.array, IRLocal):
                raw_bytes_required.add(stmt.array.name)
        for child in stmt.get_children():
            _collect_raw_bytes_required(child, _seen)

    _collect_raw_bytes_required(root, set())

    seen_upgrade: Set[int] = set()

    def _upgrade_bytes(stmt: IRStatement) -> None:
        if id(stmt) in seen_upgrade:
            return
        seen_upgrade.add(id(stmt))
        if isinstance(stmt, IRAssign) and isinstance(stmt.expr, IRCall):
            call = stmt.expr
            if (
                call.target is not None
                and isinstance(call.target, IRConst)
                and isinstance(call.target.value, Function)
            ):
                func = call.target.value
                name = root.code.full_func_name(func) or root.code.partial_func_name(func) or ""
                if "ArrayBase.alloc" in name and call.args:
                    first_arg = call.args[0]
                    if (
                        isinstance(first_arg, IRLocal)
                        and locals.get(first_arg.name) == "hl.Bytes"
                        and first_arg.name not in raw_bytes_required
                    ):
                        locals[first_arg.name] = f"hl.BytesAccess<{_alloc_element_type(name)}>"
        for child in stmt.get_children():
            _upgrade_bytes(child)

    _upgrade_bytes(root)
    return locals


def _tag_map_allocations(root: IRStatement, code: Bytecode, findex: int, locals_: List[IRLocal]) -> None:
    """Give each `new IntMap()` bound to a local the value type recovered for the local.
    Registers a variable of one name was split over share the type its name is declared with."""
    seen: Set[int] = set()
    by_name: Dict[str, str] = {}
    for local in locals_:
        found = mapargs.value_type(code, ("r", findex, local.reg_idx)) if local.reg_idx is not None else None
        if found is not None:
            by_name.setdefault(local.name, found)

    def visit(stmt: IRStatement) -> None:
        if id(stmt) in seen:
            return
        seen.add(id(stmt))
        if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRField) and isinstance(stmt.expr, IRNew):
            owner = stmt.target.target.get_type().definition
            for declaring in [owner, *_ancestors(code, owner)] if isinstance(owner, Obj) else []:
                node = mapargs.field_node(code, declaring, stmt.target.field_name)
                if node is not None:
                    setattr(stmt.expr, "map_value", mapargs.value_type(code, node))
                    break
        if (
            isinstance(stmt, IRAssign)
            and isinstance(stmt.target, IRLocal)
            and isinstance(stmt.expr, (IRNew, IRArrayLiteral))
            and stmt.target.reg_idx is not None
        ):
            setattr(
                stmt.expr, "map_value", by_name.get(stmt.target.name, getattr(stmt.expr, "map_value", None))
            )
        for child in stmt.get_children():
            visit(child)

    visit(root)
