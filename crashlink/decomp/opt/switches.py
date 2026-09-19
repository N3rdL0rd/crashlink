"""
Switch-statement pattern optimizers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Optional, Set, Tuple, cast

if TYPE_CHECKING:
    pass

from ...core import (
    Enum,
    Native,
)
from ..ir import (
    IRStatement,
    IRExpression,
    IRBlock,
    IRLocal,
    IRAssign,
    IRCall,
    IRBoolExpr,
    IRConst,
    IRConditional,
    IRSwitch,
    IRField,
    IREnumIndex,
    IREnumField,
    IREnumPattern,
    IRReturn,
)
from . import (
    TraversingIROptimizer,
    _int_const_value,
    _signed_i32,
    _stmt_lists_structurally_equal,
)


class IRIntSwitchOptimizer(TraversingIROptimizer):
    """
    Recover IRSwitch statements from lowered chains of integer equality/inequality
    conditionals. HashLink compiles sparse or negative integer switches as nested
    `if (x != c1) { if (x == c2) ... } else { ... }` patterns; this pass raises them
    back into a switch.
    """

    def visit_block(self, block: IRBlock) -> None:
        made_change = True
        while made_change:
            made_change = False
            new_statements: List[IRStatement] = []
            i = 0
            while i < len(block.statements):
                stmt = block.statements[i]
                switch = self._try_int_switch(stmt)
                if switch is not None:
                    new_statements.append(switch)
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

    def _try_int_switch(self, stmt: IRStatement) -> Optional[IRSwitch]:
        if not isinstance(stmt, IRConditional):
            return None
        cases: Dict[IRConst, IRBlock] = {}
        default: Optional[IRBlock] = None
        local: Optional[IRLocal] = None
        current: Optional[IRStatement] = stmt
        chain: List[IRStatement] = []
        while isinstance(current, IRConditional):
            chain.append(current)
            cond = current.condition
            if not isinstance(cond, IRBoolExpr) or cond.op not in (
                IRBoolExpr.CompareType.EQ,
                IRBoolExpr.CompareType.NEQ,
            ):
                return None
            left, right = cond.left, cond.right
            if (
                isinstance(left, IRLocal)
                and isinstance(right, IRConst)
                and right.const_type == IRConst.ConstType.INT
            ):
                cand_local, cand_const = left, right
            elif (
                isinstance(right, IRLocal)
                and isinstance(left, IRConst)
                and left.const_type == IRConst.ConstType.INT
            ):
                cand_local, cand_const = right, left
            else:
                return None
            if local is None:
                local = cand_local
            elif local.name != cand_local.name:
                return None
            val = _int_const_value(cand_const)
            if val is None:
                return None
            val = _signed_i32(val)
            if cond.op == IRBoolExpr.CompareType.NEQ:
                rest = current.true_block
                case_body = current.false_block
            else:
                rest = current.false_block
                case_body = current.true_block
            case_const = IRConst(self.func.code, IRConst.ConstType.INT, value=val)
            if any(_int_const_value(k) == val for k in cases):
                return None
            cases[case_const] = case_body
            rest_stmts = rest.statements
            if len(rest_stmts) == 1 and isinstance(rest_stmts[0], IRConditional):
                current = rest_stmts[0]
                continue
            default = rest
            break
        if local is None or len(cases) < 2:
            return None
        if default is None:
            default = IRBlock(self.func.code)
        return IRSwitch(self.func.code, local, cases, default).adopt(*chain)


class IRStringSwitchOptimizer(TraversingIROptimizer):
    """
    Recover IRSwitch statements from HashLink's string-switch lowering.

    HashLink compiles `switch (s) { case "foo": ...; case "bar": ...; }` into a
    chain of null checks, length checks, and std.string_compare calls. This pass
    recognises that pattern and raises it back into an IRSwitch on the original
    string local.
    """

    def visit_block(self, block: IRBlock) -> None:
        made_change = True
        while made_change:
            made_change = False
            new_statements: List[IRStatement] = []
            i = 0
            while i < len(block.statements):
                stmt = block.statements[i]
                parsed = self._try_string_switch(stmt)
                if parsed is not None:
                    switch, tail = parsed
                    i += 1
                    # The lifter flattens a conditional's "no match" continuation
                    # into the *sibling* statements of the enclosing block rather
                    # than nesting it as `default` (see IRFunction._lift_block's
                    # convergence handling). So the next case in the chain often
                    # shows up here as the following top-level statement instead
                    # of inside this switch's default block. Fold any such
                    # siblings into this switch until the chain runs out.
                    while not tail and not switch.default.statements and i < len(block.statements):
                        next_parsed = self._try_string_switch(block.statements[i])
                        if next_parsed is None:
                            break
                        next_switch, next_tail = next_parsed
                        if repr(next_switch.value) != repr(switch.value):
                            break
                        switch.cases.update(next_switch.cases)
                        switch.default = next_switch.default
                        switch.adopt(next_switch)
                        tail = next_tail
                        i += 1
                    new_statements.append(switch)
                    new_statements.extend(tail)
                    made_change = True
                    continue
                new_statements.append(stmt)
                i += 1
            block.statements = new_statements
        for stmt in block.statements:
            for child in stmt.get_children():
                if isinstance(child, IRBlock):
                    self.visit_block(child)

    def _try_string_switch(self, stmt: IRStatement) -> Optional[Tuple[IRSwitch, List[IRStatement]]]:
        if not isinstance(stmt, IRConditional):
            return None
        s_local = self._match_null_check(stmt.condition)
        if s_local is None:
            return None
        guard = self._find_length_guard(stmt.true_block, s_local)
        if guard is None:
            return None
        len_cond, temp_local = guard
        parsed = self._parse_compare_chain(len_cond.true_block, s_local, temp_local, collect_tail=True)
        if parsed is None:
            return None
        cases, default, tail, consumed = parsed
        if not default.statements:
            # The chain's no-match `rest` was empty (no explicit default). Do
            # NOT fall back to `stmt.false_block`: when the switch has no
            # explicit default and multiple cases, the compiler factors the
            # null check so the null path re-enters the next case's chain
            # (the convergence node), which the lifter duplicates into
            # `stmt.false_block`. That duplicate is NOT the switch's default —
            # it's the continuation, and using it as `default` re-emits the
            # remaining cases as a fabricated nested switch. Leave the
            # default empty: the post-switch continuation is the siblings.
            default = IRBlock(self.func.code)
        new_switch = IRSwitch(self.func.code, s_local, cases, default)
        new_switch.adopt(stmt, len_cond, *consumed)
        return new_switch, tail

    def _match_null_check(self, cond: IRExpression) -> Optional[IRLocal]:
        if (
            isinstance(cond, IRBoolExpr)
            and cond.op == IRBoolExpr.CompareType.NOT_NULL
            and isinstance(cond.left, IRLocal)
        ):
            return cond.left
        if isinstance(cond, IRBoolExpr) and cond.op == IRBoolExpr.CompareType.NEQ:
            if (
                isinstance(cond.left, IRLocal)
                and isinstance(cond.right, IRConst)
                and cond.right.const_type == IRConst.ConstType.NULL
            ):
                return cond.left
            if (
                isinstance(cond.right, IRLocal)
                and isinstance(cond.left, IRConst)
                and cond.left.const_type == IRConst.ConstType.NULL
            ):
                return cond.right
        return None

    def _find_length_guard(self, block: IRBlock, s_local: IRLocal) -> Optional[Tuple[IRConditional, IRLocal]]:
        if not block.statements:
            return None
        temp_local: Optional[IRLocal] = None
        for stmt in block.statements:
            if (
                isinstance(stmt, IRAssign)
                and isinstance(stmt.target, IRLocal)
                and isinstance(stmt.expr, IRField)
                and stmt.expr.field_name == "length"
                and stmt.expr.target == s_local
            ):
                temp_local = stmt.target
            elif isinstance(stmt, IRConditional) and temp_local is not None:
                cond = stmt.condition
                if isinstance(cond, IRBoolExpr) and cond.op == IRBoolExpr.CompareType.EQ:
                    # A single-use temp (`temp = s.length`) may already have been inlined
                    # directly into this comparison by an earlier pass, leaving `s.length`
                    # in place of `temp` even though the assignment itself still exists
                    # (kept alive by a later, non-adjacent use of `temp`, e.g. as a call
                    # argument). Accept either form.
                    def _is_len_ref(e: IRExpression) -> bool:
                        return e == temp_local or (
                            isinstance(e, IRField) and e.field_name == "length" and e.target == s_local
                        )

                    if (
                        cond.left is not None
                        and _is_len_ref(cond.left)
                        and isinstance(cond.right, IRConst)
                        and cond.right.const_type == IRConst.ConstType.INT
                    ):
                        return stmt, temp_local
                    if (
                        cond.right is not None
                        and _is_len_ref(cond.right)
                        and isinstance(cond.left, IRConst)
                        and cond.left.const_type == IRConst.ConstType.INT
                    ):
                        return stmt, temp_local
        return None

    def _parse_compare_chain(
        self,
        block: IRBlock,
        s_local: IRLocal,
        temp_local: IRLocal,
        collect_tail: bool = False,
    ) -> Optional[Tuple[Dict[IRConst, IRBlock], IRBlock, List[IRStatement], List[IRStatement]]]:
        if not block.statements:
            return None
        compare_idx: Optional[int] = None
        for idx in range(len(block.statements) - 1, -1, -1):
            if isinstance(block.statements[idx], IRConditional):
                compare_idx = idx
                break
        if compare_idx is None or compare_idx == 0:
            return None
        compare_cond = cast(IRConditional, block.statements[compare_idx])
        tail = list(block.statements[compare_idx + 1 :]) if collect_tail else []
        assign = block.statements[compare_idx - 1]
        if not isinstance(assign, IRAssign) or assign.target != temp_local:
            return None
        call = assign.expr
        if not isinstance(call, IRCall):
            return None
        if not (isinstance(call.target, IRConst) and isinstance(call.target.value, Native)):
            return None
        native = call.target.value
        if native.name.resolve(self.func.code) != "string_compare":
            return None
        if len(call.args) != 3:
            return None
        bytes_arg = call.args[0]
        if not (
            isinstance(bytes_arg, IRField) and bytes_arg.field_name == "bytes" and bytes_arg.target == s_local
        ):
            return None
        const_arg = call.args[1]
        if not isinstance(const_arg, IRConst) or const_arg.const_type != IRConst.ConstType.STRING:
            return None
        if call.args[2] != temp_local:
            return None
        cond = compare_cond.condition
        zero_side: Optional[IRExpression] = None
        if isinstance(cond, IRBoolExpr) and cond.op == IRBoolExpr.CompareType.NEQ:
            if cond.left == temp_local:
                zero_side = cond.right
            elif cond.right == temp_local:
                zero_side = cond.left
        elif isinstance(cond, IRBoolExpr) and cond.op == IRBoolExpr.CompareType.EQ:
            if cond.left == temp_local:
                zero_side = cond.right
            elif cond.right == temp_local:
                zero_side = cond.left
        if not isinstance(zero_side, IRConst) or zero_side.const_type != IRConst.ConstType.INT:
            return None
        if _int_const_value(zero_side) != 0:
            return None
        if not isinstance(cond, IRBoolExpr):
            return None
        if cond.op == IRBoolExpr.CompareType.NEQ:
            case_body = compare_cond.false_block
            rest = compare_cond.true_block
        else:
            case_body = compare_cond.true_block
            rest = compare_cond.false_block
        cases: Dict[IRConst, IRBlock] = {
            IRConst(self.func.code, IRConst.ConstType.GLOBAL_STRING, value=const_arg.value): case_body
        }
        if len(rest.statements) == 1 and isinstance(rest.statements[0], IRConditional):
            inner = self._try_string_switch(rest.statements[0])
            if inner is not None:
                inner_switch, inner_tail = inner
                cases.update(inner_switch.cases)
                default = inner_switch.default
                if not tail and collect_tail:
                    tail = inner_tail
                return cases, default, tail, [assign, compare_cond, inner_switch]
        default = rest
        return cases, default, tail, [assign, compare_cond]


class IREnumSwitchOptimizer(TraversingIROptimizer):
    """
    Transform switches on enum indices into switches on the enum value itself,
    using enum constructor names for the cases.
    """

    TARGET_OPCODES = {"EnumIndex", "EnumField"}

    def visit_block(self, block: IRBlock) -> None:
        made_change = True
        while made_change:
            made_change = False
            new_statements: List[IRStatement] = []
            i = 0
            while i < len(block.statements):
                stmt = block.statements[i]
                match = self._try_enum_tree(block.statements, i)
                if match is None:
                    match = self._try_enum_switch(block.statements, i)
                if match is None:
                    match = self._try_singleton_region(block.statements, i)
                if match:
                    switch_stmt, consumed = match
                    new_statements.append(switch_stmt)
                    i += consumed
                    made_change = True
                    continue
                new_statements.append(stmt)
                i += 1
            block.statements = new_statements

    def _try_enum_switch(self, stmts: List[IRStatement], start: int) -> Optional[Tuple[IRSwitch, int]]:
        if start >= len(stmts):
            return None
        stmt = stmts[start]
        if not isinstance(stmt, IRAssign) or not isinstance(stmt.target, IRLocal):
            return None
        if not isinstance(stmt.expr, IREnumIndex):
            return None
        idx_var = stmt.target
        enum_value = stmt.expr.value

        if start + 1 >= len(stmts):
            return None
        next_stmt = stmts[start + 1]
        if not isinstance(next_stmt, IRSwitch):
            return None
        if not isinstance(next_stmt.value, IRLocal) or next_stmt.value.name != idx_var.name:
            return None
        if not isinstance(enum_value, IRLocal):
            return None
        enum_type = enum_value.get_type()
        if not isinstance(enum_type.definition, Enum):
            return None
        if self._index_escapes(idx_var.name, {id(stmt)}, set(), {id(next_stmt)}):
            return None

        patterns: Dict[IRConst, IREnumPattern] = {}
        new_cases: Dict[IRConst, IRBlock] = {}
        enum_def = enum_type.definition
        for case_val, case_block in next_stmt.cases.items():
            if not isinstance(case_val, IRConst) or case_val.const_type != IRConst.ConstType.INT:
                return None
            idx = int(case_val.value.value if hasattr(case_val.value, "value") else case_val.value)
            if not 0 <= idx < len(enum_def.constructs):
                return None
            construct = enum_def.constructs[idx]
            # Create a new IRConst for the constructor name. We repurpose the
            # existing IRConst by changing its value to the constructor name
            # string, but create a fresh one to avoid side effects.
            new_case_val = IRConst(
                self.func.code,
                IRConst.ConstType.GLOBAL_STRING,
                value=construct.name.resolve(self.func.code),
            )
            pattern = IREnumPattern(self.func.code, enum_value.type, idx)
            body = IRBlock(self.func.code)
            consumed = 0
            for node in case_block.statements:
                field = node.expr if isinstance(node, IRAssign) and isinstance(node.target, IRLocal) else node
                if not isinstance(field, IREnumField) or field.value != enum_value:
                    break
                slot = self._valid_field(field, pattern)
                if slot is None or slot in pattern.slots:
                    break
                if isinstance(node, IRAssign):
                    node_target = cast(IRLocal, node.target)
                    if node_target == enum_value:
                        break
                    if not self._private_block(case_block) or self._mentions_outside(
                        node_target.name, {id(case_block)}
                    ):
                        binding = self._fresh_binding(field)
                        pattern.slots[slot] = binding
                        body.statements.append(IRAssign(self.func.code, node_target, binding).adopt(node))
                    else:
                        pattern.slots[slot] = node_target
                consumed += 1
            body.statements.extend(case_block.statements[consumed:])
            body.adopt(case_block, *case_block.statements[:consumed])
            new_cases[new_case_val] = body
            patterns[new_case_val] = pattern

        new_switch = IRSwitch(self.func.code, enum_value, new_cases, next_stmt.default)
        new_switch.adopt(stmt, next_stmt)
        new_switch.enum_patterns = patterns
        return new_switch, 2

    def _index_escapes(
        self,
        name: str,
        definitions: Set[int],
        excluded: Set[int],
        dispatches: Optional[Set[int]] = None,
    ) -> bool:
        """Follow tag definitions through joins; a write on one arm kills only that arm."""
        memo: Dict[Tuple[int, bool], Tuple[bool, bool]] = {}

        def visit(node: IRStatement, live: bool) -> Tuple[bool, bool]:
            key = (id(node), live)
            if key in memo:
                return memo[key]
            if id(node) in definitions:
                return True, False
            if id(node) in excluded:
                return live, False
            if isinstance(node, IRLocal):
                return live, live and node.name == name
            if isinstance(node, IRAssign) and isinstance(node.target, IRLocal):
                _, read = visit(node.expr, live)
                return live and node.target.name != name, read
            if isinstance(node, IRBlock):
                read = False
                for child in node.statements:
                    live, child_read = visit(child, live)
                    read |= child_read
                result = live, read
            elif isinstance(node, IRConditional):
                _, read = visit(node.condition, live)
                left, left_read = visit(node.true_block, live)
                right, right_read = visit(node.false_block, live)
                result = left or right, read or left_read or right_read
            elif isinstance(node, IRSwitch):
                read = False if dispatches and id(node) in dispatches else visit(node.value, live)[1]
                branches = [visit(child, live) for child in [node.default, *node.cases.values()]]
                result = any(end for end, _ in branches), read or any(read for _, read in branches)
            else:
                # Unknown control structures cannot propagate a new tag fact
                # past a backedge or exception boundary. Expression children
                # still observe the incoming state normally.
                children = [visit(child, live) for child in node.get_children()]
                result = live, any(read or end != live for end, read in children)
            memo[key] = result
            return result

        return visit(self.func.block, False)[1]

    def _private_block(self, block: IRBlock) -> bool:
        seen: Set[int] = set()
        incoming = 0

        def visit(node: IRStatement) -> None:
            nonlocal incoming
            if id(node) in seen:
                return
            seen.add(id(node))
            for child in node.get_children():
                if child is block:
                    incoming += 1
                visit(child)

        visit(self.func.block)
        return incoming == 1

    def _fresh_binding(self, field: IREnumField) -> IRLocal:
        names = {local.name for local in self.func.all_locals}
        number = len(names)
        while f"enumParam{number}" in names:
            number += 1
        local = IRLocal(f"enumParam{number}", field.field_type_idx, self.func.code)
        self.func.all_locals.append(local)
        return local

    def _reads(self, statements: List[IRStatement], name: str, excluded: Set[int]) -> bool:
        """Conservative read scan; writes on one DAG edge cannot kill another."""
        seen: Set[int] = set()

        def visit(node: IRStatement) -> bool:
            if id(node) in seen or id(node) in excluded:
                return False
            seen.add(id(node))
            if isinstance(node, IRLocal):
                return node.name == name
            if isinstance(node, IRAssign) and isinstance(node.target, IRLocal):
                return visit(node.expr)
            return any(visit(child) for child in node.get_children())

        return any(visit(node) for node in statements)

    def _mentions_outside(self, name: str, excluded: Set[int]) -> bool:
        seen: Set[int] = set()

        def visit(node: IRStatement) -> bool:
            if id(node) in seen or id(node) in excluded:
                return False
            seen.add(id(node))
            if isinstance(node, IRLocal):
                return node.name == name
            return any(visit(child) for child in node.get_children())

        return visit(self.func.block)

    def _decision(self, statements: List[IRStatement], start: int):
        if start + 1 >= len(statements):
            return None
        assignment, conditional = statements[start : start + 2]
        if not (
            isinstance(assignment, IRAssign)
            and isinstance(assignment.target, IRLocal)
            and isinstance(assignment.expr, IREnumIndex)
            and isinstance(assignment.expr.value, IRLocal)
            and isinstance(conditional, IRConditional)
        ):
            return None
        condition = conditional.condition
        if not isinstance(condition, IRBoolExpr) or condition.op not in (
            IRBoolExpr.CompareType.EQ,
            IRBoolExpr.CompareType.NEQ,
        ):
            return None
        left, right = condition.left, condition.right
        if isinstance(right, IRLocal):
            left, right = right, left
        if left != assignment.target or not isinstance(right, IRConst):
            return None
        index = _int_const_value(right)
        value = assignment.expr.value
        enum = value.get_type().definition
        if index is None or not isinstance(enum, Enum) or not 0 <= index < len(enum.constructs):
            return None
        success, failure = conditional.true_block, conditional.false_block
        if condition.op == IRBoolExpr.CompareType.NEQ:
            success, failure = failure, success
        return assignment, conditional, value, index, success, failure

    def _valid_field(self, field: IREnumField, pattern: IREnumPattern) -> Optional[int]:
        if field.constructor_index != pattern.constructor_index:
            return None
        if field.value.get_type() is not pattern.enum_type.resolve(self.func.code):
            return None
        if not field.field_name.startswith("param") or not field.field_name[5:].isdigit():
            return None
        slot = int(field.field_name[5:])
        enum = cast(Enum, pattern.enum_type.resolve(self.func.code).definition)
        params = enum.constructs[pattern.constructor_index].params
        if slot >= len(params) or params[slot].resolve(self.func.code) is not field.get_type():
            return None
        return slot

    def _try_enum_tree(self, statements: List[IRStatement], start: int) -> Optional[Tuple[IRSwitch, int]]:
        decision = self._decision(statements, start)
        if decision is None:
            return None
        assignment, conditional, value, index, success, default = decision
        root = IREnumPattern(self.func.code, value.type, index)
        facts = {value.name: root}
        # Extraction records remain ordered; materialize real destinations in
        # the successful case instead of shadowing function locals in patterns.
        fields: List[Tuple[IRStatement, IREnumField, IREnumPattern, int]] = []
        removed: List[IRStatement] = [assignment, conditional.condition]
        indices = [assignment.target.name]
        intermediates: Set[str] = set()
        seen_destinations: Set[str] = set()
        seen_slots: Set[Tuple[int, int]] = set()
        current = success
        while True:
            if not self._private_block(current):
                return None
            position = 0
            while position < len(current.statements):
                node = current.statements[position]
                field = node.expr if isinstance(node, IRAssign) and isinstance(node.target, IRLocal) else node
                if not isinstance(field, IREnumField) or not isinstance(field.value, IRLocal):
                    break
                pattern = facts.get(field.value.name)
                if pattern is None:
                    break
                slot = self._valid_field(field, pattern)
                if slot is None or (id(pattern), slot) in seen_slots:
                    return None
                seen_slots.add((id(pattern), slot))
                if isinstance(node, IRAssign):
                    if node.target.name in facts or node.target.name in seen_destinations:
                        return None
                    seen_destinations.add(node.target.name)
                fields.append((node, field, pattern, slot))
                removed.append(node)
                position += 1
            nested = self._decision(current.statements, position)
            if nested is None:
                body_statements = current.statements[position:]
                break
            nested_assign, nested_cond, nested_value, nested_index, nested_success, failure = nested
            if position + 2 != len(current.statements) or not _stmt_lists_structurally_equal(
                default.statements, failure.statements
            ):
                return None
            source = next(
                (
                    entry
                    for entry in reversed(fields)
                    if isinstance(entry[0], IRAssign) and entry[0].target == nested_value
                ),
                None,
            )
            if source is None:
                return None
            child = IREnumPattern(self.func.code, nested_value.type, nested_index)
            source[2].slots[source[3]] = child
            facts[nested_value.name] = child
            intermediates.add(nested_value.name)
            removed.extend([nested_assign, nested_cond.condition])
            indices.append(nested_assign.target.name)
            current = nested_success
        excluded = {id(node) for node in removed}
        # Index locals can be reused, but their old tag value must not escape.
        for name in indices:
            definitions = {
                id(node)
                for node in removed
                if isinstance(node, IRAssign)
                and isinstance(node.target, IRLocal)
                and node.target.name == name
                and isinstance(node.expr, IREnumIndex)
            }
            if self._index_escapes(name, definitions, excluded):
                return None
        for name in intermediates:
            if self._mentions_outside(name, excluded):
                return None
        # An extraction before a nested check was observable on that check's
        # failure edge. Never defer a destination that is live on such an edge.
        final_ids = {id(node) for node in current.statements}
        for node, field, pattern, slot in fields:
            if isinstance(node, IRAssign) and id(node) not in final_ids:
                node_target = cast(IRLocal, node.target)
                if node_target.name not in intermediates and self._mentions_outside(
                    node_target.name, excluded | {id(current)}
                ):
                    return None
        bindings: List[IRStatement] = []
        for node, field, pattern, slot in fields:
            if isinstance(pattern.slots.get(slot), IREnumPattern):
                continue
            if isinstance(node, IRAssign):
                node_target = cast(IRLocal, node.target)
                if self._private_block(current) and not self._mentions_outside(
                    node_target.name, excluded | {id(current)}
                ):
                    # The destination exists solely inside this successful case.
                    # Binding it directly cannot shadow an outer live value.
                    pattern.slots[slot] = node_target
                else:
                    binding = self._fresh_binding(field)
                    pattern.slots[slot] = binding
                    bindings.append(IRAssign(self.func.code, node_target, binding).adopt(node))
        body = IRBlock(self.func.code)
        body.statements = bindings + body_statements
        key = IRConst(
            self.func.code,
            IRConst.ConstType.GLOBAL_STRING,
            value=cast(Enum, value.get_type().definition).constructs[index].name.resolve(self.func.code),
        )
        switch = IRSwitch(self.func.code, value, {key: body}, default).adopt(*removed)
        switch.enum_patterns[key] = root
        return switch, 2

    def _try_singleton_region(
        self, statements: List[IRStatement], start: int
    ) -> Optional[Tuple[IRSwitch, int]]:
        fields: List[Tuple[IRStatement, IREnumField, int]] = []
        value: Optional[IRLocal] = None
        pattern: Optional[IREnumPattern] = None
        destinations: Set[str] = set()
        for node in statements[start:]:
            if isinstance(node, IRAssign) and isinstance(node.target, IRLocal):
                field = node.expr
            elif isinstance(node, IRReturn):
                field = node.value
            else:
                break
            if not isinstance(field, IREnumField) or not isinstance(field.value, IRLocal):
                break
            enum = field.value.get_type().definition
            # Anonymous singleton enums are HL's closure environments. Do not
            # infer constructor facts for arbitrary unguarded enum reads.
            if not isinstance(enum, Enum) or enum.name.value != 0 or len(enum.constructs) != 1:
                break
            if value is None:
                value = field.value
                pattern = IREnumPattern(self.func.code, value.type, 0)
            if field.value != value or pattern is None:
                break
            slot = self._valid_field(field, pattern)
            if slot is None:
                break
            if isinstance(node, IRAssign):
                node_target = cast(IRLocal, node.target)
                if node_target.name == value.name or node_target.name in destinations:
                    break
                destinations.add(node_target.name)
            fields.append((node, field, slot))
            if isinstance(node, IRReturn):
                break
        if not fields or pattern is None or value is None:
            return None
        body = IRBlock(self.func.code)
        for node, field, slot in fields:
            binding = pattern.slots.get(slot)
            if binding is None:
                binding = self._fresh_binding(field)
                pattern.slots[slot] = binding
            assert isinstance(binding, IRLocal)
            body.statements.append(
                IRAssign(self.func.code, node.target, binding).adopt(node)
                if isinstance(node, IRAssign)
                else IRReturn(self.func.code, binding).adopt(node)
            )
        enum = cast(Enum, value.get_type().definition)
        key = IRConst(
            self.func.code,
            IRConst.ConstType.GLOBAL_STRING,
            value=enum.constructs[0].name.resolve(self.func.code),
        )
        switch = IRSwitch(self.func.code, value, {key: body}, IRBlock(self.func.code))
        switch.enum_patterns[key] = pattern
        switch.adopt(*(node for node, _, _ in fields))
        return switch, len(fields)
