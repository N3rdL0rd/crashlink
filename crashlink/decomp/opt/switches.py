"""
Switch-statement pattern optimizers.
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
            if isinstance(left, IRLocal) and isinstance(right, IRConst) and right.const_type == IRConst.ConstType.INT:
                cand_local, cand_const = left, right
            elif isinstance(right, IRLocal) and isinstance(left, IRConst) and left.const_type == IRConst.ConstType.INT:
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
        return cast(IRSwitch, IRSwitch(self.func.code, local, cases, default).adopt(*chain))


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
                    # Whatever's left once the chain stops matching is exactly
                    # what runs when no case matched - that's the default body.
                    if not tail and not switch.default.statements and i < len(block.statements):
                        fallthrough = IRBlock(self.func.code)
                        fallthrough.statements = block.statements[i:]
                        switch.default = fallthrough
                        i = len(block.statements)
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
            default = stmt.false_block
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
                    if (
                        cond.left == temp_local
                        and isinstance(cond.right, IRConst)
                        and cond.right.const_type == IRConst.ConstType.INT
                    ):
                        return stmt, temp_local
                    if (
                        cond.right == temp_local
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
        if not (isinstance(bytes_arg, IRField) and bytes_arg.field_name == "bytes" and bytes_arg.target == s_local):
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

    TARGET_OPCODES = {"EnumIndex"}

    def visit_block(self, block: IRBlock) -> None:
        made_change = True
        while made_change:
            made_change = False
            new_statements: List[IRStatement] = []
            i = 0
            while i < len(block.statements):
                stmt = block.statements[i]
                match = self._try_enum_switch(block.statements, i)
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

        new_cases: Dict[IRConst, IRBlock] = {}
        enum_def = enum_type.definition
        for case_val, case_block in next_stmt.cases.items():
            if not isinstance(case_val, IRConst) or case_val.const_type != IRConst.ConstType.INT:
                return None
            idx = int(case_val.value.value if hasattr(case_val.value, "value") else case_val.value)
            if idx >= len(enum_def.constructs):
                return None
            construct = enum_def.constructs[idx]
            # Create a new IRConst for the constructor name. We repurpose the
            # existing IRConst by changing its value to the constructor name
            # string, but create a fresh one to avoid side effects.
            new_case_val = IRConst(
                self.func.code, IRConst.ConstType.GLOBAL_STRING, value=construct.name.resolve(self.func.code)
            )
            new_cases[new_case_val] = case_block

        new_switch = IRSwitch(self.func.code, enum_value, new_cases, next_stmt.default)
        new_switch.adopt(stmt, next_stmt)
        return new_switch, 2
