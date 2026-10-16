"""
Enum and switch helpers: case detection, exhaustiveness and pattern binding analysis.
"""

from __future__ import annotations

from typing import Optional, List, Set, Dict, FrozenSet, Tuple
from ..core import Enum
from .. import disasm
from ..decomp import (
    IRBlock,
    IRStatement,
    IRExpression,
    IRAssign,
    IRLocal,
    IRConst,
    IREnumIndex,
    IREnumField,
    IRSwitch,
)


def _is_expression_switch(
    switch_stmt: IRSwitch,
) -> Optional[Tuple[IRLocal, Dict[IRConst, IRExpression], Optional[IRExpression]]]:
    """Detect `switch (v) { case X: target = eX; ... default: target = eD; }`."""
    if switch_stmt.enum_patterns:
        return None
    target: Optional[IRLocal] = None
    cases: Dict[IRConst, IRExpression] = {}
    for val, block in switch_stmt.cases.items():
        if not isinstance(val, IRConst):
            return None
        if len(block.statements) != 1:
            return None
        s = block.statements[0]
        if not isinstance(s, IRAssign) or not isinstance(s.target, IRLocal):
            return None
        if target is None:
            target = s.target
        elif s.target.name != target.name:
            return None
        cases[val] = s.expr
    default_expr: Optional[IRExpression] = None
    # HL gives even an exhaustive enum switch a fall-through default, left empty.
    if switch_stmt.default and not (
        not switch_stmt.default.statements and _switch_is_exhaustive(switch_stmt)
    ):
        if len(switch_stmt.default.statements) != 1:
            return None
        s = switch_stmt.default.statements[0]
        if not isinstance(s, IRAssign) or not isinstance(s.target, IRLocal):
            return None
        if target is None:
            target = s.target
        elif s.target.name != target.name:
            return None
        default_expr = s.expr
    if target is None:
        return None
    return target, cases, default_expr


def _switch_enum(switch_stmt: IRSwitch) -> Tuple[Optional[Enum], IRExpression]:
    """The enum a switch dispatches on, if any, and the enum value it tests."""
    value = switch_stmt.value
    if isinstance(value, IREnumIndex):
        definition = value.value.get_type().definition
        return (definition if isinstance(definition, Enum) else None), value.value
    definition = value.get_type().definition
    if isinstance(definition, Enum):
        return definition, value
    # A switch on an int that may be an enum index: the cases read the enum's fields.
    detected = _detect_enum_value_from_cases(switch_stmt)
    if detected is not None:
        definition = detected.get_type().definition
        if isinstance(definition, Enum):
            return definition, detected
    return None, value


def _same_value(a: IRExpression, b: IRExpression) -> bool:
    """The same local, or the very same expression node."""
    if isinstance(a, IRLocal) and isinstance(b, IRLocal):
        return a.name == b.name
    return a is b


def _switch_is_exhaustive(switch_stmt: IRSwitch) -> bool:
    """Whether the cases of an enum switch cover every constructor."""
    enum, _ = _switch_enum(switch_stmt)
    if enum is None:
        return False
    names = [disasm.enum_construct_name(switch_stmt.code, enum, i) for i in range(len(enum.constructs))]
    covered: Set[int] = set()
    for key in switch_stmt.cases:
        for value in switch_stmt.case_values(key):
            if value.const_type == IRConst.ConstType.INT:
                covered.add(int(value.value.value if hasattr(value.value, "value") else value.value))
            elif isinstance(value.value, str) and value.value in names:
                covered.add(names.index(value.value))
    return len(covered) == len(enum.constructs)


def _detect_enum_value_from_cases(stmt: "IRSwitch") -> Optional["IRExpression"]:
    """For a switch on an integer (enum index) look inside case blocks to find
    the actual enum expression being indexed.  Returns it if all enum-field
    accesses agree on the same base expression, else None.
    """
    candidate: Optional["IRExpression"] = None
    for case_block in stmt.cases.values():
        for s in case_block.statements:
            if isinstance(s, IRAssign) and isinstance(s.expr, IREnumField):
                base = s.expr.value
                if candidate is None:
                    candidate = base
                elif candidate is not base:
                    return None
    return candidate


def _enum_case_params(case_block: IRBlock, switch_value: IRExpression) -> Optional[List[str]]:
    """
    Detect the lowered form of a Haxe enum pattern match.
    A case like `case Rgb(r, g, b):` is compiled as a block that starts with
    assignments `r = value.param0; g = value.param1; b = value.param2;`.
    If such a sequence is found, return the parameter names so they can be
    emitted as part of the case pattern instead of as separate statements.
    """

    def _same_expr(a: IRExpression, b: IRExpression) -> bool:
        if isinstance(a, IRLocal) and isinstance(b, IRLocal):
            return a.name == b.name
        return a is b

    params: List[str] = []
    for stmt in case_block.statements:
        if not isinstance(stmt, IRAssign) or not isinstance(stmt.target, IRLocal):
            break
        if not isinstance(stmt.expr, IREnumField):
            break
        if not _same_expr(stmt.expr.value, switch_value):
            break
        expected = f"param{len(params)}"
        if stmt.expr.field_name != expected:
            break
        params.append(stmt.target.name)
    return params if params else None


def _switch_case_bindings(switch_stmt: IRSwitch) -> Dict[int, List[str]]:
    """Per case block (by id), the locals its `local = value.paramN` prologue binds."""
    if isinstance(switch_stmt.value, IREnumIndex):
        switch_value = switch_stmt.value.value
    else:
        detected = _detect_enum_value_from_cases(switch_stmt)
        switch_value = detected if detected is not None else switch_stmt.value
    bindings: Dict[int, List[str]] = {}
    for case_value, block in switch_stmt.cases.items():
        if case_value in switch_stmt.enum_patterns:
            continue
        params = _enum_case_params(block, switch_value)
        if params:
            bindings[id(block)] = params
    return bindings


def _unbound_reads(root: IRStatement) -> Set[str]:
    """Locals read somewhere other than inside a case that binds them itself.

    A pattern variable is scoped to its case: a local read anywhere else can't be one.
    """
    names: Set[str] = set()
    seen: Set[int] = set()

    def walk(node: IRStatement, bound: FrozenSet[str]) -> None:
        if id(node) in seen:
            return
        seen.add(id(node))
        if isinstance(node, IRLocal):
            if node.name not in bound:
                names.add(node.name)
            return
        if isinstance(node, IRAssign) and isinstance(node.target, IRLocal):
            walk(node.expr, bound)
            return
        if isinstance(node, IRSwitch):
            bindings = _switch_case_bindings(node)
            for child in node.get_children():
                walk(child, bound | frozenset(bindings.get(id(child), ())))
            return
        for child in node.get_children():
            walk(child, bound)

    walk(root, frozenset())
    return names


def _pattern_captures(
    case_block: IRBlock, switch_value: IRExpression, unbound: Set[str]
) -> Optional[List[Tuple[str, Optional[str]]]]:
    """The names a case pattern binds for the `local = value.paramN` prologue of its
    block, each with the local to assign it to when that local is also read outside
    the cases binding it (see `_unbound_reads`), else None."""
    params = _enum_case_params(case_block, switch_value)
    if params is None:
        return None
    return [(f"arg{i}", name) if name in unbound else (name, None) for i, name in enumerate(params)]
