"""Optimizer contracts for address-exposed locals and mutable copy sources."""

from types import SimpleNamespace

import pytest

from crashlink.core import Bytecode, Function, tIndex
from crashlink.decomp.ir import (
    IRArithmetic,
    IRAssign,
    IRBlock,
    IRBoolExpr,
    IRCall,
    IRConditional,
    IRConst,
    IRLocal,
    IRRef,
    IRRefGet,
    IRRefNew,
    IRRefSet,
    IRReturn,
    IRWhileLoop,
)
from crashlink.decomp.opt.clean import (
    IRDeadAssignmentEliminator,
    IRDeadStoreEliminator,
    IRDeadTempEliminator,
    IRRedundantRecomputeEliminator,
    IRSequentialTempFolder,
)
from crashlink.decomp.opt.inliner import (
    IRConditionInliner,
    IRCopyPropOptimizer,
    IRTerminalValueInliner,
    IRTempAssignmentInliner,
)


def _block(code, *statements):
    block = IRBlock(code)
    block.statements = list(statements)
    return block


def _function(code, *statements):
    return SimpleNamespace(code=code, func=Function(), ops=[], block=_block(code, *statements))


def _constant(code, value):
    return IRConst(code, IRConst.ConstType.INT, value=value)


def _add(code, left, right):
    return IRArithmetic(code, left, right, IRArithmetic.ArithmeticType.ADD)


def _observe(block):
    """Interpret register cells independently of optimizer traversal/liveness."""
    values = {}
    returned = []

    def key(local):
        return local.reg_idx if local.reg_idx is not None else local.name

    def evaluate(node):
        if isinstance(node, IRBlock):
            for stmt in node.statements:
                evaluate(stmt)
                if returned:
                    break
        elif isinstance(node, IRAssign):
            values[key(node.target)] = evaluate(node.expr)
        elif isinstance(node, IRLocal):
            return values[key(node)]
        elif isinstance(node, IRConst):
            return node.value
        elif isinstance(node, (IRRef, IRRefNew)):
            # Haxe's address operator requires a local; a value-equal expression
            # or copy in another local does not identify the same cell.
            assert isinstance(node.target, IRLocal), "reference operand lost addressability"
            assert key(node.target) in values, "reference storage lost its initialization"
            return ("ref", key(node.target))
        elif isinstance(node, IRRefGet):
            return values[evaluate(node.ref)[1]]
        elif isinstance(node, IRRefSet):
            target = evaluate(node.ref)[1]
            values[target] = evaluate(node.value)
        elif isinstance(node, IRCall):
            # A native/closure can mutate a local through an escaped reference.
            target = evaluate(node.args[0])[1]
            values[target] = 7
            return 5
        elif isinstance(node, IRArithmetic):
            assert node.op == IRArithmetic.ArithmeticType.ADD
            return evaluate(node.left) + evaluate(node.right)
        elif isinstance(node, IRBoolExpr):
            assert node.op == IRBoolExpr.CompareType.LT
            return evaluate(node.left) < evaluate(node.right)
        elif isinstance(node, IRConditional):
            branch = node.true_block if evaluate(node.condition) else node.false_block
            if branch is not None:
                evaluate(branch)
        elif isinstance(node, IRWhileLoop):
            for _ in range(20):
                if not evaluate(node.condition):
                    break
                evaluate(node.body)
            else:
                raise AssertionError("optimizer changed loop termination")
        elif isinstance(node, IRReturn):
            returned.append(evaluate(node.value))
        else:
            raise AssertionError(type(node))

    evaluate(block)
    return returned[-1]


OPTIMIZERS = [
    IRConditionInliner,
    IRTempAssignmentInliner,
    lambda function: IRTempAssignmentInliner(function, aggressive=True, past_kills=True),
    IRTerminalValueInliner,
    IRCopyPropOptimizer,
    IRDeadTempEliminator,
    IRDeadStoreEliminator,
    IRDeadAssignmentEliminator,
    IRSequentialTempFolder,
    IRRedundantRecomputeEliminator,
]


@pytest.mark.parametrize("optimizer", OPTIMIZERS)
@pytest.mark.parametrize("reference", [IRRef, IRRefNew])
def test_reference_keeps_storage_and_writes_through_register_alias(optimizer, reference):
    code = Bytecode.create_empty()
    cell = IRLocal("var0", tIndex(1), code, reg_idx=0)
    renamed_cell = IRLocal("renamed", tIndex(1), code, reg_idx=0)
    ref = IRLocal("var1", tIndex(1), code, reg_idx=1)
    old = IRLocal("var2", tIndex(1), code, reg_idx=2)
    function = _function(
        code,
        IRAssign(code, cell, _add(code, _constant(code, 2), _constant(code, 3))),
        IRAssign(code, ref, reference(code, cell)),
        IRAssign(code, renamed_cell, _constant(code, 7)),
        IRAssign(code, old, IRRefGet(code, ref)),
        IRRefSet(code, ref, _constant(code, 11)),
        IRReturn(code, _add(code, old, cell)),
    )
    assert _observe(function.block) == 18
    optimizer(function).optimize()
    assert _observe(function.block) == 18


@pytest.mark.parametrize("aggressive", [False, True])
def test_inlining_keeps_snapshot_before_indirect_write(aggressive):
    code = Bytecode.create_empty()
    cell, ref, snapshot = [IRLocal(f"var{i}", tIndex(1), code) for i in range(3)]
    function = _function(
        code,
        IRAssign(code, cell, _constant(code, 1)),
        IRAssign(code, ref, IRRefNew(code, cell)),
        IRAssign(code, snapshot, cell),
        IRRefSet(code, ref, _constant(code, 2)),
        IRReturn(code, _add(code, snapshot, cell)),
    )
    assert _observe(function.block) == 3
    IRTempAssignmentInliner(function, aggressive=aggressive, past_kills=True).optimize()
    assert _observe(function.block) == 3


@pytest.mark.parametrize(
    "optimizer", [IRDeadTempEliminator, IRDeadStoreEliminator, IRDeadAssignmentEliminator]
)
def test_write_after_address_escape_is_observed_by_reference(optimizer):
    code = Bytecode.create_empty()
    cell, ref = [IRLocal(f"var{i}", tIndex(1), code) for i in range(2)]
    function = _function(
        code,
        IRAssign(code, cell, _constant(code, 1)),
        IRAssign(code, ref, IRRefNew(code, cell)),
        IRAssign(code, cell, _constant(code, 9)),
        IRReturn(code, IRRefGet(code, ref)),
    )
    optimizer(function).optimize()
    assert _observe(function.block) == 9


@pytest.mark.parametrize("aggressive", [False, True])
@pytest.mark.parametrize("loop", [False, True])
def test_snapshot_not_substituted_after_mutation_inside_consumer(aggressive, loop):
    code = Bytecode.create_empty()
    source, snapshot, result = [IRLocal(f"var{i}", tIndex(1), code) for i in range(3)]
    condition = IRBoolExpr(code, IRBoolExpr.CompareType.LT, source, _constant(code, 3))
    body = _block(
        code,
        IRAssign(code, source, _add(code, source, _constant(code, 1))),
        IRAssign(code, result, snapshot),
    )
    consumer = (
        IRWhileLoop(code, condition, body) if loop else IRConditional(code, condition, body, _block(code))
    )
    function = _function(
        code,
        IRAssign(code, source, _constant(code, 1)),
        IRAssign(code, snapshot, source),
        consumer,
        IRReturn(code, result),
    )
    assert _observe(function.block) == 1
    IRTempAssignmentInliner(function, aggressive=aggressive, past_kills=True).optimize()
    assert _observe(function.block) == 1


def test_branch_assignment_does_not_prove_unrelated_condition_copy():
    code = Bytecode.create_empty()
    user = IRLocal("user", tIndex(1), code)
    unrelated = IRLocal("var0", tIndex(1), code)
    result = IRLocal("result", tIndex(1), code)
    function = _function(
        code,
        IRAssign(code, unrelated, _constant(code, 0)),
        IRConditional(
            code,
            _constant(code, 1),
            _block(code, IRAssign(code, user, _constant(code, 10))),
            _block(code, IRAssign(code, user, _constant(code, 20))),
        ),
        IRConditional(
            code,
            IRBoolExpr(code, IRBoolExpr.CompareType.LT, unrelated, _constant(code, 1)),
            _block(code, IRAssign(code, result, _constant(code, 7))),
            _block(code, IRAssign(code, result, _constant(code, 9))),
        ),
        IRReturn(code, result),
    )
    # Model debug names through the public optimizer's existing name lookup.
    function.func.has_debug = True
    function.func.assigns = [(SimpleNamespace(resolve=lambda code: "user"), SimpleNamespace(value=0))]
    assert _observe(function.block) == 7
    IRCopyPropOptimizer(function).optimize()
    assert _observe(function.block) == 7


def test_terminal_fold_does_not_mutate_shared_arithmetic_operand():
    code = Bytecode.create_empty()
    temp = IRLocal("var0", tIndex(1), code)
    # Sharing can result from earlier substitutions. The return expression
    # re-evaluates the shared operand after temp was written; folding must
    # preserve that value without making the operand point back to itself.
    shared = _add(code, temp, _constant(code, 2))
    function = _function(
        code,
        IRAssign(code, temp, _constant(code, 1)),
        IRAssign(code, temp, shared),
        IRReturn(code, _add(code, shared, _constant(code, 4))),
    )
    assert _observe(function.block) == 9
    IRTerminalValueInliner(function).optimize()
    assert _observe(function.block) == 9


def test_call_movement_preserves_address_exposed_operand_read_order():
    code = Bytecode.create_empty()
    cell, ref, temp, result = [IRLocal(f"var{i}", tIndex(1), code) for i in range(4)]
    function = _function(
        code,
        IRAssign(code, cell, _constant(code, 1)),
        IRAssign(code, ref, IRRefNew(code, cell)),
        IRAssign(code, temp, IRCall(code, IRCall.CallType.NATIVE, None, [ref])),
        IRAssign(code, result, _add(code, cell, temp)),
        IRReturn(code, result),
    )
    assert _observe(function.block) == 12
    IRTempAssignmentInliner(function).optimize()
    assert _observe(function.block) == 12


@pytest.mark.parametrize("loop", [False, True])
def test_copy_propagation_stops_at_nested_source_write(loop):
    code = Bytecode.create_empty()
    temp, user = IRLocal("var0", tIndex(1), code), IRLocal("user", tIndex(1), code)
    body = _block(code, IRAssign(code, user, _constant(code, 5)))
    condition = IRBoolExpr(code, IRBoolExpr.CompareType.LT, user, _constant(code, 3))
    consumer = (
        IRWhileLoop(code, condition, body) if loop else IRConditional(code, condition, body, _block(code))
    )
    function = _function(
        code,
        IRAssign(code, temp, _constant(code, 1)),
        IRAssign(code, user, temp),
        consumer,
        IRReturn(code, temp),
    )
    function.func.has_debug = True
    function.func.assigns = [(SimpleNamespace(resolve=lambda code: "user"), SimpleNamespace(value=0))]
    assert _observe(function.block) == 1
    IRCopyPropOptimizer(function).optimize()
    assert _observe(function.block) == 1
