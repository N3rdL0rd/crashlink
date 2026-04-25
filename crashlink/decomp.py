"""
Decompilation, IR and control flow graph generation
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum as _Enum  # Enum is already defined in crashlink.core
from pprint import pformat
from typing import Any, Dict, List, Optional, Set, Tuple, Union, cast

from . import disasm
from .core import (
    Bytecode,
    DynObj,
    Function,
    Native,
    Obj,
    Opcode,
    ResolvableVarInt,
    Type,
    TypeDef,
    Virtual,
    Void,
    fieldRef,
    gIndex,
    tIndex,
)
from .errors import DecompError
from .globals import DEBUG, dbg_print
from .opcodes import arithmetic, conditionals, terminal, simple_calls


def _get_type_in_code(code: Bytecode, name: str) -> Type:
    for type in code.types:
        if disasm.type_name(code, type) == name:
            return type
    raise DecompError(f"Type {name} not found in code")


class CFNode:
    """
    A control flow node.
    """

    def __init__(self, ops: List[Opcode]):
        self.ops = ops
        self.branches: List[Tuple[CFNode, str]] = []
        self.base_offset: int = 0
        self.original_node: Optional[CFNode] = None

    def __repr__(self) -> str:
        return "<CFNode: %s>" % self.ops


class CFOptimizer(ABC):
    """
    Base class for control flow graph optimizers.
    """

    def __init__(self, graph: "CFGraph"):
        self.graph = graph

    @abstractmethod
    def optimize(self) -> None:
        pass


class CFJumpThreader(CFOptimizer):
    """
    Thread jumps to reduce the number of nodes in the graph.
    """

    def optimize(self) -> None:
        # map each node to its predecessors
        predecessors: Dict[CFNode, List[CFNode]] = {}
        for node in self.graph.nodes:
            for branch, _ in node.branches:
                predecessors.setdefault(branch, []).append(node)

        nodes_to_remove = set()
        for node in self.graph.nodes:
            if len(node.ops) == 1 and node.ops[0].op == "JAlways":
                if len(node.branches) == 1:
                    target_node, edge_type = node.branches[0]
                    # redirect all predecessors to target_node
                    for pred in predecessors.get(node, []):
                        pred.branches = [
                            (target_node if branch == node else branch, etype) for branch, etype in pred.branches
                        ]
                        predecessors.setdefault(target_node, []).append(pred)
                    nodes_to_remove.add(node)

        # remove nodes from graph
        self.graph.nodes = [n for n in self.graph.nodes if n not in nodes_to_remove]


class CFDeadCodeEliminator(CFOptimizer):
    """
    Remove unreachable code blocks
    """

    def optimize(self) -> None:
        reachable: Set[CFNode] = set()
        worklist = [self.graph.entry]

        while worklist:
            node = worklist.pop()
            if node not in reachable and node:
                reachable.add(node)
                for next_node, _ in node.branches:
                    worklist.append(next_node)

        self.graph.nodes = [n for n in self.graph.nodes if n in reachable]


class CFGraph:
    """
    A control flow graph.
    """

    def __init__(self, func: Function):
        self.func = func
        self.nodes: List[CFNode] = []
        self.entry: Optional[CFNode] = None
        self.applied_optimizers: List[CFOptimizer] = []

        # Maps node -> List[predecessor_node]
        self.predecessors: Dict[CFNode, List[CFNode]] = {}
        # Maps node -> Set[dominator_nodes]
        self.dominators: Dict[CFNode, Set[CFNode]] = {}
        # Maps loop_header_node -> Set[nodes_in_loop]
        self.loops: Dict[CFNode, Set[CFNode]] = {}
        # Maps node -> Set[post_dominator_nodes]
        self.post_dominators: Dict[CFNode, Set[CFNode]] = {}
        # Maps node -> immediate_post_dominator_node
        self.immediate_post_dominators: Dict[CFNode, CFNode | None] = {}

    def add_node(self, ops: List[Opcode], base_offset: int = 0) -> CFNode:
        node = CFNode(ops)
        self.nodes.append(node)
        node.base_offset = base_offset
        return node

    def add_branch(self, src: CFNode, dst: CFNode, edge_type: str) -> None:
        src.branches.append((dst, edge_type))

    def build(self, do_optimize: bool = True) -> None:
        """Build the control flow graph."""
        if not self.func.ops:
            return

        jump_targets = set()
        for i, op in enumerate(self.func.ops):
            # fmt: off
            if op.op in ["JTrue", "JFalse", "JNull", "JNotNull", 
                        "JSLt", "JSGte", "JSGt", "JSLte",
                        "JULt", "JUGte", "JNotLt", "JNotGte",
                        "JEq", "JNotEq", "JAlways", "Trap"]:
            # fmt: on
                jump_targets.add(i + op.df["offset"].value + 1)

        current_ops: List[Opcode] = []
        current_start = 0
        blocks: List[Tuple[int, List[Opcode]]] = []  # (start_idx, ops) tuples

        for i, op in enumerate(self.func.ops):
            if i in jump_targets and current_ops:
                blocks.append((current_start, current_ops))
                current_ops = []
                current_start = i

            current_ops.append(op)

            # fmt: off
            if op.op in ["JTrue", "JFalse", "JNull", "JNotNull",
                        "JSLt", "JSGte", "JSGt", "JSLte", 
                        "JULt", "JUGte", "JNotLt", "JNotGte",
                        "JEq", "JNotEq", "JAlways", "Switch", "Ret",
                        "Trap", "EndTrap"]:
            # fmt: on
                blocks.append((current_start, current_ops))
                current_ops = []
                current_start = i + 1

        if current_ops:
            blocks.append((current_start, current_ops))

        nodes_by_idx = {}
        for start_idx, ops in blocks:
            node = self.add_node(ops, start_idx)
            nodes_by_idx[start_idx] = node
            if start_idx == 0:
                self.entry = node

        for start_idx, ops in blocks:
            src_node = nodes_by_idx[start_idx]
            last_op = ops[-1]

            next_idx = start_idx + len(ops)

            # conditionals
            # fmt: off
            if last_op.op in ["JTrue", "JFalse", "JNull", "JNotNull",
                            "JSLt", "JSGte", "JSGt", "JSLte",
                            "JULt", "JUGte", "JNotLt", "JNotGte", 
                            "JEq", "JNotEq"]:
            # fmt: on

                jump_idx = start_idx + len(ops) + last_op.df["offset"].value

                # - jump target is "true" branch
                # - fall-through is "false" branch

                if jump_idx in nodes_by_idx:
                    edge_type = "true"
                    self.add_branch(
                        src_node, nodes_by_idx[jump_idx], edge_type)

                if next_idx in nodes_by_idx:
                    edge_type = "false"
                    self.add_branch(
                        src_node, nodes_by_idx[next_idx], edge_type)

            elif last_op.op == "Switch":
                for i, offset in enumerate(last_op.df['offsets'].value):
                    if offset.value != 0:
                        jump_idx = start_idx + len(ops) + offset.value
                        self.add_branch(
                            src_node, nodes_by_idx[jump_idx], f"switch: case: {i} ")
                if next_idx in nodes_by_idx:
                    self.add_branch(
                        src_node, nodes_by_idx[next_idx], "switch: default")

            elif last_op.op == "Trap":
                jump_idx = start_idx + len(ops) + last_op.df["offset"].value
                if jump_idx in nodes_by_idx:
                    self.add_branch(src_node, nodes_by_idx[jump_idx], "trap")
                if next_idx in nodes_by_idx:
                    self.add_branch(
                        src_node, nodes_by_idx[next_idx], "fall-through")

            elif last_op.op == "EndTrap":
                if next_idx in nodes_by_idx:
                    self.add_branch(
                        src_node, nodes_by_idx[next_idx], "endtrap")

            elif last_op.op == "JAlways":
                jump_idx = start_idx + len(ops) + last_op.df["offset"].value
                if jump_idx in nodes_by_idx:
                    self.add_branch(
                        src_node, nodes_by_idx[jump_idx], "unconditional")
            elif last_op.op != "Ret" and next_idx in nodes_by_idx:
                self.add_branch(
                    src_node, nodes_by_idx[next_idx], "unconditional")

        if do_optimize:
            # fmt: off
            self.optimize([
                CFJumpThreader(self),
                CFDeadCodeEliminator(self),
            ])
            # fmt: on
        if self.entry:
            self.analyze()

    def analyze(self) -> None:
        """
        Performs a full structural analysis of the CFG to identify
        dominators, post-dominators, and loops.
        """
        if not self.entry:
            return

        self._compute_predecessors()
        self._find_dominators()
        self._find_loops()
        self._find_post_dominators()
        self._find_immediate_post_dominators()

        if DEBUG:
            dbg_print("--- CFG Analysis Complete ---")
            for header, loop_nodes in self.loops.items():
                dbg_print(
                    f"Loop found with header {header.base_offset}, containing nodes: {[n.base_offset for n in loop_nodes]}"
                )
            for node, ipd in self.immediate_post_dominators.items():
                if len(node.branches) > 1:
                    dbg_print(f"Conditional node {node.base_offset} converges at {ipd.base_offset if ipd else 'None'}")
            dbg_print("-----------------------------")

    def _compute_predecessors(self) -> None:
        """Calculates the predecessors for every node in the graph."""
        self.predecessors = {node: [] for node in self.nodes}
        for node in self.nodes:
            for branch, _ in node.branches:
                if branch in self.predecessors:
                    self.predecessors[branch].append(node)

    def _find_dominators(self) -> None:
        """
        Computes the dominator for each node using an iterative algorithm.
        A node 'd' dominates 'n' if every path from entry to 'n' must pass through 'd'.
        """
        if not self.entry:
            return

        all_nodes = self.nodes
        # Initialize: The only dominator of the start_node is itself.
        # Every other node is initially "dominated" by all nodes.
        doms = {node: set(all_nodes) for node in all_nodes}
        doms[self.entry] = {self.entry}

        changed = True
        while changed:
            changed = False
            # Iterate in a fixed order for deterministic results
            for node in sorted(all_nodes, key=lambda n: n.base_offset):
                if node == self.entry:
                    continue

                # Dom(n) = {n} U intersect(Dom(p) for p in preds(n))
                preds = self.predecessors.get(node, [])
                if not preds:
                    continue  # Should not happen in a connected graph apart from entry

                pred_doms_sets = [doms[p] for p in preds]
                new_doms = {node}.union(set.intersection(*pred_doms_sets))

                if new_doms != doms[node]:
                    doms[node] = new_doms
                    changed = True

        self.dominators = doms

    def _find_loops(self) -> None:
        """
        Finds loops by identifying back edges. A back edge is an edge (u, v)
        where the destination 'v' (header) dominates the source 'u'.
        """
        if not self.dominators:
            return

        self.loops = {}
        for u in self.nodes:
            for v, _ in u.branches:
                # If the destination `v` dominates the source `u`, it's a back edge.
                if v in self.dominators.get(u, set()):
                    header = v
                    # Build the natural loop for this back-edge. Only nodes dominated
                    # by the header can belong to the loop body.
                    loop_body = {header, u}
                    stack = [u]
                    processed_for_body = {u, header}

                    while stack:
                        current = stack.pop()
                        for pred in self.predecessors.get(current, []):
                            if pred not in processed_for_body and header in self.dominators.get(pred, set()):
                                processed_for_body.add(pred)
                                loop_body.add(pred)
                                stack.append(pred)

                    if header in self.loops:
                        self.loops[header].update(loop_body)
                    else:
                        self.loops[header] = loop_body

    def _find_post_dominators(self) -> None:
        """
        Computes post-dominators by running the dominator algorithm on the
        reversed graph. Handles multiple exit points by creating a virtual exit.
        A node 'p' post-dominates 'n' if all paths from 'n' to exit pass through 'p'.
        """
        all_nodes = self.nodes
        exit_nodes = [n for n in all_nodes if not n.branches]

        if not exit_nodes:
            # Graph with an infinite loop and no exit
            self.post_dominators = {}
            return

        # Reverse the graph edges
        reversed_successors = {n: self.predecessors.get(n, []) for n in all_nodes}

        # Use a virtual exit node to handle multiple exits gracefully
        VIRTUAL_EXIT = CFNode([])
        reversed_successors[VIRTUAL_EXIT] = exit_nodes
        nodes_for_pd_analysis = all_nodes + [VIRTUAL_EXIT]

        # Run the iterative dominator algorithm on the reversed graph
        pd = {node: set(nodes_for_pd_analysis) for node in nodes_for_pd_analysis}
        pd[VIRTUAL_EXIT] = {VIRTUAL_EXIT}

        changed = True
        while changed:
            changed = False
            for node in sorted(all_nodes, key=lambda n: n.base_offset):  # Process in fixed order
                preds_in_reversed_graph = reversed_successors.get(node, [])
                if not preds_in_reversed_graph:
                    continue

                pred_pdom_sets = [pd[p] for p in preds_in_reversed_graph]
                new_pd = {node}.union(set.intersection(*pred_pdom_sets))

                if new_pd != pd[node]:
                    pd[node] = new_pd
                    changed = True

        # Remove the virtual node from the results before storing
        del pd[VIRTUAL_EXIT]
        for node in pd:
            pd[node].discard(VIRTUAL_EXIT)

        self.post_dominators = pd

    def _find_immediate_post_dominators(self) -> None:
        """
        Calculates the immediate post-dominator for each node.
        The immediate post-dominator of 'n' is the "closest" post-dominator
        on any path from 'n' to an exit. It's the parent in the post-dominator tree.
        """
        if not self.post_dominators:
            return

        self.immediate_post_dominators = {}
        for n in self.nodes:
            pdoms_of_n = self.post_dominators.get(n, set())
            # The immediate post-dominator is the one in the set (excluding n itself)
            # that is post-dominated by all others.
            # A simpler way is to find the one whose own post-dominator set has size |pdoms(n)| - 1.
            idom = None
            min_extra_pdoms = float("inf")

            for p in pdoms_of_n:
                if p == n:
                    continue

                pdoms_of_p = self.post_dominators.get(p, set())
                # The immediate post-dominator of `n` is `p` if `pdoms(n) - {n}` is a superset of `pdoms(p)`.
                # We find the `p` that has the largest set of post-dominators itself.
                if pdoms_of_n.issuperset(pdoms_of_p):
                    num_extra_pdoms = len(pdoms_of_n) - len(pdoms_of_p)
                    if num_extra_pdoms < min_extra_pdoms:
                        min_extra_pdoms = num_extra_pdoms
                        idom = p

            self.immediate_post_dominators[n] = idom

    def optimize(self, optimizers: List[CFOptimizer]) -> None:
        for optimizer in optimizers:
            if optimizer not in self.applied_optimizers:
                optimizer.optimize()
                self.applied_optimizers.append(optimizer)

    def style_node(self, node: CFNode) -> str:
        if node == self.entry:
            return "style=filled, fillcolor=pink1"
        for op in node.ops:
            if op.op == "Ret":
                return "style=filled, fillcolor=aquamarine"
        return "style=filled, fillcolor=lightblue"

    def graph(self, code: Bytecode) -> str:
        """Generate DOT format graph visualization with loops highlighted."""
        dot = ["digraph G {"]
        dot.append("  compound=true;")
        dot.append('  labelloc="t";')
        dot.append('  label="CFG for %s";' % disasm.func_header(code, self.func))
        dot.append('  fontname="Arial";')
        dot.append("  labelfontsize=20;")
        dot.append("  forcelabels=true;")
        dot.append('  node [shape=box, fontname="Courier"];')
        dot.append('  edge [fontname="Courier", fontsize=9];')

        for node in self.nodes:
            label = (
                "\n".join(
                    [
                        disasm.pseudo_from_op(op, node.base_offset + i, self.func.regs, code, terse=True)
                        for i, op in enumerate(node.ops)
                    ]
                )
                .replace('"', '\\"')
                .replace("\n", "\\n")
            )
            style = self.style_node(node)
            dot.append(f'  node_{id(node)} [label="{label}", {style}, xlabel="{node.base_offset}."];')

        loop_counter = 0
        sorted_loops = sorted(self.loops.items(), key=lambda item: item[0].base_offset)
        for header, nodes_in_loop in sorted_loops:
            loop_counter += 1
            dot.append(f"  subgraph cluster_loop_{loop_counter} {{")
            dot.append('    style="filled,rounded";')
            dot.append("    color=grey90;")  # The background color of the box
            dot.append(f'   label="Loop (header: {header.base_offset})";')
            dot.append("   fontcolor=grey50;")
            dot.append("   fontsize=12;")
            node_ids_in_loop = [f"node_{id(n)}" for n in nodes_in_loop]
            dot.append(f"   {' '.join(node_ids_in_loop)};")
            dot.append("  }")

        for node in self.nodes:
            for branch, edge_type in node.branches:
                if edge_type == "true":
                    style = 'color="green", label="true"'
                elif edge_type == "false":
                    style = 'color="crimson", label="false"'
                elif edge_type.startswith("switch: "):
                    style = f'color="{"purple" if not edge_type.split("switch: ")[1].strip() == "default" else "crimson"}", label="{edge_type.split("switch: ")[1].strip()}"'
                elif edge_type == "trap":
                    style = 'color="yellow3", label="trap"'
                else:  # unconditionals and unmatched
                    style = 'color="cornflowerblue"'

                dot.append(f"  node_{id(node)} -> node_{id(branch)} [{style}];")

        dot.append("}")
        return "\n".join(dot)


class IRStatement(ABC):
    def __init__(self, code: Bytecode):
        self.code = code
        self.comment: str = ""

    @abstractmethod
    def __repr__(self) -> str:
        pass

    @abstractmethod
    def get_children(self) -> List[IRStatement]:
        pass

    def __str__(self) -> str:
        return self.__repr__()


class IRBlock(IRStatement):
    """
    A basic unit block of IR. Contains a list of IRStatements, and can contain other IRBlocks.
    """

    def __init__(self, code: Bytecode):
        super().__init__(code)
        self.statements: List[IRStatement] = []

    def pprint(self) -> str:
        colors = [36, 31, 32, 33, 34, 35]

        depth = id(self) % len(colors)
        color = colors[depth]

        if not self.statements:
            return f"\033[{color}m[\033[0m\033[{color}m]\033[0m"

        # uniform indentation
        statements = pformat(self.statements, indent=0).replace("\n", "\n\t")

        return f"\033[{color}m[\033[0m\n\t{statements}\n\033[{color}m]\033[0m"

    def __repr__(self) -> str:
        if not self.statements:
            return "[]"

        statements = pformat(self.statements, indent=0).replace("\n", "\n\t")

        return "[\n\t" + statements + "\n]"

    def get_children(self) -> List[IRStatement]:
        return self.statements

    def __str__(self) -> str:
        return self.__repr__()


class IRExpression(IRStatement, ABC):
    """Abstract base class for expressions that produce a value"""

    def __init__(self, code: Bytecode):
        super().__init__(code)

    @abstractmethod
    def get_type(self) -> Type:
        """Get the type of value this expression produces"""
        pass

    def get_children(self) -> List[IRStatement]:
        return []


class IRLocal(IRExpression):
    def __init__(self, name: str, type: tIndex, code: Bytecode):
        super().__init__(code)
        self.name = name
        self.type = type

    def get_type(self) -> Type:
        return self.type.resolve(self.code)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IRLocal):
            return False
        return (
            self.name == other.name
            and self.type.resolve(self.code) is other.type.resolve(other.code)
            and self.code is other.code
        )

    def __repr__(self) -> str:
        return f"<IRLocal: {self.name} {disasm.type_name(self.code, self.type.resolve(self.code))}>"


class IRArithmetic(IRExpression):
    class ArithmeticType(_Enum):
        ADD = "+"
        SUB = "-"
        MUL = "*"
        SDIV = "/"
        UDIV = "/"
        SMOD = "%"
        UMOD = "%"
        SHL = "<<"
        SSHR = ">>"
        USHR = ">>>"
        AND = "&"
        OR = "|"
        XOR = "^"

    def __init__(
        self,
        code: Bytecode,
        left: IRExpression,
        right: IRExpression,
        op: "IRArithmetic.ArithmeticType",
    ):
        super().__init__(code)
        self.left = left
        self.right = right
        self.op = op
        self._cached_type: Optional[Type] = None

    def get_type(self) -> Type:
        if self._cached_type is not None:
            return self._cached_type
        node = self.left
        while isinstance(node, IRArithmetic):
            if node._cached_type is not None:
                self._cached_type = node._cached_type
                return node._cached_type
            node = node.left
        result = node.get_type()
        self._cached_type = result
        return result

    def __repr__(self) -> str:
        return f"<IRArithmetic: {self.left} {self.op.value} {self.right}>"


class IRAssign(IRStatement):
    """Assignment of an expression result to a target (local variable, field, etc.)"""

    def __init__(self, code: Bytecode, target: IRExpression, expr: IRExpression):
        super().__init__(code)
        if not isinstance(target, (IRLocal, IRField, IRArrayAccess)):
            raise DecompError(f"Invalid target for IRAssign: {type(target).__name__}. Must be IRLocal, IRField, or IRArrayAccess.")
        self.target = target
        self.expr = expr

    def get_children(self) -> List[IRStatement]:
        return [self.target, self.expr]

    def __repr__(self) -> str:
        expr_type_str = ""
        if isinstance(self.expr, IRExpression):
            expr_type_str = f" ({disasm.type_name(self.code, self.expr.get_type())})"
        return f"<IRAssign: {self.target} = {self.expr}{expr_type_str}>"


class IRCall(IRExpression):
    """Function call expression"""

    class CallType(_Enum):
        FUNC = "func"
        NATIVE = "native"
        THIS = "this"
        CLOSURE = "closure"
        METHOD = "method"

    def __init__(
        self,
        code: Bytecode,
        call_type: "IRCall.CallType",
        target: "IRConst|IRLocal|IRField|None",
        args: List[IRExpression],
    ):
        super().__init__(code)
        self.call_type = call_type
        self.target = target
        self.args = args
        if self.call_type == IRCall.CallType.THIS and self.target is not None:
            raise DecompError("THIS calls must have a None target")
        if self.call_type != IRCall.CallType.CLOSURE and isinstance(self.target, IRLocal):
            raise DecompError("Non-CLOSURE calls must not have a local target")

    def get_type(self) -> Type:
        # for now, assume closure calls return dynamic type
        if self.call_type == IRCall.CallType.CLOSURE:
            for type in self.code.types:
                if disasm.type_name(self.code, type) == "Dyn":
                    return type
            raise DecompError("Dyn type not found in code")
        if self.call_type == IRCall.CallType.THIS or self.target is None:
            return _get_type_in_code(self.code, "Obj")
        return self.target.get_type()

    def __repr__(self) -> str:
        return f"<IRCall: {self.target}({', '.join([str(arg) for arg in self.args])})>"


class IRBoolExpr(IRExpression):
    """Base class for boolean expressions"""

    class CompareType(_Enum):
        EQ = "=="
        NEQ = "!="
        LT = "<"
        LTE = "<="
        GT = ">"
        GTE = ">="
        NULL = "is null"
        NOT_NULL = "is not null"
        ISTRUE = "is true"
        ISFALSE = "is false"
        TRUE = "true"
        FALSE = "false"
        NOT = "not"

    def __init__(
        self,
        code: Bytecode,
        op: "IRBoolExpr.CompareType",
        left: Optional[IRExpression] = None,
        right: Optional[IRExpression] = None,
    ):
        super().__init__(code)
        self.op = op
        self.left = left
        self.right = right

    def get_type(self) -> Type:
        # Boolean expressions always return bool type
        for type in self.code.types:
            if disasm.type_name(self.code, type) == "Bool":
                return type
        raise DecompError("Bool type not found in code")

    def invert(self) -> None:
        if self.op == IRBoolExpr.CompareType.NOT:
            raise DecompError("Cannot invert NOT operation")
        elif self.op == IRBoolExpr.CompareType.TRUE:
            self.op = IRBoolExpr.CompareType.FALSE
        elif self.op == IRBoolExpr.CompareType.FALSE:
            self.op = IRBoolExpr.CompareType.TRUE
        elif self.op == IRBoolExpr.CompareType.ISTRUE:
            self.op = IRBoolExpr.CompareType.ISFALSE
        elif self.op == IRBoolExpr.CompareType.ISFALSE:
            self.op = IRBoolExpr.CompareType.ISTRUE
        elif self.op == IRBoolExpr.CompareType.NULL:
            self.op = IRBoolExpr.CompareType.NOT_NULL
        elif self.op == IRBoolExpr.CompareType.NOT_NULL:
            self.op = IRBoolExpr.CompareType.NULL
        elif self.op == IRBoolExpr.CompareType.EQ:
            self.op = IRBoolExpr.CompareType.NEQ
        elif self.op == IRBoolExpr.CompareType.NEQ:
            self.op = IRBoolExpr.CompareType.EQ
        elif self.op == IRBoolExpr.CompareType.LT:
            self.op = IRBoolExpr.CompareType.GTE
        elif self.op == IRBoolExpr.CompareType.GTE:
            self.op = IRBoolExpr.CompareType.LT
        elif self.op == IRBoolExpr.CompareType.GT:
            self.op = IRBoolExpr.CompareType.LTE
        elif self.op == IRBoolExpr.CompareType.LTE:
            self.op = IRBoolExpr.CompareType.GT
        else:
            raise DecompError(f"Unknown IRBoolExpr type: {self.op}")

    def __repr__(self) -> str:
        if self.op in [IRBoolExpr.CompareType.NULL, IRBoolExpr.CompareType.NOT_NULL]:
            return f"<IRBoolExpr: {self.left} {self.op.value}>"
        elif self.op == IRBoolExpr.CompareType.NOT:
            return f"<IRBoolExpr: {self.op.value} {self.left}>"
        elif self.op in [IRBoolExpr.CompareType.TRUE, IRBoolExpr.CompareType.FALSE]:
            return f"<IRBoolExpr: {self.op.value}>"
        elif self.op in [IRBoolExpr.CompareType.ISTRUE, IRBoolExpr.CompareType.ISFALSE]:
            return f"<IRBoolExpr: {self.left} {self.op.value}>"
        return f"<IRBoolExpr: {self.left} {self.op.value} {self.right}>"


class IRConst(IRExpression):
    """Represents a constant value expression"""

    class ConstType(_Enum):
        INT = "int"
        FLOAT = "float"
        BOOL = "bool"
        BYTES = "bytes"
        STRING = "string"
        NULL = "null"
        FUN = "fun"
        GLOBAL_OBJ = "obj"
        GLOBAL_STRING = "global_string"

    def __init__(
        self,
        code: Bytecode,
        const_type: "IRConst.ConstType",
        idx: Optional[ResolvableVarInt] = None,
        value: Optional[bool | int | str] = None,
    ):
        super().__init__(code)
        self.const_type = const_type
        self.value: Any = value
        self.original_index = idx

        if const_type == IRConst.ConstType.GLOBAL_STRING:
            if not isinstance(value, str):
                raise DecompError("IRConst with type GLOBAL_STRING must have a string value")
            self.value = value
            return

        if const_type == IRConst.ConstType.INT and idx is None and value is not None:
            return

        if const_type == IRConst.ConstType.BOOL:
            if value is None:
                raise DecompError("IRConst with type BOOL must have a value")
            self.value = value
        elif const_type == IRConst.ConstType.NULL:
            self.value = None
        else:
            if idx is None:
                raise DecompError("IRConst must have an index")
            self.value = idx.resolve(code)

    def get_type(self) -> Type:
        if self.const_type == IRConst.ConstType.INT:
            return _get_type_in_code(self.code, "I32")
        elif self.const_type == IRConst.ConstType.FLOAT:
            return _get_type_in_code(self.code, "F64")
        elif self.const_type == IRConst.ConstType.BOOL:
            return _get_type_in_code(self.code, "Bool")
        elif self.const_type == IRConst.ConstType.BYTES:
            return _get_type_in_code(self.code, "Bytes")
        elif self.const_type in [IRConst.ConstType.STRING, IRConst.ConstType.GLOBAL_STRING]:
            return _get_type_in_code(self.code, "String")
        elif self.const_type == IRConst.ConstType.NULL:
            return _get_type_in_code(self.code, "Null")  # FIXME: null is of a type...
        elif self.const_type == IRConst.ConstType.FUN:
            if not (isinstance(self.value, Function) or isinstance(self.value, Native)):
                raise DecompError(f"Expected function index to resolve to a function or native, got {self.value}")
            res = self.value.type.resolve(self.code)
            if isinstance(res, Type):
                return res
            raise DecompError(f"Expected function return to resolve to a type, got {res}")
        elif self.const_type == IRConst.ConstType.GLOBAL_OBJ:
            assert isinstance(self.value, Type)
            return self.value
        else:
            raise DecompError(f"Unknown IRConst type: {self.const_type}")

    def __repr__(self) -> str:
        if isinstance(self.value, Function):
            return f"<IRConst: {disasm.func_header(self.code, self.value)}>"
        elif self.const_type == IRConst.ConstType.GLOBAL_STRING:
            return f'<IRConst: "{self.value}">'
        return f"<IRConst: {self.value}>"


class IRConditional(IRStatement):
    """A conditional statement"""

    def __init__(
        self,
        code: Bytecode,
        condition: IRExpression,
        true_block: IRBlock,
        false_block: IRBlock,
    ):
        super().__init__(code)
        self.condition = condition
        self.true_block = true_block
        self.false_block = false_block

    def invert(self) -> None:
        self.true_block, self.false_block = self.false_block, self.true_block
        if isinstance(self.condition, IRBoolExpr):
            self.condition.invert()
        else:
            old_cond = self.condition
            self.condition = IRBoolExpr(self.code, IRBoolExpr.CompareType.NOT, old_cond)

    def get_children(self) -> List[IRStatement]:
        return [self.condition, self.true_block, self.false_block]

    def __repr__(self) -> str:
        return f"<IRConditional: if {self.condition} then\n\t{self.true_block}\nelse\n\t{self.false_block}>"


class IRPrimitiveLoop(IRStatement):
    """2-block simplistic loop. Has no differentiation between while/for/comprehension, this should be done in later IR layers."""

    def __init__(self, code: Bytecode, condition: IRBlock, body: IRBlock):
        super().__init__(code)
        self.condition = condition
        self.body = body

    def get_children(self) -> List[IRStatement]:
        return [self.condition, self.body]

    def __repr__(self) -> str:
        return f"<IRPrimitiveLoop: cond -> {self.condition}\n body -> {self.body}>"


class IRBreak(IRStatement):
    """Break statement"""

    def __init__(self, code: Bytecode):
        super().__init__(code)

    def get_children(self) -> List[IRStatement]:
        return []

    def __repr__(self) -> str:
        return "<IRBreak>"


class IRContinue(IRStatement):
    """Continue statement"""

    def __init__(self, code: Bytecode):
        super().__init__(code)

    def get_children(self) -> List[IRStatement]:
        return []

    def __repr__(self) -> str:
        return "<IRContinue>"


class IRReturn(IRStatement):
    """Return statement"""

    def __init__(self, code: Bytecode, value: Optional[IRExpression] = None):
        super().__init__(code)
        self.value = value

    def get_children(self) -> List[IRStatement]:
        return []

    def __repr__(self) -> str:
        return f"<IRReturn: {self.value}>"


class IRTrace(IRStatement):
    """Represents a simplified trace call."""

    def __init__(self, code: Bytecode, msg: IRExpression, pos_info: Dict[str, Any]):
        super().__init__(code)
        self.msg = msg
        self.pos_info = pos_info  # e.g., {"fileName": "Test.hx", "lineNumber": 12}

    def get_children(self) -> List[IRStatement]:
        return [self.msg]

    def __repr__(self) -> str:
        pos_str = ", ".join(f"{k}: {v}" for k, v in self.pos_info.items())
        return f"<IRTrace: msg={self.msg}, pos={{ {pos_str} }}>"


class IRTryCatch(IRStatement):
    """Structured try/catch statement."""

    def __init__(
        self,
        code: Bytecode,
        try_block: IRBlock,
        catch_block: IRBlock,
        catch_local: Optional[IRLocal] = None,
    ):
        super().__init__(code)
        self.try_block = try_block
        self.catch_block = catch_block
        self.catch_local = catch_local

    def get_children(self) -> List[IRStatement]:
        children: List[IRStatement] = [self.try_block, self.catch_block]
        if self.catch_local is not None:
            children.insert(0, self.catch_local)
        return children

    def __repr__(self) -> str:
        return f"<IRTryCatch: try\n\t{self.try_block}\ncatch ({self.catch_local})\n\t{self.catch_block}>"


class IRSwitch(IRStatement):
    """Switch statement"""

    def __init__(
        self,
        code: Bytecode,
        value: IRExpression,
        cases: Dict[IRConst, IRBlock],
        default: IRBlock,
    ):
        super().__init__(code)
        self.value = value
        self.cases = cases
        self.default = default

    def get_children(self) -> List[IRStatement]:
        return [self.value, self.default] + [block for block in self.cases.values()]

    def __repr__(self) -> str:
        cases = ""
        for case, block in self.cases.items():
            cases += f"\n\t{case}: {block}"
        cases += f"\n\tdefault: {self.default}"
        return f"<IRSwitch: {self.value}{cases}>"


class IRPrimitiveJump(IRExpression):
    """An unlifted jump to be handled by further optimization stages."""

    def __init__(self, code: Bytecode, op: Opcode):
        super().__init__(code)
        self.op = op
        assert op.op in conditionals

    def get_type(self) -> Type:
        return _get_type_in_code(self.code, "Bool")

    def __repr__(self) -> str:
        return f"<IRPrimitiveJump: {self.op}>"


class IsolatedCFGraph(CFGraph):
    """A control flow graph that contains only a subset of nodes from another graph."""

    def __init__(
        self,
        parent: CFGraph,
        nodes_to_isolate: List[CFNode],
        find_entry_intelligently: bool = True,
    ):
        """Initialize from parent graph and list of nodes to isolate."""
        if not nodes_to_isolate:
            super().__init__(parent.func)
            self.entry = None
            return

        super().__init__(parent.func)

        node_map: Dict[CFNode, CFNode] = {}

        for original_cfg_node in nodes_to_isolate:
            copied_node = self.add_node(original_cfg_node.ops, original_cfg_node.base_offset)
            copied_node.original_node = original_cfg_node
            node_map[original_cfg_node] = copied_node

        if nodes_to_isolate:
            self.entry = node_map.get(nodes_to_isolate[0])

        for original_cfg_node in nodes_to_isolate:
            copied_node_for_branching = node_map[original_cfg_node]
            for target_in_original_cfg, edge_type in original_cfg_node.branches:
                if target_in_original_cfg in node_map:
                    self.add_branch(
                        copied_node_for_branching,
                        node_map[target_in_original_cfg],
                        edge_type,
                    )

        if find_entry_intelligently and self.nodes:
            entry_candidates = []
            isolated_preds: Dict[CFNode, List[CFNode]] = {}
            for n_src_copy in self.nodes:
                for n_dst_copy, _ in n_src_copy.branches:
                    isolated_preds.setdefault(n_dst_copy, []).append(n_src_copy)

            for node_copy_in_isolated_graph in self.nodes:
                if not isolated_preds.get(node_copy_in_isolated_graph):
                    entry_candidates.append(node_copy_in_isolated_graph)

            if len(entry_candidates) == 1:
                self.entry = entry_candidates[0]
            elif not self.entry and entry_candidates:
                self.entry = entry_candidates[0]
            elif not self.entry and self.nodes:
                self.entry = self.nodes[0]


class IRWhileLoop(IRStatement):
    """
    Represents a while loop: while (condition) { body }
    """

    condition: IRExpression
    body: IRBlock

    def __init__(self, code: Bytecode, condition: IRExpression, body: IRBlock):
        super().__init__(code)

        condition_actual_type = condition.get_type()
        if condition_actual_type.kind.value != Type.Kind.BOOL.value:
            cond_type_name_str = disasm.type_name(code, condition_actual_type)
            if cond_type_name_str != "Dyn":  # Allow Dyn as it can implicitly convert
                raise DecompError(
                    f"IRWhileLoop condition must be a Bool or Dyn-typed expression, got {cond_type_name_str}"
                )

        self.condition = condition
        self.body = body
        self.comment = ""

    def get_children(self) -> List[IRStatement]:
        children: List[IRStatement] = []
        children.append(self.condition)
        children.append(self.body)
        return children

    def __repr__(self) -> str:
        body_repr = pformat(self.body, indent=0).replace("\n", "\n\t")
        return f"<IRWhileLoop: while ({self.condition}) {{\n\t{body_repr}\n}}>"

    def __str__(self) -> str:
        return self.__repr__()


class IRField(IRExpression):
    """Represents an object field access expression, e.g., `obj.field`"""

    def __init__(self, code: Bytecode, target: IRExpression, field_name: str, field_type: tIndex):
        super().__init__(code)
        self.target = target
        self.field_name = field_name
        self.field_type_idx = field_type

    def get_type(self) -> Type:
        return self.field_type_idx.resolve(self.code)

    def get_children(self) -> List[IRStatement]:
        return []

    def __repr__(self) -> str:
        return f"<IRField: {self.target}.{self.field_name}>"


class IRNew(IRExpression):
    """Represents object allocation, e.g., `new MyClass()` or `{}`"""

    def __init__(self, code: Bytecode, alloc_type: tIndex, constructor_args: Optional[List[IRExpression]] = None):
        super().__init__(code)
        self.alloc_type_idx = alloc_type
        self.constructor_args = constructor_args or []

    def get_type(self) -> Type:
        return self.alloc_type_idx.resolve(self.code)

    def get_children(self) -> List[IRStatement]:
        return [a for a in self.constructor_args if isinstance(a, IRStatement)]

    def __repr__(self) -> str:
        type_name = disasm.type_name(self.code, self.get_type())
        if type_name == "DynObj":
            return "<IRNew: {}>"
        args_str = ", ".join(repr(a) for a in self.constructor_args) if self.constructor_args else ""
        return f"<IRNew: new {type_name}({args_str})>"


class IRCast(IRExpression):
    """Represents a type cast, e.g., `(MyType)value`"""

    def __init__(self, code: Bytecode, target_type: tIndex, expr: IRExpression):
        super().__init__(code)
        self.target_type_idx = target_type
        self.expr = expr

    def get_type(self) -> Type:
        return self.target_type_idx.resolve(self.code)

    def get_children(self) -> List[IRStatement]:
        return [self.expr]

    def __repr__(self) -> str:
        type_name = disasm.type_name(self.code, self.get_type())
        return f"<IRCast: ({type_name}){self.expr}>"


class IRArrayAccess(IRExpression):
    """Represents an array/memory access expression, e.g., `arr[idx]`"""

    def __init__(self, code: Bytecode, array: IRExpression, index: IRExpression, elem_type: Optional[tIndex] = None):
        super().__init__(code)
        self.array = array
        self.index = index
        self.elem_type_idx = elem_type

    def get_type(self) -> Type:
        if self.elem_type_idx:
            return self.elem_type_idx.resolve(self.code)
        return _get_type_in_code(self.code, "Void")

    def get_children(self) -> List[IRStatement]:
        return []

    def __repr__(self) -> str:
        return f"<IRArrayAccess: {self.array}[{self.index}]>"


class IRRef(IRExpression):
    """Represents a reference/address-of expression, e.g., `&var`"""

    def __init__(self, code: Bytecode, target: IRExpression):
        super().__init__(code)
        self.target = target

    def get_type(self) -> Type:
        return _get_type_in_code(self.code, "Void")

    def get_children(self) -> List[IRStatement]:
        return []

    def __repr__(self) -> str:
        return f"<IRRef: &{self.target}>"


class IREnumConstruct(IRExpression):
    """Represents enum construction, e.g., `Rgb(255, 255, 0)`"""

    def __init__(self, code: Bytecode, construct_name: str, args: List[IRExpression], enum_type: tIndex):
        super().__init__(code)
        self.construct_name = construct_name
        self.args = args
        self.enum_type_idx = enum_type

    def get_type(self) -> Type:
        return self.enum_type_idx.resolve(self.code)

    def get_children(self) -> List[IRStatement]:
        return []

    def __repr__(self) -> str:
        args_str = ", ".join(str(a) for a in self.args)
        return f"<IREnumConstruct: {self.construct_name}({args_str})>"


class IREnumIndex(IRExpression):
    """Represents getting the index of an enum value"""

    def __init__(self, code: Bytecode, value: IRExpression):
        super().__init__(code)
        self.value = value

    def get_type(self) -> Type:
        return _get_type_in_code(self.code, "I32")

    def get_children(self) -> List[IRStatement]:
        return []

    def __repr__(self) -> str:
        return f"<IREnumIndex: indexof({self.value})>"


class IREnumField(IRExpression):
    """Represents accessing a field of an enum construct, e.g., extracting `r` from `Rgb(r, g, b)`"""

    def __init__(self, code: Bytecode, value: IRExpression, field_name: str, field_type: tIndex):
        super().__init__(code)
        self.value = value
        self.field_name = field_name
        self.field_type_idx = field_type

    def get_type(self) -> Type:
        return self.field_type_idx.resolve(self.code)

    def get_children(self) -> List[IRStatement]:
        return []

    def __repr__(self) -> str:
        return f"<IREnumField: {self.value}.{self.field_name}>"


class IRUnliftedOpcode(IRExpression):
    """Represents an opcode that has not been lifted into a higher-level IR statement."""

    def __init__(self, code: Bytecode, op: Opcode, dst_type_idx: Optional[tIndex] = None):
        super().__init__(code)
        self.op = op
        self.dst_type_idx = dst_type_idx

    def get_type(self) -> Type:
        """
        Returns the type of the destination register, or Void if not applicable.
        """
        if self.dst_type_idx:
            return self.dst_type_idx.resolve(self.code)
        return _get_type_in_code(self.code, "Void")

    def get_children(self) -> List[IRStatement]:
        return []

    def __repr__(self) -> str:
        return f"<IRUntranslatedOpcode: {self.op.op}>"


def _find_jumps_to_label(
    start_node: CFNode, label_node: CFNode, visited: Set[CFNode]
) -> List[Tuple[CFNode, List[CFNode]]]:
    """Helper function to find all jumps back up to a node by traversing down the CFG."""
    jumpers = []
    to_visit: List[Tuple[CFNode, List[CFNode]]] = [(start_node, [])]
    while to_visit:
        current, path = to_visit.pop(0)
        if current in visited:
            continue
        visited.add(current)

        for next_node, _ in current.branches:
            if next_node == label_node:
                jumpers.append((current, path))
                continue

            if next_node not in visited:
                to_visit.append((next_node, path + [current]))

    return jumpers


class IROptimizer(ABC):
    """
    Base class for intermediate representation optimization routines.
    """

    def __init__(self, function: "IRFunction"):
        self.func = function

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
            self.visit(self.func.block)

    def visit(self, statement: IRStatement) -> None:
        """
        Recursively visit an IR statement and its children.

        The traversal performs a pre-order visit (parent first, then children):
        1. Call before_visit_statement for the current statement
        2. Handle specific statement type with visit_X methods
        3. Visit all children recursively
        4. Call after_visit_statement for the current statement
        """
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


class IRPrimitiveJumpLifter(TraversingIROptimizer):
    """
    Lifts an IRPrimitiveJump at the end of an IRPrimitiveLoop's condition block
    into an IRBoolExpr. This IRBoolExpr then becomes the new last statement
    of the condition block.

    This pass makes it easier for subsequent optimizers like IRConditionInliner
    to operate on the boolean logic.
    """

    def visit_primitive_loop(self, loop: IRPrimitiveLoop) -> None:
        """
        Focus on the condition block of the primitive loop.
        """
        if not loop.condition.statements:
            return  # Nothing to do

        last_cond_stmt = loop.condition.statements[-1]
        if not isinstance(last_cond_stmt, IRPrimitiveJump):
            # dbg_print(f"IRPrimitiveJumpLifter: Loop cond for {loop} does not end with IRPrimitiveJump. Skipping.")
            return

        primitive_jump: IRPrimitiveJump = last_cond_stmt
        original_jump_op: Opcode = primitive_jump.op

        # Map bytecode jump opcodes to IRBoolExpr.CompareType
        # This jump condition means "IF THIS EXPRESSION IS TRUE, THEN JUMP (conditionally exit/continue loop based on CFG)"
        # For a loop, the PrimitiveJump in the condition block usually signifies "if true, EXIT loop".
        # So, the IRBoolExpr we create here represents the EXIT condition.
        jump_to_bool_expr_map: Dict[str, IRBoolExpr.CompareType] = {
            "JTrue": IRBoolExpr.CompareType.ISTRUE,
            "JFalse": IRBoolExpr.CompareType.ISFALSE,
            "JNull": IRBoolExpr.CompareType.NULL,
            "JNotNull": IRBoolExpr.CompareType.NOT_NULL,
            "JSLt": IRBoolExpr.CompareType.LT,
            "JSGte": IRBoolExpr.CompareType.GTE,
            "JSGt": IRBoolExpr.CompareType.GT,
            "JSLte": IRBoolExpr.CompareType.LTE,
            "JULt": IRBoolExpr.CompareType.LT,
            "JUGte": IRBoolExpr.CompareType.GTE,
            "JNotLt": IRBoolExpr.CompareType.GTE,
            "JNotGte": IRBoolExpr.CompareType.LT,
            "JEq": IRBoolExpr.CompareType.EQ,
            "JNotEq": IRBoolExpr.CompareType.NEQ,
        }

        if original_jump_op.op not in jump_to_bool_expr_map:
            dbg_print(f"IRPrimitiveJumpLifter: Jump op {original_jump_op.op} not supported for BoolExpr conversion.")
            return

        condition_type = jump_to_bool_expr_map[original_jump_op.op]

        # Create the IRBoolExpr using operands from the original jump Opcode
        # These operands will be IRLocals.
        op_df = original_jump_op.df
        left_expr: Optional[IRExpression] = None
        right_expr: Optional[IRExpression] = None
        cond_operand_expr: Optional[IRExpression] = None

        # Helper to get operand as IRLocal
        def get_local_operand(key_name: str) -> Optional[IRLocal]:
            if key_name not in op_df:
                return None
            try:
                reg_idx = op_df[key_name].value
                assert isinstance(reg_idx, int), "this should literally never happen!"
                return self.func.locals[reg_idx]  # self.func comes from TraversingIROptimizer
            except (AttributeError, IndexError, KeyError):
                dbg_print(f"IRPrimitiveJumpLifter: Could not resolve local for key {key_name} in {original_jump_op}")
                return None

        if condition_type in [
            IRBoolExpr.CompareType.ISTRUE,
            IRBoolExpr.CompareType.ISFALSE,
        ]:
            cond_operand_expr = get_local_operand("cond")
            if not cond_operand_expr:
                return  # Failed to create
        elif condition_type in [
            IRBoolExpr.CompareType.NULL,
            IRBoolExpr.CompareType.NOT_NULL,
        ]:
            cond_operand_expr = get_local_operand("reg")
            if not cond_operand_expr:
                return
        else:  # Two-operand comparisons
            left_expr = get_local_operand("a")
            right_expr = get_local_operand("b")
            if not left_expr or not right_expr:
                dbg_print(f"IRPrimitiveJumpLifter: Missing operands for binary jump {original_jump_op.op}")
                return

        if cond_operand_expr:
            bool_condition_expr = IRBoolExpr(loop.code, condition_type, left=cond_operand_expr)
        else:
            bool_condition_expr = IRBoolExpr(loop.code, condition_type, left=left_expr, right=right_expr)

        # Replace the last statement (IRPrimitiveJump) with the new IRBoolExpr
        loop.condition.statements[-1] = bool_condition_expr
        dbg_print(f"IRPrimitiveJumpLifter: Lifted jump to {bool_condition_expr}")


class IRConditionInliner(TraversingIROptimizer):
    """
    Optimizes IR by inlining expressions (especially IRConst or IRBoolExpr)
    that are assigned to a temporary local and then immediately used in a
    conditional statement (IRConditional, IRWhileLoop) or another expression.

    This helps simplify conditions and expressions before other optimization passes.
    """

    def __init__(self, function: "IRFunction"):
        super().__init__(function)
        self._user_variable_names: Set[str] = set()
        self._user_reg_indices: Set[int] = set()
        if self.func.func.has_debug and self.func.func.assigns:
            for name_ref, op_idx in self.func.func.assigns:
                self._user_variable_names.add(name_ref.resolve(self.func.code))
                val = op_idx.value - 1
                if val >= 0 and val < len(self.func.ops):
                    op = self.func.ops[val]
                    try:
                        self._user_reg_indices.add(op.df["dst"].value)
                    except KeyError:
                        pass

    def _is_user_local(self, local: IRLocal) -> bool:
        if local.name in self._user_variable_names:
            return True
        if local.name.startswith("var"):
            try:
                idx = int(local.name[3:])
                if idx in self._user_reg_indices:
                    return True
            except ValueError:
                pass
        return False

    def visit_block(self, block: IRBlock) -> None:
        """
        Iterates through statements to find inlining opportunities.
        """
        new_statements: List[IRStatement] = []

        i = 0
        while i < len(block.statements):
            current_stmt = block.statements[i]
            inlined_something = False

            if isinstance(current_stmt, IRAssign) and isinstance(current_stmt.expr, IRExpression):
                assigned_local: IRLocal | IRField | IRArrayAccess = current_stmt.target
                expr_to_inline: IRExpression = current_stmt.expr

                if isinstance(assigned_local, IRLocal) and self._is_user_local(assigned_local):
                    new_statements.append(current_stmt)
                    i += 1
                    continue

                if i + 1 < len(block.statements):
                    next_stmt = block.statements[i + 1]

                    if isinstance(next_stmt, IRConditional):
                        conditional_stmt: IRConditional = next_stmt
                        if conditional_stmt.condition == assigned_local:
                            dbg_print(
                                f"IRCondInliner: Inlining {expr_to_inline} into IRConditional condition (direct) for {assigned_local}"
                            )
                            conditional_stmt.condition = expr_to_inline
                            new_statements.append(next_stmt)
                            i += 2
                            inlined_something = True
                        elif isinstance(conditional_stmt.condition, IRBoolExpr):
                            modified_bool_expr = self._try_inline_into_boolexpr(
                                conditional_stmt.condition,
                                assigned_local,
                                expr_to_inline,
                            )
                            if modified_bool_expr:
                                dbg_print(
                                    f"IRCondInliner: Inlining {expr_to_inline} into IRBoolExpr within IRConditional for {assigned_local}"
                                )
                                conditional_stmt.condition = modified_bool_expr
                                new_statements.append(next_stmt)
                                i += 2
                                inlined_something = True

                    elif not inlined_something and isinstance(next_stmt, IRWhileLoop):
                        while_loop_stmt: IRWhileLoop = next_stmt
                        if while_loop_stmt.condition == assigned_local:
                            dbg_print(
                                f"IRCondInliner: Inlining {expr_to_inline} into IRWhileLoop condition (direct) for {assigned_local}"
                            )
                            while_loop_stmt.condition = expr_to_inline
                            new_statements.append(next_stmt)
                            i += 2
                            inlined_something = True
                        elif isinstance(while_loop_stmt.condition, IRBoolExpr):
                            modified_bool_expr = self._try_inline_into_boolexpr(
                                while_loop_stmt.condition,
                                assigned_local,
                                expr_to_inline,
                            )
                            if modified_bool_expr:
                                dbg_print(
                                    f"IRCondInliner: Inlining {expr_to_inline} into IRBoolExpr within IRWhileLoop for {assigned_local}"
                                )
                                while_loop_stmt.condition = modified_bool_expr
                                new_statements.append(next_stmt)
                                i += 2
                                inlined_something = True

                    elif (
                        not inlined_something
                        and isinstance(next_stmt, IRAssign)
                        and isinstance(next_stmt.expr, IRExpression)
                    ):
                        assign_next_stmt: IRAssign = next_stmt
                        modified_rhs_expr = self._try_inline_into_generic_expr(
                            assign_next_stmt.expr, assigned_local, expr_to_inline
                        )
                        if modified_rhs_expr:
                            dbg_print(
                                f"IRCondInliner: Inlining {expr_to_inline} into IRAssign RHS for {assigned_local}"
                            )
                            assign_next_stmt.expr = modified_rhs_expr
                            new_statements.append(assign_next_stmt)
                            i += 2
                            inlined_something = True

                    elif not inlined_something and isinstance(next_stmt, IRReturn):
                        return_stmt: IRReturn = next_stmt
                        if return_stmt.value == assigned_local:
                            dbg_print(
                                f"IRCondInliner: Inlining {expr_to_inline} into IRReturn value (direct) for {assigned_local}"
                            )
                            return_stmt.value = expr_to_inline
                            new_statements.append(next_stmt)
                            i += 2
                            inlined_something = True
                        elif isinstance(return_stmt.value, IRExpression):
                            modified_ret_val = self._try_inline_into_generic_expr(
                                return_stmt.value, assigned_local, expr_to_inline
                            )
                            if modified_ret_val:
                                dbg_print(
                                    f"IRCondInliner: Inlining {expr_to_inline} into IRReturn expression for {assigned_local}"
                                )
                                return_stmt.value = modified_ret_val
                                new_statements.append(next_stmt)
                                i += 2
                                inlined_something = True

                    elif not inlined_something and isinstance(next_stmt, IRExpression):
                        modified_next_expr = self._try_inline_into_generic_expr(
                            next_stmt, assigned_local, expr_to_inline
                        )
                        if modified_next_expr:
                            dbg_print(
                                f"IRCondInliner: Inlining {expr_to_inline} into IRExpression statement {next_stmt} (now {modified_next_expr}) for {assigned_local}"
                            )
                            new_statements.append(modified_next_expr)
                            i += 2
                            inlined_something = True

            if not inlined_something:
                new_statements.append(current_stmt)
                i += 1

        block.statements = new_statements

    def _try_inline_into_boolexpr(
        self, bool_expr: IRBoolExpr, target: IRLocal | IRField | IRArrayAccess, expr_to_inline: IRExpression
    ) -> Optional[IRBoolExpr]:
        modified = False
        new_left = bool_expr.left
        new_right = bool_expr.right

        if bool_expr.left == target:
            new_left = expr_to_inline
            modified = True
        elif isinstance(bool_expr.left, IRExpression):
            inlined_nested_left = self._try_inline_into_generic_expr(bool_expr.left, target, expr_to_inline)
            if inlined_nested_left:
                new_left = inlined_nested_left
                modified = True

        if bool_expr.right == target:
            new_right = expr_to_inline
            modified = True
        elif isinstance(bool_expr.right, IRExpression):
            inlined_nested_right = self._try_inline_into_generic_expr(bool_expr.right, target, expr_to_inline)
            if inlined_nested_right:
                new_right = inlined_nested_right
                modified = True

        if modified:
            bool_expr.left = new_left
            bool_expr.right = new_right
            return bool_expr
        return None

    def _try_inline_into_generic_expr(
        self,
        current_expr: IRExpression,
        target: IRLocal | IRField | IRArrayAccess,
        expr_to_inline: IRExpression,
    ) -> Optional[IRExpression]:
        if current_expr == target:
            return expr_to_inline

        if isinstance(current_expr, IRArithmetic):
            arith_expr: IRArithmetic = current_expr
            modified_left = arith_expr.left
            modified_right = arith_expr.right
            made_change = False

            inlined_left_child = self._try_inline_into_generic_expr(arith_expr.left, target, expr_to_inline)
            if inlined_left_child:
                modified_left = inlined_left_child
                made_change = True

            inlined_right_child = self._try_inline_into_generic_expr(arith_expr.right, target, expr_to_inline)
            if inlined_right_child:
                modified_right = inlined_right_child
                made_change = True

            if made_change:
                arith_expr.left = modified_left
                arith_expr.right = modified_right
                return arith_expr
            return None

        elif isinstance(current_expr, IRBoolExpr):
            return self._try_inline_into_boolexpr(current_expr, target, expr_to_inline)

        elif isinstance(current_expr, IRCall):
            call_expr: IRCall = current_expr
            made_change = False
            new_args = list(call_expr.args)

            for i, arg_expr in enumerate(call_expr.args):
                inlined_arg = self._try_inline_into_generic_expr(arg_expr, target, expr_to_inline)
                if inlined_arg:
                    new_args[i] = inlined_arg
                    made_change = True

            if isinstance(call_expr.target, IRExpression):
                inlined_target_expr = self._try_inline_into_generic_expr(call_expr.target, target, expr_to_inline)
                if inlined_target_expr:
                    if isinstance(inlined_target_expr, (IRConst, IRLocal, IRField, type(None))):
                        call_expr.target = inlined_target_expr
                        made_change = True

            if made_change:
                call_expr.args = new_args
                return call_expr
            return None

        elif isinstance(current_expr, IRCast):
            cast_expr: IRCast = current_expr
            inlined_inner = self._try_inline_into_generic_expr(cast_expr.expr, target, expr_to_inline)
            if inlined_inner:
                cast_expr.expr = inlined_inner
                return cast_expr
            return None

        elif isinstance(current_expr, IRField):
            field_expr: IRField = current_expr
            inlined_target = self._try_inline_into_generic_expr(field_expr.target, target, expr_to_inline)
            if inlined_target:
                field_expr.target = inlined_target
                return field_expr
            return None

        return None


class IRLoopConditionOptimizer(TraversingIROptimizer):
    """
    Optimizes IRPrimitiveLoop structures into IRWhileLoop.
    It expects the IRPrimitiveLoop's condition block to end with an IRBoolExpr
    (which would typically have been lifted from a jump by IRPrimitiveJumpLifter).
    This IRBoolExpr determines the loop *exit* condition.

    The optimizer inverts this exit condition to get the 'while' *continuation* condition.
    Any statements from the original condition block preceding the final IRBoolExpr
    are prepended to the new IRWhileLoop's body.
    """

    def _clone_bool_expr(self, expr: IRBoolExpr) -> IRBoolExpr:
        return IRBoolExpr(expr.code, expr.op, expr.left, expr.right)

    def _inline_into_boolexpr(
        self, bool_expr: IRBoolExpr, target: IRLocal | IRField | IRArrayAccess, expr_to_inline: IRExpression
    ) -> Optional[IRBoolExpr]:
        modified = False
        new_left = bool_expr.left
        new_right = bool_expr.right

        if bool_expr.left == target:
            new_left = expr_to_inline
            modified = True
        if bool_expr.right == target:
            new_right = expr_to_inline
            modified = True

        if modified:
            bool_expr.left = new_left
            bool_expr.right = new_right
            return bool_expr
        return None

    def _statement_reads_target(self, statement: IRStatement, target: IRLocal | IRField | IRArrayAccess) -> bool:
        if statement == target:
            return True
        if isinstance(statement, IRAssign):
            return self._statement_reads_target(statement.expr, target)
        if isinstance(statement, IRBoolExpr):
            return (statement.left is not None and self._statement_reads_target(statement.left, target)) or \
                   (statement.right is not None and self._statement_reads_target(statement.right, target))
        return any(self._statement_reads_target(child, target) for child in statement.get_children())

    def _convert_to_while_true_break(
        self,
        loop: IRPrimitiveLoop,
        setup_statements: List[IRStatement],
        exit_condition_expr: IRBoolExpr,
    ) -> IRWhileLoop:
        true_loop_condition = IRBoolExpr(loop.code, IRBoolExpr.CompareType.TRUE)
        break_block = IRBlock(loop.code)
        break_block.statements.append(IRBreak(loop.code))
        if_break_stmt = IRConditional(loop.code, exit_condition_expr, break_block, IRBlock(loop.code))

        new_body_block = IRBlock(loop.code)
        new_body_block.statements = setup_statements + [if_break_stmt] + list(loop.body.statements)

        new_while_loop = IRWhileLoop(loop.code, true_loop_condition, new_body_block)
        new_while_loop.comment = loop.comment
        return new_while_loop

    def visit_block(self, block: IRBlock) -> None:
        new_statements: List[IRStatement] = []
        for stmt in block.statements:
            if isinstance(stmt, IRPrimitiveLoop):
                converted_loop = self._try_convert_to_while(stmt)
                new_statements.append(converted_loop if converted_loop else stmt)
            else:
                new_statements.append(stmt)
        block.statements = new_statements

    def _try_convert_to_while(self, loop: IRPrimitiveLoop) -> Optional[IRWhileLoop]:
        if not loop.condition.statements:
            dbg_print(f"IRLoopCondOpt: PrimitiveLoop at {loop} has empty condition block. Cannot convert.")
            return None

        last_cond_stmt = loop.condition.statements[-1]

        if not isinstance(last_cond_stmt, IRBoolExpr):
            dbg_print(
                f"IRLoopCondOpt: PrimitiveLoop at {loop} condition does not end with IRBoolExpr. Ends with {type(last_cond_stmt).__name__}. Cannot convert."
            )
            return None

        setup_statements_for_body = loop.condition.statements[:-1]
        working_exit_condition = self._clone_bool_expr(last_cond_stmt)
        remaining_setup: List[IRStatement] = []

        for i, stmt in enumerate(setup_statements_for_body):
            if isinstance(stmt, IRAssign) and isinstance(stmt.expr, IRExpression):
                later_statements = list(setup_statements_for_body[i + 1 :]) + list(loop.body.statements)
                reads_later = any(self._statement_reads_target(later_stmt, stmt.target) for later_stmt in later_statements)
                reads_in_condition = self._statement_reads_target(working_exit_condition, stmt.target)
                if reads_later or reads_in_condition:
                    remaining_setup.append(stmt)
                    continue

                inlined = self._inline_into_boolexpr(working_exit_condition, stmt.target, stmt.expr)
                if inlined:
                    continue
            remaining_setup.append(stmt)

        if remaining_setup:
            dbg_print(
                "IRLoopCondOpt: Condition setup must execute each iteration; converting to while(true)+break form."
            )
            return self._convert_to_while_true_break(loop, remaining_setup, working_exit_condition)

        loop_continuation_expr = self._clone_bool_expr(working_exit_condition)
        loop_continuation_expr.invert()

        new_body_statements = list(loop.body.statements)
        new_body_block = IRBlock(loop.code)
        new_body_block.statements = new_body_statements

        new_while_loop = IRWhileLoop(loop.code, loop_continuation_expr, new_body_block)

        new_while_loop.comment = loop.comment

        dbg_print(f"IRLoopCondOpt: Converted IRPrimitiveLoop to IRWhileLoop. While condition: {loop_continuation_expr}")
        return new_while_loop


class IRSelfAssignOptimizer(TraversingIROptimizer):
    """
    Optimizes away redundant assignments like `x = x`.
    """

    def visit_block(self, block: IRBlock) -> None:
        new_statements = []

        for stmt in block.statements:
            if isinstance(stmt, IRAssign):
                if isinstance(stmt.target, IRLocal) and stmt.target == stmt.expr:
                    dbg_print(f"IRSelfAssignOptimizer: Removing redundant assignment: {stmt}")
                    continue
            new_statements.append(stmt)

        block.statements = new_statements


class IRBlockFlattener(TraversingIROptimizer):
    """
    Flattens nested IRBlock structures. For example, an IRBlock child of another IRBlock
    will have its statements merged into the parent IRBlock. This simplifies the IR by
    removing unnecessary layers of blocks.

    This optimizer works by ensuring that any IRBlock child of a currently visited IRBlock
    is itself visited (and thus potentially flattened internally) before its statements
    are pulled up into the parent.
    """

    def visit_block(self, block: IRBlock) -> None:
        original_statements = list(block.statements)
        new_statements: List[IRStatement] = []

        made_structural_change = False

        for stmt in original_statements:
            if isinstance(stmt, IRBlock):
                self.visit(stmt)

                new_statements.extend(stmt.statements)
                made_structural_change = True
            else:
                new_statements.append(stmt)

        if made_structural_change or new_statements != original_statements:
            block.statements = new_statements
            dbg_print(
                f"IRBlockFlattener: Processed block. Original item count: {len(original_statements)}, New item count: {len(new_statements)}"
            )


class IRCommonBlockMerger(TraversingIROptimizer):
    """
    Finds IRConditional statements where both the true and false blocks end
    with the same sequence of statements. It "hoists" this common suffix out
    of the conditional and places it after the if/else block.

    For example:
        if (cond) {
            do_a();
            common_code();
        } else {
            do_b();
            common_code();
        }

    Becomes:
        if (cond) {
            do_a();
        } else {
            do_b();
        }
        common_code();
    """

    def visit_block(self, block: IRBlock) -> None:
        made_change = False
        new_statements: List[IRStatement] = []

        for stmt in block.statements:
            if isinstance(stmt, IRConditional):
                # We can only merge if there is an 'else' block
                if not stmt.false_block or not stmt.false_block.statements:
                    new_statements.append(stmt)
                    continue

                true_stmts = stmt.true_block.statements
                false_stmts = stmt.false_block.statements

                common_suffix: List[IRStatement] = []
                # Compare statements from the end of each block
                t_idx, f_idx = len(true_stmts) - 1, len(false_stmts) - 1
                while t_idx >= 0 and f_idx >= 0:
                    # Using repr for structural comparison. This is a practical heuristic.
                    # A more advanced system might use a deep structural equality check.
                    if repr(true_stmts[t_idx]) == repr(false_stmts[f_idx]):
                        # Prepend to keep the order correct
                        common_suffix.insert(0, true_stmts[t_idx])
                        t_idx -= 1
                        f_idx -= 1
                    else:
                        break

                if common_suffix:
                    dbg_print(f"IRCommonBlockMerger: Found {len(common_suffix)} common statements to merge.")
                    made_change = True

                    # Truncate the original blocks
                    stmt.true_block.statements = true_stmts[: t_idx + 1]
                    stmt.false_block.statements = false_stmts[: f_idx + 1]

                    # Add the modified conditional, then the common code after it.
                    new_statements.append(stmt)
                    new_statements.extend(common_suffix)
                else:
                    new_statements.append(stmt)
            else:
                new_statements.append(stmt)

        if made_change:
            block.statements = new_statements


class IRVoidAssignOptimizer(TraversingIROptimizer):
    """
    Removes assignments to IRLocals of type Void, keeping the expression
    for its side effects and annotating the discard.
    E.g., `var_void_local:Void = some_call();` becomes `some_call();`
    """

    def visit_block(self, block: IRBlock) -> None:
        new_statements: List[IRStatement] = []
        made_change_this_pass = False

        for stmt in block.statements:
            if isinstance(stmt, IRAssign):
                target = stmt.target
                if isinstance(target, IRLocal):
                    target_type_resolved = target.type.resolve(self.func.code)
                    if target_type_resolved.kind.value == Type.Kind.VOID.value:
                        dbg_print(f"IRVoidAssignOptimizer: Removing void assignment: {stmt} (target: {target.name})")

                        expr_being_kept = stmt.expr
                        new_statements.append(expr_being_kept)
                        made_change_this_pass = True
                        continue
            new_statements.append(stmt)

        if made_change_this_pass:
            block.statements = new_statements


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


class IRTempAssignmentInliner(TraversingIROptimizer):
    """
    Optimizes IR by inlining temporary variable assignments.
    This optimizer has two modes, controlled by the `aggressive` flag.

    Crucially, this optimizer will NOT inline any assignment to a variable
    that has an explicit name in the Haxe source code's debug information.
    It only targets compiler-generated temporary variables.

    - Conservative Mode (aggressive=False, default): Only inlines an assignment
      `temp = expr` if `temp` is used in the immediately following statement.

    - Aggressive Mode (aggressive=True): Inlines "safe" expressions (like constants)
      into all subsequent uses of a temporary variable, as long as that variable
      is not redefined.
    """

    def __init__(self, function: "IRFunction", aggressive: bool = False):
        super().__init__(function)
        self.aggressive = aggressive

        # --- NEW: Pre-calculate the set of all user-named variables ---
        self._user_variable_names: Set[str] = set()
        self._user_reg_indices: Set[int] = set()
        if self.func.func.has_debug and self.func.func.assigns:
            for name_ref, op_idx in self.func.func.assigns:
                self._user_variable_names.add(name_ref.resolve(self.func.code))
                val = op_idx.value - 1
                if val >= 0 and val < len(self.func.ops):
                    op = self.func.ops[val]
                    try:
                        reg = op.df["dst"].value
                        self._user_reg_indices.add(reg)
                    except KeyError:
                        pass
        dbg_print(f"IRTempAssignmentInliner: Protecting user variables: {self._user_variable_names}")
        dbg_print(f"IRTempAssignmentInliner: Protecting user reg indices: {self._user_reg_indices}")

    def _is_user_local(self, local: IRLocal) -> bool:
        if local.name in self._user_variable_names:
            return True
        if local.name.startswith("var"):
            try:
                idx = int(local.name[3:])
                if idx in self._user_reg_indices:
                    return True
            except ValueError:
                pass
        return False

    def _substitute_in_expr(
        self, expr: IRExpression, target: IRLocal, replacement: IRExpression
    ) -> Tuple[IRExpression, bool]:
        """Recursively substitutes a local with an expression within another expression."""
        if expr == target:
            return replacement, True

        made_change = False
        if isinstance(expr, (IRArithmetic, IRBoolExpr)):
            if expr.left:
                expr.left, changed = self._substitute_in_expr(expr.left, target, replacement)
                made_change = made_change or changed
            if expr.right:
                expr.right, changed = self._substitute_in_expr(expr.right, target, replacement)
                made_change = made_change or changed
        elif isinstance(expr, IRCall):
            if expr.target is not None:
                new_target, changed = self._substitute_in_expr(expr.target, target, replacement)
                expr.target = cast(Union[IRConst, IRLocal, IRField], new_target)
                made_change = made_change or changed
            new_args = []
            for arg in expr.args:
                new_arg, changed = self._substitute_in_expr(arg, target, replacement)
                new_args.append(new_arg)
                made_change = made_change or changed
            expr.args = new_args
        elif isinstance(expr, IRField):
            expr.target, changed = self._substitute_in_expr(expr.target, target, replacement)
            made_change = made_change or changed
        elif isinstance(expr, IRCast):
            expr.expr, changed = self._substitute_in_expr(expr.expr, target, replacement)
            made_change = made_change or changed
        elif isinstance(expr, IRArrayAccess):
            expr.array, changed = self._substitute_in_expr(expr.array, target, replacement)
            made_change = made_change or changed
            expr.index, changed = self._substitute_in_expr(expr.index, target, replacement)
            made_change = made_change or changed
        elif isinstance(expr, IRRef):
            expr.target, changed = self._substitute_in_expr(expr.target, target, replacement)
            made_change = made_change or changed
        elif isinstance(expr, IREnumConstruct):
            new_args = []
            for arg in expr.args:
                new_arg, changed = self._substitute_in_expr(arg, target, replacement)
                new_args.append(new_arg)
                made_change = made_change or changed
            expr.args = new_args
        elif isinstance(expr, IREnumIndex):
            expr.value, changed = self._substitute_in_expr(expr.value, target, replacement)
            made_change = made_change or changed
        elif isinstance(expr, IREnumField):
            expr.value, changed = self._substitute_in_expr(expr.value, target, replacement)
            made_change = made_change or changed

        return expr, made_change

    def _expr_contains_local(self, expr: IRExpression, local: IRLocal) -> bool:
        if expr == local:
            return True
        if isinstance(expr, (IRArithmetic, IRBoolExpr)):
            if expr.left and self._expr_contains_local(expr.left, local):
                return True
            if expr.right and self._expr_contains_local(expr.right, local):
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
        elif isinstance(expr, IREnumIndex):
            if self._expr_contains_local(expr.value, local):
                return True
        elif isinstance(expr, IREnumField):
            if self._expr_contains_local(expr.value, local):
                return True
        for child in expr.get_children():
            if isinstance(child, IRExpression) and self._expr_contains_local(child, local):
                return True
        return False

    def _substitute_in_statement(self, stmt: IRStatement, target: IRLocal, replacement: IRExpression) -> bool:
        """
        Recursively traverses a statement to perform substitutions.
        Returns True if a substitution was made, False otherwise.
        """
        made_change = False

        if isinstance(stmt, IRAssign):
            if stmt.target != target and isinstance(stmt.target, IRExpression):
                _, changed = self._substitute_in_expr(stmt.target, target, replacement)
                made_change = made_change or changed
            if isinstance(stmt.expr, IRExpression):
                stmt.expr, changed = self._substitute_in_expr(stmt.expr, target, replacement)
                made_change = made_change or changed
        elif isinstance(stmt, IRExpression):
            _, changed = self._substitute_in_expr(stmt, target, replacement)
            made_change = made_change or changed
        elif isinstance(stmt, IRReturn):
            if stmt.value:
                stmt.value, changed = self._substitute_in_expr(stmt.value, target, replacement)
                made_change = made_change or changed

        for child in stmt.get_children():
            if child is not stmt:
                if self._substitute_in_statement(child, target, replacement):
                    made_change = True

        return made_change

    def _substitute_shallow(self, stmt: IRStatement, target: IRLocal, replacement: IRExpression) -> bool:
        """Substitute only at the top level of a statement, not recursing into child blocks."""
        made_change = False
        if isinstance(stmt, IRAssign):
            if stmt.target != target and isinstance(stmt.target, IRExpression):
                _, changed = self._substitute_in_expr(stmt.target, target, replacement)
                made_change = made_change or changed
            if isinstance(stmt.expr, IRExpression):
                stmt.expr, changed = self._substitute_in_expr(stmt.expr, target, replacement)
                made_change = made_change or changed
        elif isinstance(stmt, IRExpression):
            _, changed = self._substitute_in_expr(stmt, target, replacement)
            made_change = made_change or changed
        elif isinstance(stmt, IRReturn):
            if stmt.value:
                stmt.value, changed = self._substitute_in_expr(stmt.value, target, replacement)
                made_change = made_change or changed
        elif isinstance(stmt, IRConditional):
            stmt.condition, changed = self._substitute_in_expr(stmt.condition, target, replacement)
            made_change = made_change or changed
        elif isinstance(stmt, IRWhileLoop):
            stmt.condition, changed = self._substitute_in_expr(stmt.condition, target, replacement)
            made_change = made_change or changed
        return made_change

    def _is_local_redefined(self, local_to_check: IRLocal, statements: List[IRStatement]) -> bool:
        """Checks if a local is the target of an assignment in a list of statements."""
        for stmt in statements:
            if isinstance(stmt, IRAssign) and stmt.target == local_to_check:
                return True
            for child in stmt.get_children():
                child_stmts = child.statements if isinstance(child, IRBlock) else [child]
                if self._is_local_redefined(local_to_check, child_stmts):
                    return True
        return False

    def is_safe_to_inline_aggressively(self, expr: IRExpression) -> bool:
        """
        Determines if an expression can be safely copied multiple times
        without changing the program's semantics.
        """
        if isinstance(expr, (IRConst, IRLocal)):
            return True
        if isinstance(expr, IRField):
            return self.is_safe_to_inline_aggressively(expr.target)
        if isinstance(expr, IRCast):
            return self.is_safe_to_inline_aggressively(expr.expr)
        if isinstance(expr, IRArrayAccess):
            return self.is_safe_to_inline_aggressively(expr.array) and self.is_safe_to_inline_aggressively(expr.index)
        if isinstance(expr, IRRef):
            return False
        if isinstance(expr, IREnumConstruct):
            return all(self.is_safe_to_inline_aggressively(a) for a in expr.args)
        if isinstance(expr, IREnumIndex):
            return self.is_safe_to_inline_aggressively(expr.value)
        if isinstance(expr, IREnumField):
            return self.is_safe_to_inline_aggressively(expr.value)
        if isinstance(expr, IRArithmetic):
            return self.is_safe_to_inline_aggressively(expr.left) and self.is_safe_to_inline_aggressively(expr.right)
        return False

    def is_safe_to_inline_conservatively(self, expr: IRExpression) -> bool:
        if isinstance(expr, (IRConst, IRLocal)):
            return True
        if isinstance(expr, IRCast):
            return self.is_safe_to_inline_conservatively(expr.expr)
        if isinstance(expr, IRCall):
            return True
        # Allow flat arithmetic (both operands are leaves) to enable compound assignment detection.
        # Nested arithmetic is excluded to prevent exponential chaining.
        if isinstance(expr, IRArithmetic):
            return isinstance(expr.left, (IRConst, IRLocal)) and isinstance(expr.right, (IRConst, IRLocal))
        return False

    def visit_block(self, block: IRBlock) -> None:
        if self.aggressive:
            self._visit_block_aggressive(block)
        else:
            self._visit_block_conservative(block)

    def _visit_block_conservative(self, block: IRBlock) -> None:
        """Only inlines an assignment if it is used in the very next statement."""
        if not block.statements:
            return

        new_statements: List[IRStatement] = []
        i = 0
        statements = block.statements
        while i < len(statements):
            current_stmt = statements[i]
            inlined = False

            if isinstance(current_stmt, IRAssign) and isinstance(current_stmt.target, IRLocal):
                temp_local = current_stmt.target

                if not self._is_user_local(temp_local):
                    expr_to_inline = current_stmt.expr
                    if not self.is_safe_to_inline_conservatively(expr_to_inline):
                        new_statements.append(current_stmt)
                        i += 1
                        continue
                    if isinstance(expr_to_inline, IRExpression) and self._expr_contains_local(expr_to_inline, temp_local):
                        new_statements.append(current_stmt)
                        i += 1
                        continue
                    if i + 1 < len(statements):
                        next_stmt = statements[i + 1]
                        if self._substitute_in_statement(next_stmt, temp_local, expr_to_inline):
                            dbg_print(f"Conservatively inlining assignment for temporary '{temp_local.name}'.")
                            new_statements.append(next_stmt)
                            copy_target = None
                            if (
                                isinstance(next_stmt, IRAssign)
                                and isinstance(next_stmt.target, IRLocal)
                                and self._is_user_local(next_stmt.target)
                            ):
                                copy_target = next_stmt.target
                            for later_stmt in statements[i + 2 :]:
                                if (
                                    isinstance(later_stmt, IRAssign)
                                    and isinstance(later_stmt.target, IRLocal)
                                    and later_stmt.target == temp_local
                                ):
                                    break
                                sub = copy_target if copy_target is not None else expr_to_inline
                                self._substitute_shallow(later_stmt, temp_local, sub)
                            i += 2
                            inlined = True

            if not inlined:
                new_statements.append(current_stmt)
                i += 1

        block.statements = new_statements

    def _visit_block_aggressive(self, block: IRBlock) -> None:
        """Inlines safe expressions everywhere they are used, until no more changes can be made."""
        made_change_in_pass = True
        while made_change_in_pass:
            made_change_in_pass = False
            statements_to_remove: List[IRStatement] = []

            for i, stmt in enumerate(block.statements):
                if not (isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal)):
                    continue

                temp_local = stmt.target

                if self._is_user_local(temp_local):
                    continue

                expr_to_inline = stmt.expr

                if not isinstance(expr_to_inline, IRExpression) or not self.is_safe_to_inline_aggressively(
                    expr_to_inline
                ):
                    continue
                if self._expr_contains_local(expr_to_inline, temp_local):
                    continue

                remaining_statements = block.statements[i + 1 :]
                if self._is_local_redefined(temp_local, remaining_statements):
                    continue

                any_substituted = False
                for subsequent_stmt in remaining_statements:
                    if self._substitute_in_statement(subsequent_stmt, temp_local, expr_to_inline):
                        any_substituted = True

                if not any_substituted:
                    continue

                dbg_print(f"Aggressively inlining safe expression from temporary '{temp_local.name}'.")
                statements_to_remove.append(stmt)
                made_change_in_pass = True
                break

            if statements_to_remove:
                block.statements = [s for s in block.statements if s not in statements_to_remove]

        for stmt in block.statements:
            for child in stmt.get_children():
                if isinstance(child, IRBlock):
                    self.visit_block(child)


class IRDeadTempEliminator(IROptimizer):
    """Removes assignments to compiler-generated temp variables that are never read."""

    def optimize(self) -> None:
        if not hasattr(self.func, "block"):
            return
        user_names = self._collect_user_names()
        user_regs = self._collect_user_reg_indices()
        globally_used = self._collect_all_used_names(self.func.block)
        self._remove_dead(self.func.block, user_names, user_regs, globally_used)

    def _collect_user_names(self) -> Set[str]:
        names: Set[str] = set()
        if self.func.func.has_debug and self.func.func.assigns:
            for name_ref, _ in self.func.func.assigns:
                names.add(name_ref.resolve(self.func.code))
        return names

    def _collect_user_reg_indices(self) -> Set[int]:
        indices: Set[int] = set()
        if self.func.func.has_debug and self.func.func.assigns:
            for _, op_idx in self.func.func.assigns:
                val = op_idx.value - 1
                if val >= 0 and val < len(self.func.ops):
                    op = self.func.ops[val]
                    try:
                        indices.add(op.df["dst"].value)
                    except KeyError:
                        pass
        return indices

    def _is_user_local(
        self, local: IRLocal, user_names: Set[str], user_regs: Set[int]
    ) -> bool:
        if local.name in user_names:
            return True
        if local.name.startswith("var"):
            try:
                idx = int(local.name[3:])
                if idx in user_regs:
                    return True
            except ValueError:
                pass
        return False

    def _collect_all_used_names(self, block: IRBlock) -> Set[str]:
        used: Set[str] = set()
        for stmt in block.statements:
            if isinstance(stmt, IRAssign):
                self._collect_used_in_expr(stmt.expr, used)
            if isinstance(stmt, IRReturn) and stmt.value:
                self._collect_used_in_expr(stmt.value, used)
            for child in stmt.get_children():
                if isinstance(child, IRBlock):
                    used.update(self._collect_all_used_names(child))
        return used

    def _collect_used_in_expr(self, expr: IRExpression, used: Set[str]) -> None:
        if isinstance(expr, IRLocal):
            used.add(expr.name)
        if isinstance(expr, IRArithmetic):
            self._collect_used_in_expr(expr.left, used)
            self._collect_used_in_expr(expr.right, used)
        if isinstance(expr, IRCast):
            self._collect_used_in_expr(expr.expr, used)
        if isinstance(expr, IRCall):
            for arg in expr.args:
                self._collect_used_in_expr(arg, used)
        if isinstance(expr, IRField):
            self._collect_used_in_expr(expr.target, used)
        if isinstance(expr, IRArrayAccess):
            self._collect_used_in_expr(expr.array, used)
            self._collect_used_in_expr(expr.index, used)
        if isinstance(expr, IRRef):
            self._collect_used_in_expr(expr.target, used)
        if isinstance(expr, IREnumConstruct):
            for arg in expr.args:
                self._collect_used_in_expr(arg, used)
        if isinstance(expr, IREnumIndex):
            self._collect_used_in_expr(expr.value, used)
        if isinstance(expr, IREnumField):
            self._collect_used_in_expr(expr.value, used)

    def _remove_dead(
        self,
        block: IRBlock,
        user_names: Set[str],
        user_regs: Set[int],
        globally_used: Set[str],
    ) -> None:
        new_stmts: List[IRStatement] = []
        for stmt in block.statements:
            if (
                isinstance(stmt, IRAssign)
                and isinstance(stmt.target, IRLocal)
                and not self._is_user_local(stmt.target, user_names, user_regs)
                and stmt.target.name not in globally_used
            ):
                dbg_print(f"Removing dead temp assignment '{stmt.target.name}'.")
                continue
            new_stmts.append(stmt)
        block.statements = new_stmts
        for stmt in block.statements:
            for child in stmt.get_children():
                if isinstance(child, IRBlock):
                    self._remove_dead(child, user_names, user_regs, globally_used)


class IRDeadCodeEliminator(TraversingIROptimizer):
    """Removes statements after terminators (return, break, continue) within the same block."""

    def visit_block(self, block: IRBlock) -> None:
        new_stmts: List[IRStatement] = []
        terminated = False
        for stmt in block.statements:
            if terminated:
                continue
            new_stmts.append(stmt)
            if isinstance(stmt, (IRReturn, IRBreak, IRContinue)):
                terminated = True
        block.statements = new_stmts
        for stmt in block.statements:
            for child in stmt.get_children():
                if isinstance(child, IRBlock):
                    self.visit_block(child)


class IRConstructorFolder(TraversingIROptimizer):
    """Folds `new X; __constructor__(x, args...)` into `new X(args...)`."""

    def visit_block(self, block: IRBlock) -> None:
        made_change = True
        while made_change:
            made_change = False
            new_statements: List[IRStatement] = []
            i = 0
            while i < len(block.statements):
                stmt = block.statements[i]
                if (
                    isinstance(stmt, IRAssign)
                    and isinstance(stmt.target, IRLocal)
                    and isinstance(stmt.expr, IRNew)
                    and not stmt.expr.constructor_args
                    and i + 1 < len(block.statements)
                ):
                    next_stmt = block.statements[i + 1]
                    ctor_args = self._match_constructor_call(next_stmt, stmt.target)
                    if ctor_args is not None:
                        stmt.expr.constructor_args = ctor_args
                        new_statements.append(stmt)
                        i += 2
                        made_change = True
                        continue
                new_statements.append(stmt)
                i += 1
            block.statements = new_statements
        for stmt in block.statements:
            for child in stmt.get_children():
                if isinstance(child, IRBlock):
                    self.visit_block(child)

    def _match_constructor_call(self, stmt: IRStatement, instance_local: IRLocal) -> Optional[List[IRExpression]]:
        if not isinstance(stmt, IRCall):
            return None
        if stmt.call_type != IRCall.CallType.FUNC:
            return None
        if not stmt.args:
            return None
        first_arg = stmt.args[0]
        if not (isinstance(first_arg, IRLocal) and first_arg == instance_local):
            return None
        fun_const = stmt.target
        if not isinstance(fun_const, IRConst):
            return None
        if not isinstance(fun_const.value, Function):
            return None
        func_name = self.func.code.partial_func_name(fun_const.value)
        if func_name and "__constructor__" in func_name:
            return list(stmt.args[1:])
        return None


class IRTraceOptimizer(TraversingIROptimizer):
    """
    Finds the common `haxe.Log.trace` pattern with an anonymous object for
    position and collapses it into a single IRTrace statement.
    """

    def visit_block(self, block: IRBlock) -> None:
        made_change = True
        while made_change:
            made_change = False
            new_statements: List[IRStatement] = []
            i = 0
            while i < len(block.statements):
                stmt = block.statements[i]
                dbg_print(f"[TraceOpt] Analyzing statement {i}: {stmt}")

                temp_local = None
                start_idx = i

                if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal):
                    if isinstance(stmt.expr, IRNew) and stmt.expr.get_type().definition.__class__ == DynObj:
                        temp_local = stmt.target
                        start_idx = i + 1
                    else:
                        new_statements.append(stmt)
                        i += 1
                        continue
                elif isinstance(stmt, IRAssign) and isinstance(stmt.target, IRField):
                    temp_local = stmt.target.target
                    if isinstance(temp_local, IRLocal):
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
                                dbg_print(f"[TraceOpt]  -> Collected const field: {field_name} = {next_stmt.expr.value!r}")
                                j += 1
                                continue
                            elif isinstance(next_stmt.expr, IRLocal):
                                pos_info[field_name] = next_stmt.expr
                                dbg_print(f"[TraceOpt]  -> Collected local field: {field_name} = {next_stmt.expr}")
                                j += 1
                                continue
                    elif isinstance(next_stmt, IRAssign) and isinstance(next_stmt.target, IRLocal):
                        j += 1
                        continue
                    break

                if j < len(block.statements):
                    call_stmt = block.statements[j]
                    dbg_print(f"[TraceOpt] Checking statement {j} as potential trace call: {call_stmt}")

                    is_valid_trace_call = False
                    if isinstance(call_stmt, IRCall) and len(call_stmt.args) == 2:
                        last_arg = call_stmt.args[1]

                        is_our_var = (isinstance(last_arg, IRLocal) and last_arg == temp_local) or (
                            isinstance(last_arg, IRCast) and last_arg.expr == temp_local
                        )

                        is_trace_func = False
                        if isinstance(call_stmt.target, IRField) and call_stmt.target.field_name == "trace":
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

                        dbg_print(f"[TraceOpt]  -> Is function 'haxe.Log.trace'? {is_trace_func}")

                        if is_our_var and is_trace_func:
                            is_valid_trace_call = True

                    else:
                        dbg_print(f"[TraceOpt]  -> FAILED: Statement is not an IRCall with 2 arguments.")

                    if is_valid_trace_call:
                        assert isinstance(call_stmt, IRCall)
                        msg_expr = call_stmt.args[0]
                        resolved_pos: Dict[str, Any] = {}
                        for k, v in pos_info.items():
                            if isinstance(v, IRLocal):
                                for s_idx in range(start_idx, j):
                                    s = block.statements[s_idx]
                                    if isinstance(s, IRAssign) and s.target == v and isinstance(s.expr, IRConst):
                                        try:
                                            resolved_pos[k] = int(s.expr.value.value if hasattr(s.expr.value, 'value') else s.expr.value)
                                        except (ValueError, TypeError):
                                            resolved_pos[k] = v
                                        break
                                else:
                                    resolved_pos[k] = v
                            else:
                                resolved_pos[k] = v
                        trace_stmt = IRTrace(self.func.code, msg_expr, resolved_pos)
                        new_statements.append(trace_stmt)

                        i = j + 1
                        made_change = True
                        continue
                    else:
                        dbg_print(f"[TraceOpt] FAILED: Pattern did not match for trace call.")

                new_statements.append(stmt)
                i += 1

            block.statements = new_statements


class IRFunction:
    """
    Intermediate representation of a function.
    """

    def __init__(
        self,
        code: Bytecode,
        func: Function,
        do_optimize: bool = True,
        no_lift: bool = False,
    ) -> None:
        self.func = func
        self.cfg = CFGraph(func)
        self.cfg.build()
        self.code = code
        self.ops = func.ops
        self.locals: List[IRLocal] = []
        self.block: IRBlock
        self._lift(no_lift=no_lift)
        if do_optimize:
            self.optimizers: List[IROptimizer] = [
                IRBlockFlattener(self),
                IRPrimitiveJumpLifter(self),
                IRGlobalStringOptimizer(self),
                IRConditionInliner(self),
                IRLoopConditionOptimizer(self),
                IRSelfAssignOptimizer(self),
                IRCommonBlockMerger(self),
                IRTempAssignmentInliner(self, aggressive=False),
                IRTempAssignmentInliner(self, aggressive=True),
                IRDeadTempEliminator(self),
                IRDeadCodeEliminator(self),
                IRVoidAssignOptimizer(self),
                IRConstructorFolder(self),
                IRTraceOptimizer(self),
                IRBlockFlattener(self),
            ]
            self._optimize()

    def _lift(self, no_lift: bool = False) -> None:
        """Lift function to IR"""
        for i, reg in enumerate(self.func.regs):
            self.locals.append(IRLocal(f"var{i}", reg, code=self.code))
        self._build_assign_map()
        self._name_locals()
        if not no_lift:
            if self.cfg.entry:
                self.block = self._lift_block(self.cfg.entry, set())
            else:
                raise DecompError("Function CFG has no entry node, cannot lift to IR")
        else:
            dbg_print("Skipping lift.")

    def _build_assign_map(self) -> None:
        """Build a mapping from op index to (register, name) for SSA-esque splitting."""
        self._op_assigns: Dict[int, Dict[int, str]] = {}
        self._user_reg_indices: Set[int] = set()
        self._reg_first_assign: Dict[int, int] = {}
        self._op_id_to_idx: Dict[int, int] = {id(op): i for i, op in enumerate(self.ops)}
        if not (self.func.has_debug and self.func.assigns):
            return
        for assign in self.func.assigns:
            val = assign[1].value - 1
            if val < 0:
                continue
            op = self.ops[val]
            try:
                reg = op.df["dst"].value
            except KeyError:
                continue
            name = assign[0].resolve(self.code)
            self._user_reg_indices.add(reg)
            if val not in self._op_assigns:
                self._op_assigns[val] = {}
            self._op_assigns[val][reg] = name
            if reg not in self._reg_first_assign or val < self._reg_first_assign[reg]:
                self._reg_first_assign[reg] = val
        self._op_id_to_idx: Dict[int, int] = {id(op): i for i, op in enumerate(self.ops)}

    def _get_local(self, reg_idx: int) -> IRLocal:
        """Get the current IRLocal for a register, respecting SSA-esque name transitions."""
        return self.locals[reg_idx]

    def _split_local(self, reg_idx: int, name: str) -> IRLocal:
        """Create a new IRLocal for a register with a specific name (SSA-esque split)."""
        reg_type = self.func.regs[reg_idx]
        new_local = IRLocal(name, reg_type, code=self.code)
        self.locals[reg_idx] = new_local
        return new_local

    def _check_assign(self, op_idx: int) -> None:
        """Check if this op index has an assign entry and split the local if needed."""
        if op_idx in self._op_assigns:
            for reg_idx, name in self._op_assigns[op_idx].items():
                current = self.locals[reg_idx]
                if current.name != name:
                    self._split_local(reg_idx, name)

    def _optimize(self) -> None:
        """Optimize the IR"""
        from .globals import DEBUG
        if DEBUG:
            dbg_print("----- Disasm -----")
            dbg_print(disasm.func(self.code, self.func))
            dbg_print(f"----- LLIL -----")
            dbg_print(self.block.pprint())
        for o in self.optimizers:
            if DEBUG:
                dbg_print(f"----- {o.__class__.__name__} -----")
            o.optimize()
            if DEBUG:
                dbg_print(self.block.pprint())

    def _name_locals(self) -> None:
        """Name locals based on debug info"""
        reg_assigns: List[List[str]] = [[] for _ in self.func.regs]
        if self.func.has_debug and self.func.assigns:
            for assign in self.func.assigns:
                # assign: Tuple[strRef (name), VarInt (op index)]
                val = assign[1].value - 1
                if val < 0:
                    continue
                reg: Optional[int] = None
                op = self.ops[val]
                try:
                    op.df["dst"]
                    reg = op.df["dst"].value
                except KeyError:
                    pass
                if reg is not None:
                    name = assign[0].resolve(self.code)
                    if name not in reg_assigns[reg]:
                        reg_assigns[reg].append(name)
        if self.func.assigns and self.func.has_debug:
            for i, assign in enumerate([assign for assign in self.func.assigns if assign[1].value <= 0]):
                name = assign[0].resolve(self.code)
                if name not in reg_assigns[i]:
                    reg_assigns[i].append(name)
        for i, _reg in enumerate(self.func.regs):
            if _reg.resolve(self.code).definition and isinstance(_reg.resolve(self.code).definition, Void):
                if "voidReg" not in reg_assigns[i]:
                    reg_assigns[i].append("voidReg")
        for i, local in enumerate(self.locals):
            if reg_assigns[i]:
                if i in self._reg_first_assign and self._reg_first_assign[i] > 0:
                    pass
                else:
                    local.name = reg_assigns[i][0]
        dbg_print("Named locals:", self.locals)

    def _find_convergence(self, true_node: CFNode, false_node: CFNode, visited: Set[CFNode]) -> Optional[CFNode]:
        """Find where two branches of a conditional converge by following their control flow"""
        true_visited = set()
        false_visited = set()
        true_queue = [true_node]
        false_queue = [false_node]

        while true_queue or false_queue:
            if true_queue:
                node = true_queue.pop(0)
                if node in false_visited:
                    return node
                true_visited.add(node)
                for next_node, _ in node.branches:
                    if next_node not in true_visited:
                        true_queue.append(next_node)

            if false_queue:
                node = false_queue.pop(0)
                if node in true_visited:
                    return node
                false_visited.add(node)
                for next_node, _ in node.branches:
                    if next_node not in false_visited:
                        false_queue.append(next_node)

        return None  # No convergence found

    @dataclass
    class _LoopContext:
        header: CFNode
        nodes: Set[CFNode]
        exit_node: Optional[CFNode]

    def _lift_ops_into_block(self, block: IRBlock, ops: List[Opcode]) -> None:
        for op in ops:
            op_idx = self._op_id_to_idx.get(id(op))
            if op_idx is not None:
                self._check_assign(op_idx)
            if op.op == "Label":
                continue

            if op.op in arithmetic:
                dst = self.locals[op.df["dst"].value]
                lhs = self.locals[op.df["a"].value]
                rhs = self.locals[op.df["b"].value]
                block.statements.append(
                    IRAssign(
                        self.code, dst, IRArithmetic(self.code, lhs, rhs, IRArithmetic.ArithmeticType[op.op.upper()])
                    )
                )
            elif op.op in ["Int", "Float", "Bool", "Bytes", "String", "Null"]:
                dst = self.locals[op.df["dst"].value]
                const_type = IRConst.ConstType[op.op.upper()]
                value = op.df["value"].value if op.op == "Bool" else None
                if op.op not in ["Bool", "Null"]:
                    const = IRConst(self.code, const_type, op.df["ptr"], value)
                else:
                    const = IRConst(self.code, const_type, value=value)
                block.statements.append(IRAssign(self.code, dst, const))
            elif op.op in simple_calls:
                n = int(op.op[-1]) if op.op != "CallN" else len(op.df["args"].value)
                dst = self.locals[op.df["dst"].value]
                fun = IRConst(self.code, IRConst.ConstType.FUN, op.df["fun"])
                args = (
                    [self.locals[op.df[f"arg{i}"].value] for i in range(n)]
                    if op.op != "CallN"
                    else [self.locals[arg.value] for arg in op.df["args"].value]
                )
                call_expr = IRCall(self.code, IRCall.CallType.FUNC, fun, args)

                if dst.get_type().kind.value == Type.Kind.VOID.value:
                    block.statements.append(call_expr)
                else:
                    block.statements.append(IRAssign(self.code, dst, call_expr))
            elif op.op == "CallClosure":
                dst = self.locals[op.df["dst"].value]
                fun = self.locals[op.df["fun"].value]
                args = [self.locals[arg.value] for arg in op.df["args"].value]
                call_expr = IRCall(self.code, IRCall.CallType.CLOSURE, fun, args)

                if dst.get_type().kind.value == Type.Kind.VOID.value:
                    block.statements.append(call_expr)
                else:
                    block.statements.append(IRAssign(self.code, dst, call_expr))
            elif op.op == "Mov":
                block.statements.append(
                    IRAssign(self.code, self.locals[op.df["dst"].value], self.locals[op.df["src"].value])
                )
            elif op.op == "GetGlobal":
                block.statements.append(
                    IRAssign(
                        self.code,
                        self.locals[op.df["dst"].value],
                        IRConst(self.code, IRConst.ConstType.GLOBAL_OBJ, idx=op.df["global"]),
                    )
                )
            elif op.op == "Field":
                dst_local, obj_local = self.locals[op.df["dst"].value], self.locals[op.df["obj"].value]
                obj_type = obj_local.get_type()
                if not isinstance(obj_type.definition, (Obj, Virtual)):
                    raise DecompError(f"Field opcode used on non-object type: {obj_type.definition}")
                field_core = op.df["field"].resolve_obj(self.code, obj_type.definition)
                field_expr = IRField(self.code, obj_local, field_core.name.resolve(self.code), field_core.type)
                block.statements.append(IRAssign(self.code, dst_local, field_expr))
            elif op.op == "New":
                dst_local = self.locals[op.df["dst"].value]
                alloc_type_idx = self.func.regs[op.df["dst"].value]
                new_expr = IRNew(self.code, alloc_type_idx)
                block.statements.append(IRAssign(self.code, dst_local, new_expr))
            elif op.op == "ToSFloat":
                dst_local = self.locals[op.df["dst"].value]
                src_local = self.locals[op.df["src"].value]

                f64_idx = self.code.find_prim_type(Type.Kind.F64)

                cast_expr = IRCast(self.code, f64_idx, src_local)
                block.statements.append(IRAssign(self.code, dst_local, cast_expr))
            elif op.op == "ToDyn" or op.op == "ToVirtual":
                dst_local = self.locals[op.df["dst"].value]
                src_local = self.locals[op.df["src"].value]
                cast_expr = IRCast(self.code, self.func.regs[op.df["dst"].value], src_local)
                block.statements.append(IRAssign(self.code, dst_local, cast_expr))
            elif op.op == "ToInt":
                dst_local = self.locals[op.df["dst"].value]
                src_local = self.locals[op.df["src"].value]
                cast_expr = IRCast(self.code, self.func.regs[op.df["dst"].value], src_local)
                block.statements.append(IRAssign(self.code, dst_local, cast_expr))
            elif op.op == "Incr":
                dst_local = self.locals[op.df["dst"].value]
                block.statements.append(
                    IRAssign(
                        self.code,
                        dst_local,
                        IRArithmetic(
                            self.code,
                            dst_local,
                            IRConst(self.code, IRConst.ConstType.INT, value=1),
                            IRArithmetic.ArithmeticType.ADD,
                        ),
                    )
                )
            elif op.op == "Decr":
                dst_local = self.locals[op.df["dst"].value]
                block.statements.append(
                    IRAssign(
                        self.code,
                        dst_local,
                        IRArithmetic(
                            self.code,
                            dst_local,
                            IRConst(self.code, IRConst.ConstType.INT, value=1),
                            IRArithmetic.ArithmeticType.SUB,
                        ),
                    )
                )
            elif op.op == "GetMem":
                dst_local = self.locals[op.df["dst"].value]
                arr_local = self.locals[op.df["bytes"].value]
                idx_local = self.locals[op.df["index"].value]
                block.statements.append(
                    IRAssign(self.code, dst_local, IRArrayAccess(self.code, arr_local, idx_local, self.func.regs[op.df["dst"].value]))
                )
            elif op.op == "SetMem":
                arr_local = self.locals[op.df["bytes"].value]
                idx_local = self.locals[op.df["index"].value]
                src_local = self.locals[op.df["src"].value]
                block.statements.append(
                    IRAssign(self.code, IRArrayAccess(self.code, arr_local, idx_local), src_local)
                )
            elif op.op == "DynSet":
                obj_local = self.locals[op.df["obj"].value]
                src_local = self.locals[op.df["src"].value]
                field_name = op.df["field"].resolve(self.code)
                field_expr = IRField(self.code, obj_local, field_name, self.func.regs[op.df["src"].value])
                block.statements.append(IRAssign(self.code, field_expr, src_local))
            elif op.op == "SetField":
                obj_local = self.locals[op.df["obj"].value]
                src_local = self.locals[op.df["src"].value]
                obj_type = obj_local.get_type()
                if isinstance(obj_type.definition, (Obj, Virtual)):
                    field_core = op.df["field"].resolve_obj(self.code, obj_type.definition)
                    field_expr = IRField(self.code, obj_local, field_core.name.resolve(self.code), field_core.type)
                    block.statements.append(IRAssign(self.code, field_expr, src_local))
                else:
                    block.statements.append(IRUnliftedOpcode(self.code, op))
            elif op.op == "Type":
                dst_local = self.locals[op.df["dst"].value]
                block.statements.append(IRAssign(self.code, dst_local, IRConst(self.code, IRConst.ConstType.GLOBAL_OBJ, idx=op.df["ty"])))
            elif op.op == "Ref":
                dst_local = self.locals[op.df["dst"].value]
                src_local = self.locals[op.df["src"].value]
                block.statements.append(IRAssign(self.code, dst_local, IRRef(self.code, src_local)))
            elif op.op == "StaticClosure":
                dst_local = self.locals[op.df["dst"].value]
                fun_const = IRConst(self.code, IRConst.ConstType.FUN, idx=op.df["fun"])
                block.statements.append(IRAssign(self.code, dst_local, fun_const))
            elif op.op == "VirtualClosure":
                dst_local = self.locals[op.df["dst"].value]
                obj_local = self.locals[op.df["obj"].value]
                obj_type = obj_local.get_type()
                if isinstance(obj_type.definition, Obj):
                    fid = op.df["field"].value
                    if fid < len(obj_type.definition.virtuals):
                        from .core import fIndex
                        fun_idx = obj_type.definition.virtuals[fid]
                        fun_const = IRConst(self.code, IRConst.ConstType.FUN, idx=fIndex(fun_idx))
                        block.statements.append(IRAssign(self.code, dst_local, fun_const))
                    else:
                        block.statements.append(
                            IRAssign(self.code, dst_local, IRUnliftedOpcode(self.code, op))
                        )
                else:
                    block.statements.append(
                        IRAssign(self.code, dst_local, IRUnliftedOpcode(self.code, op))
                    )
            elif op.op == "NullCheck":
                continue
            elif op.op == "EnumIndex":
                dst_local = self.locals[op.df["dst"].value]
                src_local = self.locals[op.df["value"].value]
                block.statements.append(IRAssign(self.code, dst_local, IREnumIndex(self.code, src_local)))
            elif op.op == "MakeEnum":
                dst_local = self.locals[op.df["dst"].value]
                enum_type = self.func.regs[op.df["dst"].value]
                enum_def = enum_type.resolve(self.code).definition
                cid = op.df["construct"].value
                construct_name = enum_def.constructs[cid].name.resolve(self.code) if cid < len(enum_def.constructs) else f"construct_{cid}"
                args = [self.locals[arg.value] for arg in op.df["args"].value]
                block.statements.append(
                    IRAssign(self.code, dst_local, IREnumConstruct(self.code, construct_name, args, enum_type))
                )
            elif op.op == "EnumField":
                dst_local = self.locals[op.df["dst"].value]
                src_local = self.locals[op.df["value"].value]
                enum_type = self.func.regs[op.df["value"].value]
                enum_def = enum_type.resolve(self.code).definition
                cid = op.df["construct"].value
                fid = op.df["field"].value
                if cid < len(enum_def.constructs) and fid < len(enum_def.constructs[cid].params):
                    field_name = f"param{fid}"
                    construct = enum_def.constructs[cid]
                    field_type = construct.params[fid]
                    block.statements.append(
                        IRAssign(self.code, dst_local, IREnumField(self.code, src_local, field_name, field_type))
                    )
                else:
                    block.statements.append(
                        IRAssign(self.code, dst_local, IRUnliftedOpcode(self.code, op))
                    )
            else:
                if "dst" in op.df:
                    block.statements.append(
                        IRAssign(self.code, self.locals[op.df["dst"].value], IRUnliftedOpcode(self.code, op))
                    )
                else:
                    block.statements.append(IRUnliftedOpcode(self.code, op))

    def _shortest_distances(
        self,
        start: CFNode,
        allowed_nodes: Optional[Set[CFNode]] = None,
        stop_nodes: Optional[Set[CFNode]] = None,
    ) -> Dict[CFNode, int]:
        stop_nodes = stop_nodes or set()
        queue: List[Tuple[CFNode, int]] = [(start, 0)]
        distances: Dict[CFNode, int] = {}

        while queue:
            current, dist = queue.pop(0)
            if current in distances:
                continue
            if allowed_nodes is not None and current not in allowed_nodes:
                continue
            if current in stop_nodes:
                continue

            distances[current] = dist
            for next_node, _ in current.branches:
                if next_node not in distances:
                    queue.append((next_node, dist + 1))

        return distances

    def _find_convergence_node(
        self,
        left: Optional[CFNode],
        right: Optional[CFNode],
        allowed_nodes: Optional[Set[CFNode]] = None,
        stop_nodes: Optional[Set[CFNode]] = None,
    ) -> Optional[CFNode]:
        if left is None or right is None:
            return None

        left_distances = self._shortest_distances(left, allowed_nodes, stop_nodes)
        right_distances = self._shortest_distances(right, allowed_nodes, stop_nodes)
        common_nodes = set(left_distances).intersection(right_distances)
        if not common_nodes:
            return None

        return min(common_nodes, key=lambda node: (left_distances[node] + right_distances[node], node.base_offset))

    def _loop_exit_nodes(self, loop_nodes: Set[CFNode]) -> List[CFNode]:
        exit_nodes: Set[CFNode] = set()
        for loop_node in loop_nodes:
            for target, _ in loop_node.branches:
                if target not in loop_nodes:
                    exit_nodes.add(target)
        return sorted(exit_nodes, key=lambda n: n.base_offset)

    def _lift_loop(
        self,
        header: CFNode,
        visited: Set[CFNode],
        stop_at: Optional[CFNode],
        parent_loop: Optional[_LoopContext],
    ) -> IRBlock:
        visited.add(header)
        block = IRBlock(self.code)
        loop_nodes = self.cfg.loops[header]
        exit_nodes = self._loop_exit_nodes(loop_nodes)
        exit_node = exit_nodes[0] if len(exit_nodes) == 1 else None
        loop_ctx = self._LoopContext(header, loop_nodes, exit_node)

        header_last_op = header.ops[-1] if header.ops else None
        if header_last_op and header_last_op.op in conditionals:
            cond_block = IRBlock(self.code)
            self._lift_ops_into_block(cond_block, header.ops[:-1])
            cond_block.statements.append(IRPrimitiveJump(self.code, header_last_op))

            inside_successors = [target for target, _ in header.branches if target in loop_nodes and target != header]
            body_start = inside_successors[0] if len(inside_successors) == 1 else None
            body_block = (
                self._lift_block(body_start, visited.copy(), stop_at=header, loop_ctx=loop_ctx)
                if body_start is not None
                else IRBlock(self.code)
            )

            block.statements.append(IRPrimitiveLoop(self.code, cond_block, body_block))
        else:
            body_block = self._lift_block(header, visited.copy(), stop_at=header, loop_ctx=loop_ctx)
            block.statements.append(
                IRWhileLoop(self.code, IRBoolExpr(self.code, IRBoolExpr.CompareType.TRUE), body_block)
            )

        next_block_ir = self._lift_block(exit_node, visited, stop_at, loop_ctx=parent_loop)
        block.statements.extend(next_block_ir.statements)
        return block

    def _build_bool_expr_from_op(self, op: Opcode) -> IRBoolExpr:
        """Helper to create an IRBoolExpr from a conditional jump opcode."""
        cond_map = {
            "JTrue": IRBoolExpr.CompareType.ISTRUE,
            "JFalse": IRBoolExpr.CompareType.ISFALSE,
            "JNull": IRBoolExpr.CompareType.NULL,
            "JNotNull": IRBoolExpr.CompareType.NOT_NULL,
            "JSLt": IRBoolExpr.CompareType.LT,
            "JSGte": IRBoolExpr.CompareType.GTE,
            "JSGt": IRBoolExpr.CompareType.GT,
            "JSLte": IRBoolExpr.CompareType.LTE,
            "JULt": IRBoolExpr.CompareType.LT,
            "JUGte": IRBoolExpr.CompareType.GTE,
            "JNotLt": IRBoolExpr.CompareType.GTE,
            "JNotGte": IRBoolExpr.CompareType.LT,
            "JEq": IRBoolExpr.CompareType.EQ,
            "JNotEq": IRBoolExpr.CompareType.NEQ,
        }
        assert op.op is not None, "WTF??"
        cond = cond_map[op.op]
        left, right = None, None
        if "a" in op.df and "b" in op.df:
            left = self.locals[op.df["a"].value]
            right = self.locals[op.df["b"].value]
        else:
            reg_key = "cond" if "cond" in op.df else "reg"
            left = self.locals[op.df[reg_key].value]
        return IRBoolExpr(self.code, cond, left, right)

    def _lift_block(
        self,
        node: Optional[CFNode],
        visited: Set[CFNode],
        stop_at: Optional[CFNode] = None,
        loop_ctx: Optional[_LoopContext] = None,
    ) -> IRBlock:
        """
        Recursively lifts a CFNode and its successors into an IRBlock.

        Args:
            node: The current CFNode to process.
            visited: A set of nodes already processed in the current traversal path to prevent infinite loops.
            stop_at: A CFNode that signals the end of the current branch (the convergence point).
                     When this node is reached, the recursive call terminates.

        Returns:
            An IRBlock containing the lifted IR statements.
        """
        # --- Base Cases for Recursion Termination ---
        if node is None or node == stop_at or node in visited:
            return IRBlock(self.code)
        if loop_ctx and node not in loop_ctx.nodes:
            return IRBlock(self.code)
        if node in self.cfg.loops and (loop_ctx is None or node != loop_ctx.header):
            return self._lift_loop(node, visited, stop_at, loop_ctx)
        visited.add(node)

        block = IRBlock(self.code)
        last_op = node.ops[-1] if node.ops else None

        # --- 1. Process the Content of the Current Node ---
        # Determine which opcodes are for content vs. control flow.
        # If the last op is a branch/return, we don't lift it as a regular statement.
        is_last_op_control_flow = last_op and last_op.op in (
            conditionals + ["Switch", "Ret", "JAlways", "Throw", "Rethrow", "Trap", "EndTrap"]
        )
        ops_to_process = node.ops[:-1] if is_last_op_control_flow else node.ops

        self._lift_ops_into_block(block, ops_to_process)

        # --- 2. Handle the Control Flow based on the Last Opcode ---
        if last_op and last_op.op in conditionals:
            # HL conditional jumps: JXxx jumps to the target when condition is TRUE.
            # Compilers emit "JXxx(negated_if_condition) → else_block" so fall-through = then.
            jump_target, fall_through = None, None
            for branch_node, edge_type in node.branches:
                if edge_type == "true":
                    jump_target = branch_node    # jump target = else block in source
                elif edge_type == "false":
                    fall_through = branch_node   # fall-through = then block in source

            # Invert the jump condition to get the actual "if" condition.
            cond_expr = self._build_bool_expr_from_op(last_op)
            cond_expr.invert()

            def make_loop_branch(target: Optional[CFNode]) -> Optional[IRBlock]:
                if target is None:
                    return IRBlock(self.code)
                if loop_ctx and target == loop_ctx.header:
                    branch_block = IRBlock(self.code)
                    branch_block.statements.append(IRContinue(self.code))
                    return branch_block
                if loop_ctx and target not in loop_ctx.nodes:
                    branch_block = IRBlock(self.code)
                    branch_block.statements.append(IRBreak(self.code))
                    return branch_block
                return None

            # then = fall-through, else = jump target
            then_block_ir = make_loop_branch(fall_through)
            else_block_ir = make_loop_branch(jump_target)

            stop_nodes = {loop_ctx.header} if loop_ctx else set()
            allowed_nodes = loop_ctx.nodes if loop_ctx else None
            convergence_node = self._find_convergence_node(
                jump_target,
                fall_through,
                allowed_nodes=allowed_nodes,
                stop_nodes=stop_nodes,
            )

            if convergence_node is None and node in self.cfg.immediate_post_dominators:
                convergence_node = self.cfg.immediate_post_dominators[node]

            if then_block_ir is None:
                then_block_ir = self._lift_block(fall_through, visited.copy(), stop_at=convergence_node, loop_ctx=loop_ctx)
            if else_block_ir is None:
                else_block_ir = self._lift_block(
                    jump_target, visited.copy(), stop_at=convergence_node, loop_ctx=loop_ctx
                )

            conditional_stmt = IRConditional(self.code, cond_expr, then_block_ir, else_block_ir)
            block.statements.append(conditional_stmt)

            # Continue lifting from the convergence point
            next_block_ir = self._lift_block(convergence_node, visited, loop_ctx=loop_ctx)
            block.statements.extend(next_block_ir.statements)

        elif last_op and last_op.op == "Switch":
            convergence_node = self._find_convergence_node(
                node.branches[0][0] if node.branches else None,
                node.branches[1][0] if len(node.branches) > 1 else None,
                allowed_nodes=loop_ctx.nodes if loop_ctx else None,
                stop_nodes={loop_ctx.header} if loop_ctx else None,
            )
            val_reg = self.locals[last_op.df["reg"].value]
            cases, default_block = {}, IRBlock(self.code)

            for target_node, edge_type in node.branches:
                case_block_ir = self._lift_block(target_node, visited.copy(), stop_at=convergence_node, loop_ctx=loop_ctx)
                if edge_type.startswith("switch: case:"):
                    case_val = int(edge_type.split(":")[-1].strip())
                    cases[IRConst(self.code, IRConst.ConstType.INT, value=case_val)] = case_block_ir
                elif edge_type == "switch: default":
                    default_block = case_block_ir

            block.statements.append(IRSwitch(self.code, val_reg, cases, default_block))
            next_block_ir = self._lift_block(convergence_node, visited, loop_ctx=loop_ctx)
            block.statements.extend(next_block_ir.statements)

        elif last_op and last_op.op == "Trap":
            try_branch_node, catch_branch_node = None, None
            for branch_node, edge_type in node.branches:
                if edge_type == "fall-through":
                    try_branch_node = branch_node
                elif edge_type == "trap":
                    catch_branch_node = branch_node

            stop_nodes = {loop_ctx.header} if loop_ctx else set()
            allowed_nodes = loop_ctx.nodes if loop_ctx else None
            convergence_node = self._find_convergence_node(
                try_branch_node,
                catch_branch_node,
                allowed_nodes=allowed_nodes,
                stop_nodes=stop_nodes,
            )

            try_block_ir = self._lift_block(try_branch_node, visited.copy(), stop_at=convergence_node, loop_ctx=loop_ctx)
            catch_block_ir = self._lift_block(
                catch_branch_node, visited.copy(), stop_at=convergence_node, loop_ctx=loop_ctx
            )
            catch_local = self.locals[last_op.df["exc"].value]
            block.statements.append(IRTryCatch(self.code, try_block_ir, catch_block_ir, catch_local))

            next_block_ir = self._lift_block(convergence_node, visited, loop_ctx=loop_ctx)
            block.statements.extend(next_block_ir.statements)

        elif last_op and last_op.op == "Ret":
            ret_type = self.func.regs[last_op.df["ret"].value].resolve(self.code)
            ret_val = self.locals[last_op.df["ret"].value] if not isinstance(ret_type.definition, Void) else None
            block.statements.append(IRReturn(self.code, ret_val))

        elif last_op and last_op.op == "EndTrap":
            if node.branches:
                successor_node, _ = node.branches[0]
                next_block_ir = self._lift_block(successor_node, visited, stop_at, loop_ctx=loop_ctx)
                block.statements.extend(next_block_ir.statements)

        elif last_op and (last_op.op == "JAlways" or not is_last_op_control_flow):
            # Handles both explicit unconditional jumps and implicit fall-through
            if node.branches:
                successor_node, _ = node.branches[0]
                if loop_ctx and successor_node == loop_ctx.header:
                    return block
                if loop_ctx and successor_node not in loop_ctx.nodes:
                    block.statements.append(IRBreak(self.code))
                else:
                    next_block_ir = self._lift_block(successor_node, visited, stop_at, loop_ctx=loop_ctx)
                    block.statements.extend(next_block_ir.statements)

        return block

    def print(self) -> None:
        print(self.block.pprint())


class IRClass:
    """
    Intermediate representation of a class.
    """

    def __init__(self, code: Bytecode, obj: Obj) -> None:
        self.code = code
        self.dynamic: Optional[Obj] = None
        self.static: Optional[Obj] = None
        if obj.is_static:
            self.static = obj
            try:
                self.dynamic = obj.dynamic
            except (ValueError, AttributeError):
                self.dynamic = None
        else:
            self.dynamic = obj
            try:
                self.static = obj.static
            except (ValueError, AttributeError):
                self.static = None
        self.methods: List[IRFunction] = []
        self.static_methods: List[IRFunction] = []
        self.fields: List[Tuple[str, Type]] = []
        self.static_fields: List[Tuple[str, Type]] = []
        if self.dynamic is None and self.static is None:
            raise ValueError(
                "IRClass needs at least one valid Obj that has been preprocessed by `Bytecode.map_statics`!"
            )

        if self.dynamic:
            self.methods += self.gather_methods(self.dynamic)
            self.fields += self.gather_fields(self.dynamic)
        if self.static:
            self.static_methods += self.gather_methods(self.static)
            self.static_fields += self.gather_fields(self.static)

    def gather_methods(self, obj: Obj) -> List[IRFunction]:
        """
        Gathers all methods from an instance of Obj.
        """
        res: List[IRFunction] = []
        for proto in obj.protos:
            fn = proto.findex.resolve(self.code)
            assert isinstance(fn, Function), "Native protos aren't supported! Not even sure if this is possible tbh"
            res.append(IRFunction(self.code, fn))
        for binding in obj.bindings:
            fn = binding.findex.resolve(self.code)
            assert isinstance(fn, Function), "Native bindings aren't supported! Not even sure if this is possible tbh"
            # Avoid adding duplicates if a proto is also bound
            if fn not in [r.func for r in res]:
                res.append(IRFunction(self.code, fn))
        return res

    def gather_fields(self, obj: Obj) -> List[Tuple[str, Type]]:
        res: List[Tuple[str, Type]] = []
        binding_names: List[str] = []
        for binding in obj.bindings:
            binding_names.append(binding.field.resolve_obj(self.code, obj).name.resolve(self.code))
        for field in obj.fields:
            if not field.name.resolve(self.code) in binding_names:
                res.append((field.name.resolve(self.code), field.type.resolve(self.code)))
        return res

    def pseudo(self) -> str:
        """
        Generates Haxe pseudocode for the entire class.
        """
        from . import pseudo

        return pseudo.class_pseudo(self)

    def print(self) -> None:
        """
        Prints the Haxe pseudocode for the entire class to the console.
        """
        print(self.pseudo())


__all__ = [
    "CFDeadCodeEliminator",
    "CFGraph",
    "CFJumpThreader",
    "CFNode",
    "CFOptimizer",
    "IsolatedCFGraph",
    "IRArithmetic",
    "IRAssign",
    "IRBlock",
    "IRBoolExpr",
    "IRBreak",
    "IRCall",
    "IRConditional",
    "IRContinue",
    "IRConst",
    "IRExpression",
    "IRFunction",
    "IRLocal",
    "IRPrimitiveLoop",
    "IRPrimitiveJump",
    "IRReturn",
    "IRStatement",
    "IRSwitch",
    "IRTrace",
    "IRTryCatch",
]
