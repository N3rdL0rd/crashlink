"""
Decompilation, IR and control flow graph generation
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum as _Enum  # Enum is already defined in crashlink.core
from pprint import pformat
from typing import Any, Dict, List, Optional, Set, Tuple, Union, cast

from . import disasm
from .core import (
    Bytecode,
    DynObj,
    Enum,
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

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(s: str) -> str:
    """Remove ANSI color codes, e.g. from IRBlock.pprint(), for non-terminal output."""
    return _ANSI_ESCAPE_RE.sub("", s)


_repr_rendered_blocks: Optional[Set[int]] = None

_type_by_name_cache: Dict[int, Dict[str, Type]] = {}


def _get_type_in_code(code: Bytecode, name: str) -> Type:
    by_name = _type_by_name_cache.get(id(code))
    if by_name is None:
        by_name = {}
        for type in code.types:
            by_name.setdefault(disasm.type_name(code, type), type)
        _type_by_name_cache[id(code)] = by_name
    found = by_name.get(name)
    if found is None:
        raise DecompError(f"Type {name} not found in code")
    return found


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

        In the reversed graph G', edges are reversed: u→v in G becomes v→u in G'.
        The virtual EXIT is the start of G'. For the dominator algorithm on G':
            preds_G'(n) = successors_G(n)
        Exit nodes (no successors in G) connect only to VIRTUAL_EXIT in G'.
        """
        all_nodes = self.nodes
        exit_nodes = [n for n in all_nodes if not n.branches]

        if not exit_nodes:
            # Graph with an infinite loop and no exit
            self.post_dominators = {}
            return

        # Use a virtual exit node to unify all original exit nodes.
        VIRTUAL_EXIT = CFNode([])
        nodes_for_pd_analysis = all_nodes + [VIRTUAL_EXIT]

        # Run the iterative dominator algorithm on the reversed graph.
        pd = {node: set(nodes_for_pd_analysis) for node in nodes_for_pd_analysis}
        pd[VIRTUAL_EXIT] = {VIRTUAL_EXIT}

        changed = True
        while changed:
            changed = False
            for node in sorted(all_nodes, key=lambda n: n.base_offset):
                # In G', predecessors of `node` = successors of `node` in G.
                # Exit nodes (no successors in G) connect to VIRTUAL_EXIT in G'.
                preds_in_reversed_graph = [target for target, _ in node.branches]
                if not preds_in_reversed_graph:
                    preds_in_reversed_graph = [VIRTUAL_EXIT]

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
        global _repr_rendered_blocks
        colors = [36, 31, 32, 33, 34, 35]

        depth = id(self) % len(colors)
        color = colors[depth]

        if not self.statements:
            return f"\033[{color}m[\033[0m\033[{color}m]\033[0m"

        top = _repr_rendered_blocks is None
        if top:
            _repr_rendered_blocks = set()
        try:
            if id(self) in _repr_rendered_blocks:  # type: ignore[operator]
                return f"\033[{color}m[...]\033[0m"
            _repr_rendered_blocks.add(id(self))  # type: ignore[union-attr]
            # uniform indentation
            statements = pformat(self.statements, indent=0).replace("\n", "\n\t")
        finally:
            if top:
                _repr_rendered_blocks = None

        return f"\033[{color}m[\033[0m\n\t{statements}\n\033[{color}m]\033[0m"

    def __repr__(self) -> str:
        global _repr_rendered_blocks
        if not self.statements:
            return "[]"

        top = _repr_rendered_blocks is None
        if top:
            _repr_rendered_blocks = set()
        try:
            if id(self) in _repr_rendered_blocks:  # type: ignore[operator]
                return "[...]"
            _repr_rendered_blocks.add(id(self))  # type: ignore[union-attr]
            statements = pformat(self.statements, indent=0).replace("\n", "\n\t")
        finally:
            if top:
                _repr_rendered_blocks = None

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
    def __init__(self, name: str, type: tIndex, code: Bytecode, reg_idx: Optional[int] = None):
        super().__init__(code)
        self.name = name
        self.type = type
        self.reg_idx = reg_idx
        # Set by IRNativeArrayAllocOptimizer when this local is bound to a
        # `Native.alloc_array(ty, size)` result: the bytecode's own "Array" kind
        # carries no element-type info, but Haxe's hl.NativeArray<T> needs one,
        # so this records the `T` recovered from the allocation site for the
        # declared-type renderer to use instead of the generic Array<Dynamic>.
        self.native_elem_type: Optional[Type] = None

    def get_type(self) -> Type:
        return self.type.resolve(self.code)

    def same_register(self, other: "IRLocal") -> bool:
        """Return True if this local and `other` originate from the same VM register."""
        return self.reg_idx is not None and other.reg_idx is not None and self.reg_idx == other.reg_idx

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IRLocal):
            return False
        return (
            self.name == other.name
            and self.type.resolve(self.code) is other.type.resolve(other.code)
            and self.code is other.code
        )

    def __hash__(self) -> int:
        return hash((self.name, id(self.type.resolve(self.code)), id(self.code)))

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


class IRNeg(IRExpression):
    """Represents numeric negation, e.g. `-x` (lifted from the `Neg` opcode)."""

    def __init__(self, code: Bytecode, expr: IRExpression):
        super().__init__(code)
        self.expr = expr

    def get_type(self) -> Type:
        return self.expr.get_type()

    def get_children(self) -> List[IRStatement]:
        return [self.expr]

    def __repr__(self) -> str:
        return f"<IRNeg: -{self.expr}>"


class IRNot(IRExpression):
    """Represents boolean negation, e.g. `!x` (lifted from the `Not` opcode)."""

    def __init__(self, code: Bytecode, expr: IRExpression):
        super().__init__(code)
        self.expr = expr

    def get_type(self) -> Type:
        return self.expr.get_type()

    def get_children(self) -> List[IRStatement]:
        return [self.expr]

    def __repr__(self) -> str:
        return f"<IRNot: !{self.expr}>"


class IRTypeOf(IRExpression):
    """Represents fetching a value's runtime type, e.g. `Type.getDynamic(x)` (lifted from `GetType`)."""

    def __init__(self, code: Bytecode, expr: IRExpression, dst_type: tIndex):
        super().__init__(code)
        self.expr = expr
        self.dst_type_idx = dst_type

    def get_type(self) -> Type:
        return self.dst_type_idx.resolve(self.code)

    def get_children(self) -> List[IRStatement]:
        return [self.expr]

    def __repr__(self) -> str:
        return f"<IRTypeOf: Type.getDynamic({self.expr})>"


class IRTypeKind(IRExpression):
    """Represents reading a runtime type's kind tag, e.g. `t.kind` (lifted from `GetTID`)."""

    def __init__(self, code: Bytecode, expr: IRExpression, dst_type: tIndex):
        super().__init__(code)
        self.expr = expr
        self.dst_type_idx = dst_type

    def get_type(self) -> Type:
        return self.dst_type_idx.resolve(self.code)

    def get_children(self) -> List[IRStatement]:
        return [self.expr]

    def __repr__(self) -> str:
        return f"<IRTypeKind: {self.expr}.kind>"


class IRAssign(IRStatement):
    """Assignment of an expression result to a target (local variable, field, etc.)"""

    def __init__(self, code: Bytecode, target: IRExpression, expr: IRExpression):
        super().__init__(code)
        if not isinstance(target, (IRLocal, IRField, IRArrayAccess)):
            raise DecompError(
                f"Invalid target for IRAssign: {type(target).__name__}. Must be IRLocal, IRField, or IRArrayAccess."
            )
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
            return _get_type_in_code(self.code, "Dyn")
        if self.call_type == IRCall.CallType.THIS or self.target is None:
            return _get_type_in_code(self.code, "Obj")
        return self.target.get_type()

    def get_children(self) -> List[IRStatement]:
        children: List[IRStatement] = []
        if self.target is not None:
            children.append(self.target)
        children.extend(self.args)
        return children

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
        return _get_type_in_code(self.code, "Bool")

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

    def get_children(self) -> List[IRStatement]:
        children: List[IRStatement] = []
        if self.left is not None:
            children.append(self.left)
        if self.right is not None:
            children.append(self.right)
        return children

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
        return [self.value] if self.value is not None else []

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


class IRForEachLoop(IRStatement):
    """
    Represents a Haxe for-each loop: for (elem in array) { body }
    """

    elem: IRLocal
    array: IRExpression
    body: IRBlock

    def __init__(self, code: Bytecode, elem: IRLocal, array: IRExpression, body: IRBlock):
        super().__init__(code)
        self.elem = elem
        self.array = array
        self.body = body
        self.comment = ""

    def get_children(self) -> List[IRStatement]:
        return [self.elem, self.array, self.body]

    def __repr__(self) -> str:
        body_repr = pformat(self.body, indent=0).replace("\n", "\n\t")
        return f"<IRForEachLoop: for ({self.elem} in {self.array}) {{\n\t{body_repr}\n}}>"

    def __str__(self) -> str:
        return self.__repr__()


class IRIntRangeLoop(IRStatement):
    """
    Represents a Haxe int-range for loop: for (elem in start...end) { body }
    """

    elem: IRLocal
    start: IRExpression
    end: IRExpression
    body: IRBlock

    def __init__(self, code: Bytecode, elem: IRLocal, start: IRExpression, end: IRExpression, body: IRBlock):
        super().__init__(code)
        self.elem = elem
        self.start = start
        self.end = end
        self.body = body
        self.comment = ""

    def get_children(self) -> List[IRStatement]:
        return [self.elem, self.start, self.end, self.body]

    def __repr__(self) -> str:
        body_repr = pformat(self.body, indent=0).replace("\n", "\n\t")
        return f"<IRIntRangeLoop: for ({self.elem} in {self.start}...{self.end}) {{\n\t{body_repr}\n}}>"

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
        if self.target is not None and isinstance(self.target, IRStatement):
            return [self.target]
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


class IRNativeArrayNew(IRExpression):
    """
    Represents allocating a raw HL native array with a known element type, e.g.
    `new hl.NativeArray<Int>(3)` (lifted from `Native.alloc_array(ty, size)` by
    IRNativeArrayAllocOptimizer). `array_type` is the tIndex of the bytecode's
    own (element-type-erased) "Array" kind, used for type compatibility with the
    rest of the array-handling IR (GetArray/SetArray/ArraySize all expect it);
    `elem_type` is only used for rendering the Haxe generic parameter.
    """

    def __init__(self, code: Bytecode, array_type: tIndex, elem_type: Type, size: IRExpression):
        super().__init__(code)
        self.array_type_idx = array_type
        self.elem_type = elem_type
        self.size = size

    def get_type(self) -> Type:
        return self.array_type_idx.resolve(self.code)

    def get_children(self) -> List[IRStatement]:
        return [self.size] if isinstance(self.size, IRStatement) else []

    def __repr__(self) -> str:
        elem_name = disasm.type_name(self.code, self.elem_type)
        return f"<IRNativeArrayNew: new hl.NativeArray<{elem_name}>({self.size})>"


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


class IRArrayLiteral(IRExpression):
    """Represents a Haxe array literal, e.g. [1, 2, 3]."""

    def __init__(self, code: Bytecode, elements: List[IRExpression], elem_type: Optional[tIndex] = None):
        super().__init__(code)
        self.elements = elements
        self.elem_type_idx = elem_type

    def get_type(self) -> Type:
        if self.elem_type_idx:
            return self.elem_type_idx.resolve(self.code)
        return _get_type_in_code(self.code, "Dyn")

    def get_children(self) -> List[IRStatement]:
        return [e for e in self.elements]

    def __repr__(self) -> str:
        return f"<IRArrayLiteral: [{', '.join(repr(e) for e in self.elements)}]>"


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
        return [self.array, self.index]

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
        return [self.target]

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
        return [self.value]

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
        return [self.value]

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
            self._visited_ids: Set[int] = set()
            self.visit(self.func.block)

    def visit(self, statement: IRStatement) -> None:
        """
        Recursively visit an IR statement and its children.

        The traversal performs a pre-order visit (parent first, then children):
        1. Call before_visit_statement for the current statement
        2. Handle specific statement type with visit_X methods
        3. Visit all children recursively
        4. Call after_visit_statement for the current statement

        IRFunction._lift_block memoizes shared continuation points, so the same
        IRBlock/IRStatement object can be reachable from multiple parents (a DAG,
        not a tree). Skip a node already visited in this pass: it denotes the
        exact same content, so revisiting would just redundantly (but harmlessly,
        since mutating it once already applies everywhere it's referenced) re-walk
        an already-processed subtree, which is exponential for deeply nested,
        heavily-converging control flow.
        """
        if id(statement) in self._visited_ids:
            return
        self._visited_ids.add(id(statement))

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
                            if DEBUG:
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
            return (statement.left is not None and self._statement_reads_target(statement.left, target)) or (
                statement.right is not None and self._statement_reads_target(statement.right, target)
            )
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
                reads_later = any(
                    self._statement_reads_target(later_stmt, stmt.target) for later_stmt in later_statements
                )
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
                    if DEBUG:
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


def _ir_structurally_equal(a: Any, b: Any, memo: Optional[Set[Tuple[int, int]]] = None) -> bool:
    """Deep structural equality for IR nodes that is safe and fast on the IR DAG.

    The IR shares continuation blocks between parents (it is a DAG, not a tree),
    so rendering nodes with ``repr()`` to compare them is exponential — pprint
    re-expands every shared subtree. This walks both trees in lockstep instead,
    memoizing visited ``(id(a), id(b))`` pairs so each shared node pair is only
    compared once, which keeps the comparison linear and also tolerates cycles.
    """
    if a is b:
        return True
    if type(a) is not type(b):
        return False

    if memo is None:
        memo = set()
    key = (id(a), id(b))
    if key in memo:
        return True
    memo.add(key)

    if isinstance(a, (IRStatement, IRExpression)):
        a_fields = vars(a)
        b_fields = vars(b)
        if a_fields.keys() != b_fields.keys():
            return False
        for name, av in a_fields.items():
            # `code` is the shared Bytecode; comparing it adds nothing and would
            # recurse into the whole program.
            if name == "code":
                continue
            if not _ir_structurally_equal(av, b_fields[name], memo):
                return False
        return True

    if isinstance(a, (list, tuple)):
        if len(a) != len(b):
            return False
        return all(_ir_structurally_equal(x, y, memo) for x, y in zip(a, b))

    # ResolvableVarInt and friends carry a plain `.value`; compare it directly to
    # avoid depending on their __eq__ (which may need a Bytecode context).
    if hasattr(a, "value") and not isinstance(a, (str, int, float, bytes, bool)):
        return bool(a.value == b.value)

    return bool(a == b)


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
                    # Cheap type check first: a mismatch here means the repr()s can never
                    # be equal, so we skip fully rendering large nested subtrees (e.g. a
                    # branch ending in a deeply nested IRConditional from a cascading
                    # if/elif chain) just to find out they differ.
                    if type(true_stmts[t_idx]) is not type(false_stmts[f_idx]):
                        break
                    # Structural comparison without rendering: repr()/pformat on
                    # the IR DAG re-expands shared continuation blocks and is
                    # exponential for branchy code. _ir_structurally_equal walks
                    # the pair in lockstep with memoization instead.
                    if _ir_structurally_equal(true_stmts[t_idx], false_stmts[f_idx]):
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


class IRRedundantContinueEliminator(TraversingIROptimizer):
    """
    Removes redundant `else { continue; }` blocks that are the last statement
    of a loop body. After the if-block, control naturally falls through to the
    end of the loop body, which is equivalent to continuing the loop, so the
    explicit else-continue is just noise.
    """

    def __init__(self, function: "IRFunction") -> None:
        super().__init__(function)
        self._loop_depth = 0

    def before_visit_statement(self, statement: IRStatement) -> None:
        if isinstance(statement, (IRWhileLoop, IRPrimitiveLoop)):
            self._loop_depth += 1

    def after_visit_statement(self, statement: IRStatement) -> None:
        if isinstance(statement, (IRWhileLoop, IRPrimitiveLoop)):
            self._loop_depth -= 1

    def visit_block(self, block: IRBlock) -> None:
        if self._loop_depth == 0 or not block.statements:
            super().visit_block(block)
            return

        last = block.statements[-1]
        if isinstance(last, IRConditional) and last.false_block is not None:
            false_stmts = [s for s in last.false_block.statements if not isinstance(s, IRReturn)]
            if len(false_stmts) == 1 and isinstance(false_stmts[0], IRContinue):
                dbg_print("IRRedundantContinueEliminator: removing trailing else { continue; }")
                last.false_block = IRBlock(self.func.code)
                last.false_block.statements = []

        super().visit_block(block)


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
                        if DEBUG:
                            dbg_print(
                                f"IRVoidAssignOptimizer: Removing void assignment: {stmt} (target: {target.name})"
                            )

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
        # arg1 is the ref where byte count is stored back (IRLocal or IRRef wrapping one)
        count_ref: Optional[IRLocal] = None
        arg1 = expr.args[1]
        if isinstance(arg1, IRLocal):
            count_ref = arg1
        elif isinstance(arg1, IRRef) and isinstance(arg1.target, IRLocal):
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

        if value_local is None or count_ref_local is None:
            return None

        # Direct match: count_ref is the same local as int_arg
        if count_ref_local.name == int_arg.name:
            return value_local

        # Indirect match: count_ref = &int_arg (before IRConditionInliner runs, the Ref
        # is a separate local var6 = &var13; we need to look through it)
        if count_ref_local.name in current_assigns:
            ref_defn = current_assigns[count_ref_local.name]
            if isinstance(ref_defn.expr, IRRef) and isinstance(ref_defn.expr.target, IRLocal):
                if ref_defn.expr.target.name == int_arg.name:
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
        for stmt in block.statements:
            if isinstance(stmt, IRAssign):
                if isinstance(stmt.target, IRLocal):
                    current_assigns[stmt.target.name] = stmt
                if isinstance(stmt.expr, IRExpression):
                    stmt.expr = self._rewrite_expr(stmt.expr, current_assigns)


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
        return local.name in self._user_variable_names

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
        elif isinstance(expr, IRNew):
            new_args = []
            for arg in expr.constructor_args:
                new_arg, changed = self._substitute_in_expr(arg, target, replacement)
                new_args.append(new_arg)
                made_change = made_change or changed
            expr.constructor_args = new_args
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

    def _substitute_in_statement(
        self, stmt: IRStatement, target: IRLocal, replacement: IRExpression, _visited: Optional[Set[int]] = None
    ) -> bool:
        """
        Recursively traverses a statement to perform substitutions.
        Returns True if a substitution was made, False otherwise.
        """
        # The lifted IR is a DAG (shared continuation blocks). Mutating a shared
        # node once applies along every path that references it, so prune already
        # visited nodes to avoid exponential re-walks of converging control flow.
        if _visited is None:
            _visited = set()
        if id(stmt) in _visited:
            return False
        _visited.add(id(stmt))

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
                if self._substitute_in_statement(child, target, replacement, _visited):
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
            # Unlike a one-shot IRConditional, a while-loop's condition re-evaluates
            # on every iteration. If `target` is reassigned inside the body, the
            # condition needs that live value each time — substituting in the value
            # from before the loop would freeze it to a stale snapshot (e.g. turning
            # `idx = 0; while (idx < n)` into the loop-invariant `while (0 < n)`).
            if not self._is_local_redefined(target, stmt.body.statements):
                stmt.condition, changed = self._substitute_in_expr(stmt.condition, target, replacement)
                made_change = made_change or changed
        return made_change

    def _is_local_redefined(self, local_to_check: IRLocal, statements: List[IRStatement]) -> bool:
        """Checks if a local is the target of an assignment in a list of statements."""
        return self._is_local_redefined_walk(local_to_check, statements, set())

    def _is_local_redefined_walk(
        self, local_to_check: IRLocal, statements: List[IRStatement], visited: Set[int]
    ) -> bool:
        # The lifted IR is a DAG: shared continuation blocks are reachable from
        # many parents, so prune already-scanned nodes. Whether a local is
        # redefined inside a subtree is path-independent, so visiting it once is
        # correct and avoids exponential re-walks of converging control flow.
        for stmt in statements:
            if id(stmt) in visited:
                continue
            visited.add(id(stmt))
            if isinstance(stmt, IRAssign) and stmt.target == local_to_check:
                return True
            for child in stmt.get_children():
                child_stmts = child.statements if isinstance(child, IRBlock) else [child]
                if self._is_local_redefined_walk(local_to_check, child_stmts, visited):
                    return True
        return False

    def _collect_free_locals(self, expr: IRStatement) -> Set[str]:
        """Collect the names of all locals read within an expression.

        IR expression nodes do not implement get_children(), so traverse the
        known expression shapes explicitly (mirroring _expr_contains_local).
        """
        names: Set[str] = set()

        def walk(e: Optional[IRStatement]) -> None:
            if e is None:
                return
            if isinstance(e, IRLocal):
                names.add(e.name)
            elif isinstance(e, (IRArithmetic, IRBoolExpr)):
                walk(e.left)
                walk(e.right)
            elif isinstance(e, IRCall):
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
            elif isinstance(e, IRRef):
                walk(e.target)
            elif isinstance(e, IREnumConstruct):
                for arg in e.args:
                    walk(arg)
            elif isinstance(e, (IREnumIndex, IREnumField)):
                walk(e.value)
            elif isinstance(e, IRNew):
                for arg in e.constructor_args:
                    walk(arg)

        walk(expr)
        return names

    def _stmt_reassigns_any(self, stmt: IRStatement, names: Set[str]) -> bool:
        """Return True if `stmt` (or any nested statement) assigns to a local in `names`."""
        if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal) and stmt.target.name in names:
            return True
        for child in stmt.get_children():
            if child is not stmt and self._stmt_reassigns_any(child, names):
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
        # Avoid inlining calls in conservative mode: they can have side effects
        # and removing the assignment eliminates evidence needed by pattern
        # optimizers (e.g. alloc_bytes for array literals).
        if isinstance(expr, IRCall):
            return False
        if isinstance(expr, IRArrayLiteral):
            return True
        if isinstance(expr, (IRConst, IRLocal)):
            return True
        if isinstance(expr, IRCast):
            return self.is_safe_to_inline_conservatively(expr.expr)
        # Allow flat arithmetic (both operands are leaves) to enable compound assignment detection.
        # Nested arithmetic is excluded to prevent exponential chaining.
        if isinstance(expr, IRArithmetic):
            return isinstance(expr.left, (IRConst, IRLocal)) and isinstance(expr.right, (IRConst, IRLocal))
        # A read with simple (non-side-effecting) array/index operands is moved, not
        # duplicated, by inlining into its sole immediately-following use, so it's
        # still evaluated exactly once: safe even though it can in principle throw.
        if isinstance(expr, IRArrayAccess):
            return isinstance(expr.array, (IRConst, IRLocal)) and isinstance(expr.index, (IRConst, IRLocal))
        # Same reasoning as IRArrayAccess: an `arr.length` read on a simple target
        # is moved, not duplicated, by this inliner. This matters for recovering
        # for-loops: `len = arr.length;` immediately followed by `while (idx < len)`
        # needs to fold into `while (idx < arr.length)` for IRForEachLoopOptimizer's
        # pattern match to fire. Deliberately narrow to the Array kind (not e.g.
        # String, whose `.length` IRStringSwitchOptimizer expects to find un-inlined
        # in its own specific shape) — array length is a plain struct read with no
        # room for that kind of downstream pattern dependency.
        if (
            isinstance(expr, IRField)
            and expr.field_name == "length"
            and isinstance(expr.target, (IRConst, IRLocal))
            and expr.target.get_type().kind.value == Type.Kind.ARRAY.value
        ):
            return True
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
                    if isinstance(expr_to_inline, IRExpression) and self._expr_contains_local(
                        expr_to_inline, temp_local
                    ):
                        new_statements.append(current_stmt)
                        i += 1
                        continue
                    if i + 1 < len(statements):
                        next_stmt = statements[i + 1]
                        if self._substitute_shallow(next_stmt, temp_local, expr_to_inline):
                            dbg_print(f"Conservatively inlining assignment for temporary '{temp_local.name}'.")
                            new_statements.append(next_stmt)
                            copy_target = None
                            if (
                                isinstance(next_stmt, IRAssign)
                                and isinstance(next_stmt.target, IRLocal)
                                and self._is_user_local(next_stmt.target)
                            ):
                                copy_target = next_stmt.target
                            if self._is_local_redefined(temp_local, [next_stmt]):
                                i += 2
                                inlined = True
                            else:
                                for later_stmt in statements[i + 2 :]:
                                    if self._is_local_redefined(temp_local, [later_stmt]):
                                        break
                                    sub: IRExpression
                                    if copy_target is not None:
                                        sub = copy_target
                                    elif (
                                        isinstance(next_stmt, IRAssign)
                                        and isinstance(next_stmt.target, IRLocal)
                                        and next_stmt.target == temp_local
                                    ):
                                        sub = next_stmt.expr
                                    else:
                                        sub = expr_to_inline
                                    self._substitute_shallow(later_stmt, temp_local, sub)
                                i += 2
                                inlined = True

            if not inlined:
                new_statements.append(current_stmt)
                i += 1

        block.statements = new_statements

        for stmt in block.statements:
            for child in stmt.get_children():
                if isinstance(child, IRBlock):
                    self.visit_block(child)

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

                # The inlined expression reads other locals (its free variables).
                # If one of them is reassigned at a later statement, the value of
                # `expr_to_inline` there differs from its value at the definition
                # site, so we must not substitute past that point.
                free_vars = self._collect_free_locals(expr_to_inline)
                free_vars.discard(temp_local.name)

                any_substituted = False
                for subsequent_stmt in remaining_statements:
                    if self._substitute_in_statement(subsequent_stmt, temp_local, expr_to_inline):
                        any_substituted = True
                    # Stop once a free variable of the inlined expression is
                    # reassigned: later reads of the temp need the new value.
                    if free_vars and self._stmt_reassigns_any(subsequent_stmt, free_vars):
                        # The temp is not redefined in remaining_statements (checked
                        # above), so a later use would read a stale value. Bail on
                        # removing the definition; leave the assignment in place.
                        any_substituted = False
                        break

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


class IRCopyPropOptimizer(TraversingIROptimizer):
    """
    Propagates copies of user-named locals introduced by switch/conditional branches.

    If every branch of an IRConditional or IRSwitch ends with the same
    `user_local = temp` assignment, then after the construct `temp` is equivalent
    to `user_local`. We can replace subsequent reads of `temp` with `user_local`
    until `temp` is redefined.
    """

    def visit_block(self, block: IRBlock) -> None:
        new_statements: List[IRStatement] = []
        for stmt in block.statements:
            replacement = self._propagate(stmt, block)
            if replacement is not None:
                new_statements.append(replacement)
            else:
                new_statements.append(stmt)
        block.statements = new_statements

    def _propagate(self, stmt: IRStatement, block: IRBlock) -> Optional[IRStatement]:
        # Branch-level copy propagation for switch/conditional merge temps.
        if isinstance(stmt, (IRConditional, IRSwitch)):
            copy = self._common_copy(stmt)
            if copy is not None:
                temp_local, user_local = copy
                if block is not None:
                    idx = block.statements.index(stmt)
                    for later in block.statements[idx + 1 :]:
                        if (
                            isinstance(later, IRAssign)
                            and isinstance(later.target, IRLocal)
                            and later.target == temp_local
                        ):
                            break
                        self._replace_local_shallow(later, temp_local, user_local)
                return None

            # A branch's `temp = expr; user = temp` can get folded to `user = expr`
            # at lift time, leaving a dangling read of `temp` elsewhere (e.g. a
            # later switch's subject). Every branch set `user` to that value, so
            # an unreassigned read of another local right after must be it too.
            user_local = self._common_user_assign_target(stmt)
            if user_local is not None and block is not None:
                idx = block.statements.index(stmt)
                reassigned: Set[IRLocal] = set()
                for later in block.statements[idx + 1 :]:
                    for phantom in self._phantom_reads(later):
                        if phantom == user_local or phantom in reassigned:
                            continue
                        # Match by name pattern (not _is_user_local): the same
                        # register can be debug-named later in the function while
                        # still anonymous here.
                        if not self._is_synthetic_temp(phantom):
                            continue
                        self._replace_local_shallow(later, phantom, user_local)
                    if isinstance(later, IRAssign) and isinstance(later.target, IRLocal):
                        if later.target == user_local:
                            break
                        reassigned.add(later.target)
            return None

        # Simple sequential copy propagation: after `user = temp`, replace reads
        # of `temp` with `user` until `temp` (or `user`) is redefined.
        #
        # `temp` qualifies if it is a non-user local, or a syntactic `varN`
        # compiler temp. The latter matters when a register is later reused for
        # a user variable (so the reg-based _is_user_local check returns True)
        # but the assignment is still really `user = <synthetic temp>`.
        if (
            isinstance(stmt, IRAssign)
            and isinstance(stmt.target, IRLocal)
            and isinstance(stmt.expr, IRLocal)
            and self._is_user_local(stmt.target)
            and (not self._is_user_local(stmt.expr) or self._is_synthetic_temp(stmt.expr))
        ):
            user_local = stmt.target
            temp_local = stmt.expr
            if block is not None:
                idx = block.statements.index(stmt)
                for later in block.statements[idx + 1 :]:
                    # Stop once either name is reassigned: after that point the
                    # two are no longer guaranteed equal.
                    if (
                        isinstance(later, IRAssign)
                        and isinstance(later.target, IRLocal)
                        and (later.target == temp_local or later.target == user_local)
                    ):
                        break
                    self._replace_local_shallow(later, temp_local, user_local)
        return None

    @staticmethod
    def _is_synthetic_temp(local: IRLocal) -> bool:
        """Return True for compiler-generated `varN` temporaries (no debug name)."""
        return bool(re.fullmatch(r"var\d+", local.name))

    def _common_copy(self, stmt: IRStatement) -> Optional[Tuple[IRLocal, IRLocal]]:
        """Return (temp_local, user_local) if all branches end with user_local = temp_local."""
        branches: List[IRBlock] = []
        if isinstance(stmt, IRConditional):
            branches.append(stmt.true_block)
            if stmt.false_block:
                branches.append(stmt.false_block)
        elif isinstance(stmt, IRSwitch):
            branches.extend(stmt.cases.values())
            if stmt.default:
                branches.append(stmt.default)
        else:
            return None

        copy: Optional[Tuple[IRLocal, IRLocal]] = None
        for branch in branches:
            last = self._last_significant_statement(branch)
            if not isinstance(last, IRAssign):
                return None
            if not isinstance(last.target, IRLocal) or not isinstance(last.expr, IRLocal):
                return None
            user, temp = last.target, last.expr
            # The assignment direction must be user_local = temp (temp is the switch value).
            if self._is_user_local(user) and not self._is_user_local(temp):
                current = (temp, user)
            elif self._is_user_local(temp) and not self._is_user_local(user):
                current = (user, temp)
            else:
                return None
            if copy is None:
                copy = current
            elif copy != current:
                return None
        return copy

    def _common_user_assign_target(self, stmt: IRStatement) -> Optional[IRLocal]:
        """Return the user-named local every branch's last statement assigns to, if it's the same one."""
        branches: List[IRBlock] = []
        if isinstance(stmt, IRConditional):
            branches.append(stmt.true_block)
            if stmt.false_block:
                branches.append(stmt.false_block)
        elif isinstance(stmt, IRSwitch):
            branches.extend(stmt.cases.values())
            if stmt.default:
                branches.append(stmt.default)
        else:
            return None

        user_local: Optional[IRLocal] = None
        for branch in branches:
            last = self._last_significant_statement(branch)
            if not isinstance(last, IRAssign) or not isinstance(last.target, IRLocal):
                return None
            if not self._is_user_local(last.target):
                return None
            if user_local is None:
                user_local = last.target
            elif user_local != last.target:
                return None
        return user_local

    def _phantom_reads(self, stmt: IRStatement) -> List[IRLocal]:
        """Top-level local(s) read directly as a switch's value or a conditional's condition."""
        if isinstance(stmt, IRSwitch) and isinstance(stmt.value, IRLocal):
            return [stmt.value]
        if isinstance(stmt, IRConditional) and isinstance(stmt.condition, IRBoolExpr):
            found = []
            if isinstance(stmt.condition.left, IRLocal):
                found.append(stmt.condition.left)
            if isinstance(stmt.condition.right, IRLocal):
                found.append(stmt.condition.right)
            return found
        return []

    def _last_significant_statement(self, block: IRBlock) -> Optional[IRStatement]:
        """Return the last non-IRReturn statement in a block, or None."""
        for s in reversed(block.statements):
            if not isinstance(s, IRReturn):
                return s
        return None

    def _replace_local_shallow(self, stmt: IRStatement, target: IRLocal, replacement: IRLocal) -> bool:
        """Replace reads of target with replacement only at the top level of stmt."""
        made_change = False
        if isinstance(stmt, IRAssign):
            if isinstance(stmt.target, IRExpression) and stmt.target != target:
                _, changed = self._replace_local_in_expr(stmt.target, target, replacement)
                made_change = made_change or changed
            if isinstance(stmt.expr, IRExpression):
                stmt.expr, changed = self._replace_local_in_expr(stmt.expr, target, replacement)
                made_change = made_change or changed
        elif isinstance(stmt, IRExpression):
            _, changed = self._replace_local_in_expr(stmt, target, replacement)
            made_change = made_change or changed
        elif isinstance(stmt, IRReturn):
            if stmt.value:
                stmt.value, changed = self._replace_local_in_expr(stmt.value, target, replacement)
                made_change = made_change or changed
        elif isinstance(stmt, IRConditional):
            stmt.condition, changed = self._replace_local_in_expr(stmt.condition, target, replacement)
            made_change = made_change or changed
        elif isinstance(stmt, IRWhileLoop):
            stmt.condition, changed = self._replace_local_in_expr(stmt.condition, target, replacement)
            made_change = made_change or changed
        elif isinstance(stmt, IRSwitch):
            stmt.value, changed = self._replace_local_in_expr(stmt.value, target, replacement)
            made_change = made_change or changed
        return made_change

    def _replace_local_in_statement(self, stmt: IRStatement, target: IRLocal, replacement: IRLocal) -> bool:
        made_change = False
        if isinstance(stmt, IRAssign):
            if isinstance(stmt.target, IRExpression) and stmt.target != target:
                _, changed = self._replace_local_in_expr(stmt.target, target, replacement)
                made_change = made_change or changed
            if isinstance(stmt.expr, IRExpression):
                stmt.expr, changed = self._replace_local_in_expr(stmt.expr, target, replacement)
                made_change = made_change or changed
        elif isinstance(stmt, IRExpression):
            _, changed = self._replace_local_in_expr(stmt, target, replacement)
            made_change = made_change or changed
        elif isinstance(stmt, IRReturn):
            if stmt.value:
                stmt.value, changed = self._replace_local_in_expr(stmt.value, target, replacement)
                made_change = made_change or changed
        elif isinstance(stmt, IRConditional):
            stmt.condition, changed = self._replace_local_in_expr(stmt.condition, target, replacement)
            made_change = made_change or changed
        elif isinstance(stmt, IRWhileLoop):
            stmt.condition, changed = self._replace_local_in_expr(stmt.condition, target, replacement)
            made_change = made_change or changed

        for child in stmt.get_children():
            if child is not stmt and isinstance(child, IRStatement):
                if self._replace_local_in_statement(child, target, replacement):
                    made_change = True
        return made_change

    def _replace_local_in_expr(
        self, expr: IRExpression, target: IRLocal, replacement: IRLocal
    ) -> Tuple[IRExpression, bool]:
        if expr == target:
            return replacement, True
        made_change = False
        if isinstance(expr, (IRArithmetic, IRBoolExpr)):
            if expr.left is not None:
                expr.left, changed = self._replace_local_in_expr(expr.left, target, replacement)
                made_change = made_change or changed
            if expr.right is not None:
                expr.right, changed = self._replace_local_in_expr(expr.right, target, replacement)
                made_change = made_change or changed
        elif isinstance(expr, IRCall):
            for i, arg in enumerate(expr.args):
                expr.args[i], changed = self._replace_local_in_expr(arg, target, replacement)
                made_change = made_change or changed
        elif isinstance(expr, IRField):
            expr.target, changed = self._replace_local_in_expr(expr.target, target, replacement)
            made_change = made_change or changed
        elif isinstance(expr, IRCast):
            expr.expr, changed = self._replace_local_in_expr(expr.expr, target, replacement)
            made_change = made_change or changed
        elif isinstance(expr, (IREnumIndex, IREnumField)):
            expr.value, changed = self._replace_local_in_expr(expr.value, target, replacement)
            made_change = made_change or changed
        elif isinstance(expr, IRArrayAccess):
            expr.array, changed = self._replace_local_in_expr(expr.array, target, replacement)
            made_change = made_change or changed
            expr.index, changed = self._replace_local_in_expr(expr.index, target, replacement)
            made_change = made_change or changed
        elif isinstance(expr, IREnumConstruct):
            for i, arg in enumerate(expr.args):
                expr.args[i], changed = self._replace_local_in_expr(arg, target, replacement)
                made_change = made_change or changed
        return expr, made_change

    def _is_user_local(self, local: IRLocal) -> bool:
        if not self.func.func.has_debug or not self.func.func.assigns:
            return False
        user_names = {name_ref.resolve(self.func.code) for name_ref, _ in self.func.func.assigns}
        if local.name in user_names:
            return True
        if local.name.startswith("var"):
            try:
                idx = int(local.name[3:])
            except ValueError:
                return False
            for _, op_idx in self.func.func.assigns:
                val = op_idx.value - 1
                if 0 <= val < len(self.func.ops):
                    op = self.func.ops[val]
                    if "dst" in op.df and op.df["dst"].value == idx:
                        return True
        return False


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

    def _is_user_local(self, local: IRLocal, user_names: Set[str], user_regs: Set[int]) -> bool:
        if local.name in user_names:
            return True
        # Preserve names like `b1` that were generated to disambiguate two
        # user-named locals with different types.
        for name in user_names:
            if local.name.startswith(name) and local.name[len(name) :].isdigit():
                return True
        if local.name.startswith("var"):
            try:
                idx = int(local.name[3:])
                if idx in user_regs:
                    return True
            except ValueError:
                pass
        return False

    def _is_dead_removable(self, local: IRLocal, user_names: Set[str], user_regs: Set[int]) -> bool:
        """Return True if an unread assignment to `local` is safe to delete.

        Non-user locals are always removable. A purely synthetic `varN` temp is
        also removable even when its register index is reused by a user variable:
        the caller has already confirmed the name is never read anywhere, so the
        register-reuse protection (meant to keep live SSA-split user values) does
        not apply. User-named locals (real names, or `nameN` disambiguations) are
        never removed here.
        """
        if not self._is_user_local(local, user_names, user_regs):
            return True
        if local.name in user_names:
            return False
        for name in user_names:
            if local.name.startswith(name) and local.name[len(name) :].isdigit():
                return False
        # Only reached for `varN` names kept alive solely by register reuse.
        return bool(re.fullmatch(r"var\d+", local.name))

    def _collect_all_used_names(self, block: IRBlock, _visited: Optional[Set[int]] = None) -> Set[str]:
        # DAG-aware: shared continuation blocks are reachable from many parents,
        # so prune already-visited blocks to avoid exponential re-walks.
        if _visited is None:
            _visited = set()
        used: Set[str] = set()
        if id(block) in _visited:
            return used
        _visited.add(id(block))
        for stmt in block.statements:
            self._collect_used_in_stmt(stmt, used)
            for child in stmt.get_children():
                if isinstance(child, IRBlock):
                    used.update(self._collect_all_used_names(child, _visited))
        return used

    def _collect_used_in_stmt(self, stmt: IRStatement, used: Set[str]) -> None:
        if isinstance(stmt, IRAssign):
            self._collect_used_in_expr(stmt.expr, used)
            # For array-element assignments, the array/index expressions are still reads.
            if isinstance(stmt.target, IRArrayAccess):
                self._collect_used_in_expr(stmt.target.array, used)
                self._collect_used_in_expr(stmt.target.index, used)
        elif isinstance(stmt, IRReturn) and stmt.value:
            self._collect_used_in_expr(stmt.value, used)
        elif isinstance(stmt, IRCall):
            self._collect_used_in_expr(stmt.target, used)
            for arg in stmt.args:
                self._collect_used_in_expr(arg, used)
        elif isinstance(stmt, IRTrace):
            self._collect_used_in_expr(stmt.msg, used)
        elif isinstance(stmt, IRConditional):
            self._collect_used_in_expr(stmt.condition, used)
        elif isinstance(stmt, IRWhileLoop):
            self._collect_used_in_expr(stmt.condition, used)
        elif isinstance(stmt, IRPrimitiveLoop):
            used.update(self._collect_all_used_names(stmt.condition))
        elif isinstance(stmt, IRSwitch):
            self._collect_used_in_expr(stmt.value, used)

    def _collect_used_in_expr(self, expr: Optional[IRExpression], used: Set[str]) -> None:
        if expr is None:
            return
        if isinstance(expr, IRLocal):
            used.add(expr.name)
        elif isinstance(expr, IRArithmetic):
            self._collect_used_in_expr(expr.left, used)
            self._collect_used_in_expr(expr.right, used)
        elif isinstance(expr, IRArrayAccess):
            self._collect_used_in_expr(expr.array, used)
            self._collect_used_in_expr(expr.index, used)
        elif isinstance(expr, IRArrayLiteral):
            for element in expr.elements:
                self._collect_used_in_expr(element, used)
        elif isinstance(expr, IRBoolExpr):
            self._collect_used_in_expr(expr.left, used)
            self._collect_used_in_expr(expr.right, used)
        elif isinstance(expr, IRCast):
            self._collect_used_in_expr(expr.expr, used)
        elif isinstance(expr, IRCall):
            self._collect_used_in_expr(expr.target, used)
            for arg in expr.args:
                self._collect_used_in_expr(arg, used)
        elif isinstance(expr, IREnumConstruct):
            for arg in expr.args:
                self._collect_used_in_expr(arg, used)
        elif isinstance(expr, IREnumField):
            self._collect_used_in_expr(expr.value, used)
        elif isinstance(expr, IREnumIndex):
            self._collect_used_in_expr(expr.value, used)
        elif isinstance(expr, IRField):
            self._collect_used_in_expr(expr.target, used)
        elif isinstance(expr, IRNew):
            for arg in expr.constructor_args:
                self._collect_used_in_expr(arg, used)
        elif isinstance(expr, IRRef):
            self._collect_used_in_expr(expr.target, used)

    def _remove_dead(
        self,
        block: IRBlock,
        user_names: Set[str],
        user_regs: Set[int],
        globally_used: Set[str],
        _visited: Optional[Set[int]] = None,
    ) -> None:
        # DAG-aware: prune already-processed shared blocks. Removing a dead temp
        # in a shared block once applies to every path that references it.
        if _visited is None:
            _visited = set()
        if id(block) in _visited:
            return
        _visited.add(id(block))
        new_stmts: List[IRStatement] = []
        for stmt in block.statements:
            if (
                isinstance(stmt, IRAssign)
                and isinstance(stmt.target, IRLocal)
                and stmt.target.name not in globally_used
                and self._is_dead_removable(stmt.target, user_names, user_regs)
            ):
                dbg_print(f"Removing dead temp assignment '{stmt.target.name}'.")
                # Preserve user-visible function calls as bare statements (side effects).
                # Native calls (itos, ftos, alloc_array, etc.) can be dropped entirely
                # when their result is dead — they have no user-visible side effects beyond
                # writing through a ref argument that is itself dead.
                if (
                    isinstance(stmt.expr, IRCall)
                    and isinstance(stmt.expr.target, IRConst)
                    and isinstance(stmt.expr.target.value, Function)
                ):
                    new_stmts.append(stmt.expr)
                continue
            new_stmts.append(stmt)
        block.statements = new_stmts
        for stmt in block.statements:
            for child in stmt.get_children():
                if isinstance(child, IRBlock):
                    self._remove_dead(child, user_names, user_regs, globally_used, _visited)


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
                ):
                    folded = False
                    for j in range(i + 1, len(block.statements)):
                        next_stmt = block.statements[j]
                        ctor_args = self._match_constructor_call(next_stmt, stmt.target)
                        if ctor_args is not None:
                            # Keep any statements between the allocation and the
                            # constructor call (e.g. initializers for constructor
                            # arguments), and place the folded `new` after them.
                            stmt.expr.constructor_args = ctor_args
                            new_statements.extend(block.statements[i + 1 : j])
                            new_statements.append(stmt)
                            i = j + 1
                            made_change = True
                            folded = True
                            break
                        # We can only fold across statements that don't touch the
                        # freshly allocated instance.
                        if self._statement_uses_local(next_stmt, stmt.target):
                            break
                    if folded:
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

    def _statement_uses_local(self, stmt: IRStatement, local: IRLocal) -> bool:
        """Return True if stmt reads or writes the given local."""
        if isinstance(stmt, IRAssign):
            if stmt.target == local:
                return True
            return self._expr_uses_local(stmt.expr, local)
        if isinstance(stmt, IRExpression):
            return self._expr_uses_local(stmt, local)
        if isinstance(stmt, IRReturn):
            return stmt.value is not None and self._expr_uses_local(stmt.value, local)
        return False

    def _expr_uses_local(self, expr: IRStatement, local: IRLocal) -> bool:
        if expr == local:
            return True
        return any(self._expr_uses_local(child, local) for child in expr.get_children())


class IRNativeArrayAllocOptimizer(TraversingIROptimizer):
    """
    Folds `Native.alloc_array(ty, size)` into `new hl.NativeArray<T>(size)`.

    HL's raw "Array" kind is element-type-erased at the bytecode level — the
    only place the element type shows up is as the first argument to the
    `alloc_array` native at the allocation site (a `Type` opcode result, lifted
    to an IRConst(GLOBAL_OBJ) carrying the actual `Type`). Recovering it here
    lets the declared local be typed `hl.NativeArray<T>` instead of the much
    too generic (and, on recompile, semantically different — a boxed Haxe
    `Array<Dynamic>`) `Array<Dynamic>`.
    """

    def _is_alloc_array_call(self, expr: IRExpression) -> bool:
        if not isinstance(expr, IRCall) or len(expr.args) != 2:
            return False
        if not isinstance(expr.target, IRConst) or not isinstance(expr.target.value, Native):
            return False
        return expr.target.value.name.resolve(self.func.code) == "alloc_array"

    def visit_block(self, block: IRBlock) -> None:
        for stmt in block.statements:
            if not (isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal)):
                continue
            if not self._is_alloc_array_call(stmt.expr):
                continue
            assert isinstance(stmt.expr, IRCall)
            ty_arg, size_arg = stmt.expr.args
            if not (isinstance(ty_arg, IRConst) and ty_arg.const_type == IRConst.ConstType.GLOBAL_OBJ):
                continue
            elem_type = ty_arg.value
            if not isinstance(elem_type, Type):
                continue
            stmt.target.native_elem_type = elem_type
            stmt.expr = IRNativeArrayNew(self.func.code, stmt.target.type, elem_type, size_arg)
        for stmt in block.statements:
            for child in stmt.get_children():
                if isinstance(child, IRBlock):
                    self.visit_block(child)


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
                if DEBUG:
                    dbg_print(f"[TraceOpt] Analyzing statement {i}: {stmt}")

                if isinstance(stmt, IRConditional) and stmt.true_block is not None and stmt.false_block is not None:
                    branched = self._try_branched_trace(stmt, block.statements, i)
                    if branched is not None:
                        true_tail, false_tail, msg_true, msg_false, pos_true, pos_false, consumed_after = branched
                        stmt.true_block.statements = true_tail + [
                            IRTrace(self.func.code, msg_true, pos_true)
                        ]
                        stmt.false_block.statements = false_tail + [
                            IRTrace(self.func.code, msg_false, pos_false)
                        ]
                        new_statements.append(stmt)
                        i += 1 + consumed_after
                        made_change = True
                        continue

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
                        if (
                            isinstance(msg_expr, IRLocal)
                            and msg_expr.reg_idx is not None
                            and msg_expr.reg_idx not in self.func._user_reg_indices
                            and new_statements
                            and isinstance(new_statements[-1], IRAssign)
                            and new_statements[-1].target == msg_expr
                        ):
                            # inline if this is obviously compiler-generated (one use, right before the call, has no user assign)
                            msg_expr = new_statements.pop().expr
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
                        new_statements.append(trace_stmt)

                        i = j + 1
                        made_change = True
                        continue
                    else:
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
    ) -> Optional[Tuple[List[IRStatement], List[IRStatement], IRExpression, IRExpression, Dict[str, Any], Dict[str, Any], int]]:
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
        return False


def _int_const_value(c: IRConst) -> Optional[int]:
    """Return the integer value of an IRConst INT, handling intRef objects."""
    if c.const_type != IRConst.ConstType.INT:
        return None
    val = c.value.value if hasattr(c.value, "value") else c.value
    return int(val)


def _signed_i32(val: int) -> int:
    """Convert an unsigned 32-bit constant back to signed when needed."""
    if val >= 0x80000000:
        return val - 0x100000000
    return val


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
        while isinstance(current, IRConditional):
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
        return IRSwitch(self.func.code, local, cases, default)


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
        cases, default, tail = parsed
        if not default.statements:
            default = stmt.false_block
        return IRSwitch(self.func.code, s_local, cases, default), tail

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
    ) -> Optional[Tuple[Dict[IRConst, IRBlock], IRBlock, List[IRStatement]]]:
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
                return cases, default, tail
        default = rest
        return cases, default, tail


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

    def _find_next_header(self, stmts: List[IRStatement], start: int, elem: IRLocal, value: int) -> Optional[int]:
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
        if not self.func.func.has_debug or not self.func.func.assigns:
            return False
        user_regs: Set[int] = set()
        for _, op_idx in self.func.func.assigns:
            val = op_idx.value - 1
            if 0 <= val < len(self.func.ops):
                op = self.func.ops[val]
                if "dst" in op.df:
                    user_regs.add(op.df["dst"].value)
        if local.name.startswith("var"):
            try:
                return int(local.name[3:]) in user_regs
            except ValueError:
                pass
        return True

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
            if isinstance(cond.left, IRLocal) and isinstance(cond.right, IRField) and cond.right.field_name == "length":
                idx = cond.left
                arr = cond.right.target
        elif cond.op == IRBoolExpr.CompareType.GT:
            if isinstance(cond.right, IRLocal) and isinstance(cond.left, IRField) and cond.left.field_name == "length":
                idx = cond.right
                arr = cond.left.target
        if idx is None or arr is None:
            return None
        if self._is_user_local(idx):
            return None
        body = loop.body
        if len(body.statements) < 2:
            return None
        first = body.statements[0]
        if not isinstance(first, IRAssign) or not isinstance(first.target, IRLocal):
            return None
        if not isinstance(first.expr, IRArrayAccess):
            return None
        if first.expr.array != arr or first.expr.index != idx:
            return None
        elem = first.target
        if not self._is_index_increment(body.statements[1], idx):
            return None
        rest = body.statements[2:]
        for s in rest:
            if self._stmt_reads_local(s, idx):
                return None
            if self._stmt_assigns_local(s, elem):
                return None
        for s in body.statements:
            if self._stmt_assigns_local(s, arr):
                return None
        new_body = IRBlock(loop.code)
        new_body.statements = list(rest)
        return IRForEachLoop(loop.code, elem, arr, new_body), idx

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
        if not self.func.func.has_debug or not self.func.func.assigns:
            return False
        user_regs: Set[int] = set()
        for _, op_idx in self.func.func.assigns:
            val = op_idx.value - 1
            if 0 <= val < len(self.func.ops):
                op = self.func.ops[val]
                if "dst" in op.df:
                    user_regs.add(op.df["dst"].value)
        if local.name.startswith("var"):
            try:
                return int(local.name[3:]) in user_regs
            except ValueError:
                pass
        return True

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
        return IRIntRangeLoop(loop.code, elem, idx, end_expr, new_body), idx

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


class IREnumSwitchOptimizer(TraversingIROptimizer):
    """
    Transform switches on enum indices into switches on the enum value itself,
    using enum constructor names for the cases.
    """

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
        return new_switch, 2


class IRArrayPatternOptimizer(TraversingIROptimizer):
    """
    Recognise low-level HashLink array implementation patterns and rewrite them
    into high-level Haxe array operations.

    Currently handles:
      - Fixed-size integer array literals built with alloc_bytes + stores + allocI32.
      - Conditional arr.bytes[idx << 2] loads with length guard -> arr[idx].
      - ArrayObj allocation with <none>(alloc_array(...)) -> [].
      - temp = arr.bytes; ...; x = temp[idx << 2] -> x = arr[idx].
    """

    def visit_block(self, block: IRBlock) -> None:
        made_change = True
        while made_change:
            made_change = False
            new_statements: List[IRStatement] = []
            i = 0
            while i < len(block.statements):
                stmt = block.statements[i]
                access_match = self._try_array_access(block.statements, i)
                if access_match:
                    arr_assign, consumed, preceding_to_pop = access_match
                    for _ in range(preceding_to_pop):
                        new_statements.pop()
                    new_statements.append(arr_assign)
                    i += consumed
                    made_change = True
                    continue

                literal_match = self._try_array_literal(block.statements, i)
                if literal_match:
                    arr_assign, consumed = literal_match
                    new_statements.append(arr_assign)
                    i += consumed
                    made_change = True
                    continue

                obj_literal_match = self._try_array_obj_literal(block.statements, i)
                if obj_literal_match:
                    use_stmt, consumed = obj_literal_match
                    new_statements.append(use_stmt)
                    i += consumed
                    made_change = True
                    continue

                empty_dyn_match = self._try_empty_array_dyn(block.statements, i)
                if empty_dyn_match:
                    use_stmt, consumed = empty_dyn_match
                    new_statements.append(use_stmt)
                    i += consumed
                    made_change = True
                    continue

                dyn_literal_match = self._try_array_dyn_literal(block.statements, i)
                if dyn_literal_match:
                    use_stmt, consumed = dyn_literal_match
                    new_statements.append(use_stmt)
                    i += consumed
                    made_change = True
                    continue

                guard_match = self._try_write_bounds_guard(block.statements, i)
                if guard_match:
                    i += guard_match
                    made_change = True
                    continue

                temp_match = self._try_eliminate_bytes_temp(block.statements, i)
                if temp_match:
                    new_statements, consumed = temp_match
                    i += consumed
                    made_change = True
                    continue

                new_statements.append(stmt)
                i += 1
            block.statements = new_statements

    def _try_eliminate_bytes_temp(
        self, stmts: List[IRStatement], start: int
    ) -> Optional[Tuple[List[IRStatement], int]]:
        # Pattern: temp = expr.bytes
        # followed by zero or more statements, then a use of temp[idx << 2] that
        # can be rewritten to expr[idx].
        if start >= len(stmts):
            return None
        stmt = stmts[start]
        if not isinstance(stmt, IRAssign) or not isinstance(stmt.target, IRLocal):
            return None
        if not isinstance(stmt.expr, IRField) or stmt.expr.field_name != "bytes":
            return None
        temp = stmt.target
        arr_expr = stmt.expr.target

        # Scan forward for the first use of temp in an array access.
        for j in range(start + 1, len(stmts)):
            use = stmts[j]
            accesses = self._find_temp_accesses(use, temp, arr_expr)
            if accesses:
                new_use = self._replace_temp_accesses(use, accesses)
                return stmts[:start] + [new_use] + stmts[start + 1 : j] + stmts[j + 1 :], 1
        return None

    def _find_temp_accesses(
        self, stmt: IRStatement, temp: IRLocal, arr_expr: IRExpression
    ) -> List[Tuple[IRArrayAccess, IRExpression]]:
        """Find array accesses in stmt that read temp[idx << n].

        The shift amount is ignored; any left-shift on a raw `.bytes` temporary
        is treated as an element index, so Float (shift 3), Single/Int (shift 2)
        and UI16 (shift 1) arrays all recover correctly.
        """
        result: List[Tuple[IRArrayAccess, IRExpression]] = []
        seen: Set[int] = set()

        def visit(node: IRStatement) -> None:
            if id(node) in seen:
                return
            seen.add(id(node))
            if isinstance(node, IRArrayAccess):
                if (
                    isinstance(node.array, IRLocal)
                    and node.array.name == temp.name
                    and isinstance(node.index, IRArithmetic)
                    and node.index.op.value == "<<"
                    and isinstance(node.index.right, IRConst)
                ):
                    result.append((node, IRArrayAccess(node.code, arr_expr, node.index.left)))
            for child in node.get_children():
                visit(child)

        visit(stmt)
        return result

    def _replace_temp_accesses(
        self,
        stmt: IRStatement,
        replacements: List[Tuple[IRArrayAccess, IRExpression]],
        _seen: Optional[Set[int]] = None,
    ) -> IRStatement:
        if not replacements:
            return stmt
        if _seen is None:
            _seen = set()
        if id(stmt) in _seen:
            return stmt
        _seen.add(id(stmt))
        old, new = replacements[0]
        if stmt is old:
            return new
        for child in stmt.get_children():
            if child is old:
                # Replace child reference directly if possible.
                self._replace_child(stmt, child, new)
                return stmt
            else:
                replaced = self._replace_temp_accesses(child, replacements, _seen)
                if replaced is not child:
                    self._replace_child(stmt, child, replaced)
                    return stmt
        return stmt

    def _replace_child(self, parent: IRStatement, old: IRStatement, new: Any) -> None:
        if isinstance(parent, IRAssign):
            if parent.target is old:
                parent.target = new
            elif parent.expr is old:
                parent.expr = new
        elif isinstance(parent, IRReturn):
            parent.value = new
        elif isinstance(parent, IRArithmetic):
            if parent.left is old:
                parent.left = new
            elif parent.right is old:
                parent.right = new
        elif isinstance(parent, IRBoolExpr):
            if parent.left is old:
                parent.left = new
            elif parent.right is old:
                parent.right = new
        elif isinstance(parent, IRCall):
            if parent.target is old:
                parent.target = new
            parent.args = [new if a is old else a for a in parent.args]
        elif isinstance(parent, IRArrayAccess):
            if parent.array is old:
                parent.array = new
            elif parent.index is old:
                parent.index = new
        elif isinstance(parent, IRField):
            if parent.target is old:
                parent.target = new
        elif isinstance(parent, IRCast):
            if parent.expr is old:
                parent.expr = new
        elif isinstance(parent, IRNew):
            parent.constructor_args = [new if a is old else a for a in parent.constructor_args]
        elif isinstance(parent, IREnumConstruct):
            parent.args = [new if a is old else a for a in parent.args]
        elif isinstance(parent, IREnumField):
            if parent.value is old:
                parent.value = new
        elif isinstance(parent, IRArrayLiteral):
            parent.elements = [new if e is old else e for e in parent.elements]
        elif isinstance(parent, IRConditional):
            if parent.condition is old:
                parent.condition = new
        elif isinstance(parent, IRPrimitiveLoop):
            if parent.condition is old:
                parent.condition = new
            elif parent.body is old:
                parent.body = new
        elif isinstance(parent, IRWhileLoop):
            if parent.condition is old:
                parent.condition = new
            elif parent.body is old:
                parent.body = new
        elif isinstance(parent, IRSwitch):
            if parent.value is old:
                parent.value = new
        elif isinstance(parent, IRTryCatch):
            if parent.try_block is old:
                parent.try_block = new
            elif parent.catch_block is old:
                parent.catch_block = new
        elif isinstance(parent, IRTrace):
            if parent.msg is old:
                parent.msg = new

    def _is_alloc_bytes(self, expr: IRStatement) -> bool:
        if not isinstance(expr, IRCall):
            return False
        if not isinstance(expr.target, IRConst) or not isinstance(expr.target.value, Native):
            return False
        return expr.target.value.name.resolve(self.func.code) == "alloc_bytes"

    def _is_alloc_typed_array(self, expr: IRStatement) -> Optional[str]:
        """Return the alloc helper name (allocI32/allocF32/allocF64/allocUI16) if
        expr is a call to one of HashLink's typed ArrayBase alloc functions."""
        if not isinstance(expr, IRCall):
            return None
        if not isinstance(expr.target, IRConst) or not isinstance(expr.target.value, Function):
            return None
        name = self.func.code.partial_func_name(expr.target.value)
        if name in ("allocI32", "allocF32", "allocF64", "allocUI16"):
            return name
        return None

    _ALLOC_SHIFTS: Dict[str, int] = {
        "allocI32": 2,
        "allocF32": 2,
        "allocF64": 3,
        "allocUI16": 1,
    }

    def _is_shifted_index(self, idx: IRStatement, local: IRLocal, shift: int) -> bool:
        if not isinstance(idx, IRArithmetic):
            return False
        if idx.op.value != "<<":
            return False
        if not isinstance(idx.left, IRLocal) or idx.left.name != local.name:
            return False
        if not isinstance(idx.right, IRConst) or idx.right.const_type != IRConst.ConstType.INT:
            return False
        val = idx.right.value.value if hasattr(idx.right.value, "value") else idx.right.value
        return int(val) == shift

    def _is_alloc_array(self, expr: IRStatement) -> bool:
        if not isinstance(expr, IRCall):
            return False
        if not isinstance(expr.target, IRConst) or not isinstance(expr.target.value, Native):
            return False
        return expr.target.value.name.resolve(self.func.code) == "alloc_array"

    def _is_arrayobj_anon(self, expr: IRStatement) -> bool:
        if not isinstance(expr, IRCall):
            return False
        if not isinstance(expr.target, IRConst) or not isinstance(expr.target.value, Function):
            return False
        if len(expr.args) != 1:
            return False
        fun = expr.target.value
        try:
            path = fun.resolve_file(self.func.code)
        except Exception:
            path = ""
        if "ArrayObj.hx" not in path.replace("\\", "/"):
            return False
        try:
            sig = fun.resolve_fun(self.func.code)
            ret_name = disasm.type_name(self.func.code, sig.ret.resolve(self.func.code))
        except Exception:
            ret_name = ""
        return "ArrayObj" in ret_name or "Array" in ret_name

    def _find_anon_call(self, node: Optional[IRStatement], arr_local: IRLocal) -> Optional[IRCall]:
        if node is None:
            return None
        if isinstance(node, IRCall) and self._is_arrayobj_anon(node):
            if node.args and isinstance(node.args[0], IRLocal) and node.args[0].name == arr_local.name:
                return node
        # Many expression classes have incomplete get_children(); recurse into the
        # known attributes we care about here.
        if isinstance(node, IRAssign):
            return self._find_anon_call(node.expr, arr_local)
        if isinstance(node, IRReturn) and node.value:
            return self._find_anon_call(node.value, arr_local)
        if isinstance(node, IRCall):
            for arg in node.args:
                found = self._find_anon_call(arg, arr_local)
                if found:
                    return found
        if isinstance(node, IRCast):
            return self._find_anon_call(node.expr, arr_local)
        if isinstance(node, IRField):
            return self._find_anon_call(node.target, arr_local)
        if isinstance(node, IRArrayAccess):
            found = self._find_anon_call(node.array, arr_local)
            if found:
                return found
            return self._find_anon_call(node.index, arr_local)
        if isinstance(node, IRArithmetic):
            found = self._find_anon_call(node.left, arr_local)
            if found:
                return found
            return self._find_anon_call(node.right, arr_local)
        if isinstance(node, IRBoolExpr):
            found = self._find_anon_call(node.left, arr_local)
            if found:
                return found
            return self._find_anon_call(node.right, arr_local)
        if isinstance(node, IREnumField):
            return self._find_anon_call(node.value, arr_local)
        if isinstance(node, IREnumIndex):
            return self._find_anon_call(node.value, arr_local)
        if isinstance(node, IREnumConstruct):
            for arg in node.args:
                found = self._find_anon_call(arg, arr_local)
                if found:
                    return found
        if isinstance(node, IRArrayLiteral):
            for e in node.elements:
                found = self._find_anon_call(e, arr_local)
                if found:
                    return found
        if isinstance(node, IRNew):
            for arg in node.constructor_args:
                found = self._find_anon_call(arg, arr_local)
                if found:
                    return found
        return None

    def _try_array_obj_literal(self, stmts: List[IRStatement], start: int) -> Optional[Tuple[IRStatement, int]]:
        # Pattern:
        #   arr = alloc_array(type, size)
        #   [elem = expr;] arr[i] = elem
        #   ...
        #   use(ArrayObj.anon(arr))
        # Rewrite the ArrayObj.anon(arr) expression to [expr0, expr1, ...].
        if start >= len(stmts):
            return None
        stmt = stmts[start]
        if not isinstance(stmt, IRAssign) or not isinstance(stmt.target, IRLocal):
            return None
        arr_local = stmt.target
        if not self._is_alloc_array(stmt.expr):
            return None

        values: List[IRExpression] = []
        i = start + 1
        while i < len(stmts):
            elem_expr: Optional[IRExpression] = None
            store_stmt: Optional[IRAssign] = None
            # Look for an element initializer immediately followed by a store
            # using that same local.  This handles patterns like:
            #   var9 = new TestClass();
            #   arr[0] = var9;
            s1 = stmts[i]
            if isinstance(s1, IRAssign) and isinstance(s1.target, IRLocal) and i + 1 < len(stmts):
                s2 = stmts[i + 1]
                if (
                    isinstance(s2, IRAssign)
                    and isinstance(s2.target, IRArrayAccess)
                    and isinstance(s2.target.array, IRLocal)
                    and s2.target.array.name == arr_local.name
                    and isinstance(s2.target.index, IRConst)
                    and s2.target.index.const_type == IRConst.ConstType.INT
                    and isinstance(s2.expr, IRLocal)
                    and s2.expr.name == s1.target.name
                ):
                    elem_expr = s1.expr
                    store_stmt = s2
                    i += 2
            if elem_expr is None:
                # Otherwise accept a bare store.
                if (
                    isinstance(s1, IRAssign)
                    and isinstance(s1.target, IRArrayAccess)
                    and isinstance(s1.target.array, IRLocal)
                    and s1.target.array.name == arr_local.name
                    and isinstance(s1.target.index, IRConst)
                    and s1.target.index.const_type == IRConst.ConstType.INT
                ):
                    elem_expr = s1.expr
                    store_stmt = s1
                    i += 1
            if elem_expr is None or store_stmt is None:
                break
            store_access = cast(IRArrayAccess, store_stmt.target)
            idx_const = cast(IRConst, store_access.index)
            idx = int(idx_const.value.value if hasattr(idx_const.value, "value") else idx_const.value)
            if idx != len(values):
                break
            values.append(elem_expr)

        if not values:
            return None

        if i >= len(stmts):
            return None
        use_stmt = stmts[i]
        anon_call = self._find_anon_call(use_stmt, arr_local)
        if anon_call is None:
            return None

        literal = IRArrayLiteral(self.func.code, values)
        self._replace_child(use_stmt, anon_call, literal)
        return use_stmt, i - start + 1

    def _is_empty_alloc_array(self, expr: IRStatement) -> bool:
        if not self._is_alloc_array(expr):
            return False
        call = cast(IRCall, expr)
        if len(call.args) != 2:
            return False
        type_arg, size_arg = call.args
        if not isinstance(size_arg, IRConst) or size_arg.const_type != IRConst.ConstType.INT:
            return False
        if int(size_arg.value.value if hasattr(size_arg.value, "value") else size_arg.value) != 0:
            return False
        if isinstance(type_arg, IRConst) and (
            type_arg.const_type == IRConst.ConstType.NULL or isinstance(type_arg.value, Type)
        ):
            return True
        return False

    def _is_empty_arrayobj_anon(self, expr: IRStatement) -> bool:
        if not self._is_arrayobj_anon(expr):
            return False
        call = cast(IRCall, expr)
        return len(call.args) == 1 and self._is_empty_alloc_array(call.args[0])

    def _is_arraydyn_alloc(self, expr: IRStatement) -> bool:
        if not isinstance(expr, IRCall):
            return False
        if not isinstance(expr.target, IRConst) or not isinstance(expr.target.value, Function):
            return False
        func = expr.target.value
        name = self.func.code.full_func_name(func)
        if not name:
            name = self.func.code.partial_func_name(func)
        if not name:
            return False
        return name.endswith("ArrayDyn.alloc")

    def _try_empty_array_dyn(self, stmts: List[IRStatement], start: int) -> Optional[Tuple[IRStatement, int]]:
        # Pattern:
        #   temp = ArrayObj.anon(alloc_array(null, 0))
        #   target = ArrayDyn.alloc(temp, true)
        # Rewrite both statements to target = [] when temp has no later uses.
        if start + 1 >= len(stmts):
            return None
        s0 = stmts[start]
        if not isinstance(s0, IRAssign) or not isinstance(s0.target, IRLocal):
            return None
        temp = s0.target
        if not self._is_empty_arrayobj_anon(s0.expr):
            return None

        s1 = stmts[start + 1]
        if not isinstance(s1, IRAssign) or not isinstance(s1.expr, IRCall):
            return None
        call = s1.expr
        if not self._is_arraydyn_alloc(call):
            return None
        if len(call.args) != 2:
            return None
        first_arg, second_arg = call.args
        if not isinstance(first_arg, IRLocal) or first_arg.name != temp.name:
            return None

        true_ok = False
        if isinstance(second_arg, IRConst) and isinstance(second_arg.value, bool) and second_arg.value:
            true_ok = True
        elif (
            isinstance(second_arg, IRRef)
            and isinstance(second_arg.target, IRConst)
            and isinstance(second_arg.target.value, bool)
            and second_arg.target.value
        ):
            true_ok = True
        if not true_ok:
            return None

        for later in stmts[start + 2 :]:
            if self._local_in_stmt(later, temp):
                return None

        literal = IRArrayLiteral(self.func.code, [])
        new_assign = IRAssign(self.func.code, s1.target, literal)
        return new_assign, 2

    def _index_shift(self, idx: IRStatement, local: IRLocal) -> Optional[int]:
        """Return the shift amount if `idx` is `local << const`."""
        if not isinstance(idx, IRArithmetic):
            return None
        if idx.op.value != "<<":
            return None
        if not isinstance(idx.left, IRLocal) or idx.left.name != local.name:
            return None
        if not isinstance(idx.right, IRConst) or idx.right.const_type != IRConst.ConstType.INT:
            return None
        val = idx.right.value.value if hasattr(idx.right.value, "value") else idx.right.value
        return int(val)

    def _parse_store_and_increment(
        self,
        stmts: List[IRStatement],
        i: int,
        bytes_var: IRLocal,
        idx_var: IRLocal,
        values: List[IRExpression],
        expected_shift: Optional[int] = None,
    ) -> Optional[Tuple[int, int]]:
        """Parse one `bytes_var[idx_var << n] = value; idx_var++` pair.

        Returns `(index_after_increment, shift)` if the pattern matches, or None.
        When `expected_shift` is provided, only the given shift is accepted.
        """
        if i >= len(stmts):
            return None
        elem_expr: Optional[IRExpression] = None
        s = stmts[i]
        if (
            isinstance(s, IRAssign)
            and isinstance(s.target, IRLocal)
            and s.target.name.startswith("var")
            and i + 1 < len(stmts)
        ):
            nxt = stmts[i + 1]
            if isinstance(nxt, IRAssign) and isinstance(nxt.target, IRArrayAccess) and nxt.expr == s.target:
                elem_expr = s.expr
                i += 1
                s = nxt

        if not isinstance(s, IRAssign) or not isinstance(s.target, IRArrayAccess):
            return None
        access = s.target
        if not isinstance(access.array, IRLocal) or access.array.name != bytes_var.name:
            return None
        shift = self._index_shift(access.index, idx_var)
        if shift is None:
            return None
        if expected_shift is not None and shift != expected_shift:
            return None
        values.append(elem_expr if elem_expr is not None else s.expr)
        i += 1

        if i >= len(stmts):
            return None
        s2 = stmts[i]
        if not isinstance(s2, IRAssign) or not isinstance(s2.target, IRLocal) or s2.target.name != idx_var.name:
            return None
        if not isinstance(s2.expr, IRArithmetic) or s2.expr.op.value != "+":
            return None
        if not isinstance(s2.expr.left, IRLocal) or s2.expr.left.name != idx_var.name:
            return None
        if not isinstance(s2.expr.right, IRConst) or s2.expr.right.const_type != IRConst.ConstType.INT:
            return None
        if int(s2.expr.right.value.value if hasattr(s2.expr.right.value, "value") else s2.expr.right.value) != 1:
            return None
        return i + 1, shift

    def _try_array_literal(self, stmts: List[IRStatement], start: int) -> Optional[Tuple[IRStatement, int]]:
        # bytes_var = alloc_bytes(...)
        if start >= len(stmts):
            return None
        stmt = stmts[start]
        if not isinstance(stmt, IRAssign) or not isinstance(stmt.target, IRLocal):
            return None
        bytes_var = stmt.target
        if not self._is_alloc_bytes(stmt.expr):
            return None

        values: List[IRExpression] = []
        i: Optional[int] = None
        idx_var: Optional[IRLocal] = None
        shift: Optional[int] = None

        # Pattern 1: explicit `idx_var = 0` then a sequence of stores.
        if start + 1 < len(stmts):
            stmt2 = stmts[start + 1]
            if (
                isinstance(stmt2, IRAssign)
                and isinstance(stmt2.target, IRLocal)
                and isinstance(stmt2.expr, IRConst)
                and stmt2.expr.const_type == IRConst.ConstType.INT
                and int(stmt2.expr.value.value if hasattr(stmt2.expr.value, "value") else stmt2.expr.value) == 0
            ):
                idx_var = stmt2.target
                parsed = self._parse_store_and_increment(stmts, start + 2, bytes_var, idx_var, values)
                if parsed is not None:
                    i, shift = parsed
                    while True:
                        nxt = self._parse_store_and_increment(stmts, i, bytes_var, idx_var, values, shift)
                        if nxt is None:
                            break
                        i, _ = nxt
                    if not values:
                        i = None

        # Pattern 2: first store uses a constant 0 index; the counter is inferred
        # from the following increment (e.g. `bytes[0 << n] = v0; idx++; ...`).
        if i is None and shift is None and start + 2 < len(stmts):
            first_store = stmts[start + 1]
            if isinstance(first_store, IRAssign) and isinstance(first_store.target, IRArrayAccess):
                access = first_store.target
                if (
                    isinstance(access.array, IRLocal)
                    and access.array.name == bytes_var.name
                    and isinstance(access.index, IRArithmetic)
                    and access.index.op.value == "<<"
                    and isinstance(access.index.left, IRConst)
                    and access.index.left.const_type == IRConst.ConstType.INT
                    and int(
                        access.index.left.value.value
                        if hasattr(access.index.left.value, "value")
                        else access.index.left.value
                    )
                    == 0
                    and isinstance(access.index.right, IRConst)
                    and access.index.right.const_type == IRConst.ConstType.INT
                ):
                    shift = int(
                        access.index.right.value.value
                        if hasattr(access.index.right.value, "value")
                        else access.index.right.value
                    )
                    values = [first_store.expr]
                    inc_stmt = stmts[start + 2]
                    if (
                        isinstance(inc_stmt, IRAssign)
                        and isinstance(inc_stmt.target, IRLocal)
                        and isinstance(inc_stmt.expr, IRArithmetic)
                        and inc_stmt.expr.op.value == "+"
                        and isinstance(inc_stmt.expr.left, IRLocal)
                        and isinstance(inc_stmt.expr.right, IRConst)
                        and inc_stmt.expr.right.const_type == IRConst.ConstType.INT
                        and int(
                            inc_stmt.expr.right.value.value
                            if hasattr(inc_stmt.expr.right.value, "value")
                            else inc_stmt.expr.right.value
                        )
                        == 1
                    ):
                        idx_var = inc_stmt.target
                        parsed = self._parse_store_and_increment(stmts, start + 3, bytes_var, idx_var, values, shift)
                        if parsed is not None:
                            i, _ = parsed
                            while True:
                                nxt = self._parse_store_and_increment(stmts, i, bytes_var, idx_var, values, shift)
                                if nxt is None:
                                    break
                                i, _ = nxt
                        else:
                            values = []
                            shift = None

        if not values or idx_var is None or i is None or shift is None:
            return None

        # Allow an optional `idx_var = count` assignment before the alloc call.
        if i < len(stmts):
            opt = stmts[i]
            if (
                isinstance(opt, IRAssign)
                and isinstance(opt.target, IRLocal)
                and opt.target.name == idx_var.name
                and isinstance(opt.expr, IRConst)
                and opt.expr.const_type == IRConst.ConstType.INT
            ):
                i += 1

        # arr_var = alloc*(bytes_var, count) OR return alloc*(bytes_var, count)
        if i >= len(stmts):
            return None
        final = stmts[i]
        if isinstance(final, IRAssign) and isinstance(final.expr, IRCall):
            call = final.expr
            return_target = final.target
        elif isinstance(final, IRReturn) and isinstance(final.value, IRCall):
            call = final.value
            return_target = None
        else:
            return None
        alloc_name = self._is_alloc_typed_array(call)
        if alloc_name is None:
            return None
        if self._ALLOC_SHIFTS.get(alloc_name) != shift:
            return None
        if len(call.args) != 2 or (isinstance(call.args[0], IRLocal) and call.args[0].name != bytes_var.name):
            return None

        arr_type = _get_type_in_code(self.func.code, "Dyn")
        for t in self.func.code.types:
            if disasm.type_name(self.func.code, t) == "Array":
                arr_type = t
                break
        literal = IRArrayLiteral(self.func.code, values)

        # If the only uses of the recovered literal are constant-index reads, the
        # Haxe compiler will often constant-fold the whole array away.  Keep the
        # low-level allocation in that case so the recompiled bytecode stays close
        # to the original.
        if isinstance(return_target, IRLocal) and not self._array_literal_is_worth_recovering(return_target, stmts, i):
            return None

        if return_target is not None:
            new_assign = IRAssign(self.func.code, return_target, literal)
            return new_assign, i - start + 1
        else:
            new_return = IRReturn(self.func.code, literal)
            return new_return, i - start + 1

    def _array_literal_is_worth_recovering(self, arr_local: IRLocal, stmts: List[IRStatement], end_idx: int) -> bool:
        """Return True if `arr_local` is used for anything other than a bounds
        guard after the literal allocation.

        Constant-index reads now count as real uses: recovering the array
        literal produces much cleaner Haxe source even though the compiler may
        later constant-fold it.
        """

        def _only_guard_fields(node: Optional[IRStatement]) -> bool:
            if node is None:
                return True
            if node == arr_local:
                return False
            if isinstance(node, IRField) and node.target == arr_local and node.field_name in ("length", "bytes"):
                return True
            for child in node.get_children():
                if not _only_guard_fields(child):
                    return False
            return True

        for stmt in stmts[end_idx + 1 :]:
            if self._local_in_stmt(stmt, arr_local):
                if isinstance(stmt, IRConditional) and _only_guard_fields(stmt.condition):
                    continue
                return True
        return False

    def _local_in_stmt(self, stmt: IRStatement, local: IRLocal) -> bool:
        if stmt == local:
            return True
        for child in stmt.get_children():
            if self._local_in_stmt(child, local):
                return True
        return False

    def _array_from_length_expr(
        self, stmts: List[IRStatement], start: int, expr: IRExpression
    ) -> Optional[Tuple[IRLocal, int]]:
        """Resolve the array variable behind a `.length` expression or a temp holding it.

        Returns the array local and the index of the statement that produced the
        length value, so the caller can consume it.
        """
        if isinstance(expr, IRField) and expr.field_name == "length" and isinstance(expr.target, IRLocal):
            return expr.target, start
        if not isinstance(expr, IRLocal):
            return None
        for j in range(start - 1, max(-1, start - 5), -1):
            prev = stmts[j]
            if (
                isinstance(prev, IRAssign)
                and isinstance(prev.target, IRLocal)
                and prev.target.same_register(expr)
                and isinstance(prev.expr, IRField)
                and prev.expr.field_name == "length"
                and isinstance(prev.expr.target, IRLocal)
            ):
                return prev.expr.target, j
        return None

    def _try_array_access(self, stmts: List[IRStatement], start: int) -> Optional[Tuple[IRStatement, int, int]]:
        # Pattern:
        #   if (idx >= arr.length) { value = default; } else { value = arr.bytes[idx << 2]; }
        # Returns (replacement_stmt, consumed_from_start, preceding_statements_to_pop).
        if start >= len(stmts):
            return None
        stmt = stmts[start]
        if not isinstance(stmt, IRConditional):
            return None
        cond = stmt.condition
        if not isinstance(cond, IRBoolExpr):
            return None
        if cond.op == IRBoolExpr.CompareType.GTE:
            idx_expr = cond.left
            length_expr = cond.right
        elif cond.op == IRBoolExpr.CompareType.LTE:
            length_expr = cond.left
            idx_expr = cond.right
        else:
            return None

        const_idx: Optional[int] = None
        idx_var: Optional[IRLocal] = None
        if isinstance(idx_expr, IRConst) and idx_expr.const_type == IRConst.ConstType.INT:
            const_idx = _int_const_value(idx_expr)
            if const_idx is None:
                return None
        elif isinstance(idx_expr, IRLocal):
            idx_var = idx_expr
        else:
            return None

        if length_expr is None:
            return None
        resolved = self._array_from_length_expr(stmts, start, length_expr)
        if resolved is None:
            return None
        arr_var, length_assign_idx = resolved

        then_block = stmt.true_block
        else_block = stmt.false_block
        if len(then_block.statements) != 1 or not else_block.statements:
            return None
        then_assign = then_block.statements[0]
        else_assign = else_block.statements[-1]
        if not isinstance(then_assign, IRAssign) or not isinstance(else_assign, IRAssign):
            return None
        if then_assign.target != else_assign.target or not isinstance(then_assign.target, IRLocal):
            return None
        value_var = then_assign.target
        if not isinstance(else_assign.expr, IRArrayAccess):
            return None
        access = else_assign.expr
        if not isinstance(access.array, IRField):
            return None
        if not isinstance(access.array.target, IRLocal):
            return None
        if access.array.field_name != "bytes" or access.array.target.name != arr_var.name:
            return None
        if not isinstance(access.index, IRArithmetic) or access.index.op.value != "<<":
            return None
        if not isinstance(access.index.right, IRConst):
            return None

        if const_idx is None:
            # For constant-index accesses the compiler loads the constant into the
            # result register and then uses that register as the index scratchpad.
            # After debug-name splitting the index temp and the value temp look like
            # different locals, but reg_idx lets us recover the original constant.
            assert idx_var is not None
            const_idx = self._recover_constant_index(stmts, start, idx_var, access, value_var)
            # If the index local is a user-named variable (e.g. `i`), keep the
            # variable index so the source reads `a[i]`. This preserves the array
            # allocation instead of letting Haxe constant-fold it away.
            if const_idx is not None and idx_var is not None and not self._is_compiler_temp(idx_var):
                const_idx = None

        if const_idx is not None:
            index_expr: IRExpression = IRConst(self.func.code, IRConst.ConstType.INT, value=const_idx)
        else:
            assert idx_var is not None
            index_expr = idx_var

        new_access = IRArrayAccess(self.func.code, arr_var, index_expr)
        new_assign = IRAssign(self.func.code, value_var, new_access)
        # If the length was loaded into a temp immediately before the guard, drop
        # that temp as well; otherwise later passes can leave a dead assignment.
        preceding_to_pop = start - length_assign_idx
        return new_assign, 1, preceding_to_pop

    def _recover_constant_index(
        self,
        stmts: List[IRStatement],
        start: int,
        idx_var: IRLocal,
        access: IRArrayAccess,
        value_var: IRLocal,
    ) -> Optional[int]:
        """Look for an immediately preceding `temp = const` that loads the index."""
        candidates = [idx_var, value_var]
        if isinstance(access.index, IRArithmetic) and isinstance(access.index.left, IRLocal):
            candidates.append(access.index.left)

        for candidate in candidates:
            val = self._const_loaded_for_local(stmts, start, candidate)
            if val is not None:
                return val
        return None

    def _is_compiler_temp(self, local: IRLocal) -> bool:
        return bool(re.fullmatch(r"var\d+", local.name))

    def _const_loaded_for_local(self, stmts: List[IRStatement], start: int, local: IRLocal) -> Optional[int]:
        """Scan the few statements before `start` for `local_reg = const`."""
        for j in range(start - 1, max(-1, start - 5), -1):
            prev = stmts[j]
            if isinstance(prev, IRAssign) and isinstance(prev.target, IRLocal):
                if prev.target.same_register(local):
                    if isinstance(prev.expr, IRConst):
                        return _int_const_value(prev.expr)
                    return None
        return None

    def _try_array_dyn_literal(self, stmts: List[IRStatement], start: int) -> Optional[Tuple[IRStatement, int]]:
        """Rewrite `target = ArrayDyn.alloc([...], true)` to `target = [...]`.

        The ArrayObj.anon + ArrayDyn.alloc pair is already lowered to a typed
        array literal for the first argument. Removing the wrapper lets Haxe
        infer the target as Array<Dynamic>, which is required for mixed-type
        literals to recompile.
        """
        if start >= len(stmts):
            return None
        s = stmts[start]
        if not isinstance(s, IRAssign) or not isinstance(s.expr, IRCall):
            return None
        call = s.expr
        if not self._is_arraydyn_alloc(call):
            return None
        if len(call.args) != 2:
            return None
        first_arg, second_arg = call.args
        if not isinstance(first_arg, IRArrayLiteral):
            return None
        true_ok = False
        if isinstance(second_arg, IRConst) and isinstance(second_arg.value, bool) and second_arg.value:
            true_ok = True
        elif (
            isinstance(second_arg, IRRef)
            and isinstance(second_arg.target, IRConst)
            and isinstance(second_arg.target.value, bool)
            and second_arg.target.value
        ):
            true_ok = True
        if not true_ok:
            return None
        return IRAssign(self.func.code, s.target, first_arg), 1

    def _try_write_bounds_guard(self, stmts: List[IRStatement], start: int) -> Optional[int]:
        """Drop the no-op `if (C >= a.length) a.__expand(C)` guard before an array write."""
        if start + 1 >= len(stmts):
            return None
        stmt = stmts[start]
        if not isinstance(stmt, IRConditional):
            return None
        cond = stmt.condition
        if not isinstance(cond, IRBoolExpr):
            return None
        if cond.op == IRBoolExpr.CompareType.GTE:
            idx_expr = cond.left
            length_expr = cond.right
        elif cond.op == IRBoolExpr.CompareType.LTE:
            length_expr = cond.left
            idx_expr = cond.right
        else:
            return None

        if length_expr is None:
            return None
        arr_var = self._array_var_from_length_expr(length_expr)
        if arr_var is None:
            return None

        if len(stmt.true_block.statements) != 1 or stmt.false_block.statements:
            return None
        call_stmt = stmt.true_block.statements[0]
        if not isinstance(call_stmt, IRCall):
            return None
        if not isinstance(call_stmt.target, IRConst) or not isinstance(call_stmt.target.value, Function):
            return None
        if self.func.code.partial_func_name(call_stmt.target.value) != "__expand":
            return None
        if len(call_stmt.args) != 2:
            return None
        if call_stmt.args[0] != arr_var or call_stmt.args[1] != idx_expr:
            return None

        next_stmt = stmts[start + 1]
        if not isinstance(next_stmt, IRAssign) or not isinstance(next_stmt.target, IRArrayAccess):
            return None
        access = next_stmt.target
        # High-level store: a[idx]
        if isinstance(access.array, IRLocal) and access.array.name == arr_var.name:
            if access.index != idx_expr:
                return None
        # Low-level store: a.bytes[idx << 2]
        elif isinstance(access.array, IRField) and access.array.field_name == "bytes":
            if not isinstance(access.array.target, IRLocal) or access.array.target.name != arr_var.name:
                return None
            if not isinstance(access.index, IRArithmetic) or access.index.op.value != "<<":
                return None
            if access.index.left != idx_expr:
                return None
            if not isinstance(access.index.right, IRConst):
                return None
        else:
            return None

        return 1

    def _array_var_from_length_expr(self, expr: IRExpression) -> Optional[IRLocal]:
        """Return the array local if `expr` is `arr.length` (or a temp holding it)."""
        if isinstance(expr, IRField) and expr.field_name == "length" and isinstance(expr.target, IRLocal):
            return expr.target
        if isinstance(expr, IRLocal):
            # We do not attempt to trace back to the source here; the preceding
            # temp must have been removed or inlined by the time this runs.
            return None
        return None


def _build_enum_global_map(code: Bytecode) -> Dict[int, Tuple[str, tIndex]]:
    """
    HashLink stores parameterless enum constants as globals whose type is the
    enum type.  The declaration order of those constants matches the order of
    the enum's parameterless constructors.  Build a map from global index to
    the constructor name and enum type index so that `GetGlobal` can be lifted
    to `Red`/`Green`/... instead of an opaque enum-typed global object.
    """
    enum_globals: Dict[int, List[int]] = {}
    for gi, gt in enumerate(code.global_types):
        typ = gt.resolve(code)
        if isinstance(typ.definition, Enum):
            enum_globals.setdefault(gt.value, []).append(gi)

    result: Dict[int, Tuple[str, tIndex]] = {}
    for type_idx, globals in enum_globals.items():
        enum_def = code.types[type_idx].definition
        if not isinstance(enum_def, Enum):
            continue
        globals.sort()
        parameterless = [c for c in enum_def.constructs if c.nparams.value == 0]
        for gi, construct in zip(globals, parameterless):
            result[gi] = (construct.name.resolve(code), code.global_types[gi])
    return result


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
        capture_layers: bool = False,
    ) -> None:
        self.func = func
        self.cfg = CFGraph(func)
        self.cfg.build()
        self.code = code
        self._enum_global_map = _build_enum_global_map(code)
        self.ops = func.ops
        self.locals: List[IRLocal] = []
        self.block: IRBlock
        self.capture_layers = capture_layers
        self.opcodes: str = ""
        self.cfg_data: Dict[str, List[Dict[str, Any]]] = {"nodes": [], "edges": []}
        self.layer_snapshots: List[Tuple[str, str]] = []
        self._lift_cache: Dict[Tuple[Optional["CFNode"], Optional["CFNode"], int], IRBlock] = {}
        self._lift(no_lift=no_lift)
        if do_optimize:
            self.optimizers: List[IROptimizer] = [
                IRBlockFlattener(self),
                IRConstructorFolder(self),
                IRPrimitiveJumpLifter(self),
                IRGlobalStringOptimizer(self),
                IRStringIntConcatOptimizer(self),
                IRConditionInliner(self),
                IRLoopConditionOptimizer(self),
                IRSelfAssignOptimizer(self),
                IRCommonBlockMerger(self),
                IRRedundantContinueEliminator(self),
                IRCopyPropOptimizer(self),
                IRTempAssignmentInliner(self, aggressive=False),
                IRTempAssignmentInliner(self, aggressive=True),
                IRDeadTempEliminator(self),
                IRDeadCodeEliminator(self),
                IRArrayPatternOptimizer(self),
                IRNativeArrayAllocOptimizer(self),
                IRTempAssignmentInliner(self, aggressive=False),
                IRVoidAssignOptimizer(self),
                IRDeadCodeEliminator(self),
                IRSelfAssignOptimizer(self),
                IRTraceOptimizer(self),
                IRStringConcatFolder(self),
                IRIntSwitchOptimizer(self),
                IRStringSwitchOptimizer(self),
                IREnumSwitchOptimizer(self),
                IRDeadTempEliminator(self),
                IRDeadCodeEliminator(self),
                IRBlockFlattener(self),
                IRLoopRerollOptimizer(self),
                IRForEachLoopOptimizer(self),
                IRIntRangeLoopOptimizer(self),
            ]
            self._optimize()

    def _lift(self, no_lift: bool = False) -> None:
        """Lift function to IR"""
        for i, reg in enumerate(self.func.regs):
            self.locals.append(IRLocal(f"var{i}", reg, code=self.code, reg_idx=i))
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
        # Assigns with op index 0 name function parameters rather than pointing at
        # a `dst`-producing op, so they need the same register offset as in
        # _name_locals (register 0 is `this` in instance methods/constructors).
        is_instance = not self.code.full_func_name(self.func).startswith("$")
        has_this_ops = any(op.op in ("SetThis", "GetThis") for op in self.func.ops)
        param_start = 1 if (is_instance or has_this_ops) else 0
        param_idx = 0
        for assign in self.func.assigns:
            val = assign[1].value - 1
            if val < 0:
                reg = param_start + param_idx
                param_idx += 1
                if reg < len(self.func.regs):
                    self._user_reg_indices.add(reg)
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

    def _get_local(self, reg_idx: int) -> IRLocal:
        """Get the current IRLocal for a register, respecting SSA-esque name transitions."""
        return self.locals[reg_idx]

    def _split_local(self, reg_idx: int, name: str) -> IRLocal:
        """Create a new IRLocal for a register with a specific name (SSA-esque split)."""
        reg_type = self.func.regs[reg_idx]
        new_type = reg_type.resolve(self.code)
        # Avoid name collisions only with a different register of a different
        # type.  Same-type duplicates are usually the same source variable split
        # across registers.
        base_name = name
        suffix = 1
        existing_names = {loc.name for i, loc in enumerate(self.locals) if i != reg_idx and loc.get_type() != new_type}
        while name in existing_names:
            name = f"{base_name}{suffix}"
            suffix += 1
        new_local = IRLocal(name, reg_type, code=self.code, reg_idx=reg_idx)
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
        if self.capture_layers:
            self.opcodes = disasm.func(self.code, self.func)
            self.cfg_data = self._cfg_to_dict()
            self.layer_snapshots.append(("LLIR", _strip_ansi(self.block.pprint())))
        for o in self.optimizers:
            if DEBUG:
                dbg_print(f"----- {o.__class__.__name__} -----")
            o.optimize()
            if DEBUG:
                dbg_print(self.block.pprint())
            if self.capture_layers:
                self.layer_snapshots.append((o.__class__.__name__, _strip_ansi(self.block.pprint())))

    def _cfg_to_dict(self) -> Dict[str, Any]:
        """Serialize the control-flow graph to a JSON-friendly structure."""
        node_ids = {id(node): i for i, node in enumerate(self.cfg.nodes)}
        nodes: List[Dict[str, Any]] = []
        for i, node in enumerate(self.cfg.nodes):
            label_lines = []
            for op in node.ops:
                parts = [op.op or "?"] + [str(v) for v in op.df.values()]
                label_lines.append(". ".join(parts))
            nodes.append(
                {
                    "id": i,
                    "label": f"BB{i}",
                    "ops": label_lines,
                    "base_offset": node.base_offset,
                    "is_entry": node is self.cfg.entry,
                }
            )
        edges: List[Dict[str, Any]] = []
        for node in self.cfg.nodes:
            src = node_ids[id(node)]
            for target, edge_type in node.branches:
                dst = node_ids.get(id(target))
                if dst is not None:
                    edges.append({"from": src, "to": dst, "type": edge_type})
        return {"nodes": nodes, "edges": edges, "dot": self._cfg_to_dot(node_ids)}

    def _cfg_to_dot(self, node_ids: Dict[int, int]) -> str:
        """Produce a Graphviz DOT representation of the CFG.

        Mirrors the entry/return node coloring and per-branch-type edge
        coloring conventions of CFGraph.graph()/style_node(), just remapped
        onto the Catppuccin Mocha palette used by the crashtest site.
        """

        def _escape(s: str) -> str:
            return s.replace("\\", "\\\\").replace('"', '\\"')

        def _node_fill(node: CFNode) -> str:
            if node is self.cfg.entry:
                return '"#a6e3a1", fontcolor="#11111b"'  # green, like style_node's entry
            if any(op.op == "Ret" for op in node.ops):
                return '"#94e2d5", fontcolor="#11111b"'  # teal, like style_node's return blocks
            return '"#313244", fontcolor="#cdd6f4"'

        def _edge_style(edge_type: str) -> str:
            if edge_type == "true":
                return 'color="#a6e3a1", fontcolor="#a6e3a1", label="true"'
            if edge_type == "false":
                return 'color="#f38ba8", fontcolor="#f38ba8", label="false"'
            if edge_type.startswith("switch: "):
                case = edge_type.split("switch: ")[1].strip()
                color = "#f38ba8" if case == "default" else "#cba6f7"
                return f'color="{color}", fontcolor="{color}", label="{_escape(case)}"'
            if edge_type == "trap":
                return 'color="#f9e2af", fontcolor="#f9e2af", label="trap"'
            return 'color="#89b4fa"'

        lines = [
            "digraph CFG {",
            "  rankdir=TB;",
            "  nodesep=0.4;",
            "  ranksep=0.5;",
            '  node [shape=box, fontname="monospace", fontsize=11, margin="0.15,0.1", style="rounded,filled", fillcolor="#313244", fontcolor="#cdd6f4", color="#585b70"];',
            '  edge [fontname="monospace", fontsize=9, color="#6c7086", fontcolor="#a6adc8"];',
        ]
        for i, node in enumerate(self.cfg.nodes):
            op_lines = []
            for op in node.ops:
                parts = [op.op or "?"] + [str(v) for v in op.df.values()]
                op_lines.append(_escape(". ".join(parts)))
            label = _escape(f"BB{i}") + "\\l" + "\\l".join(op_lines) + "\\l"
            lines.append(f'  {i} [label="{label}", fillcolor={_node_fill(node)}];')
        for node in self.cfg.nodes:
            src = node_ids[id(node)]
            for target, edge_type in node.branches:
                dst = node_ids.get(id(target))
                if dst is not None:
                    lines.append(f"  {src} -> {dst} [{_edge_style(edge_type)}];")
        lines.append("}")
        return "\n".join(lines)

    def _name_locals(self) -> None:
        """Name locals based on debug info"""
        reg_assigns: List[List[str]] = [[] for _ in self.func.regs]
        # Register 0 is `this` in instance methods and constructors. Detect by
        # either: full name has no leading `$` (instance method), or the function
        # contains SetThis/GetThis opcodes (constructor). Needed up front because
        # parameter-name assigns (below) are numbered relative to the explicit
        # parameter list, which starts at register 1 when `this` occupies register 0.
        is_instance = not self.code.full_func_name(self.func).startswith("$")
        has_this_ops = any(op.op in ("SetThis", "GetThis") for op in self.func.ops)
        has_this = is_instance or has_this_ops
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
            # Assigns with op index 0 (val == -1 above) name function parameters,
            # in order — not necessarily register 0: that's `this` for instance
            # methods/constructors, so parameters start at register 1 there.
            param_start = 1 if has_this else 0
            for i, assign in enumerate([assign for assign in self.func.assigns if assign[1].value <= 0]):
                reg = param_start + i
                if reg >= len(reg_assigns):
                    break
                name = assign[0].resolve(self.code)
                if name not in reg_assigns[reg]:
                    reg_assigns[reg].append(name)
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

        # If the same debug name is assigned to two different registers with
        # different types, suffix the later one so Haxe sees two distinct
        # variables instead of a single Dynamic variable.
        name_to_regs: Dict[str, List[int]] = {}
        for i, local in enumerate(self.locals):
            name_to_regs.setdefault(local.name, []).append(i)
        for name, regs in name_to_regs.items():
            if len(regs) <= 1:
                continue
            typed_regs: Dict[int, List[int]] = {}
            for r in regs:
                typ = self.func.regs[r]
                typ_key = id(typ.resolve(self.code))
                typed_regs.setdefault(typ_key, []).append(r)
            # Only rename when the same debug name is used for variables with
            # different types.  Same-type duplicates are usually just different
            # registers for a single source variable.
            if len(typed_regs) <= 1:
                continue
            ordered = sorted(regs, key=lambda r: self._reg_first_assign.get(r, float("inf")))
            by_type: Dict[int, List[int]] = {}
            for r in ordered:
                typ = self.func.regs[r]
                typ_key = id(typ.resolve(self.code))
                by_type.setdefault(typ_key, []).append(r)
            # Keep the earliest register of the first-seen type as the base name;
            # rename duplicates of other types.
            kept = set()
            for r in ordered:
                typ_key = id(self.func.regs[r].resolve(self.code))
                if typ_key not in kept:
                    kept.add(typ_key)
                else:
                    self.locals[r].name = f"{name}{len(kept)}"
                    kept.add(typ_key)

        if self.locals and self.locals[0].name == "var0" and has_this:
            self.locals[0].name = "this"
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

    def _resolve_method_field(self, obj_local: "IRLocal", obj_type: Type, field_idx: int) -> Optional["IRField"]:
        """Build the `obj.method` IRField targeted by a CallMethod/CallThis/
        InstanceClosure `field` operand.

        For an ``Obj`` the operand indexes the virtual method table, so the
        proto is looked up by ``pindex`` across the class hierarchy. For a
        ``Virtual`` it indexes the (method-typed) data fields directly. Returns
        ``None`` when the target cannot be resolved.
        """
        defn = obj_type.definition
        if isinstance(defn, Obj):
            proto = self.code.proto_by_pindex(defn, field_idx)
            if proto is None:
                return None
            fun = proto.findex.resolve(self.code)
            return IRField(self.code, obj_local, proto.name.resolve(self.code), fun.type)
        if isinstance(defn, Virtual):
            if field_idx >= len(defn.fields):
                return None
            field_core = defn.fields[field_idx]
            return IRField(self.code, obj_local, field_core.name.resolve(self.code), field_core.type)
        return None

    def _lift_ops_into_block(self, block: IRBlock, ops: List[Opcode]) -> None:
        for op in ops:
            op_idx = self._op_id_to_idx.get(id(op))
            # Capture the register-to-local mapping before any debug-name split.
            # HashLink frequently reuses a register as both a source and the
            # destination for the same opcode (e.g. `reg0 = String.__add__(reg0,
            # reg1)`).  If we split the local for the destination first, the
            # source operand incorrectly picks up the new, empty local.  Source
            # operands below therefore read from this pre-opcode snapshot, while
            # destinations read from `self.locals` after the split.
            source_locals = self.locals.copy()
            if op_idx is not None:
                self._check_assign(op_idx)
            if op.op == "Label":
                continue

            if op.op in arithmetic:
                dst = self.locals[op.df["dst"].value]
                lhs = source_locals[op.df["a"].value]
                rhs = source_locals[op.df["b"].value]
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
                    [source_locals[op.df[f"arg{i}"].value] for i in range(n)]
                    if op.op != "CallN"
                    else [source_locals[arg.value] for arg in op.df["args"].value]
                )
                call_expr = IRCall(self.code, IRCall.CallType.FUNC, fun, args)

                if dst.get_type().kind.value == Type.Kind.VOID.value:
                    block.statements.append(call_expr)
                else:
                    block.statements.append(IRAssign(self.code, dst, call_expr))
            elif op.op == "CallClosure":
                dst = self.locals[op.df["dst"].value]
                fun = source_locals[op.df["fun"].value]
                args = [source_locals[arg.value] for arg in op.df["args"].value]
                call_expr = IRCall(self.code, IRCall.CallType.CLOSURE, fun, args)

                if dst.get_type().kind.value == Type.Kind.VOID.value:
                    block.statements.append(call_expr)
                else:
                    block.statements.append(IRAssign(self.code, dst, call_expr))
            elif op.op in ("CallMethod", "CallThis"):
                dst = self.locals[op.df["dst"].value]
                arg_regs = op.df["args"].value
                if op.op == "CallThis":
                    obj_local = source_locals[0]
                    obj_type = self.code.types[self.func.regs[0].value]
                    method_args = [source_locals[arg.value] for arg in arg_regs]
                else:
                    obj_local = source_locals[arg_regs[0].value]
                    obj_type = obj_local.get_type()
                    method_args = [source_locals[arg.value] for arg in arg_regs[1:]]
                field_expr = self._resolve_method_field(obj_local, obj_type, op.df["field"].value)
                if field_expr is not None:
                    call_expr = IRCall(self.code, IRCall.CallType.METHOD, field_expr, method_args)
                    if dst.get_type().kind.value == Type.Kind.VOID.value:
                        block.statements.append(call_expr)
                    else:
                        block.statements.append(IRAssign(self.code, dst, call_expr))
                elif dst.get_type().kind.value == Type.Kind.VOID.value:
                    block.statements.append(IRUnliftedOpcode(self.code, op))
                else:
                    block.statements.append(IRAssign(self.code, dst, IRUnliftedOpcode(self.code, op)))
            elif op.op == "Mov":
                block.statements.append(
                    IRAssign(self.code, self.locals[op.df["dst"].value], source_locals[op.df["src"].value])
                )
            elif op.op == "GetGlobal":
                global_idx = op.df["global"].value
                enum_const = self._enum_global_map.get(global_idx)
                expr: IRExpression
                if enum_const is not None:
                    construct_name, enum_type_idx = enum_const
                    expr = IREnumConstruct(self.code, construct_name, [], enum_type_idx)
                else:
                    expr = IRConst(self.code, IRConst.ConstType.GLOBAL_OBJ, idx=op.df["global"])
                block.statements.append(
                    IRAssign(
                        self.code,
                        self.locals[op.df["dst"].value],
                        expr,
                    )
                )
            elif op.op == "Field":
                dst_local = self.locals[op.df["dst"].value]
                obj_local = source_locals[op.df["obj"].value]
                obj_type = obj_local.get_type()
                if not isinstance(obj_type.definition, (Obj, Virtual)):
                    raise DecompError(f"Field opcode used on non-object type: {obj_type.definition}")
                field_core = op.df["field"].resolve_obj(self.code, obj_type.definition)
                field_expr = IRField(self.code, obj_local, field_core.name.resolve(self.code), field_core.type)
                block.statements.append(IRAssign(self.code, dst_local, field_expr))
            elif op.op == "GetThis":
                dst_local = self.locals[op.df["dst"].value]
                this_local = source_locals[0]
                this_type_def = self.code.types[self.func.regs[0].value]
                if isinstance(this_type_def.definition, (Obj, Virtual)):
                    field_core = op.df["field"].resolve_obj(self.code, this_type_def.definition)
                    field_expr = IRField(self.code, this_local, field_core.name.resolve(self.code), field_core.type)
                    block.statements.append(IRAssign(self.code, dst_local, field_expr))
                else:
                    block.statements.append(IRUnliftedOpcode(self.code, op))
            elif op.op == "SetThis":
                src_local = source_locals[op.df["src"].value]
                this_local = source_locals[0]
                this_type_def = self.code.types[self.func.regs[0].value]
                if isinstance(this_type_def.definition, (Obj, Virtual)):
                    field_core = op.df["field"].resolve_obj(self.code, this_type_def.definition)
                    field_expr = IRField(self.code, this_local, field_core.name.resolve(self.code), field_core.type)
                    block.statements.append(IRAssign(self.code, field_expr, src_local))
                else:
                    block.statements.append(IRUnliftedOpcode(self.code, op))
            elif op.op == "New":
                dst_local = self.locals[op.df["dst"].value]
                alloc_type_idx = self.func.regs[op.df["dst"].value]
                new_expr = IRNew(self.code, alloc_type_idx)
                block.statements.append(IRAssign(self.code, dst_local, new_expr))
            elif op.op == "ToSFloat":
                dst_local = self.locals[op.df["dst"].value]
                src_local = source_locals[op.df["src"].value]

                f64_idx = self.code.find_prim_type(Type.Kind.F64)

                cast_expr = IRCast(self.code, f64_idx, src_local)
                block.statements.append(IRAssign(self.code, dst_local, cast_expr))
            elif op.op == "ToDyn" or op.op == "ToVirtual":
                dst_local = self.locals[op.df["dst"].value]
                src_local = source_locals[op.df["src"].value]
                cast_expr = IRCast(self.code, self.func.regs[op.df["dst"].value], src_local)
                block.statements.append(IRAssign(self.code, dst_local, cast_expr))
            elif op.op == "ToInt":
                dst_local = self.locals[op.df["dst"].value]
                src_local = source_locals[op.df["src"].value]
                cast_expr = IRCast(self.code, self.func.regs[op.df["dst"].value], src_local)
                block.statements.append(IRAssign(self.code, dst_local, cast_expr))
            elif op.op in ("SafeCast", "UnsafeCast"):
                dst_local = self.locals[op.df["dst"].value]
                src_local = source_locals[op.df["src"].value]
                cast_expr = IRCast(self.code, self.func.regs[op.df["dst"].value], src_local)
                block.statements.append(IRAssign(self.code, dst_local, cast_expr))
            elif op.op == "GetArray":
                dst_local = self.locals[op.df["dst"].value]
                arr_local = source_locals[op.df["array"].value]
                idx_local = source_locals[op.df["index"].value]
                block.statements.append(
                    IRAssign(
                        self.code,
                        dst_local,
                        IRArrayAccess(self.code, arr_local, idx_local, self.func.regs[op.df["dst"].value]),
                    )
                )
            elif op.op == "ArraySize":
                dst_local = self.locals[op.df["dst"].value]
                arr_local = source_locals[op.df["array"].value]
                i32_idx = self.code.find_prim_type(Type.Kind.I32)
                length_expr = IRField(self.code, arr_local, "length", i32_idx)
                block.statements.append(IRAssign(self.code, dst_local, length_expr))
            elif op.op == "GetType":
                dst_local = self.locals[op.df["dst"].value]
                src_local = source_locals[op.df["src"].value]
                block.statements.append(
                    IRAssign(self.code, dst_local, IRTypeOf(self.code, src_local, self.func.regs[op.df["dst"].value]))
                )
            elif op.op == "GetTID":
                dst_local = self.locals[op.df["dst"].value]
                src_local = source_locals[op.df["src"].value]
                block.statements.append(
                    IRAssign(
                        self.code, dst_local, IRTypeKind(self.code, src_local, self.func.regs[op.df["dst"].value])
                    )
                )
            elif op.op == "Incr":
                dst_local = self.locals[op.df["dst"].value]
                old_local = source_locals[op.df["dst"].value]
                block.statements.append(
                    IRAssign(
                        self.code,
                        dst_local,
                        IRArithmetic(
                            self.code,
                            old_local,
                            IRConst(self.code, IRConst.ConstType.INT, value=1),
                            IRArithmetic.ArithmeticType.ADD,
                        ),
                    )
                )
            elif op.op == "Decr":
                dst_local = self.locals[op.df["dst"].value]
                old_local = source_locals[op.df["dst"].value]
                block.statements.append(
                    IRAssign(
                        self.code,
                        dst_local,
                        IRArithmetic(
                            self.code,
                            old_local,
                            IRConst(self.code, IRConst.ConstType.INT, value=1),
                            IRArithmetic.ArithmeticType.SUB,
                        ),
                    )
                )
            elif op.op == "Neg":
                dst_local = self.locals[op.df["dst"].value]
                src_local = source_locals[op.df["src"].value]
                block.statements.append(IRAssign(self.code, dst_local, IRNeg(self.code, src_local)))
            elif op.op == "Not":
                dst_local = self.locals[op.df["dst"].value]
                src_local = source_locals[op.df["src"].value]
                block.statements.append(IRAssign(self.code, dst_local, IRNot(self.code, src_local)))
            elif op.op == "GetMem":
                dst_local = self.locals[op.df["dst"].value]
                arr_local = source_locals[op.df["bytes"].value]
                idx_local = source_locals[op.df["index"].value]
                block.statements.append(
                    IRAssign(
                        self.code,
                        dst_local,
                        IRArrayAccess(self.code, arr_local, idx_local, self.func.regs[op.df["dst"].value]),
                    )
                )
            elif op.op in ("GetI16", "GetI8"):
                dst_local = self.locals[op.df["dst"].value]
                arr_local = source_locals[op.df["bytes"].value]
                idx_local = source_locals[op.df["index"].value]
                block.statements.append(
                    IRAssign(
                        self.code,
                        dst_local,
                        IRArrayAccess(self.code, arr_local, idx_local, self.func.regs[op.df["dst"].value]),
                    )
                )
            elif op.op == "SetMem":
                arr_local = source_locals[op.df["bytes"].value]
                idx_local = source_locals[op.df["index"].value]
                src_local = source_locals[op.df["src"].value]
                block.statements.append(IRAssign(self.code, IRArrayAccess(self.code, arr_local, idx_local), src_local))
            elif op.op in ("SetI16", "SetI8"):
                arr_local = source_locals[op.df["bytes"].value]
                idx_local = source_locals[op.df["index"].value]
                src_local = source_locals[op.df["src"].value]
                block.statements.append(IRAssign(self.code, IRArrayAccess(self.code, arr_local, idx_local), src_local))
            elif op.op == "SetArray":
                arr_local = source_locals[op.df["array"].value]
                idx_local = source_locals[op.df["index"].value]
                src_local = source_locals[op.df["src"].value]
                block.statements.append(
                    IRAssign(self.code, IRArrayAccess(self.code, arr_local, idx_local, src_local.get_type()), src_local)
                )
            elif op.op == "DynSet":
                obj_local = source_locals[op.df["obj"].value]
                src_local = source_locals[op.df["src"].value]
                field_name = op.df["field"].resolve(self.code)
                field_expr = IRField(self.code, obj_local, field_name, self.func.regs[op.df["src"].value])
                block.statements.append(IRAssign(self.code, field_expr, src_local))
            elif op.op == "SetField":
                obj_local = source_locals[op.df["obj"].value]
                src_local = source_locals[op.df["src"].value]
                obj_type = obj_local.get_type()
                if isinstance(obj_type.definition, (Obj, Virtual)):
                    field_core = op.df["field"].resolve_obj(self.code, obj_type.definition)
                    field_expr = IRField(self.code, obj_local, field_core.name.resolve(self.code), field_core.type)
                    block.statements.append(IRAssign(self.code, field_expr, src_local))
                else:
                    block.statements.append(IRUnliftedOpcode(self.code, op))
            elif op.op == "Type":
                dst_local = self.locals[op.df["dst"].value]
                block.statements.append(
                    IRAssign(self.code, dst_local, IRConst(self.code, IRConst.ConstType.GLOBAL_OBJ, idx=op.df["ty"]))
                )
            elif op.op == "Ref":
                dst_local = self.locals[op.df["dst"].value]
                src_local = source_locals[op.df["src"].value]
                block.statements.append(IRAssign(self.code, dst_local, IRRef(self.code, src_local)))
            elif op.op == "Unref":
                # References are modelled transparently (IRRef renders as its
                # inner expression), so dereferencing one is just a copy of the
                # underlying value.
                dst_local = self.locals[op.df["dst"].value]
                src_local = source_locals[op.df["src"].value]
                block.statements.append(IRAssign(self.code, dst_local, src_local))
            elif op.op == "StaticClosure":
                dst_local = self.locals[op.df["dst"].value]
                fun_const = IRConst(self.code, IRConst.ConstType.FUN, idx=op.df["fun"])
                block.statements.append(IRAssign(self.code, dst_local, fun_const))
            elif op.op == "InstanceClosure":
                dst_local = self.locals[op.df["dst"].value]
                obj_local = source_locals[op.df["obj"].value]
                fun = op.df["fun"].resolve(self.code)
                method_name = self.code.partial_func_name(fun)
                field_expr = IRField(self.code, obj_local, method_name, self.func.regs[op.df["dst"].value])
                block.statements.append(IRAssign(self.code, dst_local, field_expr))
            elif op.op == "VirtualClosure":
                dst_local = self.locals[op.df["dst"].value]
                obj_local = source_locals[op.df["obj"].value]
                obj_type = obj_local.get_type()
                if isinstance(obj_type.definition, Obj):
                    fid = op.df["field"].value
                    if fid < len(obj_type.definition.virtuals):
                        from .core import fIndex

                        fun_idx = obj_type.definition.virtuals[fid]
                        fun_const = IRConst(self.code, IRConst.ConstType.FUN, idx=fIndex(fun_idx))
                        block.statements.append(IRAssign(self.code, dst_local, fun_const))
                    else:
                        block.statements.append(IRAssign(self.code, dst_local, IRUnliftedOpcode(self.code, op)))
                else:
                    block.statements.append(IRAssign(self.code, dst_local, IRUnliftedOpcode(self.code, op)))
            elif op.op == "NullCheck":
                continue
            elif op.op == "EnumIndex":
                dst_local = self.locals[op.df["dst"].value]
                src_local = source_locals[op.df["value"].value]
                block.statements.append(IRAssign(self.code, dst_local, IREnumIndex(self.code, src_local)))
            elif op.op == "MakeEnum":
                dst_local = self.locals[op.df["dst"].value]
                enum_type = self.func.regs[op.df["dst"].value]
                enum_def = enum_type.resolve(self.code).definition
                cid = op.df["construct"].value
                construct_name = (
                    enum_def.constructs[cid].name.resolve(self.code)
                    if cid < len(enum_def.constructs)
                    else f"construct_{cid}"
                )
                args = [source_locals[arg.value] for arg in op.df["args"].value]
                block.statements.append(
                    IRAssign(self.code, dst_local, IREnumConstruct(self.code, construct_name, args, enum_type))
                )
            elif op.op == "EnumField":
                dst_local = self.locals[op.df["dst"].value]
                src_local = source_locals[op.df["value"].value]
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
                    block.statements.append(IRAssign(self.code, dst_local, IRUnliftedOpcode(self.code, op)))
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

    def _is_terminal_branch_node(self, node: Optional[CFNode], loop_ctx: Optional[_LoopContext]) -> bool:
        """Return True if a branch target has no live successors within the current region."""
        if node is None:
            return True
        if loop_ctx is not None and node == loop_ctx.header:
            return False
        if not node.branches:
            return True
        # A node that only leaves the current region is also terminal for our purposes.
        if loop_ctx is not None:
            return all(successor not in loop_ctx.nodes for successor, _ in node.branches)
        return False

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

    def _clone_ir(self, block: IRBlock) -> IRBlock:
        """
        Clones a cached IRBlock so a memoized `_lift_block` result can be reused without
        making the same object reachable from multiple parents. `self.code` (the whole
        Bytecode) and `self.locals` (the register->IRLocal identities used throughout
        the function) are shared rather than duplicated; everything else in the
        statement/expression tree is copied. Hand-rolled instead of `copy.deepcopy`:
        deepcopy's generic `__reduce_ex__`/pickling-protocol dispatch is much slower
        than just walking `__dict__`, and this runs once per cache hit.
        """
        memo: Dict[int, Any] = {id(self.code): self.code}
        for local in self.locals:
            memo[id(local)] = local
        return cast(IRBlock, self._clone_value(block, memo))

    def _clone_value(self, value: Any, memo: Dict[int, Any]) -> Any:
        if value is None or isinstance(value, (int, float, str, bool, bytes, _Enum)):
            return value
        vid = id(value)
        if vid in memo:
            return memo[vid]
        if isinstance(value, list):
            new_list: List[Any] = []
            memo[vid] = new_list
            new_list.extend(self._clone_value(v, memo) for v in value)
            return new_list
        if isinstance(value, tuple):
            return tuple(self._clone_value(v, memo) for v in value)
        if isinstance(value, dict):
            new_dict: Dict[Any, Any] = {}
            memo[vid] = new_dict
            for k, v in value.items():
                new_dict[self._clone_value(k, memo)] = self._clone_value(v, memo)
            return new_dict
        if isinstance(value, set):
            new_set: Set[Any] = set()
            memo[vid] = new_set
            new_set.update(self._clone_value(v, memo) for v in value)
            return new_set
        if not hasattr(value, "__dict__"):
            # Unknown leaf type (e.g. a Bytecode/Function/Type reference) - share it.
            return value
        new_obj = object.__new__(type(value))
        memo[vid] = new_obj
        for k, v in vars(value).items():
            setattr(new_obj, k, self._clone_value(v, memo))
        return new_obj

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
        if loop_ctx and node not in loop_ctx.nodes and node.branches:
            block = IRBlock(self.code)
            block.statements.append(IRBreak(self.code))
            return block
        if node in self.cfg.loops and (loop_ctx is None or node != loop_ctx.header):
            return self._lift_loop(node, visited, stop_at, loop_ctx)

        # Memoize on (node, stop_at, loop_ctx): without this, CFGs where many branches
        # funnel into a small set of shared continuation points cause the same
        # (node, stop_at) region to be re-lifted independently from every branch that
        # reaches it, which is exponential in the nesting depth of the function. Since
        # loops are handled separately above, everything reachable here is acyclic, so
        # the *logical content* for an identical (node, stop_at, loop_ctx) request never
        # depends on which ancestor path got there. We still hand back a fresh clone
        # rather than the cached object itself: returning the same instance would make
        # the IR a real DAG, and nothing downstream (repr(), pprint(), the optimizer
        # passes' generic statement walk) expects a node to be reachable from multiple
        # parents, so they would re-render/re-process the shared subtree once per
        # reference path - the same exponential blowup we're trying to avoid, just
        # moved into every later consumer instead of the lifter.
        # _LoopContext is a non-frozen @dataclass, so it's unhashable; key on identity instead.
        cache_key = (node, stop_at, id(loop_ctx))
        cached = self._lift_cache.get(cache_key)
        if cached is not None:
            visited.add(node)
            return self._clone_ir(cached)

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
                    jump_target = branch_node  # jump target = else block in source
                elif edge_type == "false":
                    fall_through = branch_node  # fall-through = then block in source

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
                    # A return inside a loop is not a loop break; let the normal
                    # Ret handler lift it as an IRReturn.  The exception is the
                    # loop's own exit node, which post-dominates the header and
                    # therefore represents leaving the loop normally.
                    if (
                        not target.branches
                        and target.ops
                        and target.ops[-1].op == "Ret"
                        and loop_ctx.header not in self.cfg.post_dominators.get(target, set())
                    ):
                        return None
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

            # If the branches do not share a real convergence point because one of
            # them terminates (e.g. returns), use the post-dominator of the live
            # branch as the convergence.  This keeps the code after the terminating
            # branch outside the conditional instead of inlining it into the other
            # branch.
            if convergence_node is None:
                terminal_left = self._is_terminal_branch_node(jump_target, loop_ctx)
                terminal_right = self._is_terminal_branch_node(fall_through, loop_ctx)
                if terminal_left and not terminal_right and fall_through in self.cfg.immediate_post_dominators:
                    convergence_node = self.cfg.immediate_post_dominators[fall_through]
                elif terminal_right and not terminal_left and jump_target in self.cfg.immediate_post_dominators:
                    convergence_node = self.cfg.immediate_post_dominators[jump_target]

            # If no convergence point could be determined at all, never let a branch
            # explore past the boundary the *enclosing* call already established. Without
            # this, a live branch recurses with stop_at=None and re-walks the entire rest
            # of the function independently of the outer continuation, which re-walks the
            # same nodes again - doubling work at every such conditional and blowing up
            # exponentially for long chains of terminal-vs-live branches.
            if convergence_node is None:
                convergence_node = stop_at

            if then_block_ir is None:
                then_block_ir = self._lift_block(
                    fall_through, visited.copy(), stop_at=convergence_node, loop_ctx=loop_ctx
                )
            if else_block_ir is None:
                else_block_ir = self._lift_block(
                    jump_target, visited.copy(), stop_at=convergence_node, loop_ctx=loop_ctx
                )

            conditional_stmt = IRConditional(self.code, cond_expr, then_block_ir, else_block_ir)
            block.statements.append(conditional_stmt)

            # Continue lifting from the convergence point, but stop at the outer boundary.
            # This prevents the convergence node from being consumed here when it equals
            # the outer stop_at, which would leave the outer caller with nothing to lift.
            next_block_ir = self._lift_block(convergence_node, visited, stop_at=stop_at, loop_ctx=loop_ctx)
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
                case_block_ir = self._lift_block(
                    target_node, visited.copy(), stop_at=convergence_node, loop_ctx=loop_ctx
                )
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

            try_block_ir = self._lift_block(
                try_branch_node, visited.copy(), stop_at=convergence_node, loop_ctx=loop_ctx
            )
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

        self._lift_cache[cache_key] = block
        return block

    def print(self) -> None:
        print(self.block.pprint())


class IRClass:
    """
    Intermediate representation of a class.
    """

    def __init__(self, code: Bytecode, obj: Obj, capture_layers: bool = False) -> None:
        self.code = code
        self.capture_layers = capture_layers
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
            res.append(IRFunction(self.code, fn, capture_layers=self.capture_layers))
        for binding in obj.bindings:
            fn = binding.findex.resolve(self.code)
            assert isinstance(fn, Function), "Native bindings aren't supported! Not even sure if this is possible tbh"
            # Avoid adding duplicates if a proto is also bound
            if fn not in [r.func for r in res]:
                res.append(IRFunction(self.code, fn, capture_layers=self.capture_layers))
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
