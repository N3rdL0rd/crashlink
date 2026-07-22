"""
Control-flow graph construction and optimization.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Set, Tuple

from ..core import (
    Bytecode,
    Function,
    Opcode,
)
from ..globals import DEBUG, dbg_print
from .. import disasm


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
