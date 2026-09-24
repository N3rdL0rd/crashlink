"""
Control-flow graph construction and optimization.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Set, Tuple

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
        # Resolve whole chains before mutating edges. Keep every member of a
        # jump-only cycle: removing its last node would erase an infinite loop.
        jumps = {
            node: node.branches[0][0]
            for node in self.graph.nodes
            if len(node.ops) == 1 and node.ops[0].op == "JAlways" and len(node.branches) == 1
        }
        resolved: Dict[CFNode, CFNode] = {}
        for start in jumps:
            path: List[CFNode] = []
            positions: Dict[CFNode, int] = {}
            node = start
            while node in jumps and node not in resolved and node not in positions:
                positions[node] = len(path)
                path.append(node)
                node = jumps[node]
            if node in positions:
                cycle_start = positions[node]
                for member in path[cycle_start:]:
                    resolved[member] = member
                path = path[:cycle_start]
            target = resolved.get(node, node)
            for member in reversed(path):
                resolved[member] = target

        for node in self.graph.nodes:
            node.branches = [(resolved.get(dst, dst), kind) for dst, kind in node.branches]
        if self.graph.entry is not None:
            self.graph.entry = resolved.get(self.graph.entry, self.graph.entry)
        self.graph.nodes = [node for node in self.graph.nodes if resolved.get(node, node) is node]


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


def _immediate_dominators(
    root: CFNode,
    successors: Callable[[CFNode], List[CFNode]],
    predecessors: Callable[[CFNode], Optional[List[CFNode]]],
) -> Dict[CFNode, CFNode]:
    """Immediate dominators of every node reachable from `root` (Cooper, Harvey and Kennedy,
    "A Simple, Fast Dominance Algorithm"). The root maps to itself."""
    order: List[CFNode] = []  # postorder
    seen = {root}
    stack = [(root, iter(successors(root)))]
    while stack:
        node, it = stack[-1]
        for nxt in it:
            if nxt not in seen:
                seen.add(nxt)
                stack.append((nxt, iter(successors(nxt))))
                break
        else:
            stack.pop()
            order.append(node)
    order.reverse()  # reverse postorder
    index = {node: i for i, node in enumerate(order)}
    idom: Dict[CFNode, CFNode] = {root: root}

    def intersect(a: CFNode, b: CFNode) -> CFNode:
        while a is not b:
            while index[a] > index[b]:
                a = idom[a]
            while index[b] > index[a]:
                b = idom[b]
        return a

    changed = True
    while changed:
        changed = False
        for node in order[1:]:
            new: Optional[CFNode] = None
            for pred in predecessors(node) or ():
                if pred in idom:
                    new = pred if new is None else intersect(pred, new)
            if new is not None and idom.get(node) is not new:
                idom[node] = new
                changed = True
    return idom


class _DominatorSet:
    """One node's (post-)dominators: the node and its ancestors in the dominator tree.
    A read-only set view: membership is O(1) and nothing is materialised."""

    __slots__ = ("_map", "_node")

    def __init__(self, dmap: "_DominatorMap", node: CFNode) -> None:
        self._map = dmap
        self._node = node

    def __contains__(self, other: object) -> bool:
        return self._map.dominates(other, self._node)

    def __len__(self) -> int:
        return self._map.size(self._node)

    def __iter__(self) -> Iterator[CFNode]:
        return self._map.chain(self._node)

    def issuperset(self, other: Iterable[CFNode]) -> bool:
        return all(node in self for node in other)

    def __repr__(self) -> str:
        return f"<dominators of {self._node.base_offset}: {sorted(n.base_offset for n in self)}>"


class _DominatorMap(Mapping[CFNode, _DominatorSet]):
    """node -> its dominator set, backed by the dominator tree (`idom`). Nodes the tree's
    root doesn't reach are dominated by every node, matching the iterative fixpoint."""

    def __init__(self, nodes: List[CFNode], idom: Dict[CFNode, CFNode], root: CFNode) -> None:
        self._nodes = nodes
        self._node_set = set(nodes)
        self._idom = idom
        self._root = root
        # Pre/post numbering of the tree gives O(1) ancestor tests; depth gives set sizes.
        children: Dict[CFNode, List[CFNode]] = {}
        for node, parent in idom.items():
            if node is not root:
                children.setdefault(parent, []).append(node)
        self._pre: Dict[CFNode, int] = {}
        self._post: Dict[CFNode, int] = {}
        self._size: Dict[CFNode, int] = {}
        counter = 0
        root_counts = root in self._node_set  # a virtual root isn't part of any set
        stack: List[Tuple[CFNode, bool]] = [(root, False)]
        while stack:
            node, leaving = stack.pop()
            if leaving:
                self._post[node] = counter
                counter += 1
                continue
            self._pre[node] = counter
            counter += 1
            parent_size = self._size[idom[node]] if node is not root else (0 if root_counts else -1)
            self._size[node] = parent_size + 1
            stack.append((node, True))
            stack.extend((child, False) for child in children.get(node, ()))

    def dominates(self, a: object, b: CFNode) -> bool:
        if not isinstance(a, CFNode) or a not in self._node_set:
            return False
        if b not in self._pre:  # unreached: dominated by every node
            return True
        pre_a = self._pre.get(a)
        return pre_a is not None and pre_a <= self._pre[b] and self._post[b] <= self._post[a]

    def size(self, node: CFNode) -> int:
        return self._size[node] if node in self._pre else len(self._nodes)

    def chain(self, node: CFNode) -> Iterator[CFNode]:
        if node not in self._pre:
            yield from self._nodes
            return
        while True:
            if node in self._node_set:
                yield node
            if node is self._root:
                return
            node = self._idom[node]

    def immediate(self, node: CFNode) -> Optional[CFNode]:
        """Parent in the tree (None for the root, or when the parent is a virtual root).
        For an unreached node, which every node dominates, the nearest other unreached node
        by offset stands in (the old iterative code picked one arbitrarily)."""
        if node in self._pre:
            parent = self._idom[node]
            return parent if parent is not node and parent in self._node_set else None
        others = [n for n in self._nodes if n is not node and n not in self._pre]
        if others:
            return min(others, key=lambda n: (abs(n.base_offset - node.base_offset), n.base_offset))
        reached = [n for n in self._nodes if n in self._pre]
        return max(reached, key=lambda n: (self._size[n], -n.base_offset)) if reached else None

    def __getitem__(self, node: CFNode) -> _DominatorSet:
        if node not in self._node_set:
            raise KeyError(node)
        return _DominatorSet(self, node)

    def __iter__(self) -> Iterator[CFNode]:
        return iter(self._nodes)

    def __len__(self) -> int:
        return len(self._nodes)


def loop_post_dominators(header: CFNode, loop_nodes: Set[CFNode]) -> "_DominatorMap":
    """Post-dominators within one loop body: a jump back to `header` (a continue), an edge
    leaving the loop, and a return/throw all end a path. So a node's post-dominator here
    is where every path through the current iteration that doesn't leave it early meets."""
    virtual_exit = CFNode([])
    exits = [
        n
        for n in loop_nodes
        if not n.branches or any(t is header or t not in loop_nodes for t, _ in n.branches)
    ]
    preds: Dict[CFNode, List[CFNode]] = {n: [] for n in loop_nodes}
    for n in loop_nodes:
        for t, _ in n.branches:
            if t is not header and t in loop_nodes:
                preds[t].append(n)

    def successors(node: CFNode) -> List[CFNode]:  # in the reversed graph
        return exits if node is virtual_exit else preds.get(node, [])

    def predecessors(node: CFNode) -> List[CFNode]:  # in the reversed graph
        out = [virtual_exit if (t is header or t not in loop_nodes) else t for t, _ in node.branches]
        return out or [virtual_exit]

    ordered = sorted(loop_nodes, key=lambda n: n.base_offset)
    return _DominatorMap(
        ordered, _immediate_dominators(virtual_exit, successors, predecessors), root=virtual_exit
    )


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
        self.dominators: Mapping[CFNode, _DominatorSet] = {}
        # Maps loop_header_node -> Set[nodes_in_loop]
        self.loops: Dict[CFNode, Set[CFNode]] = {}
        # Maps node -> Set[post_dominator_nodes]
        self.post_dominators: Mapping[CFNode, _DominatorSet] = {}
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
            elif op.op == "Switch":
                for offset in op.df["offsets"].value:
                    jump_targets.add(i + offset.value + 1)

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
                        "Trap", "EndTrap", "Throw", "Rethrow"]:
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
                next_node = nodes_by_idx[next_idx]
                # A throw never continues into its paired EndTrap; that edge
                # would let the trap's catch entry pose as the try/catch
                # convergence point and leave the catch block empty. Every
                # other successor keeps the edge (it is what lets `if (...) throw;`
                # restructure with the throw as the if-body).
                if last_op.op in ("Throw", "Rethrow") and next_node.ops and next_node.ops[0].op == "EndTrap":
                    pass
                else:
                    self.add_branch(
                        src_node, next_node, "unconditional")

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
                    dbg_print(
                        f"Conditional node {node.base_offset} converges at {ipd.base_offset if ipd else 'None'}"
                    )
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
        Computes each node's dominators: 'd' dominates 'n' if every path from entry to 'n'
        passes through 'd'. A node the entry can't reach is dominated by every node (the
        fixpoint the classic iterative formulation leaves it at).
        """
        if not self.entry:
            return
        idom = _immediate_dominators(self.entry, lambda n: [t for t, _ in n.branches], self.predecessors.get)
        self.dominators = _DominatorMap(self.nodes, idom, root=self.entry)

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
        Computes post-dominators ('p' post-dominates 'n' if every path from 'n' to an exit
        passes through 'p') as dominators of the reversed graph, whose root is a virtual
        node joining every exit. A node that can't reach an exit is post-dominated by every
        node, as in the classic iterative formulation.
        """
        exit_nodes = [n for n in self.nodes if not n.branches]
        if not exit_nodes:
            # Graph with an infinite loop and no exit
            self.post_dominators = {}
            return

        virtual_exit = CFNode([])
        preds = self.predecessors

        def successors(node: CFNode) -> List[CFNode]:  # in the reversed graph
            return exit_nodes if node is virtual_exit else preds.get(node, [])

        def predecessors(node: CFNode) -> List[CFNode]:  # in the reversed graph
            return [t for t, _ in node.branches] or [virtual_exit]

        idom = _immediate_dominators(virtual_exit, successors, predecessors)
        self.post_dominators = _DominatorMap(self.nodes, idom, root=virtual_exit)

    def _find_immediate_post_dominators(self) -> None:
        """
        Calculates the immediate post-dominator for each node: its parent in the
        post-dominator tree, or None when only the (virtual) exit post-dominates it.
        """
        if not self.post_dominators:
            return
        pdoms = self.post_dominators
        assert isinstance(pdoms, _DominatorMap)
        self.immediate_post_dominators = {n: pdoms.immediate(n) for n in self.nodes}

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
