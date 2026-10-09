"""Turn a value graph into a hash that depends only on what the function does.

Pure nodes hash from their kind and the hashes of their operands (sorted, for commutative ones).
A phi is the one place a value can depend on itself (a loop counter), so its hash is found by
colour refinement: start from the block it is in and the type it holds, then repeatedly fold in
the hashes of what flows into it until no two phis are told apart any further. For graphs whose
edges are ordered and labelled this is exactly bisimulation: two values get the same colour if and
only if they unfold to the same infinite term, which is what makes equal digests mean equal
behaviour.
"""

from __future__ import annotations

import hashlib
from typing import Dict, List, Set, Tuple

from .build import Built
from .lift import Unsupported
from .terms import Node

COMMUTATIVE = frozenset({"Add", "Mul", "And", "Or", "Xor"})


def _h(value: object) -> str:
    return hashlib.blake2b(repr(value).encode("utf-8", "surrogatepass"), digest_size=16).hexdigest()


class _Digester:
    def __init__(self, built: Built, colors: Dict[int, str]) -> None:
        self.g = built.graph
        self.colors = colors
        self.memo: Dict[int, str] = {}

    def __call__(self, root: Node) -> str:
        g = self.g
        root = g.find(root)
        stack: List[Tuple[Node, bool]] = [(root, False)]
        active: Set[int] = set()
        while stack:
            node, expanded = stack.pop()
            node = g.find(node)
            if node.id in self.memo:
                continue
            if node.kind == "phi":
                self.memo[node.id] = self.colors[node.id]
                continue
            if node.kind == "lazy":
                raise Unsupported("an object that was never emitted")
            if expanded:
                active.discard(node.id)
                children = [self.memo[g.find(a).id] for a in node.args]
                if node.kind in COMMUTATIVE:
                    children.sort()
                self.memo[node.id] = _h((node.kind, node.attrs, tuple(children)))
                continue
            if node.id in active:
                raise Unsupported("a value defined in terms of itself")
            active.add(node.id)
            stack.append((node, True))
            for a in node.args:
                a = g.find(a)
                if a.id not in self.memo:
                    stack.append((a, False))
        return self.memo[root.id]


def digest(built: Built, header: object) -> str:
    g = built.graph
    lifted = built.lifted
    roots: List[Node] = []
    for mem in built.exit_mem:
        roots.append(mem)
    for nodes in built.term_nodes:
        roots.extend(nodes)

    # Everything reachable from the roots; only phis among them take part in refinement.
    seen: Set[int] = set()
    phis: List[Node] = []
    stack = [g.find(r) for r in roots]
    while stack:
        node = g.find(stack.pop())
        if node.id in seen:
            continue
        seen.add(node.id)
        if node.kind == "phi":
            phis.append(node)
        stack.extend(node.args)
    phis.sort(key=lambda n: n.id)

    colors: Dict[int, str] = {p.id: _h(("phi", p.block, p.ty)) for p in phis}
    count = len(set(colors.values()))
    while True:
        d = _Digester(built, colors)
        fresh = {p.id: _h((colors[p.id], tuple(d(a) for a in p.args))) for p in phis}
        fresh_count = len(set(fresh.values()))
        colors = fresh
        if fresh_count == count:
            break
        count = fresh_count

    d = _Digester(built, colors)
    records: List[object] = [header]
    for b, block in enumerate(lifted.blocks):
        term = block.term
        operands = [d(n) for n in built.term_nodes[b]]
        if term.pred == "eq":
            operands.sort()
        records.append((b, term.kind, term.pred, term.succs, tuple(operands), d(built.exit_mem[b])))
    records.append(tuple(sorted({_h((colors[p.id], tuple(d(a) for a in p.args))) for p in phis})))
    return _h(tuple(records))
