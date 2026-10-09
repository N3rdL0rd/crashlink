"""The value graph a function is summarised as.

A node is either a pure value (equal operands give an equal node, so they are shared), an effect
(unique: it happens once, in order, and carries the effect before it), or a phi (the value a
variable has on entry to a join). Nothing here knows about opcodes.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple, Union

Var = Union[int, str]
"""A register number, or "mem" for the chain of effects."""

COMMUTATIVE = frozenset({"Add", "Mul", "And", "Or", "Xor", "eq"})


class Node:
    __slots__ = ("id", "kind", "attrs", "args", "nonnull", "ty", "block", "var")

    def __init__(
        self,
        id: int,
        kind: str,
        attrs: Tuple[object, ...],
        args: List["Node"],
        nonnull: bool,
        ty: str,
    ) -> None:
        self.id = id
        self.kind = kind
        self.attrs = attrs
        self.args = args
        self.nonnull = nonnull
        self.ty = ty
        self.block = -1
        self.var: Optional[Var] = None

    def __repr__(self) -> str:
        if self.kind == "phi":
            return f"<phi#{self.id} b{self.block} {self.var}>"
        inner = ",".join(f"#{a.id}" for a in self.args)
        return f"<{self.kind}#{self.id} {self.attrs} ({inner})>"


class Graph:
    def __init__(self) -> None:
        self.nodes: List[Node] = []
        self._consed: Dict[Tuple[object, ...], Node] = {}
        self._alias: Dict[int, Node] = {}

    def _new(self, kind: str, attrs: Tuple[object, ...], args: List[Node], nonnull: bool, ty: str) -> Node:
        node = Node(len(self.nodes), kind, attrs, args, nonnull, ty)
        self.nodes.append(node)
        return node

    def pure(
        self, kind: str, attrs: Tuple[object, ...], *args: Node, nonnull: bool = False, ty: str = ""
    ) -> Node:
        key = (kind, attrs, tuple(self.find(a).id for a in args))
        found = self._consed.get(key)
        if found is not None:
            return found
        node = self._new(kind, attrs, list(args), nonnull, ty)
        self._consed[key] = node
        return node

    def effect(
        self, kind: str, attrs: Tuple[object, ...], *args: Node, nonnull: bool = False, ty: str = ""
    ) -> Node:
        return self._new(kind, attrs, list(args), nonnull, ty)

    def phi(self, block: int, var: Var, ty: str) -> Node:
        node = self._new("phi", (), [], False, ty)
        node.block = block
        node.var = var
        return node

    # -- aliases (a phi that always takes one value *is* that value) ---------------------------

    def find(self, node: Node) -> Node:
        while node.id in self._alias:
            node = self._alias[node.id]
        return node

    def alias(self, node: Node, target: Node) -> None:
        self._alias[node.id] = target

    def simplify_phis(self) -> None:
        """Replace phis whose operands all come down to one other value."""
        phis = [n for n in self.nodes if n.kind == "phi"]
        while True:
            external: Dict[int, Optional[set]] = {}
            # `external[p]` = the non-phi values reachable through chains of phi operands
            sets: Dict[int, set] = {p.id: set() for p in phis}
            changed = True
            while changed:
                changed = False
                for p in phis:
                    if p.id in self._alias:
                        continue
                    acc = sets[p.id]
                    before = len(acc)
                    for operand in p.args:
                        operand = self.find(operand)
                        if operand.kind == "phi":
                            acc |= sets[operand.id]
                        else:
                            acc.add(operand.id)
                    if len(acc) != before:
                        changed = True
            del external
            done = True
            for p in phis:
                if p.id in self._alias:
                    continue
                if len(sets[p.id]) == 1:
                    (only,) = sets[p.id]
                    self.alias(p, self.nodes[only])
                    done = False
            if done:
                return
