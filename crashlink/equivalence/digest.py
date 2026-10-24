"""Turn a value graph into a hash that depends only on what the function does."""

from __future__ import annotations

import hashlib
import re
from typing import Dict, List, Set, Tuple

from ..core import Bytecode, Function
from .build import Built, Node, build
from .lift import Unsupported, lift
from .names import Namer

# ============================================================================
# digest
# ============================================================================

_DIGEST_COMMUTATIVE = frozenset({"Add", "Mul", "And", "Or", "Xor"})


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
                if node.kind == "lin":
                    # attrs = (type, constant, coefficients): the terms are a set, whatever order they were built in
                    desc, const, coeffs = node.attrs[0], node.attrs[1], node.attrs[2]
                    assert isinstance(coeffs, tuple)
                    self.memo[node.id] = _h(("lin", desc, const, tuple(sorted(zip(coeffs, children)))))
                    continue
                if node.kind == "catchmem":
                    children = sorted(set(children))  # one of these histories
                elif node.kind == "catchval":
                    # (history, value) pairs: the value is the one written before that point
                    children = sorted(zip(children[0::2], children[1::2]))  # type: ignore[assignment]
                elif node.kind in _DIGEST_COMMUTATIVE:
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


# ============================================================================
# explain
#
# Readable rendering of the canonical form a signature is computed from, for diffing two functions.
# ============================================================================


def explain(code: Bytecode, func: Function, *, strict: bool = True, depth: int = 6) -> str:
    from . import _signer

    namer = Namer(code, _signer(code, strict, True)._anon_digest)
    lifted = lift(func.ops, [t.value for t in func.regs], namer)
    built = build(code, func, lifted, namer, strict)
    return f"type: {namer.type_index(func.type.value)}\n" + render(built, depth)


def render(built: Built, limit: int = 6) -> str:
    g = built.graph
    lines: List[str] = []
    for b, block in enumerate(built.lifted.blocks):
        names: Dict[int, str] = {}

        def show(node: Node, depth: int = 0) -> str:
            node = g.find(node)
            if node.id in names:
                return names[node.id]
            if node.kind == "phi":
                return f"phi[b{node.block}:{node.ty}]"
            if node.kind in (
                "int",
                "str",
                "float",
                "null",
                "param",
                "global",
                "type",
                "entrymem",
                "excmem",
                "exc",
                "undef",
            ):
                return f"{node.kind}{node.attrs}".replace("'", "")
            if depth > limit:
                return "..."
            inner = ", ".join(show(a, depth + 1) for a in node.args)
            attrs = "" if not node.attrs else str(node.attrs).replace("'", "")
            return f"{node.kind}{attrs}({inner})"

        chain: List[Node] = []
        node = g.find(built.exit_mem[b])
        while node.kind not in ("phi", "entrymem", "excmem"):
            chain.append(node)
            node = g.find(node.args[0])
        chain.reverse()
        term = block.term
        lines.append(f"b{b}: preds={built.lifted.preds[b]}")
        for i, e in enumerate(chain):
            names[e.id] = f"@{i}"
            args = ", ".join(show(a) for a in e.args[1:])
            attrs = "" if not e.attrs else str(e.attrs).replace("'", "")
            lines.append(f"    @{i} = {e.kind}{attrs}({args})")
        operands = ", ".join(show(n) for n in built.term_nodes[b])
        lines.append(f"    -> {term.kind} {term.pred} ({operands}) {term.succs}")
    return re.sub(r"\b[0-9a-f]{32}\b", lambda m: m.group(0)[:6], "\n".join(lines))
