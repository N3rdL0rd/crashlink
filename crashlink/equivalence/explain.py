"""Readable rendering of the canonical form a signature is computed from, for diffing two functions."""

from __future__ import annotations

from typing import Dict, List

from ..core import Bytecode, Function
from .build import Built, build
from .lift import check_trap_handlers, lift
from .names import Namer
from .terms import Node


def explain(code: Bytecode, func: Function, *, strict: bool = True) -> str:
    namer = Namer(code, lambda f: "anon")
    lifted = lift(func.ops, [t.value for t in func.regs], namer)
    check_trap_handlers(lifted)
    built = build(code, func, lifted, namer, strict)
    return render(built)


def render(built: Built) -> str:
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
            if depth > 6:
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
    return "\n".join(lines)
