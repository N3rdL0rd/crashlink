"""
Decompilation and control flow graph generation
"""

from abc import ABC, abstractmethod
from typing import Callable, Dict, List, Optional, Set, Tuple

from .core import *
from .errors import *
from .globals import dbg_print
from .opcodes import opcodes
from . import disasm


class CFNode:
    """
    A control flow node.
    """

    def __init__(self, ops: List[Opcode]):
        self.ops = ops
        self.branches: List[Tuple[CFNode, str]] = []
        self.base_offset: int = 0

    def __repr__(self):
        return "<CFNode: %s>" % self.ops


class CFOptimizer:
    """
    Base class for control flow graph optimizers.
    """

    def __init__(self, graph: "CFGraph"):
        self.graph = graph

    def optimize(self):
        raise NotImplementedError()


class CFJumpThreader(CFOptimizer):
    """
    Thread jumps to reduce the number of nodes in the graph.
    """

    def optimize(self):
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

    def optimize(self):
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

    def add_node(self, ops: List[Opcode], base_offset: int = 0) -> CFNode:
        node = CFNode(ops)
        self.nodes.append(node)
        node.base_offset = base_offset
        return node

    def add_branch(self, src: CFNode, dst: CFNode, edge_type: str):
        src.branches.append((dst, edge_type))

    def build(self, do_optimize: bool = True):
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
                jump_targets.add(i + op.definition["offset"].value + 1)

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
                
                jump_idx = start_idx + len(ops) + last_op.definition["offset"].value
                
                # - jump target is "true" branch
                # - fall-through is "false" branch
                    
                if jump_idx in nodes_by_idx:
                    edge_type = "true"
                    self.add_branch(src_node, nodes_by_idx[jump_idx], edge_type)
                    
                if next_idx in nodes_by_idx:
                    edge_type = "false" 
                    self.add_branch(src_node, nodes_by_idx[next_idx], edge_type)
            
            elif last_op.op == "Switch":
                for i, offset in enumerate(last_op.definition['offsets'].value):
                    if offset.value != 0:
                        jump_idx = start_idx + len(ops) + offset.value
                        self.add_branch(src_node, nodes_by_idx[jump_idx], f"switch: case: {i} ")
                if next_idx in nodes_by_idx:
                    self.add_branch(src_node, nodes_by_idx[next_idx], "switch: default")
            
            elif last_op.op == "Trap":
                jump_idx = start_idx + len(ops) + last_op.definition["offset"].value
                if jump_idx in nodes_by_idx:
                    self.add_branch(src_node, nodes_by_idx[jump_idx], "trap")
                if next_idx in nodes_by_idx:
                    self.add_branch(src_node, nodes_by_idx[next_idx], "fall-through")
            
            elif last_op.op == "EndTrap":
                if next_idx in nodes_by_idx:
                    self.add_branch(src_node, nodes_by_idx[next_idx], "endtrap")
            
            elif last_op.op == "JAlways":
                jump_idx = start_idx + len(ops) + last_op.definition["offset"].value
                if jump_idx in nodes_by_idx:
                    self.add_branch(src_node, nodes_by_idx[jump_idx], "unconditional")
            elif last_op.op != "Ret" and next_idx in nodes_by_idx:
                self.add_branch(src_node, nodes_by_idx[next_idx], "unconditional")

        # fmt: off
        self.optimize([
            CFJumpThreader(self),
            CFDeadCodeEliminator(self),
        ])
        # fmt: on

    def optimize(self, optimizers: List[CFOptimizer]):
        for optimizer in optimizers:
            if optimizer not in self.applied_optimizers:
                optimizer.optimize()
                self.applied_optimizers.append(optimizer)

    def style_node(self, node: CFNode):
        if node == self.entry:
            return "style=filled, fillcolor=pink1"
        for op in node.ops:
            if op.op == "Ret":
                return "style=filled, fillcolor=aquamarine"
        return "style=filled, fillcolor=lightblue"

    def graph(self, code: Bytecode):
        """Generate DOT format graph visualization."""
        dot = ["digraph G {"]
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


class IRNode(ABC):
    """Base class for all IR nodes"""

    def __init__(self):
        self.parent: Optional[IRNode] = None

    @abstractmethod
    def accept(self, visitor: "IRVisitor") -> None:
        pass


class IRVisitor(ABC):
    """Base visitor for IR nodes"""

    @abstractmethod
    def visit_statement(self, stmt: "IRStatement") -> None:
        pass

    @abstractmethod
    def visit_expression(self, expr: "IRExpression") -> None:
        pass
    
    @abstractmethod
    def visit_if(self, stmt: "IRIf") -> None:
        pass
    
    @abstractmethod
    def visit_loop(self, stmt: "IRLoop") -> None:
        pass
    
    @abstractmethod
    def visit_switch(self, stmt: "IRSwitch") -> None:
        pass


class IRStatement(IRNode):
    """Base class for IR statements"""

    pass


class IRExpression(IRNode):
    """Base class for IR expressions"""

    pass


class IRControlFlow(IRStatement):
    """Base class for control flow statements"""

    pass


class IRIf(IRControlFlow):
    def __init__(
        self, condition: IRExpression, then_block: List[IRStatement], else_block: Optional[List[IRStatement]] = None
    ):
        super().__init__()
        self.condition = condition
        self.then_block = then_block
        self.else_block = else_block

    def accept(self, visitor: IRVisitor):
        visitor.visit_if(self)


class IRLoop(IRControlFlow):
    def __init__(self, condition: IRExpression, body: List[IRStatement]):
        super().__init__()
        self.condition = condition
        self.body = body

    def accept(self, visitor: IRVisitor):
        visitor.visit_loop(self)


class IRSwitch(IRControlFlow):
    def __init__(
        self, value: IRExpression, cases: Dict[int, List[IRStatement]], default: Optional[List[IRStatement]] = None
    ):
        super().__init__()
        self.value = value
        self.cases = cases
        self.default = default

    def accept(self, visitor: IRVisitor):
        visitor.visit_switch(self)


class InlineOp(IRStatement):
    """Inline opcode in IR"""

    def __init__(self, op: Opcode):
        super().__init__()
        self.op = op

    def accept(self, visitor: IRVisitor):
        visitor.visit_statement(self)


class IRLifter:
    """Lifts opcodes to IR"""

    def __init__(self):
        self.lifters: Dict[str, Callable] = {}
        self._register_lifters()

    def register(self, opcode: str, lifter: Callable):
        """Register a lifter for an opcode"""
        self.lifters[opcode] = lifter

    def _register_lifters(self):
        for opcode in opcodes:
            if hasattr(self, f"lift_{opcode.lower()}"):
                self.register(opcode, getattr(self, f"lift_{opcode.lower()}"))

    def lift(self, op: Opcode) -> IRNode:
        """Lift an opcode to IR"""
        if op.op not in self.lifters:
            print(f"Warning: No lifter for {op.op}")
            return InlineOp(op)
        return self.lifters[op.op](op)
    
    def lift_switch(self, op: Opcode) -> IRSwitch:
        # TODO
        pass

class IRLocal:
    def __init__(self, name: str, type: tIndex):
        self.name = name
        self.type = type

    def __repr__(self):
        return f"<IRLocal: {self.name} {self.type}>"


class IRFunction:
    def __init__(self, code: Bytecode, func: Function):
        self.func = func
        self.cfg = CFGraph(func)
        self.cfg.build()
        self.code = code
        self.ops = func.ops
        self.statements: List[IRStatement] = []
        self.lifter = IRLifter()
        self.locals: List[IRLocal] = []
        self._lift()

    def _lift(self):
        """Lift function to IR"""
        for i, reg in enumerate(self.func.regs):
            self.locals.append(IRLocal(f"reg{i}", reg))
        self._name_locals()
        for node in self.cfg.nodes:
            for op in node.ops:
                ir_node = self.lifter.lift(op)
                if isinstance(ir_node, IRStatement):
                    self.statements.append(ir_node)

    def _name_locals(self):
        """Name locals based on debug info"""
        reg_assigns: List[Set[str]] = [set() for _ in self.func.regs]
        if self.func.has_debug and self.func.assigns:
            for assign in self.func.assigns:
                val = assign[1].value - 1
                # Tuple[strRef (name), VarInt (op index)]
                if val < 0:
                    continue  # TODO: handle this - negative indexes are argument names
                reg: Optional[int] = None
                op = self.ops[val]
                try:
                    op.definition["dst"]
                    reg = op.definition["dst"].value
                except KeyError:
                    pass
                if reg is not None:
                    reg_assigns[reg].add(assign[0].resolve(self.code))
        for i, _reg in enumerate(self.func.regs):
            if _reg.resolve(self.code).definition and isinstance(_reg.resolve(self.code).definition, Void):
                reg_assigns[i].add("void")
        dbg_print("Named regs:", reg_assigns)
        for i, local in enumerate(self.locals):
            if reg_assigns[i] and len(reg_assigns[i]) == 1:
                local.name = reg_assigns[i].pop()