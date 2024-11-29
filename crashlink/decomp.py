"""
Decompilation and control flow graph generation
"""

from abc import ABC, abstractmethod
from enum import Enum as _Enum  # Enum is already defined in crashlink.core
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from . import disasm
from .core import *
from .errors import *
from .globals import dbg_print
from .opcodes import opcodes


class CFNode:
    """
    A control flow node.
    """

    def __init__(self, ops: List[Opcode]):
        self.ops = ops
        self.branches: List[Tuple[CFNode, str]] = []
        self.base_offset: int = 0

    def __repr__(self) -> str:
        return "<CFNode: %s>" % self.ops


class CFOptimizer:
    """
    Base class for control flow graph optimizers.
    """

    def __init__(self, graph: "CFGraph"):
        self.graph = graph

    def optimize(self) -> None:
        raise NotImplementedError()


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


class IRLocal:
    def __init__(self, name: str, type: tIndex, code: Optional[Bytecode] = None):
        self.name = name
        self.type = type
        self.code = code

    def __repr__(self) -> str:
        return f"<IRLocal: {self.name} {disasm.type_name(self.code, self.type.resolve(self.code)) if self.code else f't@{self.type}'}>"


class IRStatement(ABC):
    def __init__(self, code: Bytecode):
        self.code = code

    @abstractmethod
    def __repr__(self) -> str:
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

    def __repr__(self) -> str:
        statements = "\n\t  ".join(map(str, self.statements))
        return f"<IRBlock: {statements}>"


class IRArithmetic(IRStatement):
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

    def __init__(self, code: Bytecode, dst: IRLocal, lhs: IRLocal, rhs: IRLocal, op: "IRArithmetic.ArithmeticType"):
        super().__init__(code)
        self.dst = dst
        self.lhs = lhs
        self.rhs = rhs
        self.op = op

    def __repr__(self) -> str:
        return f"<IRArithmetic: {self.dst} = {self.lhs} {self.op.value} {self.rhs}>"


class IRCall(IRStatement):
    class CallType(_Enum):
        FUNC = 0
        METHOD = 1
        THIS = 2
        CLOSURE = 3

    def __init__(self, code: Bytecode, dst: IRLocal, func: IRLocal, args: List[IRLocal], call_type: "IRCall.CallType"):
        super().__init__(code)
        self.dst = dst
        self.func = func
        self.args = args
        self.call_type = call_type

    def __repr__(self) -> str:
        return f"<IRCall: {self.dst} = {self.func}({', '.join(map(str, self.args))})>"


class IRConst(IRStatement):
    class ConstType(_Enum):
        INT = "int"
        FLOAT = "float"
        BOOL = "bool"
        BYTES = "bytes"
        STRING = "string"
        NULL = "null"

    def __init__(
        self,
        code: Bytecode,
        dst: IRLocal,
        const_type: "IRConst.ConstType",
        idx: Optional[ResolvableVarInt] = None,
        value: Optional[bool] = None,
    ):
        super().__init__(code)
        self.dst = dst
        self.const_type = const_type
        self.value: Any = value
        if const_type == IRConst.ConstType.BOOL:
            if not value:
                raise DecompError("IRConst with type BOOL must have a value")
            self.value = value
        else:
            if not idx:
                raise DecompError("IRConst must have an index")
            self.value = idx.resolve(code)

    def __repr__(self) -> str:
        # return f"<IRConst: {self.dst} = {self.const_type.value} {self.value}>"
        return f"<IRConst: {self.dst} = {self.value}>"


class IRFunction:
    def __init__(self, code: Bytecode, func: Function) -> None:
        self.func = func
        self.cfg = CFGraph(func)
        self.cfg.build()
        self.code = code
        self.ops = func.ops
        self.locals: List[IRLocal] = []
        self.block = IRBlock(code)
        self._lift()

    def _lift(self) -> None:
        """Lift function to IR"""
        for i, reg in enumerate(self.func.regs):
            self.locals.append(IRLocal(f"reg{i}", reg, code=self.code))
        self._name_locals()
        if self.cfg.entry:
            self._lift_block(self.cfg.entry)
        else:
            raise DecompError("Function CFG has no entry node, cannot lift to IR")

    def _name_locals(self) -> None:
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
        for i, local in enumerate(self.locals):
            if reg_assigns[i] and len(reg_assigns[i]) == 1:
                local.name = reg_assigns[i].pop()
        dbg_print("Named locals:", self.locals)

    def _lift_block(self, node: CFNode) -> None:
        """Lift a control flow node to an IR block"""
        for op in node.ops:
            if op.op in [
                "Add",
                "Sub",
                "Mul",
                "SDiv",
                "UDiv",
                "SMod",
                "UMod",
                "Shl",
                "SShr",
                "UShr",
                "And",
                "Or",
                "Xor",
            ]:
                dst = self.locals[op.definition["dst"].value]
                lhs = self.locals[op.definition["a"].value]
                rhs = self.locals[op.definition["b"].value]
                self.block.statements.append(
                    IRArithmetic(self.code, dst, lhs, rhs, IRArithmetic.ArithmeticType[op.op.upper()])
                )
            elif op.op in ["Int", "Float", "Bool", "Bytes", "String", "Null"]:
                dst = self.locals[op.definition["dst"].value]
                const_type = IRConst.ConstType[op.op.upper()]
                if op.op == "Bool":
                    value = op.definition["value"].value
                else:
                    value = None
                self.block.statements.append(IRConst(self.code, dst, const_type, op.definition["ptr"], value))

    def print(self) -> None:
        print(self.block)
