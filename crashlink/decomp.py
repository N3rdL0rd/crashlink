"""
Decompilation, IR and control flow graph generation
"""

from abc import ABC, abstractmethod
from enum import Enum as _Enum  # Enum is already defined in crashlink.core
from typing import Any, Dict, List, Optional, Set, Tuple

from . import disasm
from .core import *
from .errors import *
from .globals import dbg_print


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


class IRStatement(ABC):
    def __init__(self, code: Bytecode):
        self.code = code
        self.comment: Optional[str] = None

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
        if not self.statements:
            return "<IRBlock:>"

        formatted_statements = []
        base_indent = "    "

        for stmt in self.statements:
            if isinstance(stmt, IRConditional):
                cond_lines = str(stmt).split("\n")
                formatted_statements.append(base_indent + cond_lines[0])

                true_block_lines = str(stmt.true_block).split("\n")
                for line in true_block_lines:
                    if line.strip():
                        formatted_statements.append(base_indent + "    " + line.strip())

                formatted_statements.append(base_indent + "else")

                false_block_lines = str(stmt.false_block).split("\n")
                for line in false_block_lines:
                    if line.strip():
                        formatted_statements.append(base_indent + "    " + line.strip())
            else:
                formatted_statements.append(base_indent + str(stmt))

        statements = "\n".join(formatted_statements)
        return f"<IRBlock:\n{statements}>"


class IRExpression(IRStatement, ABC):
    """Abstract base class for expressions that produce a value"""

    def __init__(self, code: Bytecode):
        super().__init__(code)

    @abstractmethod
    def get_type(self) -> Type:
        """Get the type of value this expression produces"""
        pass


class IRLocal(IRExpression):
    def __init__(self, name: str, type: tIndex, code: Bytecode):
        super().__init__(code)
        self.name = name
        self.type = type

    def get_type(self) -> Type:
        return self.type.resolve(self.code)

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

    def __init__(self, code: Bytecode, left: IRExpression, right: IRExpression, op: "IRArithmetic.ArithmeticType"):
        super().__init__(code)
        self.left = left
        self.right = right
        self.op = op

    def get_type(self) -> Type:
        # For arithmetic, result type matches left operand type
        return self.left.get_type()

    def __repr__(self) -> str:
        return f"<IRArithmetic: {self.left} {self.op.value} {self.right}>"


class IRAssign(IRStatement):
    """Assignment of an expression result to a local variable"""

    def __init__(self, code: Bytecode, target: IRLocal, expr: IRExpression):
        super().__init__(code)
        self.target = target
        self.expr = expr

    def __repr__(self) -> str:
        return f"<IRAssign: {self.target} = {self.expr} ({disasm.type_name(self.code, self.expr.get_type())})>"


class IRCall(IRExpression):
    """Function call expression"""

    class CallType(_Enum):
        FUNC = "func"
        NATIVE = "native"
        THIS = "this"
        CLOSURE = "closure"
        METHOD = "method"

    def __init__(
        self, code: Bytecode, call_type: "IRCall.CallType", target: "IRConst|IRLocal|None", args: List[IRExpression]
    ):
        super().__init__(code)
        self.call_type = call_type
        self.target = target
        self.args = args
        if self.call_type == IRCall.CallType.THIS and self.target is not None:
            raise DecompError("THIS calls must have a None target")
        if self.call_type != IRCall.CallType.CLOSURE and isinstance(self.target, IRLocal):
            raise DecompError("Non-CLOSURE calls must have a constant target")

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
        if self.op in [IRBoolExpr.CompareType.TRUE, IRBoolExpr.CompareType.FALSE]:
            raise DecompError("Cannot invert TRUE/FALSE operation")
        if self.op == IRBoolExpr.CompareType.NULL:
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

    def __init__(
        self,
        code: Bytecode,
        const_type: "IRConst.ConstType",
        idx: Optional[ResolvableVarInt] = None,
        value: Optional[bool] = None,
    ):
        super().__init__(code)
        self.const_type = const_type
        self.value: Any = value

        if const_type == IRConst.ConstType.BOOL:
            if value is None:
                raise DecompError("IRConst with type BOOL must have a value")
            self.value = value
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
        elif self.const_type == IRConst.ConstType.STRING:
            return _get_type_in_code(self.code, "String")
        elif self.const_type == IRConst.ConstType.NULL:
            return _get_type_in_code(self.code, "Null")
        elif self.const_type == IRConst.ConstType.FUN:
            if not isinstance(self.value, Function):
                raise DecompError(f"Expected function index to resolve to a function, got {self.value}")
            res = self.value.type.resolve(self.code)
            if isinstance(res, Type):
                return res
            raise DecompError(f"Expected function return to resolve to a type, got {res}")
        else:
            raise DecompError(f"Unknown IRConst type: {self.const_type}")

    def __repr__(self) -> str:
        if isinstance(self.value, Function):
            return f"<IRConst: {disasm.func_header(self.code, self.value)}>"
        return f"<IRConst: {self.value}>"


class IRConditional(IRStatement):
    """A conditional statement"""

    def __init__(self, code: Bytecode, condition: IRExpression, true_block: IRBlock, false_block: IRBlock):
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

    def __repr__(self) -> str:
        return f"<IRConditional: if {self.condition} then\n{self.true_block}\nelse\n{self.false_block}>"


class IRReturn(IRStatement):
    """Return statement"""

    def __init__(self, code: Bytecode, value: Optional[IRExpression] = None):
        super().__init__(code)
        self.value = value

    def __repr__(self) -> str:
        return f"<IRReturn: {self.value}>"


class IRTrace(IRStatement):
    """Trace statement"""

    def __init__(self, code: Bytecode, filename: gIndex, line: int, class_name: gIndex, method_name: gIndex):
        super().__init__(code)
        self.filename = filename
        self.line = line
        self.class_name = class_name
        self.method_name = method_name

    def __repr__(self) -> str:
        return f"<IRTrace>" # TODO: resolve globals


class IRFunction:
    """
    Intermediate representation of a function.
    """

    def __init__(self, code: Bytecode, func: Function) -> None:
        self.func = func
        self.cfg = CFGraph(func)
        self.cfg.build()
        self.code = code
        self.ops = func.ops
        self.locals: List[IRLocal] = []
        self.block: IRBlock
        self._lift()
        self._optimize()

    def _lift(self) -> None:
        """Lift function to IR"""
        for i, reg in enumerate(self.func.regs):
            self.locals.append(IRLocal(f"reg{i}", reg, code=self.code))
        self._name_locals()
        if self.cfg.entry:
            self.block = self._lift_block(self.cfg.entry)
        else:
            raise DecompError("Function CFG has no entry node, cannot lift to IR")

    def _optimize(self) -> None:
        """Optimize the IR"""
        pass  # TODO

    def _name_locals(self) -> None:
        """Name locals based on debug info"""
        reg_assigns: List[Set[str]] = [set() for _ in self.func.regs]
        if self.func.has_debug and self.func.assigns:
            for assign in self.func.assigns:
                # assign: Tuple[strRef (name), VarInt (op index)]
                val = assign[1].value - 1
                if val < 0:
                    continue  # arg name
                reg: Optional[int] = None
                op = self.ops[val]
                try:
                    op.definition["dst"]
                    reg = op.definition["dst"].value
                except KeyError:
                    pass
                if reg is not None:
                    reg_assigns[reg].add(assign[0].resolve(self.code))
        # loop through arg names: all with value < 0, eg:
        # Assigns:
        # Op -1: argument_name (corresponds to reg 0)
        # Op -1: other_arg_name (corresponds to reg 1)
        # Op -1: third_arg_name (corresponds to reg 2)
        if self.func.assigns and self.func.has_debug:
            for i, assign in enumerate([assign for assign in self.func.assigns if assign[1].value < 0]):
                reg_assigns[i].add(assign[0].resolve(self.code))
        for i, _reg in enumerate(self.func.regs):
            if _reg.resolve(self.code).definition and isinstance(_reg.resolve(self.code).definition, Void):
                reg_assigns[i].add("void")
        for i, local in enumerate(self.locals):
            if reg_assigns[i] and len(reg_assigns[i]) == 1:
                local.name = reg_assigns[i].pop()
        dbg_print("Named locals:", self.locals)

    def _lift_block(self, node: CFNode, visited: Optional[Set[CFNode]] = None) -> IRBlock:
        """Lift a control flow node to an IR block"""
        if visited is None:
            visited = set()

        if node in visited:
            return IRBlock(self.code)  # Return empty block for cycles

        visited.add(node)
        block = IRBlock(self.code)

        # Process operations in current block
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
                block.statements.append(
                    IRAssign(
                        self.code, dst, IRArithmetic(self.code, lhs, rhs, IRArithmetic.ArithmeticType[op.op.upper()])
                    )
                )
            elif op.op in ["Int", "Float", "Bool", "Bytes", "String", "Null"]:
                dst = self.locals[op.definition["dst"].value]
                const_type = IRConst.ConstType[op.op.upper()]
                value = op.definition["value"].value if op.op == "Bool" else None
                if op.op not in ["Bool"]:
                    const = IRConst(self.code, const_type, op.definition["ptr"], value)
                else:
                    const = IRConst(self.code, const_type, value=value)
                block.statements.append(IRAssign(self.code, dst, const))
            # Handle conditionals
            elif op.op in [
                "JTrue",
                "JFalse",
                "JNull",
                "JNotNull",
                "JSLt",
                "JSGte",
                "JSGt",
                "JSLte",
                "JULt",
                "JUGte",
                "JEq",
                "JNotEq",
            ]:
                jump_to_compare = {
                    "JTrue": IRBoolExpr.CompareType.TRUE,
                    "JFalse": IRBoolExpr.CompareType.FALSE,
                    "JNull": IRBoolExpr.CompareType.NULL,
                    "JNotNull": IRBoolExpr.CompareType.NOT_NULL,
                    "JSLt": IRBoolExpr.CompareType.LT,
                    "JSGte": IRBoolExpr.CompareType.GTE,
                    "JSGt": IRBoolExpr.CompareType.GT,
                    "JSLte": IRBoolExpr.CompareType.LTE,
                    "JULt": IRBoolExpr.CompareType.LT,
                    "JUGte": IRBoolExpr.CompareType.GTE,
                    "JEq": IRBoolExpr.CompareType.EQ,
                    "JNotEq": IRBoolExpr.CompareType.NEQ,
                }

                # Build condition expression
                if op.op in ["JTrue", "JFalse"]:
                    cond = self.locals[op.definition["cond"].value]
                    condition = IRBoolExpr(self.code, jump_to_compare[op.op], cond)
                elif op.op in ["JNull", "JNotNull"]:
                    val = self.locals[op.definition["value"].value]
                    condition = IRBoolExpr(self.code, jump_to_compare[op.op], val)
                else:  # Comparison operations
                    left = self.locals[op.definition["a"].value]
                    right = self.locals[op.definition["b"].value]
                    condition = IRBoolExpr(self.code, jump_to_compare[op.op], left, right)

                true_node = None
                false_node = None

                for next_node, edge_type in node.branches:
                    if edge_type == "true":
                        true_node = next_node
                    elif edge_type == "false":
                        false_node = next_node

                if true_node or false_node:
                    true_block = self._lift_block(true_node, visited.copy()) if true_node else IRBlock(self.code)
                    false_block = self._lift_block(false_node, visited.copy()) if false_node else IRBlock(self.code)
                    cond = IRConditional(self.code, condition, true_block, false_block)
                    # cond.invert()
                    block.statements.append(cond)

            # NOTE: never EVER handle JAlways here, jump threading is already done with the CFG

            elif op.op in ["Call0", "Call1", "Call2", "Call3", "Call4"]:
                n = int(op.op[-1])
                dst = self.locals[op.definition["dst"].value]
                fun = IRConst(self.code, IRConst.ConstType.FUN, op.definition["fun"])
                args = [self.locals[op.definition[f"arg{i}"].value] for i in range(n)]
                block.statements.append(IRAssign(self.code, dst, IRCall(self.code, IRCall.CallType.FUNC, fun, args)))

            elif op.op == "CallMethod":
                dst = self.locals[op.definition["dst"].value]
                target = self.locals[op.definition["target"].value]
                args = [self.locals[op.definition[f"arg{i}"].value] for i in range(op.definition["nargs"].value)]
                block.statements.append(
                    IRAssign(self.code, dst, IRCall(self.code, IRCall.CallType.METHOD, target, args))
                )

            elif op.op == "CallThis":
                dst = self.locals[op.definition["dst"].value]
                args = [self.locals[op.definition[f"arg{i}"].value] for i in range(op.definition["nargs"].value)]
                block.statements.append(IRAssign(self.code, dst, IRCall(self.code, IRCall.CallType.THIS, None, args)))

            elif op.op == "Ret":
                if isinstance(op.definition["ret"].resolve(self.code).definition, Void):
                    block.statements.append(IRReturn(self.code))
                else:
                    block.statements.append(IRReturn(self.code, self.locals[op.definition["ret"].value]))

        return block

    def print(self) -> None:
        print(self.block)
