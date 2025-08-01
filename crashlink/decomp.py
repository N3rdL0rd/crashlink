"""
Decompilation, IR and control flow graph generation
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum as _Enum  # Enum is already defined in crashlink.core
from pprint import pformat
from typing import Any, Dict, List, Optional, Set, Tuple

from . import disasm
from .core import (
    Bytecode,
    DynObj,
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
from .opcodes import arithmetic, conditionals


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

    def predecessors(self, node: CFNode) -> List[CFNode]:
        """Get predecessors of a node"""
        preds = []
        for n in self.nodes:
            for succ, _ in n.branches:
                if succ == node:
                    preds.append(n)
        return preds


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
        colors = [36, 31, 32, 33, 34, 35]

        depth = id(self) % len(colors)
        color = colors[depth]

        if not self.statements:
            return f"\033[{color}m[\033[0m\033[{color}m]\033[0m"

        # uniform indentation
        statements = pformat(self.statements, indent=0).replace("\n", "\n\t")

        return f"\033[{color}m[\033[0m\n\t{statements}\n\033[{color}m]\033[0m"

    def __repr__(self) -> str:
        if not self.statements:
            return "[]"

        statements = pformat(self.statements, indent=0).replace("\n", "\n\t")

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
    def __init__(self, name: str, type: tIndex, code: Bytecode):
        super().__init__(code)
        self.name = name
        self.type = type

    def get_type(self) -> Type:
        return self.type.resolve(self.code)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IRLocal):
            return False
        return (
            self.name == other.name
            and self.type.resolve(self.code) is other.type.resolve(other.code)
            and self.code is other.code
        )

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

    def get_type(self) -> Type:
        # For arithmetic, result type matches left operand type
        return self.left.get_type()

    def __repr__(self) -> str:
        return f"<IRArithmetic: {self.left} {self.op.value} {self.right}>"


class IRAssign(IRStatement):
    """Assignment of an expression result to a target (local variable, field, etc.)"""

    def __init__(self, code: Bytecode, target: IRExpression, expr: IRExpression):
        super().__init__(code)
        if not isinstance(target, (IRLocal, IRField)):
            raise DecompError(f"Invalid target for IRAssign: {type(target).__name__}. Must be IRLocal or IRField.")
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
        target: "IRConst|IRLocal|None",
        args: List[IRExpression],
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
        for type in self.code.types:
            if disasm.type_name(self.code, type) == "Bool":
                return type
        raise DecompError("Bool type not found in code")

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


class IRReturn(IRStatement):
    """Return statement"""

    def __init__(self, code: Bytecode, value: Optional[IRExpression] = None):
        super().__init__(code)
        self.value = value

    def get_children(self) -> List[IRStatement]:
        return []

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

    condition: IRStatement
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
        children = []
        if isinstance(self.condition, IRStatement):
            children.append(self.condition)
        children.append(self.body)
        return children

    def __repr__(self) -> str:
        body_repr = pformat(self.body, indent=0).replace("\n", "\n\t")
        return f"<IRWhileLoop: while ({self.condition}) {{\n\t{body_repr}\n}}>"

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
        return []

    def __repr__(self) -> str:
        return f"<IRField: {self.target}.{self.field_name}>"


class IRNew(IRExpression):
    """Represents object allocation, e.g., `new MyClass()` or `{}`"""

    def __init__(self, code: Bytecode, alloc_type: tIndex):
        super().__init__(code)
        self.alloc_type_idx = alloc_type

    def get_type(self) -> Type:
        return self.alloc_type_idx.resolve(self.code)

    def __repr__(self) -> str:
        type_name = disasm.type_name(self.code, self.get_type())
        if type_name == "DynObj":
            return "<IRNew: {}>"
        return f"<IRNew: new {type_name}>"


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
            self.visit(self.func.block)

    def visit(self, statement: IRStatement) -> None:
        """
        Recursively visit an IR statement and its children.

        The traversal performs a pre-order visit (parent first, then children):
        1. Call before_visit_statement for the current statement
        2. Handle specific statement type with visit_X methods
        3. Visit all children recursively
        4. Call after_visit_statement for the current statement
        """
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
        elif isinstance(statement, IRBreak):
            self.visit_break(statement)
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
        pass

    def visit_break(self, brk: IRBreak) -> None:
        """Visit an IRBreak. Override in subclasses for custom behavior."""
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
                assigned_local: IRLocal | IRField = current_stmt.target
                expr_to_inline: IRExpression = current_stmt.expr

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
        self, bool_expr: IRBoolExpr, target: IRLocal | IRField, expr_to_inline: IRExpression
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
        target: IRLocal | IRField,
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
                    if isinstance(inlined_target_expr, (IRConst, IRLocal, type(None))):
                        call_expr.target = inlined_target_expr
                        made_change = True

            if made_change:
                call_expr.args = new_args
                return call_expr
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

    def _try_convert_to_while_true_break(self, loop: IRPrimitiveLoop) -> Optional[IRWhileLoop]:
        """
        Attempts to convert an IRPrimitiveLoop into a while(true) { body; if (exit_cond) break; } structure.
        This is suitable for loops originating from Haxe's `while(true) { ... if(cond) break; }`.
        """
        if not loop.condition.statements:
            dbg_print(f"IRLoopCondOpt(while-true): PrimitiveLoop at {loop} has empty condition. Cannot convert.")
            return None

        # Heuristic: The original IRPrimitiveLoop's body should be empty,
        # meaning the loop's logic is all in the condition block + its final jump.
        if loop.body.statements:
            dbg_print(
                f"IRLoopCondOpt(while-true): PrimitiveLoop.body is not empty. Not a candidate. Body: {loop.body.statements}"
            )
            return None

        last_cond_stmt = loop.condition.statements[-1]
        if not isinstance(last_cond_stmt, IRBoolExpr):
            dbg_print(
                f"IRLoopCondOpt(while-true): PrimitiveLoop condition does not end with IRBoolExpr. Ends with {type(last_cond_stmt).__name__}. Cannot convert."
            )
            return None

        exit_condition_expr: IRBoolExpr = last_cond_stmt
        actual_body_statements = list(loop.condition.statements[:-1])

        if not actual_body_statements:
            dbg_print(
                f"IRLoopCondOpt(while-true): No actual body statements found before exit condition. Not a typical while(true)+break pattern."
            )
            return None

        dbg_print(f"IRLoopCondOpt(while-true): Candidate for while(true) + if-break found for {loop}")

        true_loop_condition = IRBoolExpr(loop.code, IRBoolExpr.CompareType.TRUE)

        break_block = IRBlock(loop.code)
        break_block.statements.append(IRBreak(loop.code))

        empty_else_block = IRBlock(loop.code)

        if_break_stmt = IRConditional(loop.code, exit_condition_expr, break_block, empty_else_block)

        new_loop_body_stmts = actual_body_statements + [if_break_stmt]
        new_body_block = IRBlock(loop.code)
        new_body_block.statements = new_loop_body_stmts

        new_while_loop = IRWhileLoop(loop.code, true_loop_condition, new_body_block)

        new_while_loop.comment = loop.comment

        dbg_print(
            f"IRLoopCondOpt(while-true): Converted IRPrimitiveLoop to IRWhileLoop(true) with if-break. Exit condition: {exit_condition_expr}"
        )
        return new_while_loop

    def visit_block(self, block: IRBlock) -> None:
        new_statements: List[IRStatement] = []
        for stmt in block.statements:
            if isinstance(stmt, IRPrimitiveLoop):
                converted_loop = self._try_convert_to_while_true_break(stmt)
                if converted_loop:
                    new_statements.append(converted_loop)
                else:
                    fallback_converted_loop = self._try_convert_to_while(stmt)
                    if fallback_converted_loop:
                        new_statements.append(fallback_converted_loop)
                    else:
                        new_statements.append(stmt)
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

        exit_condition_expr: IRBoolExpr = last_cond_stmt

        loop_continuation_expr = IRBoolExpr(
            loop.code,
            exit_condition_expr.op,
            exit_condition_expr.left,
            exit_condition_expr.right,
        )
        loop_continuation_expr.invert()

        setup_statements_for_body = loop.condition.statements[:-1]

        new_body_statements = setup_statements_for_body + loop.body.statements
        new_body_block = IRBlock(loop.code)
        new_body_block.statements = new_body_statements

        new_while_loop = IRWhileLoop(loop.code, loop_continuation_expr, new_body_block)

        new_while_loop.comment = loop.comment

        if setup_statements_for_body:
            moved_comment = "(Condition setup moved into body)"
            if new_while_loop.comment:
                new_while_loop.comment += " " + moved_comment
            else:
                new_while_loop.comment = moved_comment

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
                    # Using repr for structural comparison. This is a practical heuristic.
                    # A more advanced system might use a deep structural equality check.
                    if repr(true_stmts[t_idx]) == repr(false_stmts[f_idx]):
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
                        dbg_print(f"IRVoidAssignOptimizer: Removing void assignment: {stmt} (target: {target.name})")

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


class IRTempAssignmentInliner(TraversingIROptimizer):
    """
    Optimizes IR by inlining temporary variable assignments.
    It finds assignments `temp = expr` and replaces subsequent uses of `temp`
    with `expr`, provided the expression is safe to duplicate and `temp` is not
    redefined in between.
    """

    def is_safe_to_inline(self, expr: IRExpression) -> bool:
        """
        Determines if an expression can be safely copied without changing
        the program's semantics.
        """
        if isinstance(expr, (IRConst, IRLocal)):
            return True
        if isinstance(expr, IRField):
            # A field access is only safe if the object it's accessing is also safe.
            return self.is_safe_to_inline(expr.target)
        # Anything else (IRNew, IRCall, IRArithmetic) is considered unsafe.
        return False

    def _substitute_in_expr(self, expr: IRExpression, target: IRLocal, replacement: IRExpression) -> IRExpression:
        """Recursively substitutes a local with an expression within another expression."""
        if expr == target:
            return replacement

        if isinstance(expr, (IRArithmetic, IRBoolExpr)):
            if expr.left:
                expr.left = self._substitute_in_expr(expr.left, target, replacement)
            if expr.right:
                expr.right = self._substitute_in_expr(expr.right, target, replacement)
        elif isinstance(expr, IRCall):
            if isinstance(expr.target, IRExpression):
                expr.target = self._substitute_in_expr(expr.target, target, replacement)
            expr.args = [self._substitute_in_expr(arg, target, replacement) for arg in expr.args]
        elif isinstance(expr, IRField):
            # *** FIX IS HERE: Correctly recurse on the target of the field access ***
            expr.target = self._substitute_in_expr(expr.target, target, replacement)
        elif isinstance(expr, IRCast):
            expr.expr = self._substitute_in_expr(expr.expr, target, replacement)

        return expr

    def _substitute_in_statement(self, stmt: IRStatement, target: IRLocal, replacement: IRExpression) -> None:
        """Recursively traverses a statement to perform substitutions."""
        if isinstance(stmt, IRAssign):
            if stmt.target != target and isinstance(stmt.target, IRExpression):
                self._substitute_in_expr(stmt.target, target, replacement)
            if isinstance(stmt.expr, IRExpression):
                stmt.expr = self._substitute_in_expr(stmt.expr, target, replacement)
        elif isinstance(stmt, IRExpression):  # Handles standalone calls and other expressions
            self._substitute_in_expr(stmt, target, replacement)
        elif isinstance(stmt, IRReturn):
            if stmt.value:
                stmt.value = self._substitute_in_expr(stmt.value, target, replacement)
        # Recurse into control flow structures
        for child in stmt.get_children():
            if child is not stmt:  # Avoid infinite recursion
                self._substitute_in_statement(child, target, replacement)

    def _is_local_redefined(self, local_to_check: IRLocal, statements: List[IRStatement]) -> bool:
        """Checks if a local is the target of an assignment in a list of statements."""
        for stmt in statements:
            if isinstance(stmt, IRAssign) and stmt.target == local_to_check:
                return True
            # Recurse into control flow structures
            for child in stmt.get_children():
                if self._is_local_redefined(
                    local_to_check, [child] if not isinstance(child, IRBlock) else child.statements
                ):
                    return True
        return False

    def visit_block(self, block: IRBlock) -> None:
        made_change_in_pass = True
        while made_change_in_pass:
            made_change_in_pass = False
            statements_to_remove = []

            for i, stmt in enumerate(block.statements):
                if not (isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal)):
                    continue

                temp_local = stmt.target
                expr_to_inline = stmt.expr

                if not isinstance(expr_to_inline, IRExpression) or not self.is_safe_to_inline(expr_to_inline):
                    continue

                if isinstance(expr_to_inline, IRExpression) and (
                    temp_local in expr_to_inline.get_children() or temp_local == expr_to_inline
                ):
                    continue

                remaining_statements = block.statements[i + 1 :]

                if self._is_local_redefined(temp_local, remaining_statements):
                    continue

                dbg_print(f"Inlining safe expression from {stmt} into subsequent statements.")
                for subsequent_stmt in remaining_statements:
                    self._substitute_in_statement(subsequent_stmt, temp_local, expr_to_inline)

                statements_to_remove.append(stmt)
                made_change_in_pass = True
                break

            if statements_to_remove:
                block.statements = [s for s in block.statements if s not in statements_to_remove]

        # After inlining, recurse into child blocks
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
                dbg_print(f"[TraceOpt] Analyzing statement {i}: {stmt}")

                if not (isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal)):
                    new_statements.append(stmt)
                    i += 1
                    continue

                assign_new = stmt
                temp_local = assign_new.target
                if not (
                    isinstance(assign_new.expr, IRNew) and assign_new.expr.get_type().definition.__class__ == DynObj
                ):
                    new_statements.append(stmt)
                    i += 1
                    continue

                dbg_print(
                    f"[TraceOpt] Found potential start of trace pattern at index {i} with temp local '{temp_local.name}'"
                )

                pos_info: Dict[str, Any] = {}
                j = i + 1

                while j < len(block.statements):
                    next_stmt = block.statements[j]
                    if not (
                        isinstance(next_stmt, IRAssign)
                        and isinstance(next_stmt.target, IRField)
                        and next_stmt.target.target == temp_local
                        and isinstance(next_stmt.expr, IRConst)
                    ):
                        dbg_print(f"[TraceOpt] Sequence of field sets for '{temp_local.name}' ended at index {j}.")
                        break

                    field_assign = next_stmt
                    field_name = field_assign.target.field_name
                    field_value = field_assign.expr.value
                    pos_info[field_name] = field_value
                    dbg_print(f"[TraceOpt]  -> Collected field: {field_name} = {field_value!r}")
                    j += 1

                if j < len(block.statements):
                    call_stmt = block.statements[j]
                    dbg_print(f"[TraceOpt] Checking statement {j} as potential trace call: {call_stmt}")

                    is_valid_trace_call = False
                    if isinstance(call_stmt, IRCall) and len(call_stmt.args) == 2:
                        last_arg = call_stmt.args[1]

                        is_our_var = (isinstance(last_arg, IRLocal) and last_arg == temp_local) or (
                            isinstance(last_arg, IRCast) and last_arg.expr == temp_local
                        )
                        dbg_print(f"[TraceOpt]  -> Is last arg '{last_arg}' our temp '{temp_local.name}'? {is_our_var}")

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
                        msg_expr = call_stmt.args[0]
                        trace_stmt = IRTrace(self.func.code, msg_expr, pos_info)
                        new_statements.append(trace_stmt)

                        i = j + 1
                        made_change = True
                        continue
                    else:
                        dbg_print(f"[TraceOpt] FAILED: Pattern did not match for trace call.")

                new_statements.append(stmt)
                i += 1

            block.statements = new_statements


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
    ) -> None:
        self.func = func
        self.cfg = CFGraph(func)
        self.cfg.build()
        self.code = code
        self.ops = func.ops
        self.locals: List[IRLocal] = []
        self.block: IRBlock
        self._lift(no_lift=no_lift)
        if do_optimize:
            self.optimizers: List[IROptimizer] = [
                IRBlockFlattener(self),
                IRPrimitiveJumpLifter(self),
                IRGlobalStringOptimizer(self),
                IRConditionInliner(self),
                IRLoopConditionOptimizer(self),
                IRSelfAssignOptimizer(self),
                IRCommonBlockMerger(self),
                IRTempAssignmentInliner(self),
                IRVoidAssignOptimizer(self),
                IRTraceOptimizer(self),
                IRBlockFlattener(self),
            ]
            self._optimize()

    def _lift(self, no_lift: bool = False) -> None:
        """Lift function to IR"""
        for i, reg in enumerate(self.func.regs):
            self.locals.append(IRLocal(f"var{i}", reg, code=self.code))
        self._name_locals()
        if not no_lift:
            if self.cfg.entry:
                self.block = self._lift_block(self.cfg.entry)
            else:
                raise DecompError("Function CFG has no entry node, cannot lift to IR")
        else:
            dbg_print("Skipping lift.")

    def _optimize(self) -> None:
        """Optimize the IR"""
        # TODO: store layers
        dbg_print("----- Disasm -----")
        dbg_print(disasm.func(self.code, self.func))
        dbg_print(f"----- LLIL -----")
        dbg_print(self.block.pprint())
        for o in self.optimizers:
            dbg_print(f"----- {o.__class__.__name__} -----")
            o.optimize()
            dbg_print(self.block.pprint())

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
                    op.df["dst"]
                    reg = op.df["dst"].value
                except KeyError:
                    pass
                if reg is not None:
                    reg_assigns[reg].add(assign[0].resolve(self.code))
        # loop through arg names: all with value < 0, eg:
        # Op -1: argument_name (corresponds to reg 0)
        # Op -1: other_arg_name (corresponds to reg 1)
        # Op -1: third_arg_name (corresponds to reg 2)
        if self.func.assigns and self.func.has_debug:
            for i, assign in enumerate([assign for assign in self.func.assigns if assign[1].value < 0]):
                reg_assigns[i].add(assign[0].resolve(self.code))
        for i, _reg in enumerate(self.func.regs):
            if _reg.resolve(self.code).definition and isinstance(_reg.resolve(self.code).definition, Void):
                reg_assigns[i].add("voidReg")
        for i, local in enumerate(self.locals):
            if reg_assigns[i] and len(reg_assigns[i]) == 1:
                local.name = reg_assigns[i].pop()
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

    def _patch_loop_condition(self, node: CFNode) -> None:
        """Patches a loop condition block to remove the Label and anything else that could get it detected as a nested loop or other statement unintentionally."""
        assert node.ops[0].op == "Label", "This isn't a label! This should never happen!"
        node.ops = node.ops[1:]  # remove Label
        assert node.ops[-1].op in conditionals

    def _lift_block(
        self,
        node: CFNode,
        visited: Optional[Set[CFNode]] = None,
        convert_jumps_to_primitive: bool = False,
        flag_conditionals: bool = False,
        current_loop_scope_nodes: Optional[Set[CFNode]] = None,
    ) -> IRBlock:
        if visited is None:
            visited = set()

        if node in visited:
            return IRBlock(self.code)
        visited.add(node)

        block = IRBlock(self.code)

        for i, op in enumerate(node.ops):
            if op.op == "Label":
                assert i == 0, "Label should be the first operation in a CFNode."
                jumpers = _find_jumps_to_label(node, node, set())

                loop_nodes_for_this_loop: Set[CFNode] = {node}
                for jumper_node, path_to_jumper in jumpers:
                    loop_nodes_for_this_loop.add(jumper_node)
                    loop_nodes_for_this_loop.update(path_to_jumper)

                body_nodes_for_isolated_graph: Set[CFNode] = loop_nodes_for_this_loop.copy()
                body_nodes_for_isolated_graph.discard(node)

                isolated = IsolatedCFGraph(
                    self.cfg,
                    list(body_nodes_for_isolated_graph) if body_nodes_for_isolated_graph else [self.cfg.add_node([])],
                )
                condition = IsolatedCFGraph(self.cfg, [node], find_entry_intelligently=False)
                dbg_print("--- isolated ---")
                dbg_print(isolated.graph(self.code))
                dbg_print("--- condition ---")
                dbg_print(condition.graph(self.code))

                if not condition.entry:
                    raise DecompError("Empty condition block found for loop.")
                self._patch_loop_condition(condition.entry)

                condition_ir_block = self._lift_block(condition.entry, visited.copy(), convert_jumps_to_primitive=True)

                body_ir_block: IRBlock
                if isolated.entry and isolated.entry.ops:
                    body_ir_block = self._lift_block(
                        isolated.entry,
                        visited.copy(),
                        flag_conditionals=True,
                        current_loop_scope_nodes=loop_nodes_for_this_loop,
                    )
                else:
                    dbg_print(
                        f"Warning: Empty or non-meaningful loop body found for loop starting at {node.base_offset}."
                    )
                    body_ir_block = IRBlock(self.code)

                visited.add(node)
                for body_node in body_nodes_for_isolated_graph:
                    visited.add(body_node)

                loop_stmt = IRPrimitiveLoop(self.code, condition_ir_block, body_ir_block)
                block.statements.append(loop_stmt)

                loop_exit_node: Optional[CFNode] = None
                for successor_node, _edge_type in node.branches:
                    if successor_node not in loop_nodes_for_this_loop:
                        loop_exit_node = successor_node
                        break

                if not loop_exit_node:
                    for body_member_node in loop_nodes_for_this_loop:
                        if body_member_node == node:
                            continue
                        for successor_node, _edge_type in body_member_node.branches:
                            if successor_node not in loop_nodes_for_this_loop:
                                loop_exit_node = successor_node
                                break
                        if loop_exit_node:
                            break

                if loop_exit_node:
                    dbg_print(f"Loop at {node.base_offset} determined to exit to CFNode {loop_exit_node.base_offset}")
                    next_sequential_block = self._lift_block(loop_exit_node, visited, current_loop_scope_nodes=None)
                    if next_sequential_block.statements:
                        block.statements.append(next_sequential_block)
                    elif next_sequential_block.comment:
                        if block.statements:
                            block.statements[-1].comment += " " + next_sequential_block.comment
                        else:
                            block.comment += " " + next_sequential_block.comment

                else:
                    dbg_print(f"Warning: Could not determine a single CFG exit node after loop at {node.base_offset}.")

                break

            elif op.op in arithmetic:
                dst = self.locals[op.df["dst"].value]
                lhs = self.locals[op.df["a"].value]
                rhs = self.locals[op.df["b"].value]
                block.statements.append(
                    IRAssign(
                        self.code,
                        dst,
                        IRArithmetic(
                            self.code,
                            lhs,
                            rhs,
                            IRArithmetic.ArithmeticType[op.op.upper()],
                        ),
                    )
                )

            elif op.op in ["Int", "Float", "Bool", "Bytes", "String", "Null"]:
                dst = self.locals[op.df["dst"].value]
                const_type = IRConst.ConstType[op.op.upper()]
                value = op.df["value"].value if op.op == "Bool" else None
                if op.op not in ["Bool"]:
                    const = IRConst(self.code, const_type, op.df["ptr"], value)
                else:
                    const = IRConst(self.code, const_type, value=value)
                block.statements.append(IRAssign(self.code, dst, const))

            elif op.op in conditionals:
                if flag_conditionals:
                    dbg_print("!!! Conditional !!!")
                if not convert_jumps_to_primitive:
                    # conditionals create a diamond shape in the IR - the two branches will at some point converge again.
                    true_branch = None
                    false_branch = None
                    for branch_node, edge_type in node.branches:
                        if edge_type == "true":
                            true_branch = branch_node
                        elif edge_type == "false":
                            false_branch = branch_node
                    if true_branch is None or false_branch is None:
                        dbg_print("true:", true_branch, "false:", false_branch)
                        dbg_print(node)
                        raise DecompError(
                            "Conditional jump missing true/false branch. This is almost certainly an issue with the decompiler and not the bytecode itself."
                        )

                    # HACK: blocks that have multiple branches coming into them shouldn't exist for generated if statements.
                    # therefore, we can assume that if a conditional branch leads to a node that has multiple incoming branches,
                    # it's an empty block and that's what comes *after* the conditional branches altogether.
                    should_lift_t = True
                    should_lift_f = True
                    if len(self.cfg.predecessors(true_branch)) > 1:
                        should_lift_t = False
                    if len(self.cfg.predecessors(false_branch)) > 1:
                        should_lift_f = False

                    if not should_lift_t and not should_lift_f:
                        dbg_print("Warning: Skipping conditional due to weird incoming branches.")
                        block.comment += "WARNING: Skipping conditional due to weird incoming branches."
                        continue

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
                        "JEq": IRBoolExpr.CompareType.EQ,
                        "JNotEq": IRBoolExpr.CompareType.NEQ,
                    }
                    cond = cond_map[op.op]
                    left, right = None, None
                    if cond not in [
                        IRBoolExpr.CompareType.ISTRUE,
                        IRBoolExpr.CompareType.ISFALSE,
                        IRBoolExpr.CompareType.NULL,
                        IRBoolExpr.CompareType.NOT_NULL,
                    ]:
                        left = self.locals[op.df["a"].value]
                        right = self.locals[op.df["b"].value]
                    else:
                        l = op.df.get("cond", op.df.get("reg"))
                        assert l is not None
                        left = self.locals[l.value]

                    condition_expr = IRBoolExpr(self.code, cond, left, right)
                    true_block = (
                        self._lift_block(
                            true_branch,
                            visited.copy(),
                            current_loop_scope_nodes=current_loop_scope_nodes,
                        )
                        if should_lift_t
                        else IRBlock(self.code)
                    )
                    false_block = (
                        self._lift_block(
                            false_branch,
                            visited.copy(),
                            current_loop_scope_nodes=current_loop_scope_nodes,
                        )
                        if should_lift_f
                        else IRBlock(self.code)
                    )
                    _cond = IRConditional(self.code, condition_expr, true_block, false_block)
                    _cond.invert()
                    block.statements.append(_cond)

                    convergence = self._find_convergence(true_branch, false_branch, visited)
                    if convergence and convergence.ops and convergence.ops[-1].op == "Ret":
                        true_exits_to_convergence = (
                            len(true_branch.branches) == 1 and true_branch.branches[0][0] == convergence
                        )
                        false_exits_to_convergence = (
                            len(false_branch.branches) == 1 and false_branch.branches[0][0] == convergence
                        )

                        if true_exits_to_convergence and false_exits_to_convergence:
                            return block

                    # now, find the next block and lift it.
                    next_node = None
                    if not should_lift_f:
                        next_node = false_branch
                    elif not should_lift_t:
                        next_node = true_branch
                    else:
                        convergence = self._find_convergence(true_branch, false_branch, visited)
                        if convergence:
                            next_node = convergence
                        else:
                            dbg_print("WARNING: No convergence point found for conditional branches")
                    if not next_node:
                        raise DecompError("No next node found for conditional branches")
                    next_block = self._lift_block(
                        next_node,
                        visited,
                        current_loop_scope_nodes=current_loop_scope_nodes,
                    )
                    block.statements.append(next_block)
                else:
                    # convert jumps to IRPrimitiveJump so that later lifting stages can handle them
                    # TODO: instead of just wrapping an opcode, we can resolve this to a local and generate a Bool-type IRExpression
                    block.statements.append(IRPrimitiveJump(self.code, op))

            elif op.op in ["Call0", "Call1", "Call2", "Call3", "Call4"]:
                n = int(op.op[-1])
                dst = self.locals[op.df["dst"].value]
                fun = IRConst(self.code, IRConst.ConstType.FUN, op.df["fun"])
                args = [self.locals[op.df[f"arg{i}"].value] for i in range(n)]
                block.statements.append(
                    IRAssign(
                        self.code,
                        dst,
                        IRCall(self.code, IRCall.CallType.FUNC, fun, args),
                    )
                )

            elif op.op == "CallMethod":
                dst = self.locals[op.df["dst"].value]
                target = self.locals[op.df["target"].value]
                args = [self.locals[op.df[f"arg{i}"].value] for i in range(op.df["nargs"].value)]
                block.statements.append(
                    IRAssign(
                        self.code,
                        dst,
                        IRCall(self.code, IRCall.CallType.METHOD, target, args),
                    )
                )

            elif op.op == "CallThis":
                dst = self.locals[op.df["dst"].value]
                args = [self.locals[op.df[f"arg{i}"].value] for i in range(op.df["nargs"].value)]
                block.statements.append(
                    IRAssign(
                        self.code,
                        dst,
                        IRCall(self.code, IRCall.CallType.THIS, None, args),
                    )
                )

            elif op.op == "Ret":
                if isinstance(op.df["ret"].resolve(self.code).definition, Void):
                    block.statements.append(IRReturn(self.code))
                else:
                    block.statements.append(IRReturn(self.code, self.locals[op.df["ret"].value]))

            elif op.op == "Switch":
                val = self.locals[op.df["reg"].value]
                offsets = op.df["offsets"].value
                cases = {}
                case_nodes = []

                for i, offset in enumerate(offsets):
                    if offset.value != 0:
                        jump_idx = node.base_offset + len(node.ops) + offset.value
                        target_node = None
                        for nod in self.cfg.nodes:
                            if nod.base_offset == jump_idx:
                                target_node = nod
                                break

                        if target_node:
                            case_const = IRConst(self.code, IRConst.ConstType.INT, value=i)
                            case_nodes.append(target_node)
                            cases[case_const] = self._lift_block(target_node, visited)

                default_node = None
                for branch_node, edge_type in node.branches:
                    if edge_type == "switch: default":
                        default_node = branch_node
                        break

                if not default_node:
                    raise DecompError("Switch missing default branch")

                case_nodes.append(default_node)
                default_block = self._lift_block(default_node, visited)

                switch = IRSwitch(self.code, val, cases, default_block)
                block.statements.append(switch)

                convergence = None
                for possible_node in self.cfg.nodes:
                    is_convergence = True
                    for case_node in case_nodes:
                        if not any(succ == possible_node for succ, _ in case_node.branches):
                            is_convergence = False
                            break
                    if is_convergence:
                        convergence = possible_node
                        break

                if convergence:
                    next_block = self._lift_block(convergence, visited)
                    block.statements.append(next_block)

            elif op.op == "Mov":
                block.statements.append(
                    IRAssign(
                        self.code,
                        self.locals[op.df["dst"].value],
                        self.locals[op.df["src"].value],
                    )
                )

            elif op.op == "GetGlobal":
                block.statements.append(
                    IRAssign(
                        self.code,
                        self.locals[op.df["dst"].value],
                        IRConst(self.code, IRConst.ConstType.GLOBAL_OBJ, idx=op.df["global"]),
                    )
                )

            elif op.op == "JAlways":
                jump_idx = node.base_offset + len(node.ops) + op.df["offset"].value
                target_node = None
                for nod in self.cfg.nodes:
                    if nod.base_offset == jump_idx:
                        target_node = nod
                        break

                if current_loop_scope_nodes and target_node and (target_node not in current_loop_scope_nodes):
                    block.statements.append(IRBreak(self.code))
                    return block
                elif target_node:
                    next_block = self._lift_block(
                        target_node,
                        visited,
                        current_loop_scope_nodes=current_loop_scope_nodes,
                    )
                    block.statements.append(next_block)

            elif op.op == "Field":
                dst_local = self.locals[op.df["dst"].value]
                obj_local = self.locals[op.df["obj"].value]

                obj_type = obj_local.get_type()
                if not isinstance(obj_type.definition, (Obj, Virtual)):
                    raise DecompError(f"Field opcode used on a non-object type: {obj_type.definition}")

                field_ref_op: fieldRef = op.df["field"]
                field_core = field_ref_op.resolve_obj(self.code, obj_type.definition)
                field_name = field_core.name.resolve(self.code)

                field_expr = IRField(self.code, obj_local, field_name, field_core.type)
                assign_stmt = IRAssign(self.code, dst_local, field_expr)
                block.statements.append(assign_stmt)

            elif op.op == "New":
                dst_local = self.locals[op.df["dst"].value]
                alloc_type_idx = self.func.regs[op.df["dst"].value]
                new_expr = IRNew(self.code, alloc_type_idx)
                block.statements.append(IRAssign(self.code, dst_local, new_expr))

            elif op.op == "DynSet":
                obj_local = self.locals[op.df["obj"].value]
                src_local = self.locals[op.df["src"].value]

                field_name = op.df["field"].resolve(self.code)

                field_type_idx = self.func.regs[op.df["src"].value]

                field_target = IRField(self.code, obj_local, field_name, field_type_idx)

                assign_stmt = IRAssign(self.code, field_target, src_local)
                block.statements.append(assign_stmt)

            elif op.op == "ToVirtual":
                dst_local = self.locals[op.df["dst"].value]
                src_local = self.locals[op.df["src"].value]

                target_type_idx = self.func.regs[op.df["dst"].value]

                cast_expr = IRCast(self.code, target_type_idx, src_local)
                assign_stmt = IRAssign(self.code, dst_local, cast_expr)
                block.statements.append(assign_stmt)

            elif op.op == "CallClosure":
                dst_local = self.locals[op.df["dst"].value]
                fun_local = self.locals[op.df["fun"].value]
                arg_locals = [self.locals[arg.value] for arg in op.df["args"].value]

                call_expr = IRCall(self.code, IRCall.CallType.CLOSURE, fun_local, arg_locals)
                if dst_local.get_type().kind.value == Type.Kind.VOID.value:
                    block.statements.append(call_expr)
                else:
                    assign_stmt = IRAssign(self.code, dst_local, call_expr)
                    block.statements.append(assign_stmt)

            elif op.op in [
                "NullCheck",  # we ignore NullCheck because that's generated at compile-time
            ]:
                pass  # silently pass

            else:
                dbg_print("Skipping unimplemented node op:", op)

        if len(node.branches) == 1:
            next_node, _ = node.branches[0]
            next_block = self._lift_block(next_node, visited, current_loop_scope_nodes=current_loop_scope_nodes)
            block.statements.append(next_block)

        return block

    def print(self) -> None:
        print(self.block.pprint())


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
]
