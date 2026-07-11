"""
IR node types for the decompilation pipeline.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from enum import Enum as _Enum
from pprint import pformat
from typing import Any, Dict, List, Optional, Set, Tuple, Union, cast

from ..core import (
    Bytecode,
    DynObj,
    Enum,
    Fun,
    Function,
    Native,
    Obj,
    Opcode,
    Ref,
    Reg,
    ResolvableVarInt,
    Type,
    TypeDef,
    Virtual,
    Void,
    fieldRef,
    gIndex,
    tIndex,
)
from .. import disasm
from ..errors import DecompError
from ..globals import DEBUG, dbg_print
from ..opcodes import arithmetic, conditionals, terminal, simple_calls


_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(s: str) -> str:
    """Remove ANSI color codes, e.g. from IRBlock.pprint(), for non-terminal output."""
    return _ANSI_ESCAPE_RE.sub("", s)


_repr_rendered_blocks: Optional[Set[int]] = None

_type_by_name_cache: Dict[int, Dict[str, Type]] = {}


def _get_type_in_code(code: Bytecode, name: str) -> Type:
    by_name = _type_by_name_cache.get(id(code))
    if by_name is None:
        by_name = {}
        for type in code.types:
            by_name.setdefault(disasm.type_name(code, type), type)
        _type_by_name_cache[id(code)] = by_name
    found = by_name.get(name)
    if found is None:
        raise DecompError(f"Type {name} not found in code")
    return found


class IRStatement(ABC):
    def __init__(self, code: Bytecode):
        self.code = code
        self.comment: str = ""
        self.src_line: Optional[int] = None
        self.src_file_idx: Optional[int] = None
        # All original opcode indices this statement represents. Populated with a
        # single index at initial lift time; when an optimizer folds several
        # statements into one, it should call `.adopt(*originals)` so every
        # constituent opcode still resolves back to the resulting line (for
        # disasm<->pseudocode sync and per-opcode comments) instead of only
        # whichever one happened to seed the replacement statement.
        self.src_op_idxs: Set[int] = set()

    @property
    def src_op_idx(self) -> Optional[int]:
        """Primary (lowest) source opcode index. Prefer `src_op_idxs` for anything
        that needs to account for statements folded from multiple opcodes."""
        return min(self.src_op_idxs) if self.src_op_idxs else None

    @src_op_idx.setter
    def src_op_idx(self, value: Optional[int]) -> None:
        self.src_op_idxs = {value} if value is not None else set()

    def adopt(self, *others: "IRStatement") -> "IRStatement":
        """Merge in the source-opcode indices of statement(s) this one replaces."""
        for o in others:
            self.src_op_idxs |= o.src_op_idxs
        return self

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
        global _repr_rendered_blocks
        colors = [36, 31, 32, 33, 34, 35]

        depth = id(self) % len(colors)
        color = colors[depth]

        if not self.statements:
            return f"\033[{color}m[\033[0m\033[{color}m]\033[0m"

        top = _repr_rendered_blocks is None
        if top:
            _repr_rendered_blocks = set()
        try:
            # Ancestor-stack guard: only collapse a block that is its own
            # ancestor (a real cycle). Shared acyclic continuations render fully.
            if id(self) in _repr_rendered_blocks:  # type: ignore[operator]
                return f"\033[{color}m[...]\033[0m"
            _repr_rendered_blocks.add(id(self))  # type: ignore[union-attr]
            try:
                # uniform indentation
                statements = pformat(self.statements, indent=0).replace("\n", "\n\t")
            finally:
                _repr_rendered_blocks.discard(id(self))  # type: ignore[union-attr]
        finally:
            if top:
                _repr_rendered_blocks = None

        return f"\033[{color}m[\033[0m\n\t{statements}\n\033[{color}m]\033[0m"

    def __repr__(self) -> str:
        global _repr_rendered_blocks
        if not self.statements:
            return "[]"

        top = _repr_rendered_blocks is None
        if top:
            _repr_rendered_blocks = set()
        try:
            # Ancestor-stack guard: only collapse a block that is its own
            # ancestor (a real cycle). Shared acyclic continuations render fully.
            if id(self) in _repr_rendered_blocks:  # type: ignore[operator]
                return "[...]"
            _repr_rendered_blocks.add(id(self))  # type: ignore[union-attr]
            try:
                statements = pformat(self.statements, indent=0).replace("\n", "\n\t")
            finally:
                _repr_rendered_blocks.discard(id(self))  # type: ignore[union-attr]
        finally:
            if top:
                _repr_rendered_blocks = None

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
    def __init__(
        self,
        name: str,
        type: tIndex,
        code: Bytecode,
        reg_idx: Optional[int] = None,
        defining_op_idx: Optional[int] = None,
    ):
        super().__init__(code)
        self.name = name
        self.type = type
        self.reg_idx = reg_idx
        self.defining_op_idx: Optional[int] = defining_op_idx
        # Set by IRNativeArrayAllocOptimizer when this local is bound to a
        # `Native.alloc_array(ty, size)` result: the bytecode's own "Array" kind
        # carries no element-type info, but Haxe's hl.NativeArray<T> needs one,
        # so this records the `T` recovered from the allocation site for the
        # declared-type renderer to use instead of the generic Array<Dynamic>.
        self.native_elem_type: Optional[Type] = None
        # Set by IRNativeMapAllocOptimizer when this local is bound to one of
        # HL's raw map-abstract allocators (e.g. `Native.hballoc()`): the
        # bytecode's Abstract type carries no usable name (see
        # IRNativeMapNew), so this records the recovered Haxe class name for
        # the declared-type renderer to use instead of the generic Abstract.
        self.native_map_class: Optional[str] = None
        # Set when this I32 local feeds a `ToUFloat` conversion: HL has no
        # separate UInt register kind (it's an I32 like Int), so this is the
        # only signal that the source used `UInt` rather than `Int` — without
        # it, the conversion recompiles as the (wrong) signed `ToSFloat`.
        self.is_unsigned: bool = False

    def get_type(self) -> Type:
        return self.type.resolve(self.code)

    def same_register(self, other: "IRLocal") -> bool:
        """Return True if this local and `other` originate from the same VM register."""
        return self.reg_idx is not None and other.reg_idx is not None and self.reg_idx == other.reg_idx

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IRLocal):
            return False
        return (
            self.name == other.name
            and self.type.resolve(self.code) is other.type.resolve(other.code)
            and self.code is other.code
        )

    def __hash__(self) -> int:
        return hash((self.name, id(self.type.resolve(self.code)), id(self.code)))

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
        self._cached_type: Optional[Type] = None

    def get_type(self) -> Type:
        if self._cached_type is not None:
            return self._cached_type
        node = self.left
        while isinstance(node, IRArithmetic):
            if node._cached_type is not None:
                self._cached_type = node._cached_type
                return node._cached_type
            node = node.left
        result = node.get_type()
        self._cached_type = result
        return result

    def __repr__(self) -> str:
        return f"<IRArithmetic: {self.left} {self.op.value} {self.right}>"


class IRNeg(IRExpression):
    """Represents numeric negation, e.g. `-x` (lifted from the `Neg` opcode)."""

    def __init__(self, code: Bytecode, expr: IRExpression):
        super().__init__(code)
        self.expr = expr

    def get_type(self) -> Type:
        return self.expr.get_type()

    def get_children(self) -> List[IRStatement]:
        return [self.expr]

    def __repr__(self) -> str:
        return f"<IRNeg: -{self.expr}>"


class IRNot(IRExpression):
    """Represents boolean negation, e.g. `!x` (lifted from the `Not` opcode)."""

    def __init__(self, code: Bytecode, expr: IRExpression):
        super().__init__(code)
        self.expr = expr

    def get_type(self) -> Type:
        return self.expr.get_type()

    def get_children(self) -> List[IRStatement]:
        return [self.expr]

    def __repr__(self) -> str:
        return f"<IRNot: !{self.expr}>"


class IRTypeOf(IRExpression):
    """Represents fetching a value's runtime type, e.g. `Type.getDynamic(x)` (lifted from `GetType`)."""

    def __init__(self, code: Bytecode, expr: IRExpression, dst_type: tIndex):
        super().__init__(code)
        self.expr = expr
        self.dst_type_idx = dst_type

    def get_type(self) -> Type:
        return self.dst_type_idx.resolve(self.code)

    def get_children(self) -> List[IRStatement]:
        return [self.expr]

    def __repr__(self) -> str:
        return f"<IRTypeOf: Type.getDynamic({self.expr})>"


class IRTypeKind(IRExpression):
    """Represents reading a runtime type's kind tag, e.g. `t.kind` (lifted from `GetTID`)."""

    def __init__(self, code: Bytecode, expr: IRExpression, dst_type: tIndex):
        super().__init__(code)
        self.expr = expr
        self.dst_type_idx = dst_type

    def get_type(self) -> Type:
        return self.dst_type_idx.resolve(self.code)

    def get_children(self) -> List[IRStatement]:
        return [self.expr]

    def __repr__(self) -> str:
        return f"<IRTypeKind: {self.expr}.kind>"


class IRAssign(IRStatement):
    """Assignment of an expression result to a target (local variable, field, etc.)"""

    def __init__(self, code: Bytecode, target: IRExpression, expr: IRExpression):
        super().__init__(code)
        is_global_target = isinstance(target, IRConst) and target.const_type == IRConst.ConstType.GLOBAL_OBJ
        if not isinstance(target, (IRLocal, IRField, IRArrayAccess, IREnumField)) and not is_global_target:
            raise DecompError(
                f"Invalid target for IRAssign: {type(target).__name__}. "
                "Must be IRLocal, IRField, IRArrayAccess, IREnumField, or a GLOBAL_OBJ IRConst (SetGlobal)."
            )
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
        target: "IRConst|IRLocal|IRField|None",
        args: List[IRExpression],
    ):
        super().__init__(code)
        self.call_type = call_type
        self.target = target
        self.args = args
        if self.call_type == IRCall.CallType.THIS and self.target is not None:
            raise DecompError("THIS calls must have a None target")
        if self.call_type != IRCall.CallType.CLOSURE and isinstance(self.target, IRLocal):
            raise DecompError("Non-CLOSURE calls must not have a local target")

    def get_type(self) -> Type:
        # for now, assume closure calls return dynamic type
        if self.call_type == IRCall.CallType.CLOSURE:
            return _get_type_in_code(self.code, "Dyn")
        if self.call_type == IRCall.CallType.THIS or self.target is None:
            return _get_type_in_code(self.code, "Obj")
        return self.target.get_type()

    def get_children(self) -> List[IRStatement]:
        children: List[IRStatement] = []
        if self.target is not None:
            children.append(self.target)
        children.extend(self.args)
        return children

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
        # Synthesized short-circuit combinators (see IRGuardOrMerger); `left`
        # and `right` are themselves full boolean expressions, not operands.
        OR = "or"
        AND = "and"

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
        return _get_type_in_code(self.code, "Bool")

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

    def get_children(self) -> List[IRStatement]:
        children: List[IRStatement] = []
        if self.left is not None:
            children.append(self.left)
        if self.right is not None:
            children.append(self.right)
        return children

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
        elif const_type == IRConst.ConstType.NULL:
            self.value = None
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


class IRContinue(IRStatement):
    """Continue statement"""

    def __init__(self, code: Bytecode):
        super().__init__(code)

    def get_children(self) -> List[IRStatement]:
        return []

    def __repr__(self) -> str:
        return "<IRContinue>"


class IRReturn(IRStatement):
    """Return statement"""

    def __init__(self, code: Bytecode, value: Optional[IRExpression] = None):
        super().__init__(code)
        self.value = value

    def get_children(self) -> List[IRStatement]:
        return [self.value] if self.value is not None else []

    def __repr__(self) -> str:
        return f"<IRReturn: {self.value}>"


class IRThrow(IRStatement):
    """Throw statement"""

    def __init__(self, code: Bytecode, value: IRExpression):
        super().__init__(code)
        self.value = value

    def get_children(self) -> List[IRStatement]:
        return [self.value]

    def __repr__(self) -> str:
        return f"<IRThrow: {self.value}>"


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


class IRTryCatch(IRStatement):
    """Structured try/catch statement."""

    def __init__(
        self,
        code: Bytecode,
        try_block: IRBlock,
        catch_block: IRBlock,
        catch_local: Optional[IRLocal] = None,
        explicit_catch_type: bool = False,
    ):
        super().__init__(code)
        self.try_block = try_block
        self.catch_block = catch_block
        self.catch_local = catch_local
        # Haxe's codegen for a catch clause differs depending on whether the
        # source wrote an explicit `catch (e: Dynamic)` or just `catch (e)`,
        # even though both infer the same type — see
        # IRFunction._catch_has_explicit_type for the bytecode fingerprint.
        self.explicit_catch_type = explicit_catch_type

    def get_children(self) -> List[IRStatement]:
        children: List[IRStatement] = [self.try_block, self.catch_block]
        if self.catch_local is not None:
            children.insert(0, self.catch_local)
        return children

    def __repr__(self) -> str:
        return f"<IRTryCatch: try\n\t{self.try_block}\ncatch ({self.catch_local})\n\t{self.catch_block}>"


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

    def __init__(
        self,
        code: Bytecode,
        op: Opcode,
        left: Optional[IRExpression] = None,
        right: Optional[IRExpression] = None,
        cond: Optional[IRExpression] = None,
    ):
        super().__init__(code)
        self.op = op
        self.left = left
        self.right = right
        self.cond = cond
        assert op.op in conditionals

    def get_type(self) -> Type:
        return _get_type_in_code(self.code, "Bool")

    def __repr__(self) -> str:
        return f"<IRPrimitiveJump: {self.op}>"


class IRWhileLoop(IRStatement):
    """
    Represents a while loop: while (condition) { body }
    """

    condition: IRExpression
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
        children: List[IRStatement] = []
        children.append(self.condition)
        children.append(self.body)
        return children

    def __repr__(self) -> str:
        body_repr = pformat(self.body, indent=0).replace("\n", "\n\t")
        return f"<IRWhileLoop: while ({self.condition}) {{\n\t{body_repr}\n}}>"

    def __str__(self) -> str:
        return self.__repr__()


class IRForEachLoop(IRStatement):
    """
    Represents a Haxe for-each loop: for (elem in array) { body }
    """

    elem: IRLocal
    array: IRExpression
    body: IRBlock

    def __init__(self, code: Bytecode, elem: IRLocal, array: IRExpression, body: IRBlock):
        super().__init__(code)
        self.elem = elem
        self.array = array
        self.body = body
        self.comment = ""

    def get_children(self) -> List[IRStatement]:
        return [self.elem, self.array, self.body]

    def __repr__(self) -> str:
        body_repr = pformat(self.body, indent=0).replace("\n", "\n\t")
        return f"<IRForEachLoop: for ({self.elem} in {self.array}) {{\n\t{body_repr}\n}}>"

    def __str__(self) -> str:
        return self.__repr__()


class IRIntRangeLoop(IRStatement):
    """
    Represents a Haxe int-range for loop: for (elem in start...end) { body }
    """

    elem: IRLocal
    start: IRExpression
    end: IRExpression
    body: IRBlock

    def __init__(self, code: Bytecode, elem: IRLocal, start: IRExpression, end: IRExpression, body: IRBlock):
        super().__init__(code)
        self.elem = elem
        self.start = start
        self.end = end
        self.body = body
        self.comment = ""

    def get_children(self) -> List[IRStatement]:
        return [self.elem, self.start, self.end, self.body]

    def __repr__(self) -> str:
        body_repr = pformat(self.body, indent=0).replace("\n", "\n\t")
        return f"<IRIntRangeLoop: for ({self.elem} in {self.start}...{self.end}) {{\n\t{body_repr}\n}}>"

    def __str__(self) -> str:
        return self.__repr__()


class IRField(IRExpression):
    """Represents an object field access expression, e.g., `obj.field`"""

    def __init__(self, code: Bytecode, target: IRExpression, field_name: str, field_type: tIndex):
        super().__init__(code)
        self.target = target
        self.field_name = field_name
        self.field_type_idx = field_type
        # Set when this field access is a method closure lifted from a
        # VirtualClosure opcode; see IRFunction._lift_ops_into_block.
        self.virtual_dispatch_fun: Optional["Function"] = None

    def get_type(self) -> Type:
        return self.field_type_idx.resolve(self.code)

    def get_children(self) -> List[IRStatement]:
        if self.target is not None and isinstance(self.target, IRStatement):
            return [self.target]
        return []

    def __repr__(self) -> str:
        return f"<IRField: {self.target}.{self.field_name}>"


class IRNew(IRExpression):
    """Represents object allocation, e.g., `new MyClass()` or `{}`"""

    def __init__(self, code: Bytecode, alloc_type: tIndex, constructor_args: Optional[List[IRExpression]] = None):
        super().__init__(code)
        self.alloc_type_idx = alloc_type
        self.constructor_args = constructor_args or []

    def get_type(self) -> Type:
        return self.alloc_type_idx.resolve(self.code)

    def get_children(self) -> List[IRStatement]:
        return [a for a in self.constructor_args if isinstance(a, IRStatement)]

    def __repr__(self) -> str:
        type_name = disasm.type_name(self.code, self.get_type())
        if type_name == "DynObj":
            return "<IRNew: {}>"
        args_str = ", ".join(repr(a) for a in self.constructor_args) if self.constructor_args else ""
        return f"<IRNew: new {type_name}({args_str})>"


class IRNativeArrayNew(IRExpression):
    """
    Represents allocating a raw HL native array with a known element type, e.g.
    `new hl.NativeArray<Int>(3)` (lifted from `Native.alloc_array(ty, size)` by
    IRNativeArrayAllocOptimizer). `array_type` is the tIndex of the bytecode's
    own (element-type-erased) "Array" kind, used for type compatibility with the
    rest of the array-handling IR (GetArray/SetArray/ArraySize all expect it);
    `elem_type` is only used for rendering the Haxe generic parameter.
    """

    def __init__(self, code: Bytecode, array_type: tIndex, elem_type: Type, size: IRExpression):
        super().__init__(code)
        self.array_type_idx = array_type
        self.elem_type = elem_type
        self.size = size

    def get_type(self) -> Type:
        return self.array_type_idx.resolve(self.code)

    def get_children(self) -> List[IRStatement]:
        return [self.size] if isinstance(self.size, IRStatement) else []

    def __repr__(self) -> str:
        elem_name = disasm.type_name(self.code, self.elem_type)
        return f"<IRNativeArrayNew: new hl.NativeArray<{elem_name}>({self.size})>"


class IRNativeMapNew(IRExpression):
    """
    Represents allocating one of HL's raw map abstracts via its no-arg native
    allocator, e.g. `new hl.types.BytesMap()` (lifted from `Native.hballoc()`
    by IRNativeMapAllocOptimizer). The bytecode's Abstract type carries no
    usable name (disasm.type_name falls back to the generic "Abstract" for
    every abstract kind), so `haxe_class_name` is recovered from the native's
    own name instead and used purely for rendering; `abstract_type` is the
    actual bytecode type, kept for type compatibility with the rest of the IR.
    """

    def __init__(self, code: Bytecode, abstract_type: tIndex, haxe_class_name: str):
        super().__init__(code)
        self.abstract_type_idx = abstract_type
        self.haxe_class_name = haxe_class_name

    def get_type(self) -> Type:
        return self.abstract_type_idx.resolve(self.code)

    def get_children(self) -> List[IRStatement]:
        return []

    def __repr__(self) -> str:
        return f"<IRNativeMapNew: new {self.haxe_class_name}()>"


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


class IRArrayLiteral(IRExpression):
    """Represents a Haxe array literal, e.g. [1, 2, 3]."""

    def __init__(self, code: Bytecode, elements: List[IRExpression], elem_type: Optional[tIndex] = None):
        super().__init__(code)
        self.elements = elements
        self.elem_type_idx = elem_type

    def get_type(self) -> Type:
        if self.elem_type_idx:
            return self.elem_type_idx.resolve(self.code)
        return _get_type_in_code(self.code, "Dyn")

    def get_children(self) -> List[IRStatement]:
        return [e for e in self.elements]

    def __repr__(self) -> str:
        return f"<IRArrayLiteral: [{', '.join(repr(e) for e in self.elements)}]>"


class IRObjectLiteral(IRExpression):
    """Represents a Haxe anonymous object literal, e.g. `{ foo: 1, bar: "x" }`.

    HashLink always lowers these to `{}` (an empty DynObj allocation) followed
    by one field-assignment statement per key — including the `?pos:haxe.
    PosInfos` argument the compiler silently attaches to functions that
    declare one (most visibly `haxe.PosException` subclasses), so recovering
    this at IRAnonObjectLiteralOptimizer time keeps e.g. `throw new
    SomeException()` from ballooning into six lines of DynObj scaffolding.
    """

    def __init__(self, code: Bytecode, fields: List[Tuple[str, IRExpression]]):
        super().__init__(code)
        self.fields = fields

    def get_type(self) -> Type:
        return _get_type_in_code(self.code, "Dyn")

    def get_children(self) -> List[IRStatement]:
        return [v for _, v in self.fields]

    def __repr__(self) -> str:
        inner = ", ".join(f"{k}: {v!r}" for k, v in self.fields)
        return f"<IRObjectLiteral: {{{inner}}}>"


class IRArrayAccess(IRExpression):
    """Represents an array/memory access expression, e.g., `arr[idx]`"""

    def __init__(self, code: Bytecode, array: IRExpression, index: IRExpression, elem_type: Optional[tIndex] = None):
        super().__init__(code)
        self.array = array
        self.index = index
        self.elem_type_idx = elem_type
        # Set for raw hl.Bytes memory accesses (GetMem/GetI16/GetI8 and their
        # Set counterparts) to the HL.Bytes accessor method's value suffix
        # (e.g. "UI8", "UI16", "I32", "F32", "F64"). hl.Bytes's `arr[idx]`
        # bracket syntax only actually exists for `getUI8`/`setUI8` — every
        # other width requires calling the named method explicitly — so the
        # renderer needs this to know which form is valid. None for ordinary
        # typed-array accesses (GetArray/SetArray), where the wrapper's own
        # `@:arrayAccess` already does the right thing for any element type.
        self.bytes_access_kind: Optional[str] = None

    def get_type(self) -> Type:
        if self.elem_type_idx:
            return self.elem_type_idx.resolve(self.code)
        return _get_type_in_code(self.code, "Void")

    def get_children(self) -> List[IRStatement]:
        return [self.array, self.index]

    def __repr__(self) -> str:
        return f"<IRArrayAccess: {self.array}[{self.index}]>"


class IRRef(IRExpression):
    """Represents a reference/address-of expression, e.g., `&var`"""

    def __init__(self, code: Bytecode, target: IRExpression):
        super().__init__(code)
        self.target = target

    def get_type(self) -> Type:
        return _get_type_in_code(self.code, "Void")

    def get_children(self) -> List[IRStatement]:
        return [self.target]

    def __repr__(self) -> str:
        return f"<IRRef: &{self.target}>"


class IRRefNew(IRExpression):
    """Represents `new hl.Ref(value)`"""

    def __init__(self, code: Bytecode, target: IRExpression):
        super().__init__(code)
        self.target = target

    def get_type(self) -> Type:
        return _get_type_in_code(self.code, "Ref")

    def get_children(self) -> List[IRStatement]:
        return [self.target]

    def __repr__(self) -> str:
        return f"<IRRefNew: new Ref({self.target})>"


class IRRefGet(IRExpression):
    """Represents reading the value stored in an `hl.Ref`, e.g. `r.get()`"""

    def __init__(self, code: Bytecode, ref: IRExpression):
        super().__init__(code)
        self.ref = ref

    def get_type(self) -> Type:
        ref_type = self.ref.get_type()
        if isinstance(ref_type.definition, Ref):
            return ref_type.definition.type.resolve(self.code)
        return ref_type

    def get_children(self) -> List[IRStatement]:
        return [self.ref]

    def __repr__(self) -> str:
        return f"<IRRefGet: {self.ref}.get()>"


class IRRefSet(IRStatement):
    """Represents writing to an `hl.Ref`, e.g. `r.set(value)`"""

    def __init__(self, code: Bytecode, ref: IRExpression, value: IRExpression):
        super().__init__(code)
        self.ref = ref
        self.value = value

    def get_type(self) -> Type:
        return _get_type_in_code(self.code, "Void")

    def get_children(self) -> List[IRStatement]:
        return [self.ref, self.value]

    def __repr__(self) -> str:
        return f"<IRRefSet: {self.ref}.set({self.value})>"


class IREnumConstruct(IRExpression):
    """Represents enum construction, e.g., `Rgb(255, 255, 0)`"""

    def __init__(self, code: Bytecode, construct_name: str, args: List[IRExpression], enum_type: tIndex):
        super().__init__(code)
        self.construct_name = construct_name
        self.args = args
        self.enum_type_idx = enum_type

    def get_type(self) -> Type:
        return self.enum_type_idx.resolve(self.code)

    def get_children(self) -> List[IRStatement]:
        return []

    def __repr__(self) -> str:
        args_str = ", ".join(str(a) for a in self.args)
        return f"<IREnumConstruct: {self.construct_name}({args_str})>"


class IREnumIndex(IRExpression):
    """Represents getting the index of an enum value"""

    def __init__(self, code: Bytecode, value: IRExpression):
        super().__init__(code)
        self.value = value

    def get_type(self) -> Type:
        return _get_type_in_code(self.code, "I32")

    def get_children(self) -> List[IRStatement]:
        return [self.value]

    def __repr__(self) -> str:
        return f"<IREnumIndex: indexof({self.value})>"


class IREnumField(IRExpression):
    """Represents accessing a field of an enum construct, e.g., extracting `r` from `Rgb(r, g, b)`"""

    def __init__(self, code: Bytecode, value: IRExpression, field_name: str, field_type: tIndex):
        super().__init__(code)
        self.value = value
        self.field_name = field_name
        self.field_type_idx = field_type

    def get_type(self) -> Type:
        return self.field_type_idx.resolve(self.code)

    def get_children(self) -> List[IRStatement]:
        return [self.value]

    def __repr__(self) -> str:
        return f"<IREnumField: {self.value}.{self.field_name}>"


class IRUnliftedOpcode(IRExpression):
    """Represents an opcode that has not been lifted into a higher-level IR statement."""

    def __init__(self, code: Bytecode, op: Opcode, dst_type_idx: Optional[tIndex] = None):
        super().__init__(code)
        self.op = op
        self.dst_type_idx = dst_type_idx

    def get_type(self) -> Type:
        """
        Returns the type of the destination register, or Void if not applicable.
        """
        if self.dst_type_idx:
            return self.dst_type_idx.resolve(self.code)
        return _get_type_in_code(self.code, "Void")

    def get_children(self) -> List[IRStatement]:
        return []

    def __repr__(self) -> str:
        return f"<IRUntranslatedOpcode: {self.op.op}>"


class IRNativeStub(IRStatement):
    """Placeholder for a raw native function entry that has no HL bytecode."""

    def __init__(self, code: Bytecode, native: "Native"):
        super().__init__(code)
        self.native = native

    def get_type(self) -> Type:
        return _get_type_in_code(self.code, "Void")

    def get_children(self) -> List[IRStatement]:
        return []

    def __repr__(self) -> str:
        return f"<IRNativeStub: {self.native.name.resolve(self.code)}>"
