"""
Array and bytes-buffer pattern optimizers.
"""

from __future__ import annotations

import copy
import re
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple, Union, cast

if TYPE_CHECKING:
    from ..function import IRFunction

from ...core import (
    Bytecode,
    DynObj,
    Enum,
    Fun,
    Function,
    Native,
    Obj,
    Opcode,
    Ref,
    ResolvableVarInt,
    Type,
    TypeDef,
    Virtual,
    Void,
    fieldRef,
    gIndex,
    tIndex,
)
from ...errors import DecompError
from ...globals import DEBUG, dbg_print
from ... import disasm
from ...opcodes import arithmetic, conditionals, terminal, simple_calls
from ..ir import (
    IRStatement,
    IRExpression,
    IRBlock,
    IRLocal,
    IRArithmetic,
    IRNeg,
    IRNot,
    IRTypeOf,
    IRTypeKind,
    IRAssign,
    IRCall,
    IRBoolExpr,
    IRConst,
    IRConditional,
    IRPrimitiveLoop,
    IRBreak,
    IRContinue,
    IRReturn,
    IRThrow,
    IRTrace,
    IRTryCatch,
    IRSwitch,
    IRPrimitiveJump,
    IRWhileLoop,
    IRForEachLoop,
    IRIntRangeLoop,
    IRField,
    IRNew,
    IRNativeArrayNew,
    IRNativeMapNew,
    IRCast,
    IRArrayLiteral,
    IRArrayAccess,
    IRRef,
    IREnumConstruct,
    IREnumIndex,
    IREnumField,
    IRUnliftedOpcode,
    IRNativeStub,
    _get_type_in_code,
    _strip_ansi,
)
from ..cfg import CFNode, CFGraph, IsolatedCFGraph, _find_jumps_to_label
from . import (
    IROptimizer,
    TraversingIROptimizer,
    _ir_structurally_equal,
    _structurally_equal,
    _stmt_lists_structurally_equal,
    _bytes_mem_kind,
    _int_const_value,
    _signed_i32,
)


class IRNativeArrayAllocOptimizer(TraversingIROptimizer):
    """
    Folds `Native.alloc_array(ty, size)` into `new hl.NativeArray<T>(size)`.

    HL's raw "Array" kind is element-type-erased at the bytecode level — the
    only place the element type shows up is as the first argument to the
    `alloc_array` native at the allocation site (a `Type` opcode result, lifted
    to an IRConst(GLOBAL_OBJ) carrying the actual `Type`). Recovering it here
    lets the declared local be typed `hl.NativeArray<T>` instead of the much
    too generic (and, on recompile, semantically different — a boxed Haxe
    `Array<Dynamic>`) `Array<Dynamic>`.
    """

    TARGET_OPCODES = {"Type"}

    def _is_alloc_array_call(self, expr: IRExpression) -> bool:
        if not isinstance(expr, IRCall) or len(expr.args) != 2:
            return False
        if not isinstance(expr.target, IRConst) or not isinstance(expr.target.value, Native):
            return False
        return expr.target.value.name.resolve(self.func.code) == "alloc_array"

    def visit_block(self, block: IRBlock) -> None:
        local_defs: Dict[IRLocal, IRExpression] = {}
        for stmt in block.statements:
            if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal):
                local_defs[stmt.target] = stmt.expr
            if not (isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal)):
                continue
            if not self._is_alloc_array_call(stmt.expr):
                continue
            assert isinstance(stmt.expr, IRCall)
            ty_arg, size_arg = stmt.expr.args
            elem_type: Optional[Type] = None
            if isinstance(ty_arg, IRConst) and ty_arg.const_type == IRConst.ConstType.GLOBAL_OBJ:
                if isinstance(ty_arg.value, Type):
                    elem_type = ty_arg.value
            elif isinstance(ty_arg, IRLocal):
                defn = local_defs.get(ty_arg)
                if (
                    isinstance(defn, IRConst)
                    and defn.const_type == IRConst.ConstType.GLOBAL_OBJ
                    and isinstance(defn.value, Type)
                ):
                    elem_type = defn.value
            if elem_type is None:
                continue
            stmt.target.native_elem_type = elem_type
            stmt.expr = IRNativeArrayNew(self.func.code, stmt.target.type, elem_type, size_arg)
        for stmt in block.statements:
            for child in stmt.get_children():
                if isinstance(child, IRBlock):
                    self.visit_block(child)


class IRArrayObjWrapperOptimizer(TraversingIROptimizer):
    """
    Folds stdlib ArrayObj/ArrayDyn wrapper calls into Haxe array literals.

    Haxe's `new Array<Dynamic>()` and `[]` lower to calls like
    `__std_234_anon(Native.alloc_array(...))` or `__std_253_anon(new ArrayObj())`.
    These anonymous wrapper functions live in `hl/types/Array*.hx` and simply
    initialize an array object.  Rendering them as `[]` recovers the original
    source idiom.
    """

    _ARRAY_WRAPPER_RE = re.compile(r"__std_\d+_anon$")

    def _is_array_wrapper_call(self, expr: IRExpression) -> bool:
        if not isinstance(expr, IRCall) or len(expr.args) != 1:
            return False
        target = expr.target
        if not isinstance(target, IRConst) or not isinstance(target.value, Function):
            return False
        func = target.value
        try:
            path = func.resolve_file(self.func.code).replace("\\", "/")
        except Exception:
            return False
        if "hl/types/Array" not in path:
            return False
        partial = self.func.code.partial_func_name(func)
        return partial in (None, "", "<none>")

    def _is_empty_array_alloc(
        self,
        expr: Optional[IRExpression],
        local_defs: Dict["IRLocal", IRExpression],
        seen: Optional[Set[int]] = None,
    ) -> bool:
        """True when `expr` resolves to a zero-length array allocation."""
        if expr is None or not isinstance(expr, IRStatement):
            return False
        if seen is None:
            seen = set()
        if id(expr) in seen:
            return False
        seen.add(id(expr))

        if isinstance(expr, IRArrayLiteral):
            return not expr.elements
        if isinstance(expr, IRCall) and len(expr.args) == 2:
            target = expr.target
            if (
                isinstance(target, IRConst)
                and isinstance(target.value, Native)
                and target.value.name.resolve(self.func.code) == "alloc_array"
            ):
                size = expr.args[1]
                if isinstance(size, IRLocal):
                    size = local_defs.get(size, size)
                if isinstance(size, IRConst):
                    size_val = getattr(size.value, "value", size.value)
                    if size.const_type == IRConst.ConstType.INT and size_val == 0:
                        return True
        if isinstance(expr, IRNativeArrayNew):
            size = expr.size
            if isinstance(size, IRLocal):
                size = local_defs.get(size, size)
            if not isinstance(size, IRConst):
                return False
            size_val = getattr(size.value, "value", size.value)
            return size.const_type == IRConst.ConstType.INT and size_val == 0
        if isinstance(expr, IRLocal):
            return self._is_empty_array_alloc(local_defs.get(expr), local_defs, seen)
        return False

    def visit_block(self, block: IRBlock) -> None:
        local_defs: Dict[IRLocal, IRExpression] = {}
        new_statements: List[IRStatement] = []
        for stmt in block.statements:
            if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal):
                local_defs[stmt.target] = stmt.expr
            if isinstance(stmt, IRAssign) and isinstance(stmt.expr, IRCall) and self._is_array_wrapper_call(stmt.expr):
                if self._is_empty_array_alloc(stmt.expr.args[0], local_defs):
                    stmt.expr = IRArrayLiteral(self.func.code, [])
                # Non-empty wrappers (e.g. ArrayObj.alloc(anew) after blitting)
                # must stay so pseudo can render `alloc(anew)`.
            elif isinstance(stmt, IRCall) and self._is_array_wrapper_call(stmt):
                # Bare wrapper call (typically a constructor wrapper on a fresh
                # `new ArrayObj()`).  It has no observable effect beyond
                # initializing the array, so drop it.
                continue
            new_statements.append(stmt)
        block.statements = new_statements
        for stmt in block.statements:
            for child in stmt.get_children():
                if isinstance(child, IRBlock):
                    self.visit_block(child)


class IRNativeMapAllocOptimizer(TraversingIROptimizer):
    """
    Folds the no-arg native allocators backing HL's raw map abstracts into
    their Haxe constructor calls, e.g. `Native.hballoc()` -> `new
    hl.types.BytesMap()`.

    hl/types/{Bytes,Int,Int64,Object}Map.hx each wrap a single Abstract in a
    `new()` that's just `extern public inline function new() this = alloc();`,
    with `alloc` a `@:hlNative("std", ...)` call taking no arguments (see
    src/std/maps.c's `hballoc`/`hialloc`/`hi64alloc`/`hoalloc` in the
    hashlink runtime). The Abstract type itself carries no name we can
    recover (see IRNativeMapNew), so the native's own name is the only way
    to tell which map class an allocation belongs to.
    """

    TARGET_OPCODES = {"Call0"}

    NATIVE_TO_CLASS = {
        "hballoc": "hl.types.BytesMap",
        "hialloc": "hl.types.IntMap",
        "hi64alloc": "hl.types.Int64Map",
        "hoalloc": "hl.types.ObjectMap",
    }

    def _map_alloc(self, expr: IRExpression) -> Optional[Tuple[str, Native]]:
        if not isinstance(expr, IRCall) or expr.args:
            return None
        if not (isinstance(expr.target, IRConst) and isinstance(expr.target.value, Native)):
            return None
        native = expr.target.value
        if native.lib.resolve(self.func.code) != "std":
            return None
        class_name = self.NATIVE_TO_CLASS.get(native.name.resolve(self.func.code))
        return (class_name, native) if class_name is not None else None

    def visit_block(self, block: IRBlock) -> None:
        for stmt in block.statements:
            if not isinstance(stmt, IRAssign):
                continue
            alloc = self._map_alloc(stmt.expr)
            if alloc is None:
                continue
            class_name, native = alloc
            # The allocation site itself is the only place that carries the
            # Abstract return type by way of the native's own signature; a
            # local target's declared (register) type is the same value, but
            # by the time this optimizer runs the assignment may already be
            # copy-propagated onto a non-local target (e.g. SetGlobal).
            fun_def = native.type.resolve(self.func.code).definition
            assert isinstance(fun_def, Fun)
            abstract_type = fun_def.ret
            if isinstance(stmt.target, IRLocal):
                stmt.target.native_map_class = class_name
            stmt.expr = IRNativeMapNew(self.func.code, abstract_type, class_name)
        for stmt in block.statements:
            for child in stmt.get_children():
                if isinstance(child, IRBlock):
                    self.visit_block(child)


class IRArrayPatternOptimizer(TraversingIROptimizer):
    """
    Recognise low-level HashLink array implementation patterns and rewrite them
    into high-level Haxe array operations.

    Currently handles:
      - Fixed-size integer array literals built with alloc_bytes + stores + allocI32.
      - Conditional arr.bytes[idx << 2] loads with length guard -> arr[idx].
      - ArrayObj allocation with <none>(alloc_array(...)) -> [].
      - temp = arr.bytes; ...; x = temp[idx << 2] -> x = arr[idx].

    Too many distinct opcode triggers to gate safely by TARGET_OPCODES — runs
    unconditionally.
    """

    def visit_block(self, block: IRBlock) -> None:
        made_change = True
        while made_change:
            made_change = False
            new_statements: List[IRStatement] = []
            i = 0
            while i < len(block.statements):
                stmt = block.statements[i]
                access_match = self._try_array_access(block.statements, i)
                if access_match:
                    arr_assign, consumed, preceding_to_pop = access_match
                    for _ in range(preceding_to_pop):
                        new_statements.pop()
                    new_statements.append(arr_assign)
                    i += consumed
                    made_change = True
                    continue

                literal_match = self._try_array_literal(block.statements, i)
                if literal_match:
                    arr_assign, consumed = literal_match
                    new_statements.append(arr_assign)
                    i += consumed
                    made_change = True
                    continue

                obj_literal_match = self._try_array_obj_literal(block.statements, i)
                if obj_literal_match:
                    use_stmt, consumed = obj_literal_match
                    new_statements.append(use_stmt)
                    i += consumed
                    made_change = True
                    continue

                empty_dyn_match = self._try_empty_array_dyn(block.statements, i)
                if empty_dyn_match:
                    use_stmt, consumed = empty_dyn_match
                    new_statements.append(use_stmt)
                    i += consumed
                    made_change = True
                    continue

                dyn_literal_match = self._try_array_dyn_literal(block.statements, i)
                if dyn_literal_match:
                    use_stmt, consumed = dyn_literal_match
                    new_statements.append(use_stmt)
                    i += consumed
                    made_change = True
                    continue

                guard_match = self._try_write_bounds_guard(block.statements, i)
                if guard_match:
                    i += guard_match
                    made_change = True
                    continue

                temp_match = self._try_eliminate_bytes_temp(block.statements, i)
                if temp_match:
                    # Unlike the other _try_* helpers above, this one returns
                    # a full replacement for the whole statement list (the
                    # match can reach arbitrarily far ahead of `i`), not just
                    # a local edit at the current position — apply it
                    # immediately and restart the scan, instead of appending
                    # more onto `new_statements` from `i` in the *original*
                    # list, which would duplicate everything already folded
                    # into the returned list.
                    new_full_statements, _consumed = temp_match
                    block.statements = new_full_statements
                    made_change = True
                    break

                new_statements.append(stmt)
                i += 1
            else:
                block.statements = new_statements

    def _try_eliminate_bytes_temp(
        self, stmts: List[IRStatement], start: int
    ) -> Optional[Tuple[List[IRStatement], int]]:
        # Pattern: temp = expr.bytes
        # followed by zero or more statements, then a use of temp[idx << 2] that
        # can be rewritten to expr[idx].
        if start >= len(stmts):
            return None
        stmt = stmts[start]
        if not isinstance(stmt, IRAssign) or not isinstance(stmt.target, IRLocal):
            return None
        if not isinstance(stmt.expr, IRField) or stmt.expr.field_name != "bytes":
            return None
        temp = stmt.target
        arr_expr: IRExpression = stmt.expr.target
        # When the bytes field is loaded off `this`, the receiver is the array
        # impl class itself: collapse to `this.bytes[i]`, not `this[i]` (which
        # has no array accessor and won't recompile).
        if isinstance(arr_expr, IRLocal) and arr_expr.name == "this":
            arr_expr = stmt.expr

        # Scan forward for the first use of temp in an array access. The shift
        # offset may have been hoisted into its own temp (`idxTmp = idx << n`)
        # rather than appearing inline in the access; track those as we go.
        idx_temp_map: Dict[str, IRExpression] = {}
        for j in range(start + 1, len(stmts)):
            use = stmts[j]
            if (
                isinstance(use, IRAssign)
                and isinstance(use.target, IRLocal)
                and isinstance(use.expr, IRArithmetic)
                and use.expr.op.value == "<<"
                and isinstance(use.expr.right, IRConst)
            ):
                idx_temp_map[use.target.name] = use.expr.left
            accesses = self._find_temp_accesses(use, temp, arr_expr, idx_temp_map)
            if accesses:
                new_use = self._replace_temp_accesses(use, accesses)
                # Drop only the temp definition itself; the statements between
                # it and the use (start+1..j-1) must stay in their original
                # relative order *before* the (now-collapsed) use — moving the
                # use back to the definition's old position would run it
                # before intervening statements it may depend on (e.g. an
                # index-shift temp recomputed in between).
                return stmts[:start] + stmts[start + 1 : j] + [new_use] + stmts[j + 1 :], 1
        return None

    def _find_temp_accesses(
        self,
        stmt: IRStatement,
        temp: IRLocal,
        arr_expr: IRExpression,
        idx_temp_map: Optional[Dict[str, IRExpression]] = None,
    ) -> List[Tuple[IRArrayAccess, IRExpression]]:
        """Find array accesses in stmt that read temp[idx << n].

        The shift amount is ignored; any left-shift on a raw `.bytes` temporary
        is treated as an element index, so Float (shift 3), Single/Int (shift 2)
        and UI16 (shift 1) arrays all recover correctly.
        """
        result: List[Tuple[IRArrayAccess, IRExpression]] = []
        seen: Set[int] = set()
        idx_temp_map = idx_temp_map or {}

        def visit(node: IRStatement) -> None:
            if id(node) in seen:
                return
            seen.add(id(node))
            if isinstance(node, IRArrayAccess):
                if isinstance(node.array, IRLocal) and node.array.name == temp.name:
                    if (
                        isinstance(node.index, IRArithmetic)
                        and node.index.op.value == "<<"
                        and isinstance(node.index.right, IRConst)
                    ):
                        result.append((node, IRArrayAccess(node.code, arr_expr, node.index.left)))
                    elif isinstance(node.index, IRLocal) and node.index.name in idx_temp_map:
                        result.append((node, IRArrayAccess(node.code, arr_expr, idx_temp_map[node.index.name])))
            for child in node.get_children():
                visit(child)

        visit(stmt)
        return result

    def _replace_temp_accesses(
        self,
        stmt: IRStatement,
        replacements: List[Tuple[IRArrayAccess, IRExpression]],
        _seen: Optional[Set[int]] = None,
    ) -> IRStatement:
        if not replacements:
            return stmt
        if _seen is None:
            _seen = set()
        if id(stmt) in _seen:
            return stmt
        _seen.add(id(stmt))
        old, new = replacements[0]
        if stmt is old:
            return new
        for child in stmt.get_children():
            if child is old:
                # Replace child reference directly if possible.
                self._replace_child(stmt, child, new)
                return stmt
            else:
                replaced = self._replace_temp_accesses(child, replacements, _seen)
                if replaced is not child:
                    self._replace_child(stmt, child, replaced)
                    return stmt
        return stmt

    def _replace_child(self, parent: IRStatement, old: IRStatement, new: Any) -> None:
        if isinstance(parent, IRAssign):
            if parent.target is old:
                parent.target = new
            elif parent.expr is old:
                parent.expr = new
        elif isinstance(parent, IRReturn):
            parent.value = new
        elif isinstance(parent, IRArithmetic):
            if parent.left is old:
                parent.left = new
            elif parent.right is old:
                parent.right = new
        elif isinstance(parent, IRBoolExpr):
            if parent.left is old:
                parent.left = new
            elif parent.right is old:
                parent.right = new
        elif isinstance(parent, IRCall):
            if parent.target is old:
                parent.target = new
            parent.args = [new if a is old else a for a in parent.args]
        elif isinstance(parent, IRArrayAccess):
            if parent.array is old:
                parent.array = new
            elif parent.index is old:
                parent.index = new
        elif isinstance(parent, IRField):
            if parent.target is old:
                parent.target = new
        elif isinstance(parent, IRCast):
            if parent.expr is old:
                parent.expr = new
        elif isinstance(parent, IRNew):
            parent.constructor_args = [new if a is old else a for a in parent.constructor_args]
        elif isinstance(parent, IREnumConstruct):
            parent.args = [new if a is old else a for a in parent.args]
        elif isinstance(parent, IREnumField):
            if parent.value is old:
                parent.value = new
        elif isinstance(parent, IRArrayLiteral):
            parent.elements = [new if e is old else e for e in parent.elements]
        elif isinstance(parent, IRConditional):
            if parent.condition is old:
                parent.condition = new
        elif isinstance(parent, IRPrimitiveLoop):
            if parent.condition is old:
                parent.condition = new
            elif parent.body is old:
                parent.body = new
        elif isinstance(parent, IRWhileLoop):
            if parent.condition is old:
                parent.condition = new
            elif parent.body is old:
                parent.body = new
        elif isinstance(parent, IRSwitch):
            if parent.value is old:
                parent.value = new
        elif isinstance(parent, IRTryCatch):
            if parent.try_block is old:
                parent.try_block = new
            elif parent.catch_block is old:
                parent.catch_block = new
        elif isinstance(parent, IRTrace):
            if parent.msg is old:
                parent.msg = new

    def _is_alloc_bytes(self, expr: IRStatement) -> bool:
        if not isinstance(expr, IRCall):
            return False
        if not isinstance(expr.target, IRConst) or not isinstance(expr.target.value, Native):
            return False
        return expr.target.value.name.resolve(self.func.code) == "alloc_bytes"

    def _is_alloc_typed_array(self, expr: IRStatement) -> Optional[str]:
        """Return the alloc helper name (allocI32/allocF32/allocF64/allocUI16) if
        expr is a call to one of HashLink's typed ArrayBase alloc functions."""
        if not isinstance(expr, IRCall):
            return None
        if not isinstance(expr.target, IRConst) or not isinstance(expr.target.value, Function):
            return None
        name = self.func.code.partial_func_name(expr.target.value)
        if name in ("allocI32", "allocF32", "allocF64", "allocUI16"):
            return name
        return None

    _ALLOC_SHIFTS: Dict[str, int] = {
        "allocI32": 2,
        "allocF32": 2,
        "allocF64": 3,
        "allocUI16": 1,
    }

    def _is_shifted_index(self, idx: IRStatement, local: IRLocal, shift: int) -> bool:
        if not isinstance(idx, IRArithmetic):
            return False
        if idx.op.value != "<<":
            return False
        if not isinstance(idx.left, IRLocal) or idx.left.name != local.name:
            return False
        if not isinstance(idx.right, IRConst) or idx.right.const_type != IRConst.ConstType.INT:
            return False
        val = idx.right.value.value if hasattr(idx.right.value, "value") else idx.right.value
        return int(val) == shift

    def _is_alloc_array(self, expr: IRStatement) -> bool:
        if not isinstance(expr, IRCall):
            return False
        if not isinstance(expr.target, IRConst) or not isinstance(expr.target.value, Native):
            return False
        return expr.target.value.name.resolve(self.func.code) == "alloc_array"

    def _is_arrayobj_anon(self, expr: IRStatement) -> bool:
        if not isinstance(expr, IRCall):
            return False
        if not isinstance(expr.target, IRConst) or not isinstance(expr.target.value, Function):
            return False
        if len(expr.args) != 1:
            return False
        fun = expr.target.value
        try:
            path = fun.resolve_file(self.func.code)
        except Exception:
            path = ""
        if "ArrayObj.hx" not in path.replace("\\", "/"):
            return False
        try:
            sig = fun.resolve_fun(self.func.code)
            ret_name = disasm.type_name(self.func.code, sig.ret.resolve(self.func.code))
        except Exception:
            ret_name = ""
        return "ArrayObj" in ret_name or "Array" in ret_name

    def _find_anon_call(self, node: Optional[IRStatement], arr_local: IRLocal) -> Optional[IRCall]:
        if node is None:
            return None
        if isinstance(node, IRCall) and self._is_arrayobj_anon(node):
            if node.args and isinstance(node.args[0], IRLocal) and node.args[0].name == arr_local.name:
                return node
        # Many expression classes have incomplete get_children(); recurse into the
        # known attributes we care about here.
        if isinstance(node, IRAssign):
            return self._find_anon_call(node.expr, arr_local)
        if isinstance(node, IRReturn) and node.value:
            return self._find_anon_call(node.value, arr_local)
        if isinstance(node, IRCall):
            for arg in node.args:
                found = self._find_anon_call(arg, arr_local)
                if found:
                    return found
        if isinstance(node, IRCast):
            return self._find_anon_call(node.expr, arr_local)
        if isinstance(node, IRField):
            return self._find_anon_call(node.target, arr_local)
        if isinstance(node, IRArrayAccess):
            found = self._find_anon_call(node.array, arr_local)
            if found:
                return found
            return self._find_anon_call(node.index, arr_local)
        if isinstance(node, IRArithmetic):
            found = self._find_anon_call(node.left, arr_local)
            if found:
                return found
            return self._find_anon_call(node.right, arr_local)
        if isinstance(node, IRBoolExpr):
            found = self._find_anon_call(node.left, arr_local)
            if found:
                return found
            return self._find_anon_call(node.right, arr_local)
        if isinstance(node, IREnumField):
            return self._find_anon_call(node.value, arr_local)
        if isinstance(node, IREnumIndex):
            return self._find_anon_call(node.value, arr_local)
        if isinstance(node, IREnumConstruct):
            for arg in node.args:
                found = self._find_anon_call(arg, arr_local)
                if found:
                    return found
        if isinstance(node, IRArrayLiteral):
            for e in node.elements:
                found = self._find_anon_call(e, arr_local)
                if found:
                    return found
        if isinstance(node, IRNew):
            for arg in node.constructor_args:
                found = self._find_anon_call(arg, arr_local)
                if found:
                    return found
        return None

    def _try_array_obj_literal(self, stmts: List[IRStatement], start: int) -> Optional[Tuple[IRStatement, int]]:
        # Pattern:
        #   arr = alloc_array(type, size)
        #   [elem = expr;] arr[i] = elem
        #   ...
        #   use(ArrayObj.anon(arr))
        # Rewrite the ArrayObj.anon(arr) expression to [expr0, expr1, ...].
        if start >= len(stmts):
            return None
        stmt = stmts[start]
        if not isinstance(stmt, IRAssign) or not isinstance(stmt.target, IRLocal):
            return None
        arr_local = stmt.target
        if not self._is_alloc_array(stmt.expr):
            return None

        values: List[IRExpression] = []
        i = start + 1
        while i < len(stmts):
            elem_expr: Optional[IRExpression] = None
            store_stmt: Optional[IRAssign] = None
            # Look for an element initializer immediately followed by a store
            # using that same local.  This handles patterns like:
            #   var9 = new TestClass();
            #   arr[0] = var9;
            s1 = stmts[i]
            if isinstance(s1, IRAssign) and isinstance(s1.target, IRLocal) and i + 1 < len(stmts):
                s2 = stmts[i + 1]
                if (
                    isinstance(s2, IRAssign)
                    and isinstance(s2.target, IRArrayAccess)
                    and isinstance(s2.target.array, IRLocal)
                    and s2.target.array.name == arr_local.name
                    and isinstance(s2.target.index, IRConst)
                    and s2.target.index.const_type == IRConst.ConstType.INT
                    and isinstance(s2.expr, IRLocal)
                    and s2.expr.name == s1.target.name
                ):
                    elem_expr = s1.expr
                    store_stmt = s2
                    i += 2
            if elem_expr is None:
                # Otherwise accept a bare store.
                if (
                    isinstance(s1, IRAssign)
                    and isinstance(s1.target, IRArrayAccess)
                    and isinstance(s1.target.array, IRLocal)
                    and s1.target.array.name == arr_local.name
                    and isinstance(s1.target.index, IRConst)
                    and s1.target.index.const_type == IRConst.ConstType.INT
                ):
                    elem_expr = s1.expr
                    store_stmt = s1
                    i += 1
            if elem_expr is None or store_stmt is None:
                break
            store_access = cast(IRArrayAccess, store_stmt.target)
            idx_const = cast(IRConst, store_access.index)
            idx = int(idx_const.value.value if hasattr(idx_const.value, "value") else idx_const.value)
            if idx != len(values):
                break
            values.append(elem_expr)

        if not values:
            return None

        if i >= len(stmts):
            return None
        use_stmt = stmts[i]
        anon_call = self._find_anon_call(use_stmt, arr_local)
        if anon_call is None:
            return None

        literal = IRArrayLiteral(self.func.code, values)
        self._replace_child(use_stmt, anon_call, literal)
        return use_stmt, i - start + 1

    def _is_empty_alloc_array(self, expr: IRStatement) -> bool:
        if not self._is_alloc_array(expr):
            return False
        call = cast(IRCall, expr)
        if len(call.args) != 2:
            return False
        type_arg, size_arg = call.args
        if not isinstance(size_arg, IRConst) or size_arg.const_type != IRConst.ConstType.INT:
            return False
        if int(size_arg.value.value if hasattr(size_arg.value, "value") else size_arg.value) != 0:
            return False
        if isinstance(type_arg, IRConst) and (
            type_arg.const_type == IRConst.ConstType.NULL or isinstance(type_arg.value, Type)
        ):
            return True
        return False

    def _is_empty_arrayobj_anon(self, expr: IRStatement) -> bool:
        if not self._is_arrayobj_anon(expr):
            return False
        call = cast(IRCall, expr)
        return len(call.args) == 1 and self._is_empty_alloc_array(call.args[0])

    def _is_arraydyn_alloc(self, expr: IRStatement) -> bool:
        if not isinstance(expr, IRCall):
            return False
        if not isinstance(expr.target, IRConst) or not isinstance(expr.target.value, Function):
            return False
        func = expr.target.value
        name = self.func.code.full_func_name(func)
        if not name:
            name = self.func.code.partial_func_name(func)
        if not name:
            return False
        return name.endswith("ArrayDyn.alloc")

    def _try_empty_array_dyn(self, stmts: List[IRStatement], start: int) -> Optional[Tuple[IRStatement, int]]:
        # Pattern:
        #   temp = ArrayObj.anon(alloc_array(null, 0))
        #   target = ArrayDyn.alloc(temp, true)
        # Rewrite both statements to target = [] when temp has no later uses.
        if start + 1 >= len(stmts):
            return None
        s0 = stmts[start]
        if not isinstance(s0, IRAssign) or not isinstance(s0.target, IRLocal):
            return None
        temp = s0.target
        if not self._is_empty_arrayobj_anon(s0.expr):
            return None

        s1 = stmts[start + 1]
        if not isinstance(s1, IRAssign) or not isinstance(s1.expr, IRCall):
            return None
        call = s1.expr
        if not self._is_arraydyn_alloc(call):
            return None
        if len(call.args) != 2:
            return None
        first_arg, second_arg = call.args
        if not isinstance(first_arg, IRLocal) or first_arg.name != temp.name:
            return None

        true_ok = False
        if isinstance(second_arg, IRConst) and isinstance(second_arg.value, bool) and second_arg.value:
            true_ok = True
        elif (
            isinstance(second_arg, IRRef)
            and isinstance(second_arg.target, IRConst)
            and isinstance(second_arg.target.value, bool)
            and second_arg.target.value
        ):
            true_ok = True
        if not true_ok:
            return None

        for later in stmts[start + 2 :]:
            if self._local_in_stmt(later, temp):
                return None

        literal = IRArrayLiteral(self.func.code, [])
        new_assign = IRAssign(self.func.code, s1.target, literal)
        return new_assign, 2

    def _index_shift(self, idx: IRStatement, local: IRLocal) -> Optional[int]:
        """Return the shift amount if `idx` is `local << const`."""
        if not isinstance(idx, IRArithmetic):
            return None
        if idx.op.value != "<<":
            return None
        if not isinstance(idx.left, IRLocal) or idx.left.name != local.name:
            return None
        if not isinstance(idx.right, IRConst) or idx.right.const_type != IRConst.ConstType.INT:
            return None
        val = idx.right.value.value if hasattr(idx.right.value, "value") else idx.right.value
        return int(val)

    def _parse_store_and_increment(
        self,
        stmts: List[IRStatement],
        i: int,
        bytes_var: IRLocal,
        idx_var: IRLocal,
        values: List[IRExpression],
        expected_shift: Optional[int] = None,
    ) -> Optional[Tuple[int, int]]:
        """Parse one element store of a typed array literal.

        HashLink lowers a single element in several ways; the smallest window is
        ``bytes[idx << n] = value; idx++`` and larger windows may cache the value
        and/or the shifted index in temporaries.  We accept any window of up to
        five statements that ends with ``idx_var++`` and whose preceding
        statements are only assignments to the temporaries consumed by the store.

        Returns ``(index_after_increment, shift)`` or None.
        """

        def is_idx_increment(stmt: IRStatement) -> bool:
            if not isinstance(stmt, IRAssign) or stmt.target != idx_var:
                return False
            expr = stmt.expr
            if isinstance(expr, IRCast):
                expr = expr.expr
            if not isinstance(expr, IRArithmetic) or expr.op != IRArithmetic.ArithmeticType.ADD:
                return False
            if expr.left != idx_var:
                return False
            if not isinstance(expr.right, IRConst) or expr.right.const_type != IRConst.ConstType.INT:
                return False
            return _int_const_value(expr.right) == 1

        def effective_shift(index_expr: IRExpression, before: int) -> Optional[int]:
            if isinstance(index_expr, IRArithmetic):
                return self._index_shift(index_expr, idx_var)
            if isinstance(index_expr, IRLocal):
                for k in range(before - 1, -1, -1):
                    s = stmts[i + k]
                    if isinstance(s, IRAssign) and s.target == index_expr:
                        if isinstance(s.expr, IRArithmetic):
                            return self._index_shift(s.expr, idx_var)
                        break
            return None

        def unwrap_value(expr: IRExpression, before: int) -> Optional[IRExpression]:
            if not isinstance(expr, IRLocal):
                return expr
            for k in range(before - 1, -1, -1):
                s = stmts[i + k]
                if isinstance(s, IRAssign) and s.target == expr:
                    return s.expr
            return None

        max_window = 5
        for inc_offset in range(1, max_window + 1):
            if i + inc_offset >= len(stmts):
                break
            if not is_idx_increment(stmts[i + inc_offset]):
                continue
            store_offset = inc_offset - 1
            store = stmts[i + store_offset]
            if not isinstance(store, IRAssign) or not isinstance(store.target, IRArrayAccess):
                continue
            access = store.target
            if not isinstance(access.array, IRLocal) or access.array.name != bytes_var.name:
                continue

            shift = effective_shift(access.index, store_offset)
            if shift is None:
                continue
            if expected_shift is not None and shift != expected_shift:
                continue

            value = unwrap_value(store.expr, store_offset)
            if value is None:
                continue

            consumed: Set[str] = set()
            if isinstance(access.index, IRLocal):
                consumed.add(access.index.name)
            if isinstance(store.expr, IRLocal):
                consumed.add(store.expr.name)
            # The shifted-index temp may be computed as ``tmp = const; tmp = idx << tmp``.
            for k in range(store_offset - 1, -1, -1):
                s = stmts[i + k]
                if isinstance(s, IRAssign) and isinstance(s.target, IRLocal):
                    if s.target.name in consumed:
                        if (
                            isinstance(s.expr, IRArithmetic)
                            and s.expr.op.value == "<<"
                            and isinstance(s.expr.right, IRLocal)
                        ):
                            consumed.add(s.expr.right.name)
                        continue
                    # Allow dead compiler-temp assignments that are not read before the store.
                    dead = True
                    for m in range(k + 1, store_offset + 1):
                        if self._local_in_stmt(stmts[i + m], s.target):
                            dead = False
                            break
                    if dead:
                        continue
                break
            else:
                values.append(value)
                return i + inc_offset + 1, shift
        return None

    def _try_array_literal(self, stmts: List[IRStatement], start: int) -> Optional[Tuple[IRStatement, int]]:
        # bytes_var = alloc_bytes(...)
        if start >= len(stmts):
            return None
        stmt = stmts[start]
        if not isinstance(stmt, IRAssign) or not isinstance(stmt.target, IRLocal):
            return None
        bytes_var = stmt.target
        if not self._is_alloc_bytes(stmt.expr):
            return None

        values: List[IRExpression] = []
        i: Optional[int] = None
        idx_var: Optional[IRLocal] = None
        shift: Optional[int] = None

        # Pattern 1: explicit `idx_var = 0` then a sequence of stores.
        if start + 1 < len(stmts):
            stmt2 = stmts[start + 1]
            if (
                isinstance(stmt2, IRAssign)
                and isinstance(stmt2.target, IRLocal)
                and isinstance(stmt2.expr, IRConst)
                and stmt2.expr.const_type == IRConst.ConstType.INT
                and int(stmt2.expr.value.value if hasattr(stmt2.expr.value, "value") else stmt2.expr.value) == 0
            ):
                idx_var = stmt2.target
                parsed = self._parse_store_and_increment(stmts, start + 2, bytes_var, idx_var, values)
                if parsed is not None:
                    i, shift = parsed
                    while True:
                        nxt = self._parse_store_and_increment(stmts, i, bytes_var, idx_var, values, shift)
                        if nxt is None:
                            break
                        i, _ = nxt
                    if not values:
                        i = None

        # Pattern 2: first store uses a constant 0 index; the counter is inferred
        # from the following increment (e.g. `bytes[0 << n] = v0; idx++; ...`).
        if i is None and shift is None and start + 2 < len(stmts):
            first_store = stmts[start + 1]
            if isinstance(first_store, IRAssign) and isinstance(first_store.target, IRArrayAccess):
                access = first_store.target
                if (
                    isinstance(access.array, IRLocal)
                    and access.array.name == bytes_var.name
                    and isinstance(access.index, IRArithmetic)
                    and access.index.op.value == "<<"
                    and isinstance(access.index.left, IRConst)
                    and access.index.left.const_type == IRConst.ConstType.INT
                    and int(
                        access.index.left.value.value
                        if hasattr(access.index.left.value, "value")
                        else access.index.left.value
                    )
                    == 0
                    and isinstance(access.index.right, IRConst)
                    and access.index.right.const_type == IRConst.ConstType.INT
                ):
                    shift = int(
                        access.index.right.value.value
                        if hasattr(access.index.right.value, "value")
                        else access.index.right.value
                    )
                    values = [first_store.expr]
                    inc_stmt = stmts[start + 2]
                    if (
                        isinstance(inc_stmt, IRAssign)
                        and isinstance(inc_stmt.target, IRLocal)
                        and isinstance(inc_stmt.expr, IRArithmetic)
                        and inc_stmt.expr.op.value == "+"
                        and isinstance(inc_stmt.expr.left, IRLocal)
                        and isinstance(inc_stmt.expr.right, IRConst)
                        and inc_stmt.expr.right.const_type == IRConst.ConstType.INT
                        and int(
                            inc_stmt.expr.right.value.value
                            if hasattr(inc_stmt.expr.right.value, "value")
                            else inc_stmt.expr.right.value
                        )
                        == 1
                    ):
                        idx_var = inc_stmt.target
                        parsed = self._parse_store_and_increment(stmts, start + 3, bytes_var, idx_var, values, shift)
                        if parsed is not None:
                            i, _ = parsed
                            while True:
                                nxt = self._parse_store_and_increment(stmts, i, bytes_var, idx_var, values, shift)
                                if nxt is None:
                                    break
                                i, _ = nxt
                        else:
                            values = []
                            shift = None

        if not values or idx_var is None or i is None or shift is None:
            return None

        # Allow an optional `idx_var = count` assignment before the alloc call.
        if i < len(stmts):
            opt = stmts[i]
            if (
                isinstance(opt, IRAssign)
                and isinstance(opt.target, IRLocal)
                and opt.target.name == idx_var.name
                and isinstance(opt.expr, IRConst)
                and opt.expr.const_type == IRConst.ConstType.INT
            ):
                i += 1

        # arr_var = alloc*(bytes_var, count) OR return alloc*(bytes_var, count)
        if i >= len(stmts):
            return None
        final = stmts[i]
        if isinstance(final, IRAssign) and isinstance(final.expr, IRCall):
            call = final.expr
            return_target = final.target
        elif isinstance(final, IRReturn) and isinstance(final.value, IRCall):
            call = final.value
            return_target = None
        else:
            return None
        alloc_name = self._is_alloc_typed_array(call)
        if alloc_name is None:
            return None
        if self._ALLOC_SHIFTS.get(alloc_name) != shift:
            return None
        if len(call.args) != 2 or (isinstance(call.args[0], IRLocal) and call.args[0].name != bytes_var.name):
            return None

        arr_type = _get_type_in_code(self.func.code, "Dyn")
        for t in self.func.code.types:
            if disasm.type_name(self.func.code, t) == "Array":
                arr_type = t
                break
        literal = IRArrayLiteral(self.func.code, values)

        # If the only uses of the recovered literal are constant-index reads, the
        # Haxe compiler will often constant-fold the whole array away.  Keep the
        # low-level allocation in that case so the recompiled bytecode stays close
        # to the original.
        if isinstance(return_target, IRLocal) and not self._array_literal_is_worth_recovering(return_target, stmts, i):
            return None

        if return_target is not None:
            new_assign = IRAssign(self.func.code, return_target, literal)
            return new_assign, i - start + 1
        else:
            new_return = IRReturn(self.func.code, literal)
            return new_return, i - start + 1

    def _array_literal_is_worth_recovering(self, arr_local: IRLocal, stmts: List[IRStatement], end_idx: int) -> bool:
        """Return True if `arr_local` is used for anything other than a bounds
        guard after the literal allocation.

        Constant-index reads now count as real uses: recovering the array
        literal produces much cleaner Haxe source even though the compiler may
        later constant-fold it.
        """

        def _only_guard_fields(node: Optional[IRStatement]) -> bool:
            if node is None:
                return True
            if node == arr_local:
                return False
            if isinstance(node, IRField) and node.target == arr_local and node.field_name in ("length", "bytes"):
                return True
            for child in node.get_children():
                if not _only_guard_fields(child):
                    return False
            return True

        for stmt in stmts[end_idx + 1 :]:
            if self._local_in_stmt(stmt, arr_local):
                if isinstance(stmt, IRConditional) and _only_guard_fields(stmt.condition):
                    continue
                return True
        return False

    def _local_in_stmt(self, stmt: IRStatement, local: IRLocal) -> bool:
        if stmt == local:
            return True
        for child in stmt.get_children():
            if self._local_in_stmt(child, local):
                return True
        return False

    def _array_from_length_expr(
        self, stmts: List[IRStatement], start: int, expr: IRExpression
    ) -> Optional[Tuple[IRLocal, int]]:
        """Resolve the array variable behind a `.length` expression or a temp holding it.

        Returns the array local and the index of the statement that produced the
        length value, so the caller can consume it.
        """
        if isinstance(expr, IRField) and expr.field_name == "length" and isinstance(expr.target, IRLocal):
            return expr.target, start
        if not isinstance(expr, IRLocal):
            return None
        for j in range(start - 1, max(-1, start - 5), -1):
            prev = stmts[j]
            if (
                isinstance(prev, IRAssign)
                and isinstance(prev.target, IRLocal)
                and prev.target.same_register(expr)
                and isinstance(prev.expr, IRField)
                and prev.expr.field_name == "length"
                and isinstance(prev.expr.target, IRLocal)
            ):
                return prev.expr.target, j
        return None

    def _try_array_access(self, stmts: List[IRStatement], start: int) -> Optional[Tuple[IRStatement, int, int]]:
        # Pattern:
        #   if (idx >= arr.length) { value = default; } else { value = arr.bytes[idx << 2]; }
        # Returns (replacement_stmt, consumed_from_start, preceding_statements_to_pop).
        if start >= len(stmts):
            return None
        stmt = stmts[start]
        if not isinstance(stmt, IRConditional):
            return None
        cond = stmt.condition
        if not isinstance(cond, IRBoolExpr):
            return None
        if cond.op == IRBoolExpr.CompareType.GTE:
            idx_expr = cond.left
            length_expr = cond.right
        elif cond.op == IRBoolExpr.CompareType.LTE:
            length_expr = cond.left
            idx_expr = cond.right
        else:
            return None

        const_idx: Optional[int] = None
        idx_var: Optional[IRLocal] = None
        if isinstance(idx_expr, IRConst) and idx_expr.const_type == IRConst.ConstType.INT:
            const_idx = _int_const_value(idx_expr)
            if const_idx is None:
                return None
        elif isinstance(idx_expr, IRLocal):
            idx_var = idx_expr
        else:
            return None

        if length_expr is None:
            return None
        resolved = self._array_from_length_expr(stmts, start, length_expr)
        if resolved is None:
            return None
        arr_var, length_assign_idx = resolved

        then_block = stmt.true_block
        else_block = stmt.false_block
        if len(then_block.statements) != 1 or not else_block.statements:
            return None
        then_assign = then_block.statements[0]
        else_assign = else_block.statements[-1]
        if not isinstance(then_assign, IRAssign) or not isinstance(else_assign, IRAssign):
            return None
        if then_assign.target != else_assign.target or not isinstance(then_assign.target, IRLocal):
            return None
        value_var = then_assign.target
        if not isinstance(else_assign.expr, IRArrayAccess):
            return None
        access = else_assign.expr
        if not isinstance(access.array, IRField):
            return None
        if not isinstance(access.array.target, IRLocal):
            return None
        if access.array.field_name != "bytes" or access.array.target.name != arr_var.name:
            return None
        if not isinstance(access.index, IRArithmetic) or access.index.op.value != "<<":
            return None
        if not isinstance(access.index.right, IRConst):
            return None

        if const_idx is None:
            # For constant-index accesses the compiler loads the constant into the
            # result register and then uses that register as the index scratchpad.
            # After debug-name splitting the index temp and the value temp look like
            # different locals, but reg_idx lets us recover the original constant.
            assert idx_var is not None
            const_idx = self._recover_constant_index(stmts, start, idx_var, access, value_var)
            # If the index local is a user-named variable (e.g. `i`), keep the
            # variable index so the source reads `a[i]`. This preserves the array
            # allocation instead of letting Haxe constant-fold it away.
            if const_idx is not None and idx_var is not None and not self._is_compiler_temp(idx_var):
                const_idx = None

        if const_idx is not None:
            index_expr: IRExpression = IRConst(self.func.code, IRConst.ConstType.INT, value=const_idx)
        else:
            assert idx_var is not None
            index_expr = idx_var

        new_access = IRArrayAccess(self.func.code, arr_var, index_expr)
        new_assign = IRAssign(self.func.code, value_var, new_access)
        # If the length was loaded into a temp immediately before the guard, drop
        # that temp as well; otherwise later passes can leave a dead assignment.
        preceding_to_pop = start - length_assign_idx
        return new_assign, 1, preceding_to_pop

    def _recover_constant_index(
        self,
        stmts: List[IRStatement],
        start: int,
        idx_var: IRLocal,
        access: IRArrayAccess,
        value_var: IRLocal,
    ) -> Optional[int]:
        """Look for an immediately preceding `temp = const` that loads the index."""
        candidates = [idx_var, value_var]
        if isinstance(access.index, IRArithmetic) and isinstance(access.index.left, IRLocal):
            candidates.append(access.index.left)

        for candidate in candidates:
            val = self._const_loaded_for_local(stmts, start, candidate)
            if val is not None:
                return val
        return None

    def _is_compiler_temp(self, local: IRLocal) -> bool:
        return bool(re.fullmatch(r"var\d+", local.name))

    def _const_loaded_for_local(self, stmts: List[IRStatement], start: int, local: IRLocal) -> Optional[int]:
        """Scan the few statements before `start` for `local_reg = const`."""
        for j in range(start - 1, max(-1, start - 5), -1):
            prev = stmts[j]
            if isinstance(prev, IRAssign) and isinstance(prev.target, IRLocal):
                if prev.target.same_register(local):
                    if isinstance(prev.expr, IRConst):
                        return _int_const_value(prev.expr)
                    return None
        return None

    def _try_array_dyn_literal(self, stmts: List[IRStatement], start: int) -> Optional[Tuple[IRStatement, int]]:
        """Rewrite `target = ArrayDyn.alloc([...], true)` to `target = [...]`.

        The ArrayObj.anon + ArrayDyn.alloc pair is already lowered to a typed
        array literal for the first argument. Removing the wrapper lets Haxe
        infer the target as Array<Dynamic>, which is required for mixed-type
        literals to recompile.
        """
        if start >= len(stmts):
            return None
        s = stmts[start]
        if not isinstance(s, IRAssign) or not isinstance(s.expr, IRCall):
            return None
        call = s.expr
        if not self._is_arraydyn_alloc(call):
            return None
        if len(call.args) != 2:
            return None
        first_arg, second_arg = call.args
        if not isinstance(first_arg, IRArrayLiteral):
            return None
        true_ok = False
        if isinstance(second_arg, IRConst) and isinstance(second_arg.value, bool) and second_arg.value:
            true_ok = True
        elif (
            isinstance(second_arg, IRRef)
            and isinstance(second_arg.target, IRConst)
            and isinstance(second_arg.target.value, bool)
            and second_arg.target.value
        ):
            true_ok = True
        if not true_ok:
            return None
        return IRAssign(self.func.code, s.target, first_arg), 1

    @staticmethod
    def _expr_eq(a: Optional[IRExpression], b: Optional[IRExpression]) -> bool:
        """Equality that also handles IRConst, which has no value-based `__eq__`
        (constant propagation creates a fresh IRConst node per substitution site,
        so identity/default equality spuriously fails for equal constants)."""
        if isinstance(a, IRConst) and isinstance(b, IRConst):
            return _int_const_value(a) == _int_const_value(b) and a.const_type == b.const_type
        return a == b

    def _try_write_bounds_guard(self, stmts: List[IRStatement], start: int) -> Optional[int]:
        """Drop the no-op `if (C >= a.length) a.__expand(C)` guard before an array write."""
        if start + 1 >= len(stmts):
            return None
        stmt = stmts[start]
        if not isinstance(stmt, IRConditional):
            return None
        cond = stmt.condition
        if not isinstance(cond, IRBoolExpr):
            return None
        if cond.op == IRBoolExpr.CompareType.GTE:
            idx_expr = cond.left
            length_expr = cond.right
        elif cond.op == IRBoolExpr.CompareType.LTE:
            length_expr = cond.left
            idx_expr = cond.right
        else:
            return None

        if length_expr is None:
            return None
        arr_var = self._array_var_from_length_expr(length_expr)
        if arr_var is None:
            return None

        if len(stmt.true_block.statements) != 1 or stmt.false_block.statements:
            return None
        call_stmt = stmt.true_block.statements[0]
        if not isinstance(call_stmt, IRCall):
            return None
        if not isinstance(call_stmt.target, IRConst) or not isinstance(call_stmt.target.value, Function):
            return None
        if self.func.code.partial_func_name(call_stmt.target.value) != "__expand":
            return None
        if len(call_stmt.args) != 2:
            return None
        # Keep the guard when __expand is called on `this`: that's the array
        # impl class's own setDyn body (real source), not a compiler-inserted
        # guard fronting a user's `arr[i] = v`.
        if isinstance(call_stmt.args[0], IRLocal) and call_stmt.args[0].name == "this":
            return None
        if call_stmt.args[0] != arr_var or not self._expr_eq(call_stmt.args[1], idx_expr):
            return None

        pos = start + 1
        bytes_temp_name: Optional[str] = None
        _s = stmts[pos] if pos < len(stmts) else None
        if (
            _s is not None
            and isinstance(_s, IRAssign)
            and isinstance(_s.target, IRLocal)
            and isinstance(_s.expr, IRField)
            and _s.expr.field_name == "bytes"
            and isinstance(_s.expr.target, IRLocal)
            and _s.expr.target.name == arr_var.name
        ):
            # `a.bytes` was hoisted into a temp before the write; look past it.
            bytes_temp_name = _s.target.name
            pos += 1

        # A leftover dead store (e.g. loading the shift amount into a scratch
        # register that the actual shift below recomputes from constants
        # directly) can sit here too; skip over a bounded run of those.
        while pos < len(stmts) and pos + 1 < len(stmts):
            _cur = stmts[pos]
            _nxt = stmts[pos + 1]
            if (
                isinstance(_cur, IRAssign)
                and isinstance(_cur.target, IRLocal)
                and isinstance(_cur.expr, IRConst)
                and isinstance(_nxt, IRAssign)
                and isinstance(_nxt.target, IRLocal)
                and _nxt.target.name == _cur.target.name
            ):
                pos += 1
            else:
                break

        # The `idx << 2` byte offset may also have been hoisted into its own temp
        # rather than appearing inline in the array access.
        idx_temp_expr: Optional[IRExpression] = None
        _s2 = stmts[pos] if pos < len(stmts) else None
        if (
            _s2 is not None
            and isinstance(_s2, IRAssign)
            and isinstance(_s2.target, IRLocal)
            and isinstance(_s2.expr, IRArithmetic)
            and _s2.expr.op.value == "<<"
            and self._expr_eq(_s2.expr.left, idx_expr)
            and isinstance(_s2.expr.right, IRConst)
        ):
            idx_temp_expr = _s2.target
            pos += 1

        if pos >= len(stmts):
            return None
        next_stmt = stmts[pos]
        if not isinstance(next_stmt, IRAssign) or not isinstance(next_stmt.target, IRArrayAccess):
            return None
        access = next_stmt.target

        def _matches_shifted_index(index: IRExpression) -> bool:
            if idx_temp_expr is not None:
                return self._expr_eq(index, idx_temp_expr)
            if not isinstance(index, IRArithmetic) or index.op.value != "<<":
                return False
            if not self._expr_eq(index.left, idx_expr):
                return False
            return isinstance(index.right, IRConst)

        # High-level store: a[idx]
        if isinstance(access.array, IRLocal) and access.array.name == arr_var.name:
            if not self._expr_eq(access.index, idx_expr):
                return None
        # Low-level store via the hoisted bytes temp: tmp[idx << 2]
        elif bytes_temp_name is not None and isinstance(access.array, IRLocal) and access.array.name == bytes_temp_name:
            if not _matches_shifted_index(access.index):
                return None
        # Low-level store: a.bytes[idx << 2]
        elif isinstance(access.array, IRField) and access.array.field_name == "bytes":
            if not isinstance(access.array.target, IRLocal) or access.array.target.name != arr_var.name:
                return None
            if not isinstance(access.index, IRArithmetic) or access.index.op.value != "<<":
                return None
            if not self._expr_eq(access.index.left, idx_expr):
                return None
            if not isinstance(access.index.right, IRConst):
                return None
        else:
            return None

        return 1

    def _array_var_from_length_expr(self, expr: IRExpression) -> Optional[IRLocal]:
        """Return the array local if `expr` is `arr.length` (or a temp holding it)."""
        if isinstance(expr, IRField) and expr.field_name == "length" and isinstance(expr.target, IRLocal):
            return expr.target
        if isinstance(expr, IRLocal):
            # We do not attempt to trace back to the source here; the preceding
            # temp must have been removed or inlined by the time this runs.
            return None
        return None
