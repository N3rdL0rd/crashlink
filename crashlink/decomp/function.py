"""
IRFunction and IRClass — the top-level decompilation orchestrators.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from enum import Enum as _Enum
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
    Regs,
    ResolvableVarInt,
    Type,
    TypeDef,
    Virtual,
    Void,
    fieldRef,
    gIndex,
    tIndex,
)
from ..errors import DecompError
from ..globals import DEBUG, dbg_print
from .. import disasm
from ..opcodes import arithmetic, conditionals, terminal, simple_calls
from .ir import (
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
    _type_by_name_cache,
    _repr_rendered_blocks,
)
from .cfg import CFNode, CFGraph, IsolatedCFGraph, _find_jumps_to_label
from .opt import (
    IROptimizer,
    TraversingIROptimizer,
    _ir_structurally_equal,
    _structurally_equal,
    _stmt_lists_structurally_equal,
    _bytes_mem_kind,
    _int_const_value,
    _signed_i32,
)
from .opt.inliner import (
    IRPrimitiveJumpLifter,
    IRConditionInliner,
    IRTempAssignmentInliner,
    IRCopyPropOptimizer,
)
from .opt.clean import (
    IRLoopConditionOptimizer,
    IRSelfAssignOptimizer,
    IRArrayGrowGuardEliminator,
    IRRedundantRecomputeEliminator,
    IRBlockFlattener,
    IRCommonBlockMerger,
    IRRedundantContinueEliminator,
    IRVoidAssignOptimizer,
    IRDeadTempEliminator,
    IRDeadCodeEliminator,
    IRDeadStoreEliminator,
    IRSequentialTempFolder,
    IRDeadAssignmentEliminator,
    IRConstructorFolder,
    IRShiftConstantOptimizer,
    IRGuardOrMerger,
)
from .opt.strings import (
    IRGlobalStringOptimizer,
    IRStringIntConcatOptimizer,
    IRStringAllocOptimizer,
    IRTraceOptimizer,
    IRStringConcatFolder,
)
from .opt.arrays import (
    IRNativeArrayAllocOptimizer,
    IRArrayObjWrapperOptimizer,
    IRNativeMapAllocOptimizer,
    IRArrayPatternOptimizer,
)
from .opt.loops import (
    IRLoopRerollOptimizer,
    IRForEachLoopOptimizer,
    IRIntRangeLoopOptimizer,
)
from .opt.switches import (
    IRIntSwitchOptimizer,
    IRStringSwitchOptimizer,
    IREnumSwitchOptimizer,
)


def _build_enum_global_map(code: Bytecode) -> Dict[int, Tuple[str, tIndex]]:
    """
    HashLink stores parameterless enum constants as globals whose type is the
    enum type. Build a map from global index to the constructor name and enum
    type index so that `GetGlobal` can be lifted to `Red`/`Green`/... instead
    of an opaque enum-typed global object.

    The static initializer that populates these globals reads them out of the
    enum's own `__evalues__` array by construct index (`GetArray(evalues,
    Int(N))` then `SetGlobal(g, ...)`), so trace that pattern directly to
    recover the exact (global -> construct index) mapping. The order globals
    are *allocated* in (their numeric index) does not necessarily match
    declaration order — it depends on which construct is first referenced
    during compilation — so guessing via sorted-globals-zip-constructs is
    unreliable and silently mismatches names when an enum has more than one
    construct referenced across the program (see e.g. haxe.io.Error, where
    `OutsideBounds`, not `Blocked`, ends up at the lowest global index).
    """
    enum_globals: Dict[int, List[int]] = {}
    for gi, gt in enumerate(code.global_types):
        typ = gt.resolve(code)
        if isinstance(typ.definition, Enum):
            enum_globals.setdefault(gt.value, []).append(gi)

    result: Dict[int, Tuple[str, tIndex]] = {}
    resolved_globals: Set[int] = set()
    all_enum_globals: Set[int] = set()
    for globals_for_type in enum_globals.values():
        all_enum_globals.update(globals_for_type)

    # Pass 1: trace the actual `__evalues__[N]` initializer pattern.
    for func in code.functions:
        if isinstance(func, Native):
            continue
        reg_int_value: Dict[int, int] = {}
        reg_array_index: Dict[int, int] = {}  # GetArray dst -> construct index
        for op in func.ops:
            if op.op == "Int":
                try:
                    resolved = op.df["ptr"].resolve(code)
                    reg_int_value[op.df["dst"].value] = int(getattr(resolved, "value", resolved))
                except Exception:
                    pass
            elif op.op == "GetArray":
                idx_reg = op.df["index"].value
                if idx_reg in reg_int_value:
                    reg_array_index[op.df["dst"].value] = reg_int_value[idx_reg]
            elif op.op in ("SafeCast", "UnsafeCast", "Mov"):
                src_reg = op.df["src"].value
                if src_reg in reg_array_index:
                    reg_array_index[op.df["dst"].value] = reg_array_index[src_reg]
            elif op.op == "SetGlobal":
                gi = op.df["global"].value
                src_reg = op.df["src"].value
                if gi in all_enum_globals and src_reg in reg_array_index:
                    type_idx = code.global_types[gi].value
                    enum_def = code.types[type_idx].definition
                    if isinstance(enum_def, Enum):
                        construct_idx = reg_array_index[src_reg]
                        if 0 <= construct_idx < len(enum_def.constructs):
                            construct = enum_def.constructs[construct_idx]
                            result[gi] = (construct.name.resolve(code), code.global_types[gi])
                            resolved_globals.add(gi)

    # Pass 2: fall back to the declaration-order guess for anything the
    # initializer trace didn't cover (e.g. an enum with only one referenced
    # parameterless construct, where ordering can't be ambiguous anyway).
    for type_idx, globals_for_type in enum_globals.items():
        enum_def = code.types[type_idx].definition
        if not isinstance(enum_def, Enum):
            continue
        remaining = sorted(gi for gi in globals_for_type if gi not in resolved_globals)
        if not remaining:
            continue
        parameterless = [c for c in enum_def.constructs if c.nparams.value == 0]
        used_names = {result[gi][0] for gi in globals_for_type if gi in result}
        remaining_constructs = [c for c in parameterless if c.name.resolve(code) not in used_names]
        for gi, construct in zip(remaining, remaining_constructs):
            result[gi] = (construct.name.resolve(code), code.global_types[gi])
    return result


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
        capture_layers: bool = False,
    ) -> None:
        self.func = func
        self.code = code
        # Declare all instance attributes with types upfront so mypy can track them.
        self.cfg: Optional[CFGraph] = None
        self.block: IRBlock = IRBlock(code)
        self.locals: List[IRLocal] = []
        self.all_locals: List[IRLocal] = []  # all created locals including superseded splits
        self.opcodes: str = ""
        self.cfg_data: Dict[str, List[Dict[str, Any]]] = {"nodes": [], "edges": []}
        self.layer_snapshots: List[Tuple[str, str, bool]] = []
        self._lift_cache: Dict[Tuple[Optional[CFNode], Optional[CFNode], int], IRBlock] = {}
        self._enum_global_map: Dict[int, Tuple[str, tIndex]] = {}
        self.capture_layers: bool = capture_layers
        if isinstance(func, Native):
            # Native entries have no HL bytecode; represent them as a stub block.
            self.block.statements.append(IRNativeStub(code, func))
            self._enum_global_map = _build_enum_global_map(code)
            return
        self.cfg = CFGraph(func)
        self.cfg.build()
        self._enum_global_map = _build_enum_global_map(code)
        self.ops = func.ops
        self._lift(no_lift=no_lift)
        if do_optimize:
            self.optimizers: List[IROptimizer] = [
                IRBlockFlattener(self),
                IRConstructorFolder(self),
                IRPrimitiveJumpLifter(self),
                IRGlobalStringOptimizer(self),
                IRStringIntConcatOptimizer(self),
                IRConditionInliner(self),
                IRArrayGrowGuardEliminator(self),
                IRLoopConditionOptimizer(self),
                IRSelfAssignOptimizer(self),
                IRRedundantContinueEliminator(self),
                IRCopyPropOptimizer(self),
                IRShiftConstantOptimizer(self),
                IRTempAssignmentInliner(self, aggressive=False),
                IRTempAssignmentInliner(self, aggressive=True),
                IRStringAllocOptimizer(self),
                IRSequentialTempFolder(self),
                IRDeadTempEliminator(self),
                IRDeadCodeEliminator(self),
                IRArrayPatternOptimizer(self),
                IRNativeArrayAllocOptimizer(self),
                IRArrayObjWrapperOptimizer(self),
                IRNativeMapAllocOptimizer(self),
                IRTempAssignmentInliner(self, aggressive=False),
                IRVoidAssignOptimizer(self),
                IRDeadCodeEliminator(self),
                IRSelfAssignOptimizer(self),
                IRTraceOptimizer(self),
                IRStringConcatFolder(self),
                IRIntSwitchOptimizer(self),
                IRStringSwitchOptimizer(self),
                IREnumSwitchOptimizer(self),
                IRDeadTempEliminator(self),
                IRDeadCodeEliminator(self),
                IRBlockFlattener(self),
                IRLoopRerollOptimizer(self),
                IRForEachLoopOptimizer(self),
                IRIntRangeLoopOptimizer(self),
                IRDeadStoreEliminator(self),
                IRGuardOrMerger(self),
                IRRedundantRecomputeEliminator(self),
            ]
            self._optimize()
            self.apply_annotations()

    def _lift(self, no_lift: bool = False) -> None:
        """Lift function to IR"""
        assert self.cfg is not None
        for i, reg in enumerate(self.func.regs):
            local = IRLocal(f"var{i}", reg, code=self.code, reg_idx=i, defining_op_idx=None)
            self.locals.append(local)
            self.all_locals.append(local)
        self._build_assign_map()
        self._name_locals()
        if not no_lift:
            if self.cfg.entry:
                self.block = self._lift_block(self.cfg.entry, set())
            else:
                raise DecompError("Function CFG has no entry node, cannot lift to IR")
        else:
            dbg_print("Skipping lift.")

    def _is_instance_method(self) -> bool:
        """Return True if this function is bound as a prototype on a class."""
        for t in self.code.types:
            if t.kind.value != Type.Kind.OBJ.value:
                continue
            obj = t.definition
            if not isinstance(obj, Obj):
                continue
            for proto in obj.protos:
                fn = proto.findex.resolve(self.code)
                if fn is self.func:
                    return True
        return False

    def _build_assign_map(self) -> None:
        """Build a mapping from op index to (register, name) for SSA-esque splitting."""
        self._op_assigns: Dict[int, Dict[int, str]] = {}
        self._user_reg_indices: Set[int] = set()
        self._reg_first_assign: Dict[int, int] = {}
        self._op_id_to_idx: Dict[int, int] = {id(op): i for i, op in enumerate(self.ops)}
        if not (self.func.has_debug and self.func.assigns):
            return
        # Assigns with op index 0 name function parameters rather than pointing at
        # a `dst`-producing op, so they need the same register offset as in
        # _name_locals (register 0 is `this` in instance methods/constructors).
        is_instance = self._is_instance_method()
        has_this_ops = any(op.op in ("SetThis", "GetThis") for op in self.func.ops)
        param_start = 1 if (is_instance or has_this_ops) else 0
        param_idx = 0
        for assign in self.func.assigns:
            val = assign[1].value - 1
            if val < 0:
                reg = param_start + param_idx
                param_idx += 1
                if reg < len(self.func.regs):
                    self._user_reg_indices.add(reg)
                continue
            op = self.ops[val]
            try:
                reg = op.df["dst"].value
            except KeyError:
                continue
            name = assign[0].resolve(self.code)
            self._user_reg_indices.add(reg)
            if val not in self._op_assigns:
                self._op_assigns[val] = {}
            self._op_assigns[val][reg] = name
            if reg not in self._reg_first_assign or val < self._reg_first_assign[reg]:
                self._reg_first_assign[reg] = val

    def _get_local(self, reg_idx: int) -> IRLocal:
        """Get the current IRLocal for a register, respecting SSA-esque name transitions."""
        return self.locals[reg_idx]

    def _split_local(self, reg_idx: int, name: str, defining_op_idx: Optional[int] = None) -> IRLocal:
        """Create a new IRLocal for a register with a specific name (SSA-esque split)."""
        reg_type = self.func.regs[reg_idx]
        new_type = reg_type.resolve(self.code)
        # Avoid name collisions only with a different register of a different
        # type.  Same-type duplicates are usually the same source variable split
        # across registers.
        base_name = name
        suffix = 1
        existing_names = {loc.name for i, loc in enumerate(self.locals) if i != reg_idx and loc.get_type() != new_type}
        while name in existing_names:
            name = f"{base_name}{suffix}"
            suffix += 1
        new_local = IRLocal(name, reg_type, code=self.code, reg_idx=reg_idx, defining_op_idx=defining_op_idx)
        self.locals[reg_idx] = new_local
        self.all_locals.append(new_local)
        # Cached blocks may still reference the old local object; force them to
        # be re-lifted so they pick up the new name.
        self._lift_cache.clear()
        return new_local

    def _check_assign(self, op_idx: int) -> None:
        """Check if this op index has an assign entry and split the local if needed."""
        if op_idx in self._op_assigns:
            for reg_idx, name in self._op_assigns[op_idx].items():
                current = self.locals[reg_idx]
                if current.name != name:
                    self._split_local(reg_idx, name, defining_op_idx=op_idx)

    def apply_annotations(self) -> None:
        """Apply renames and comments from code.annotations to this IR function in-place."""
        store = self.code.annotations
        findex = self.func.findex.value
        for local in self.all_locals:
            if local.reg_idx is not None:
                rename = store.get_rename(findex, local.reg_idx, local.defining_op_idx)
                if rename is not None:
                    local.name = rename

        def _walk(block: IRBlock) -> None:
            for stmt in block.statements:
                if stmt.src_op_idx is not None:
                    comment = store.get_comment(findex, stmt.src_op_idx)
                    if comment is not None:
                        stmt.comment = comment
                for child in stmt.get_children():
                    if isinstance(child, IRBlock):
                        _walk(child)

        _walk(self.block)

    def _optimize(self) -> None:
        """Optimize the IR"""
        from ..globals import DEBUG

        if DEBUG:
            dbg_print("----- Disasm -----")
            dbg_print(disasm.func(self.code, self.func))
            dbg_print(f"----- LLIL -----")
            dbg_print(self.block.pprint())
        if self.capture_layers:
            self.opcodes = disasm.func(self.code, self.func)
            self.cfg_data = self._cfg_to_dict()
            self.layer_snapshots.append(("LLIR", _strip_ansi(self.block.pprint()), True))
        for o in self.optimizers:
            ran = o.should_run()
            if DEBUG:
                dbg_print(f"----- {o.__class__.__name__} ({'ran' if ran else 'skipped'}) -----")
            if ran:
                o.optimize()
            if DEBUG:
                dbg_print(self.block.pprint())
            if self.capture_layers:
                self.layer_snapshots.append((o.__class__.__name__, _strip_ansi(self.block.pprint()), ran))

    def _cfg_to_dict(self) -> Dict[str, Any]:
        """Serialize the control-flow graph to a JSON-friendly structure."""
        assert self.cfg is not None
        cfg = self.cfg
        node_ids = {id(node): i for i, node in enumerate(cfg.nodes)}
        nodes: List[Dict[str, Any]] = []
        for i, node in enumerate(cfg.nodes):
            label_lines = []
            for op in node.ops:
                parts = [op.op or "?"] + [str(v) for v in op.df.values()]
                label_lines.append(". ".join(parts))
            nodes.append(
                {
                    "id": i,
                    "label": f"BB{i}",
                    "ops": label_lines,
                    "base_offset": node.base_offset,
                    "is_entry": node is cfg.entry,
                }
            )
        edges: List[Dict[str, Any]] = []
        for node in cfg.nodes:
            src = node_ids[id(node)]
            for target, edge_type in node.branches:
                dst = node_ids.get(id(target))
                if dst is not None:
                    edges.append({"from": src, "to": dst, "type": edge_type})
        return {"nodes": nodes, "edges": edges, "dot": self._cfg_to_dot(node_ids)}

    def to_dot(self) -> Optional[str]:
        """Render this function's CFG as Graphviz DOT source, or None for natives
        (which have no bytecode/CFG). `self.cfg` is built unconditionally for
        non-natives in `__init__`, so this works regardless of `capture_layers`."""
        if self.cfg is None:
            return None
        node_ids = {id(node): i for i, node in enumerate(self.cfg.nodes)}
        return self._cfg_to_dot(node_ids)

    def _cfg_to_dot(self, node_ids: Dict[int, int]) -> str:
        """Produce a Graphviz DOT representation of the CFG.

        Mirrors the entry/return node coloring and per-branch-type edge
        coloring conventions of CFGraph.graph()/style_node(), just remapped
        onto the Catppuccin Mocha palette used by the crashtest site.
        """
        assert self.cfg is not None
        cfg = self.cfg

        def _escape(s: str) -> str:
            return s.replace("\\", "\\\\").replace('"', '\\"')

        def _node_fill(node: CFNode) -> str:
            if node is cfg.entry:
                return '"#a6e3a1", fontcolor="#11111b"'  # green, like style_node's entry
            if any(op.op == "Ret" for op in node.ops):
                return '"#94e2d5", fontcolor="#11111b"'  # teal, like style_node's return blocks
            return '"#313244", fontcolor="#cdd6f4"'

        def _edge_style(edge_type: str) -> str:
            if edge_type == "true":
                return 'color="#a6e3a1", fontcolor="#a6e3a1", label="true"'
            if edge_type == "false":
                return 'color="#f38ba8", fontcolor="#f38ba8", label="false"'
            if edge_type.startswith("switch: "):
                case = edge_type.split("switch: ")[1].strip()
                color = "#f38ba8" if case == "default" else "#cba6f7"
                return f'color="{color}", fontcolor="{color}", label="{_escape(case)}"'
            if edge_type == "trap":
                return 'color="#f9e2af", fontcolor="#f9e2af", label="trap"'
            return 'color="#89b4fa"'

        lines = [
            "digraph CFG {",
            "  rankdir=TB;",
            "  nodesep=0.4;",
            "  ranksep=0.5;",
            '  node [shape=box, fontname="monospace", fontsize=11, margin="0.15,0.1", style="rounded,filled", fillcolor="#313244", fontcolor="#cdd6f4", color="#585b70"];',
            '  edge [fontname="monospace", fontsize=9, color="#6c7086", fontcolor="#a6adc8"];',
        ]
        for i, node in enumerate(cfg.nodes):
            op_lines = []
            for op in node.ops:
                parts = [op.op or "?"] + [str(v) for v in op.df.values()]
                op_lines.append(_escape(". ".join(parts)))
            label = _escape(f"BB{i}") + "\\l" + "\\l".join(op_lines) + "\\l"
            lines.append(f'  {i} [label="{label}", fillcolor={_node_fill(node)}];')
        for node in cfg.nodes:
            src = node_ids[id(node)]
            for target, edge_type in node.branches:
                dst = node_ids.get(id(target))
                if dst is not None:
                    lines.append(f"  {src} -> {dst} [{_edge_style(edge_type)}];")
        lines.append("}")
        return "\n".join(lines)

    def _name_locals(self) -> None:
        """Name locals based on debug info"""
        reg_assigns: List[List[str]] = [[] for _ in self.func.regs]
        # Register 0 is `this` in instance methods and constructors. Detect by
        # either: the function is bound as a prototype on a class, or the
        # function contains SetThis/GetThis opcodes (constructor).
        is_instance = self._is_instance_method()
        has_this_ops = any(op.op in ("SetThis", "GetThis") for op in self.func.ops)
        # A constructor that only delegates to `super(...)` (no field writes of
        # its own) has neither SetThis/GetThis ops nor a vtable proto entry
        # (constructors aren't virtual), so it would otherwise be misdetected
        # as a plain static function and have all its parameter names shifted
        # by one onto the wrong registers.
        is_ctor_wrapper = self.code.partial_func_name(self.func) == "__constructor__"
        has_this = is_instance or has_this_ops or is_ctor_wrapper
        if self.func.has_debug and self.func.assigns:
            for assign in self.func.assigns:
                # assign: Tuple[strRef (name), VarInt (op index)]
                val = assign[1].value - 1
                if val < 0:
                    continue
                reg: Optional[int] = None
                op = self.ops[val]
                try:
                    op.df["dst"]
                    reg = op.df["dst"].value
                except KeyError:
                    pass
                if reg is not None:
                    name = assign[0].resolve(self.code)
                    if name not in reg_assigns[reg]:
                        reg_assigns[reg].append(name)
        if self.func.assigns and self.func.has_debug:
            # Assigns with op index 0 (val == -1 above) name function parameters,
            # in order — not necessarily register 0: that's `this` for instance
            # methods/constructors, so parameters start at register 1 there.
            param_start = 1 if has_this else 0
            param_candidates = [assign for assign in self.func.assigns if assign[1].value <= 0]
            param_count: Optional[int] = None
            fun_def = self.func.type.resolve(self.code).definition
            if isinstance(fun_def, Fun):
                param_count = max(0, len(fun_def.args) - (1 if has_this else 0))
            seen_param_names: Set[str] = set()
            param_idx = 0
            for assign in param_candidates:
                if param_count is not None and param_idx >= param_count:
                    break
                name = assign[0].resolve(self.code)
                # A body local can shadow a parameter with the same debug name
                # (e.g. ArrayBytes.getDyn's `pos`). Keep only the first parameter
                # use of a name and continue with the next parameter slot.
                if name in seen_param_names:
                    continue
                reg = param_start + param_idx
                if reg >= len(reg_assigns):
                    break
                if name not in reg_assigns[reg]:
                    reg_assigns[reg].append(name)
                # A parameter name applies from the start of the function, even if
                # the same register is later reassigned with the same debug name.
                self._reg_first_assign[reg] = -1
                seen_param_names.add(name)
                param_idx += 1
        for i, _reg in enumerate(self.func.regs):
            if _reg.resolve(self.code).definition and isinstance(_reg.resolve(self.code).definition, Void):
                if "voidReg" not in reg_assigns[i]:
                    reg_assigns[i].append("voidReg")

        # A register may be used as an anonymous temporary before the first
        # debug-named assignment that names it. Naming the whole register after
        # that later debug name makes the earlier uses look like the named
        # variable (e.g. String.split's empty-delimiter loop bound becomes
        # `dlen` because reg6 is later named for delimiter.length). In that
        # case keep the pre-name segment as a temp; _check_assign will split
        # off the named segment at the debug assignment.
        first_def: Dict[int, int] = {}
        for op_idx, op in enumerate(self.ops):
            if op.df and "dst" in op.df:
                reg = op.df["dst"].value
                if reg not in first_def:
                    first_def[reg] = op_idx

        for i, local in enumerate(self.locals):
            if reg_assigns[i]:
                named_op = self._reg_first_assign.get(i)
                if named_op is not None and named_op > 0 and first_def.get(i, float("inf")) < named_op:
                    continue
                local.name = reg_assigns[i][0]

        # If the same debug name is assigned to two different registers with
        # different types, suffix the later one so Haxe sees two distinct
        # variables instead of a single Dynamic variable.
        name_to_regs: Dict[str, List[int]] = {}
        for i, local in enumerate(self.locals):
            name_to_regs.setdefault(local.name, []).append(i)
        for name, regs in name_to_regs.items():
            if len(regs) <= 1:
                continue
            typed_regs: Dict[int, List[int]] = {}
            for r in regs:
                typ = self.func.regs[r]
                typ_key = id(typ.resolve(self.code))
                typed_regs.setdefault(typ_key, []).append(r)
            # Only rename when the same debug name is used for variables with
            # different types.  Same-type duplicates are usually just different
            # registers for a single source variable.
            if len(typed_regs) <= 1:
                # Exception: a parameter shadowed by a body local with the same
                # name must be disambiguated (e.g. ArrayBytes.getDyn's `pos`).
                ordered = sorted(regs, key=lambda r: self._reg_first_assign.get(r, float("inf")))
                param_regs = [r for r in ordered if self._reg_first_assign.get(r, float("inf")) == -1]
                if param_regs:
                    suffix = 1
                    for r in ordered:
                        if r == param_regs[0]:
                            continue
                        self.locals[r].name = f"{name}{suffix}"
                        suffix += 1
                continue
            ordered = sorted(regs, key=lambda r: self._reg_first_assign.get(r, float("inf")))
            by_type: Dict[int, List[int]] = {}
            for r in ordered:
                typ = self.func.regs[r]
                typ_key = id(typ.resolve(self.code))
                by_type.setdefault(typ_key, []).append(r)
            # Keep the earliest register of the first-seen type as the base name;
            # rename duplicates of other types.
            kept = set()
            for r in ordered:
                typ_key = id(self.func.regs[r].resolve(self.code))
                if typ_key not in kept:
                    kept.add(typ_key)
                else:
                    self.locals[r].name = f"{name}{len(kept)}"
                    kept.add(typ_key)

        if self.locals and self.locals[0].name == "var0" and has_this:
            self.locals[0].name = "this"
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

    @dataclass
    class _LoopContext:
        header: CFNode
        nodes: Set[CFNode]
        exit_node: Optional[CFNode]

    def _catch_has_explicit_type(self, catch_branch_node: "CFNode") -> bool:
        """Detect whether the original source wrote an explicit type on the
        catch clause (`catch (e: Dynamic)`) rather than leaving it untyped
        (`catch (e)`).

        Both infer to the same Haxe type, but Haxe's codegen differs subtly:
        an explicit annotation emits a dead `Null` store to a scratch register
        that's never read again, used here purely as a bytecode fingerprint to
        reproduce the same choice when recompiling decompiled source.
        """

        def _read_regs(o: Opcode) -> Set[int]:
            regs: Set[int] = set()
            for key, val in o.df.items():
                if key == "dst":
                    continue
                if isinstance(val, Reg):
                    regs.add(val.value)
                elif isinstance(val, Regs):
                    regs.update(r.value for r in val.value)
            return regs

        for op in catch_branch_node.ops:
            if op.op != "Null":
                continue
            dst = op.df["dst"].value
            if not any(dst in _read_regs(o) for o in self.func.ops if o is not op):
                return True
        return False

    def _resolve_method_field(self, obj_local: "IRLocal", obj_type: Type, field_idx: int) -> Optional["IRField"]:
        """Build the `obj.method` IRField targeted by a CallMethod/CallThis/
        InstanceClosure `field` operand.

        For an ``Obj`` the operand indexes the virtual method table, so the
        proto is looked up by ``pindex`` across the class hierarchy. For a
        ``Virtual`` it indexes the (method-typed) data fields directly. Returns
        ``None`` when the target cannot be resolved.
        """
        defn = obj_type.definition
        if isinstance(defn, Obj):
            proto = self.code.proto_by_pindex(defn, field_idx)
            if proto is None:
                return None
            fun = proto.findex.resolve(self.code)
            return IRField(self.code, obj_local, proto.name.resolve(self.code), fun.type)
        if isinstance(defn, Virtual):
            if field_idx >= len(defn.fields):
                return None
            field_core = defn.fields[field_idx]
            return IRField(self.code, obj_local, field_core.name.resolve(self.code), field_core.type)
        return None

    def _lift_ops_into_block(self, block: IRBlock, ops: List[Opcode]) -> None:
        _debuginfo = self.func.debuginfo.value if (self.func.has_debug and self.func.debuginfo) else None
        for op in ops:
            op_idx = self._op_id_to_idx.get(id(op))
            # Capture the register-to-local mapping before any debug-name split.
            # HashLink frequently reuses a register as both a source and the
            # destination for the same opcode (e.g. `reg0 = String.__add__(reg0,
            # reg1)`).  If we split the local for the destination first, the
            # source operand incorrectly picks up the new, empty local.  Source
            # operands below therefore read from this pre-opcode snapshot, while
            # destinations read from `self.locals` after the split.
            source_locals = self.locals.copy()
            if op_idx is not None:
                self._check_assign(op_idx)
            if op.op == "Label":
                continue
            _prev_len = len(block.statements)

            if op.op == "Nop":
                continue

            if op.op in arithmetic:
                dst = self.locals[op.df["dst"].value]
                lhs = source_locals[op.df["a"].value]
                rhs = source_locals[op.df["b"].value]
                block.statements.append(
                    IRAssign(
                        self.code, dst, IRArithmetic(self.code, lhs, rhs, IRArithmetic.ArithmeticType[op.op.upper()])
                    )
                )
            elif op.op in ["Int", "Float", "Bool", "Bytes", "String", "Null"]:
                dst = self.locals[op.df["dst"].value]
                const_type = IRConst.ConstType[op.op.upper()]
                value = op.df["value"].value if op.op == "Bool" else None
                if op.op not in ["Bool", "Null"]:
                    const = IRConst(self.code, const_type, op.df["ptr"], value)
                else:
                    const = IRConst(self.code, const_type, value=value)
                block.statements.append(IRAssign(self.code, dst, const))
            elif op.op in simple_calls:
                n = int(op.op[-1]) if op.op != "CallN" else len(op.df["args"].value)
                dst = self.locals[op.df["dst"].value]
                fun = IRConst(self.code, IRConst.ConstType.FUN, op.df["fun"])
                args = (
                    [source_locals[op.df[f"arg{i}"].value] for i in range(n)]
                    if op.op != "CallN"
                    else [source_locals[arg.value] for arg in op.df["args"].value]
                )
                call_expr = IRCall(self.code, IRCall.CallType.FUNC, fun, args)

                if dst.get_type().kind.value == Type.Kind.VOID.value:
                    block.statements.append(call_expr)
                else:
                    block.statements.append(IRAssign(self.code, dst, call_expr))
            elif op.op == "CallClosure":
                dst = self.locals[op.df["dst"].value]
                fun = source_locals[op.df["fun"].value]
                args = [source_locals[arg.value] for arg in op.df["args"].value]
                call_expr = IRCall(self.code, IRCall.CallType.CLOSURE, fun, args)

                if dst.get_type().kind.value == Type.Kind.VOID.value:
                    block.statements.append(call_expr)
                else:
                    block.statements.append(IRAssign(self.code, dst, call_expr))
            elif op.op in ("CallMethod", "CallThis"):
                dst = self.locals[op.df["dst"].value]
                arg_regs = op.df["args"].value
                if op.op == "CallThis":
                    obj_local = source_locals[0]
                    obj_type = self.code.types[self.func.regs[0].value]
                    method_args = [source_locals[arg.value] for arg in arg_regs]
                else:
                    obj_local = source_locals[arg_regs[0].value]
                    obj_type = obj_local.get_type()
                    method_args = [source_locals[arg.value] for arg in arg_regs[1:]]
                field_expr = self._resolve_method_field(obj_local, obj_type, op.df["field"].value)
                if field_expr is not None:
                    call_expr = IRCall(self.code, IRCall.CallType.METHOD, field_expr, method_args)
                    if dst.get_type().kind.value == Type.Kind.VOID.value:
                        block.statements.append(call_expr)
                    else:
                        block.statements.append(IRAssign(self.code, dst, call_expr))
                elif dst.get_type().kind.value == Type.Kind.VOID.value:
                    block.statements.append(IRUnliftedOpcode(self.code, op))
                else:
                    block.statements.append(IRAssign(self.code, dst, IRUnliftedOpcode(self.code, op)))
            elif op.op == "Mov":
                block.statements.append(
                    IRAssign(self.code, self.locals[op.df["dst"].value], source_locals[op.df["src"].value])
                )
            elif op.op == "GetGlobal":
                global_idx = op.df["global"].value
                enum_const = self._enum_global_map.get(global_idx)
                expr: IRExpression
                if enum_const is not None:
                    construct_name, enum_type_idx = enum_const
                    expr = IREnumConstruct(self.code, construct_name, [], enum_type_idx)
                else:
                    expr = IRConst(self.code, IRConst.ConstType.GLOBAL_OBJ, idx=op.df["global"])
                block.statements.append(
                    IRAssign(
                        self.code,
                        self.locals[op.df["dst"].value],
                        expr,
                    )
                )
            elif op.op == "SetGlobal":
                global_idx = op.df["global"].value
                # Enum singletons are reconstructed inline at each read (see
                # GetGlobal above), so the write that populates the cache has
                # no separate effect to preserve.
                if global_idx in self._enum_global_map:
                    continue
                src_local = source_locals[op.df["src"].value]
                global_target = IRConst(self.code, IRConst.ConstType.GLOBAL_OBJ, idx=op.df["global"])
                block.statements.append(IRAssign(self.code, global_target, src_local))
            elif op.op == "Field":
                dst_local = self.locals[op.df["dst"].value]
                obj_local = source_locals[op.df["obj"].value]
                obj_type = obj_local.get_type()
                if not isinstance(obj_type.definition, (Obj, Virtual)):
                    raise DecompError(f"Field opcode used on non-object type: {obj_type.definition}")
                field_core = op.df["field"].resolve_obj(self.code, obj_type.definition)
                field_expr = IRField(self.code, obj_local, field_core.name.resolve(self.code), field_core.type)
                block.statements.append(IRAssign(self.code, dst_local, field_expr))
            elif op.op == "GetThis":
                dst_local = self.locals[op.df["dst"].value]
                this_local = source_locals[0]
                this_type_def = self.code.types[self.func.regs[0].value]
                if isinstance(this_type_def.definition, (Obj, Virtual)):
                    field_core = op.df["field"].resolve_obj(self.code, this_type_def.definition)
                    field_expr = IRField(self.code, this_local, field_core.name.resolve(self.code), field_core.type)
                    block.statements.append(IRAssign(self.code, dst_local, field_expr))
                else:
                    block.statements.append(IRUnliftedOpcode(self.code, op))
            elif op.op == "SetThis":
                src_local = source_locals[op.df["src"].value]
                this_local = source_locals[0]
                this_type_def = self.code.types[self.func.regs[0].value]
                if isinstance(this_type_def.definition, (Obj, Virtual)):
                    field_core = op.df["field"].resolve_obj(self.code, this_type_def.definition)
                    field_expr = IRField(self.code, this_local, field_core.name.resolve(self.code), field_core.type)
                    block.statements.append(IRAssign(self.code, field_expr, src_local))
                else:
                    block.statements.append(IRUnliftedOpcode(self.code, op))
            elif op.op == "New":
                dst_local = self.locals[op.df["dst"].value]
                alloc_type_idx = self.func.regs[op.df["dst"].value]
                new_expr = IRNew(self.code, alloc_type_idx)
                block.statements.append(IRAssign(self.code, dst_local, new_expr))
            elif op.op in ("ToSFloat", "ToUFloat"):
                dst_local = self.locals[op.df["dst"].value]
                src_local = source_locals[op.df["src"].value]
                if op.op == "ToUFloat" and isinstance(src_local, IRLocal):
                    src_local.is_unsigned = True

                f64_idx = self.code.find_prim_type(Type.Kind.F64)

                cast_expr = IRCast(self.code, f64_idx, src_local)
                block.statements.append(IRAssign(self.code, dst_local, cast_expr))
            elif op.op == "ToDyn" or op.op == "ToVirtual":
                dst_local = self.locals[op.df["dst"].value]
                src_local = source_locals[op.df["src"].value]
                cast_expr = IRCast(self.code, self.func.regs[op.df["dst"].value], src_local)
                block.statements.append(IRAssign(self.code, dst_local, cast_expr))
            elif op.op == "ToInt":
                dst_local = self.locals[op.df["dst"].value]
                src_local = source_locals[op.df["src"].value]
                cast_expr = IRCast(self.code, self.func.regs[op.df["dst"].value], src_local)
                block.statements.append(IRAssign(self.code, dst_local, cast_expr))
            elif op.op in ("SafeCast", "UnsafeCast"):
                dst_local = self.locals[op.df["dst"].value]
                src_local = source_locals[op.df["src"].value]
                cast_expr = IRCast(self.code, self.func.regs[op.df["dst"].value], src_local)
                block.statements.append(IRAssign(self.code, dst_local, cast_expr))
            elif op.op == "GetArray":
                dst_local = self.locals[op.df["dst"].value]
                arr_local = source_locals[op.df["array"].value]
                idx_local = source_locals[op.df["index"].value]
                block.statements.append(
                    IRAssign(
                        self.code,
                        dst_local,
                        IRArrayAccess(self.code, arr_local, idx_local, self.func.regs[op.df["dst"].value]),
                    )
                )
            elif op.op == "ArraySize":
                dst_local = self.locals[op.df["dst"].value]
                arr_local = source_locals[op.df["array"].value]
                i32_idx = self.code.find_prim_type(Type.Kind.I32)
                length_expr = IRField(self.code, arr_local, "length", i32_idx)
                block.statements.append(IRAssign(self.code, dst_local, length_expr))
            elif op.op == "GetType":
                dst_local = self.locals[op.df["dst"].value]
                src_local = source_locals[op.df["src"].value]
                block.statements.append(
                    IRAssign(self.code, dst_local, IRTypeOf(self.code, src_local, self.func.regs[op.df["dst"].value]))
                )
            elif op.op == "GetTID":
                dst_local = self.locals[op.df["dst"].value]
                src_local = source_locals[op.df["src"].value]
                block.statements.append(
                    IRAssign(self.code, dst_local, IRTypeKind(self.code, src_local, self.func.regs[op.df["dst"].value]))
                )
            elif op.op == "Incr":
                dst_local = self.locals[op.df["dst"].value]
                old_local = source_locals[op.df["dst"].value]
                block.statements.append(
                    IRAssign(
                        self.code,
                        dst_local,
                        IRArithmetic(
                            self.code,
                            old_local,
                            IRConst(self.code, IRConst.ConstType.INT, value=1),
                            IRArithmetic.ArithmeticType.ADD,
                        ),
                    )
                )
            elif op.op == "Decr":
                dst_local = self.locals[op.df["dst"].value]
                old_local = source_locals[op.df["dst"].value]
                block.statements.append(
                    IRAssign(
                        self.code,
                        dst_local,
                        IRArithmetic(
                            self.code,
                            old_local,
                            IRConst(self.code, IRConst.ConstType.INT, value=1),
                            IRArithmetic.ArithmeticType.SUB,
                        ),
                    )
                )
            elif op.op == "Neg":
                dst_local = self.locals[op.df["dst"].value]
                src_local = source_locals[op.df["src"].value]
                block.statements.append(IRAssign(self.code, dst_local, IRNeg(self.code, src_local)))
            elif op.op == "Not":
                dst_local = self.locals[op.df["dst"].value]
                src_local = source_locals[op.df["src"].value]
                block.statements.append(IRAssign(self.code, dst_local, IRNot(self.code, src_local)))
            elif op.op == "GetMem":
                dst_local = self.locals[op.df["dst"].value]
                arr_local = source_locals[op.df["bytes"].value]
                idx_local = source_locals[op.df["index"].value]
                access = IRArrayAccess(self.code, arr_local, idx_local, self.func.regs[op.df["dst"].value])
                access.bytes_access_kind = _bytes_mem_kind(self.code, self.func.regs[op.df["dst"].value])
                block.statements.append(IRAssign(self.code, dst_local, access))
            elif op.op in ("GetI16", "GetI8"):
                dst_local = self.locals[op.df["dst"].value]
                arr_local = source_locals[op.df["bytes"].value]
                idx_local = source_locals[op.df["index"].value]
                access = IRArrayAccess(self.code, arr_local, idx_local, self.func.regs[op.df["dst"].value])
                access.bytes_access_kind = "UI16" if op.op == "GetI16" else "UI8"
                block.statements.append(IRAssign(self.code, dst_local, access))
            elif op.op == "SetMem":
                arr_local = source_locals[op.df["bytes"].value]
                idx_local = source_locals[op.df["index"].value]
                src_local = source_locals[op.df["src"].value]
                src_reg = op.df["src"].value
                access = IRArrayAccess(self.code, arr_local, idx_local, self.func.regs[src_reg])
                access.bytes_access_kind = _bytes_mem_kind(self.code, self.func.regs[src_reg])
                block.statements.append(IRAssign(self.code, access, src_local))
            elif op.op in ("SetI16", "SetI8"):
                arr_local = source_locals[op.df["bytes"].value]
                idx_local = source_locals[op.df["index"].value]
                src_local = source_locals[op.df["src"].value]
                access = IRArrayAccess(self.code, arr_local, idx_local, self.func.regs[op.df["src"].value])
                access.bytes_access_kind = "UI16" if op.op == "SetI16" else "UI8"
                block.statements.append(IRAssign(self.code, access, src_local))
            elif op.op == "SetArray":
                arr_local = source_locals[op.df["array"].value]
                idx_local = source_locals[op.df["index"].value]
                src_local = source_locals[op.df["src"].value]
                block.statements.append(
                    IRAssign(self.code, IRArrayAccess(self.code, arr_local, idx_local, src_local.get_type()), src_local)
                )
            elif op.op == "DynSet":
                obj_local = source_locals[op.df["obj"].value]
                src_local = source_locals[op.df["src"].value]
                field_name = op.df["field"].resolve(self.code)
                field_expr = IRField(self.code, obj_local, field_name, self.func.regs[op.df["src"].value])
                block.statements.append(IRAssign(self.code, field_expr, src_local))
            elif op.op == "DynGet":
                dst_local = self.locals[op.df["dst"].value]
                obj_local = source_locals[op.df["obj"].value]
                field_name = op.df["field"].resolve(self.code)
                field_expr = IRField(self.code, obj_local, field_name, self.func.regs[op.df["dst"].value])
                block.statements.append(IRAssign(self.code, dst_local, field_expr))
            elif op.op == "SetField":
                obj_local = source_locals[op.df["obj"].value]
                src_local = source_locals[op.df["src"].value]
                obj_type = obj_local.get_type()
                if isinstance(obj_type.definition, (Obj, Virtual)):
                    field_core = op.df["field"].resolve_obj(self.code, obj_type.definition)
                    field_expr = IRField(self.code, obj_local, field_core.name.resolve(self.code), field_core.type)
                    block.statements.append(IRAssign(self.code, field_expr, src_local))
                else:
                    block.statements.append(IRUnliftedOpcode(self.code, op))
            elif op.op == "Type":
                dst_local = self.locals[op.df["dst"].value]
                block.statements.append(
                    IRAssign(self.code, dst_local, IRConst(self.code, IRConst.ConstType.GLOBAL_OBJ, idx=op.df["ty"]))
                )
            elif op.op == "Ref":
                dst_local = self.locals[op.df["dst"].value]
                src_local = source_locals[op.df["src"].value]
                block.statements.append(IRAssign(self.code, dst_local, IRRef(self.code, src_local)))
            elif op.op == "Unref":
                # References are modelled transparently (IRRef renders as its
                # inner expression), so dereferencing one is just a copy of the
                # underlying value.
                dst_local = self.locals[op.df["dst"].value]
                src_local = source_locals[op.df["src"].value]
                block.statements.append(IRAssign(self.code, dst_local, src_local))
            elif op.op == "Setref":
                # References are modelled transparently; writing through one is
                # represented as a copy to the reference register itself.
                dst_local = self.locals[op.df["dst"].value]
                src_local = source_locals[op.df["value"].value]
                block.statements.append(IRAssign(self.code, dst_local, src_local))
            elif op.op == "StaticClosure":
                dst_local = self.locals[op.df["dst"].value]
                fun_const = IRConst(self.code, IRConst.ConstType.FUN, idx=op.df["fun"])
                block.statements.append(IRAssign(self.code, dst_local, fun_const))
            elif op.op == "InstanceClosure":
                dst_local = self.locals[op.df["dst"].value]
                obj_local = source_locals[op.df["obj"].value]
                fun = op.df["fun"].resolve(self.code)
                method_name = self.code.partial_func_name(fun)
                obj_def = obj_local.get_type().definition
                if method_name in (None, "<none>") or not isinstance(obj_def, (Obj, Virtual)):
                    # Not a real `obj.method` binding: the compiler also uses
                    # InstanceClosure to wrap a `Dynamic` value as the captured
                    # `this` of a small synthesized adapter function (e.g. the
                    # type-converting closure built for `cast f` on a
                    # function value), which has no name and no real receiver
                    # object. There's no Haxe syntax for "this anonymous
                    # function bound with this capture", but the adapter
                    # always exists to make `obj` itself callable with a
                    # different signature, so a type cast renders the same
                    # observable result without inventing a bogus field name.
                    cast_expr = IRCast(self.code, self.func.regs[op.df["dst"].value], obj_local)
                    block.statements.append(IRAssign(self.code, dst_local, cast_expr))
                else:
                    field_expr = IRField(self.code, obj_local, method_name, self.func.regs[op.df["dst"].value])
                    block.statements.append(IRAssign(self.code, dst_local, field_expr))
            elif op.op == "VirtualClosure":
                dst_local = self.locals[op.df["dst"].value]
                obj_local = source_locals[op.df["obj"].value]
                obj_type = obj_local.get_type()
                field_expr = self._resolve_method_field(obj_local, obj_type, op.df["field"].value)
                if field_expr is not None:
                    # Unlike InstanceClosure, this opcode means the original Haxe
                    # source resolved the closure through a statically-typed
                    # receiver that required virtual dispatch (e.g. the receiver
                    # was typed as a base class). The lifted local's type is the
                    # concrete allocated type, which would make the recompiled
                    # closure bind directly instead of virtually — record the
                    # declaring function so pseudo-rendering can widen the
                    # receiver's declared type back to where dispatch is virtual.
                    defn = obj_type.definition
                    if isinstance(defn, Obj):
                        proto = self.code.proto_by_pindex(defn, op.df["field"].value)
                        if proto is not None:
                            resolved_fun = proto.findex.resolve(self.code)
                            if isinstance(resolved_fun, Function):
                                field_expr.virtual_dispatch_fun = resolved_fun
                    block.statements.append(IRAssign(self.code, dst_local, field_expr))
                else:
                    block.statements.append(IRAssign(self.code, dst_local, IRUnliftedOpcode(self.code, op)))
            elif op.op == "NullCheck":
                continue
            elif op.op == "EnumIndex":
                dst_local = self.locals[op.df["dst"].value]
                src_local = source_locals[op.df["value"].value]
                block.statements.append(IRAssign(self.code, dst_local, IREnumIndex(self.code, src_local)))
            elif op.op == "MakeEnum":
                dst_local = self.locals[op.df["dst"].value]
                enum_type = self.func.regs[op.df["dst"].value]
                enum_def = enum_type.resolve(self.code).definition
                cid = op.df["construct"].value
                construct_name = (
                    enum_def.constructs[cid].name.resolve(self.code)
                    if cid < len(enum_def.constructs)
                    else f"construct_{cid}"
                )
                args = [source_locals[arg.value] for arg in op.df["args"].value]
                block.statements.append(
                    IRAssign(self.code, dst_local, IREnumConstruct(self.code, construct_name, args, enum_type))
                )
            elif op.op == "EnumAlloc":
                dst_local = self.locals[op.df["dst"].value]
                enum_type = self.func.regs[op.df["dst"].value]
                enum_def = enum_type.resolve(self.code).definition
                cid = op.df["construct"].value
                construct_name = (
                    enum_def.constructs[cid].name.resolve(self.code)
                    if cid < len(enum_def.constructs)
                    else f"construct_{cid}"
                )
                block.statements.append(
                    IRAssign(self.code, dst_local, IREnumConstruct(self.code, construct_name, [], enum_type))
                )
            elif op.op == "EnumField":
                dst_local = self.locals[op.df["dst"].value]
                src_local = source_locals[op.df["value"].value]
                enum_type = self.func.regs[op.df["value"].value]
                enum_def = enum_type.resolve(self.code).definition
                cid = op.df["construct"].value
                fid = op.df["field"].value
                if cid < len(enum_def.constructs) and fid < len(enum_def.constructs[cid].params):
                    field_name = f"param{fid}"
                    construct = enum_def.constructs[cid]
                    field_type = construct.params[fid]
                    block.statements.append(
                        IRAssign(self.code, dst_local, IREnumField(self.code, src_local, field_name, field_type))
                    )
                else:
                    block.statements.append(IRAssign(self.code, dst_local, IRUnliftedOpcode(self.code, op)))
            elif op.op == "SetEnumField":
                value_local = source_locals[op.df["value"].value]
                src_local = source_locals[op.df["src"].value]
                enum_type = self.func.regs[op.df["value"].value]
                enum_def = enum_type.resolve(self.code).definition
                fid = op.df["field"].value
                # SetEnumField has no explicit construct operand; use the only
                # construct when the enum is a singleton, otherwise pick the first
                # construct that has a parameter at this index.
                construct = None
                if len(enum_def.constructs) == 1:
                    construct = enum_def.constructs[0]
                else:
                    for c in enum_def.constructs:
                        if fid < len(c.params):
                            construct = c
                            break
                if construct is not None and fid < len(construct.params):
                    field_name = f"param{fid}"
                    field_type = construct.params[fid]
                    block.statements.append(
                        IRAssign(self.code, IREnumField(self.code, value_local, field_name, field_type), src_local)
                    )
                else:
                    block.statements.append(IRUnliftedOpcode(self.code, op))
            else:
                if "dst" in op.df:
                    block.statements.append(
                        IRAssign(self.code, self.locals[op.df["dst"].value], IRUnliftedOpcode(self.code, op))
                    )
                else:
                    block.statements.append(IRUnliftedOpcode(self.code, op))

            # Tag the newly-appended statement with source location and opcode index
            if op_idx is not None and len(block.statements) > _prev_len:
                stmt = block.statements[-1]
                stmt.src_op_idx = op_idx
                if _debuginfo is not None:
                    try:
                        ref = _debuginfo[op_idx]
                        stmt.src_line = ref.line
                        stmt.src_file_idx = ref.value
                    except IndexError:
                        pass

    def _shortest_distances(
        self,
        start: CFNode,
        allowed_nodes: Optional[Set[CFNode]] = None,
        stop_nodes: Optional[Set[CFNode]] = None,
    ) -> Dict[CFNode, int]:
        stop_nodes = stop_nodes or set()
        queue: List[Tuple[CFNode, int]] = [(start, 0)]
        distances: Dict[CFNode, int] = {}

        while queue:
            current, dist = queue.pop(0)
            if current in distances:
                continue
            if allowed_nodes is not None and current not in allowed_nodes:
                continue
            if current in stop_nodes:
                continue

            distances[current] = dist
            for next_node, _ in current.branches:
                if next_node not in distances:
                    queue.append((next_node, dist + 1))

        return distances

    def _find_convergence_node(
        self,
        left: Optional[CFNode],
        right: Optional[CFNode],
        allowed_nodes: Optional[Set[CFNode]] = None,
        stop_nodes: Optional[Set[CFNode]] = None,
    ) -> Optional[CFNode]:
        if left is None or right is None:
            return None

        left_distances = self._shortest_distances(left, allowed_nodes, stop_nodes)
        right_distances = self._shortest_distances(right, allowed_nodes, stop_nodes)
        common_nodes = set(left_distances).intersection(right_distances)
        if not common_nodes:
            return None

        return min(common_nodes, key=lambda node: (left_distances[node] + right_distances[node], node.base_offset))

    def _is_terminal_branch_node(self, node: Optional[CFNode], loop_ctx: Optional[_LoopContext]) -> bool:
        """Return True if a branch target has no live successors within the current region."""
        if node is None:
            return True
        if loop_ctx is not None and node == loop_ctx.header:
            return False
        if not node.branches:
            return True
        # A node that only leaves the current region is also terminal for our purposes.
        if loop_ctx is not None:
            return all(successor not in loop_ctx.nodes for successor, _ in node.branches)
        return False

    def _loop_exit_nodes(self, loop_nodes: Set[CFNode]) -> List[CFNode]:
        exit_nodes: Set[CFNode] = set()
        for loop_node in loop_nodes:
            for target, _ in loop_node.branches:
                if target not in loop_nodes:
                    exit_nodes.add(target)
        return sorted(exit_nodes, key=lambda n: n.base_offset)

    def _lift_loop(
        self,
        header: CFNode,
        visited: Set[CFNode],
        stop_at: Optional[CFNode],
        parent_loop: Optional[_LoopContext],
    ) -> IRBlock:
        assert self.cfg is not None
        visited.add(header)
        block = IRBlock(self.code)
        loop_nodes = self.cfg.loops[header]
        # Prefer the header's own outside successor as the loop exit when the header
        # is a conditional. This correctly identifies post-loop code even when the
        # loop body contains internal returns that would otherwise look like extra
        # exits (e.g. String.lastIndexOf).
        exit_node: Optional[CFNode] = None
        header_last_op = header.ops[-1] if header.ops else None
        if header_last_op and header_last_op.op in conditionals:
            outside_header_successors = [target for target, _ in header.branches if target not in loop_nodes]
            if len(outside_header_successors) == 1:
                exit_node = outside_header_successors[0]
        if exit_node is None:
            exit_nodes = self._loop_exit_nodes(loop_nodes)
            exit_node = exit_nodes[0] if len(exit_nodes) == 1 else None
        loop_ctx = self._LoopContext(header, loop_nodes, exit_node)

        header_last_op = header.ops[-1] if header.ops else None
        if header_last_op and header_last_op.op in conditionals:
            cond_block = IRBlock(self.code)
            self._lift_ops_into_block(cond_block, header.ops[:-1])

            def _jump_operand(key: str) -> Optional[IRExpression]:
                if key not in header_last_op.df:
                    return None
                return cast(IRExpression, self.locals[header_last_op.df[key].value])

            pj_left = _jump_operand("a")
            pj_right = _jump_operand("b")
            pj_cond = _jump_operand("cond") if "cond" in header_last_op.df else _jump_operand("reg")
            cond_block.statements.append(IRPrimitiveJump(self.code, header_last_op, pj_left, pj_right, pj_cond))

            inside_successors = [target for target, _ in header.branches if target in loop_nodes and target != header]
            body_start = inside_successors[0] if len(inside_successors) == 1 else None
            body_block = (
                self._lift_block(body_start, visited.copy(), stop_at=header, loop_ctx=loop_ctx)
                if body_start is not None
                else IRBlock(self.code)
            )

            block.statements.append(IRPrimitiveLoop(self.code, cond_block, body_block))
        else:
            body_block = self._lift_block(header, visited.copy(), stop_at=header, loop_ctx=loop_ctx)
            block.statements.append(
                IRWhileLoop(self.code, IRBoolExpr(self.code, IRBoolExpr.CompareType.TRUE), body_block)
            )

        next_block_ir = self._lift_block(exit_node, visited, stop_at, loop_ctx=parent_loop)
        block.statements.extend(next_block_ir.statements)
        return block

    def _build_bool_expr_from_op(self, op: Opcode) -> IRBoolExpr:
        """Helper to create an IRBoolExpr from a conditional jump opcode."""
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
            "JNotLt": IRBoolExpr.CompareType.GTE,
            "JNotGte": IRBoolExpr.CompareType.LT,
            "JEq": IRBoolExpr.CompareType.EQ,
            "JNotEq": IRBoolExpr.CompareType.NEQ,
        }
        assert op.op is not None, "WTF??"
        cond = cond_map[op.op]
        left, right = None, None
        if "a" in op.df and "b" in op.df:
            left = self.locals[op.df["a"].value]
            right = self.locals[op.df["b"].value]
        else:
            reg_key = "cond" if "cond" in op.df else "reg"
            left = self.locals[op.df[reg_key].value]
        return IRBoolExpr(self.code, cond, left, right)

    def _clone_ir(self, block: IRBlock) -> IRBlock:
        """
        Clones a cached IRBlock so a memoized `_lift_block` result can be reused without
        making the same object reachable from multiple parents. `self.code` (the whole
        Bytecode) and `self.locals` (the register->IRLocal identities used throughout
        the function) are shared rather than duplicated; everything else in the
        statement/expression tree is copied. Hand-rolled instead of `copy.deepcopy`:
        deepcopy's generic `__reduce_ex__`/pickling-protocol dispatch is much slower
        than just walking `__dict__`, and this runs once per cache hit.
        """
        memo: Dict[int, Any] = {id(self.code): self.code}
        for local in self.locals:
            memo[id(local)] = local
        return cast(IRBlock, self._clone_value(block, memo))

    def _clone_value(self, value: Any, memo: Dict[int, Any]) -> Any:
        if value is None or isinstance(value, (int, float, str, bool, bytes, _Enum)):
            return value
        vid = id(value)
        if vid in memo:
            return memo[vid]
        if isinstance(value, list):
            new_list: List[Any] = []
            memo[vid] = new_list
            new_list.extend(self._clone_value(v, memo) for v in value)
            return new_list
        if isinstance(value, tuple):
            return tuple(self._clone_value(v, memo) for v in value)
        if isinstance(value, dict):
            new_dict: Dict[Any, Any] = {}
            memo[vid] = new_dict
            for k, v in value.items():
                new_dict[self._clone_value(k, memo)] = self._clone_value(v, memo)
            return new_dict
        if isinstance(value, set):
            new_set: Set[Any] = set()
            memo[vid] = new_set
            new_set.update(self._clone_value(v, memo) for v in value)
            return new_set
        if not hasattr(value, "__dict__"):
            # Unknown leaf type (e.g. a Bytecode/Function/Type reference) - share it.
            return value
        new_obj = object.__new__(type(value))
        memo[vid] = new_obj
        for k, v in vars(value).items():
            setattr(new_obj, k, self._clone_value(v, memo))
        return new_obj

    def _lift_block(
        self,
        node: Optional[CFNode],
        visited: Set[CFNode],
        stop_at: Optional[CFNode] = None,
        loop_ctx: Optional[_LoopContext] = None,
    ) -> IRBlock:
        """
        Recursively lifts a CFNode and its successors into an IRBlock.

        Args:
            node: The current CFNode to process.
            visited: A set of nodes already processed in the current traversal path to prevent infinite loops.
            stop_at: A CFNode that signals the end of the current branch (the convergence point).
                     When this node is reached, the recursive call terminates.

        Returns:
            An IRBlock containing the lifted IR statements.
        """
        # --- Base Cases for Recursion Termination ---
        assert self.cfg is not None
        cfg = self.cfg
        if node is None or node == stop_at or node in visited:
            return IRBlock(self.code)
        if loop_ctx and node not in loop_ctx.nodes and node.branches:
            block = IRBlock(self.code)
            block.statements.append(IRBreak(self.code))
            return block
        if node in cfg.loops and (loop_ctx is None or node != loop_ctx.header):
            return self._lift_loop(node, visited, stop_at, loop_ctx)

        # Memoize on (node, stop_at, loop_ctx): without this, CFGs where many branches
        # funnel into a small set of shared continuation points cause the same
        # (node, stop_at) region to be re-lifted independently from every branch that
        # reaches it, which is exponential in the nesting depth of the function. Since
        # loops are handled separately above, everything reachable here is acyclic, so
        # the *logical content* for an identical (node, stop_at, loop_ctx) request never
        # depends on which ancestor path got there. We still hand back a fresh clone
        # rather than the cached object itself: returning the same instance would make
        # the IR a real DAG, and nothing downstream (repr(), pprint(), the optimizer
        # passes' generic statement walk) expects a node to be reachable from multiple
        # parents, so they would re-render/re-process the shared subtree once per
        # reference path - the same exponential blowup we're trying to avoid, just
        # moved into every later consumer instead of the lifter.
        # _LoopContext is a non-frozen @dataclass, so it's unhashable; key on identity instead.
        cache_key = (node, stop_at, id(loop_ctx))
        cached = self._lift_cache.get(cache_key)
        if cached is not None:
            visited.add(node)
            return self._clone_ir(cached)

        visited.add(node)

        block = IRBlock(self.code)
        last_op = node.ops[-1] if node.ops else None

        # --- 1. Process the Content of the Current Node ---
        # Determine which opcodes are for content vs. control flow.
        # If the last op is a branch/return, we don't lift it as a regular statement.
        is_last_op_control_flow = last_op and last_op.op in (
            conditionals + ["Switch", "Ret", "JAlways", "Throw", "Rethrow", "Trap", "EndTrap"]
        )
        ops_to_process = node.ops[:-1] if is_last_op_control_flow else node.ops

        self._lift_ops_into_block(block, ops_to_process)

        # --- 2. Handle the Control Flow based on the Last Opcode ---
        if last_op and last_op.op in conditionals:
            # HL conditional jumps: JXxx jumps to the target when condition is TRUE.
            # Compilers emit "JXxx(negated_if_condition) → else_block" so fall-through = then.
            jump_target, fall_through = None, None
            for branch_node, edge_type in node.branches:
                if edge_type == "true":
                    jump_target = branch_node  # jump target = else block in source
                elif edge_type == "false":
                    fall_through = branch_node  # fall-through = then block in source

            # Invert the jump condition to get the actual "if" condition.
            cond_expr = self._build_bool_expr_from_op(last_op)
            cond_expr.invert()

            def make_loop_branch(target: Optional[CFNode]) -> Optional[IRBlock]:
                if target is None:
                    return IRBlock(self.code)
                if loop_ctx and target == loop_ctx.header:
                    branch_block = IRBlock(self.code)
                    branch_block.statements.append(IRContinue(self.code))
                    return branch_block
                if loop_ctx and target not in loop_ctx.nodes:
                    # A return inside a loop is not a loop break; let the normal
                    # Ret handler lift it as an IRReturn.  The exception is the
                    # loop's own exit node, which post-dominates the header and
                    # therefore represents leaving the loop normally.
                    if (
                        not target.branches
                        and target.ops
                        and target.ops[-1].op == "Ret"
                        and loop_ctx.header not in cfg.post_dominators.get(target, set())
                    ):
                        return None
                    # Branches that leave the loop may contain side effects before the
                    # exit (e.g. a final push before breaking out of while(true)). Lift
                    # them up to the loop's normal exit node and append a break only if
                    # the branch does not already terminate on its own.
                    if loop_ctx.exit_node is not None:
                        # Lift the exiting branch outside the current loop context so
                        # its statements are preserved; stop at the loop's normal exit
                        # node so post-loop code is not duplicated here.
                        branch_block = self._lift_block(
                            target, visited.copy(), stop_at=loop_ctx.exit_node, loop_ctx=None
                        )
                        if branch_block.statements and isinstance(branch_block.statements[-1], (IRReturn, IRThrow)):
                            return branch_block
                        branch_block.statements.append(IRBreak(self.code))
                        return branch_block
                    branch_block = IRBlock(self.code)
                    branch_block.statements.append(IRBreak(self.code))
                    return branch_block
                return None

            # then = fall-through, else = jump target
            then_block_ir = make_loop_branch(fall_through)
            else_block_ir = make_loop_branch(jump_target)

            stop_nodes = {loop_ctx.header} if loop_ctx else set()
            allowed_nodes = loop_ctx.nodes if loop_ctx else None
            convergence_node = self._find_convergence_node(
                jump_target,
                fall_through,
                allowed_nodes=allowed_nodes,
                stop_nodes=stop_nodes,
            )

            if convergence_node is None and node in cfg.immediate_post_dominators:
                convergence_node = cfg.immediate_post_dominators[node]

            # If the branches do not share a real convergence point because one of
            # them terminates (e.g. returns), use the post-dominator of the live
            # branch as the convergence.  This keeps the code after the terminating
            # branch outside the conditional instead of inlining it into the other
            # branch.
            if convergence_node is None:
                terminal_left = self._is_terminal_branch_node(jump_target, loop_ctx)
                terminal_right = self._is_terminal_branch_node(fall_through, loop_ctx)
                if terminal_left and not terminal_right and fall_through in cfg.immediate_post_dominators:
                    convergence_node = cfg.immediate_post_dominators[fall_through]
                elif terminal_right and not terminal_left and jump_target in cfg.immediate_post_dominators:
                    convergence_node = cfg.immediate_post_dominators[jump_target]

            # If no convergence point could be determined at all, never let a branch
            # explore past the boundary the *enclosing* call already established. Without
            # this, a live branch recurses with stop_at=None and re-walks the entire rest
            # of the function independently of the outer continuation, which re-walks the
            # same nodes again - doubling work at every such conditional and blowing up
            # exponentially for long chains of terminal-vs-live branches.
            if convergence_node is None:
                convergence_node = stop_at

            # When one branch leaves the loop and the other loops back, do not let the
            # convergence point be outside the loop. Lifting the exit node here would
            # pull post-loop code into the body and emit a spurious trailing break.
            if (
                loop_ctx
                and convergence_node is not None
                and convergence_node not in loop_ctx.nodes
                and convergence_node != loop_ctx.header
            ):
                loops_back = (fall_through is not None and fall_through in loop_ctx.nodes) or (
                    jump_target is not None and jump_target in loop_ctx.nodes
                )
                if loops_back:
                    convergence_node = loop_ctx.header

            if then_block_ir is None:
                then_block_ir = self._lift_block(
                    fall_through, visited.copy(), stop_at=convergence_node, loop_ctx=loop_ctx
                )
            if else_block_ir is None:
                else_block_ir = self._lift_block(
                    jump_target, visited.copy(), stop_at=convergence_node, loop_ctx=loop_ctx
                )

            conditional_stmt = IRConditional(self.code, cond_expr, then_block_ir, else_block_ir)
            block.statements.append(conditional_stmt)

            # Continue lifting from the convergence point, but stop at the outer boundary.
            # This prevents the convergence node from being consumed here when it equals
            # the outer stop_at, which would leave the outer caller with nothing to lift.
            next_block_ir = self._lift_block(convergence_node, visited, stop_at=stop_at, loop_ctx=loop_ctx)
            block.statements.extend(next_block_ir.statements)

        elif last_op and last_op.op == "Switch":
            convergence_node = self._find_convergence_node(
                node.branches[0][0] if node.branches else None,
                node.branches[1][0] if len(node.branches) > 1 else None,
                allowed_nodes=loop_ctx.nodes if loop_ctx else None,
                stop_nodes={loop_ctx.header} if loop_ctx else None,
            )
            val_reg = self.locals[last_op.df["reg"].value]
            cases, default_block = {}, IRBlock(self.code)

            for target_node, edge_type in node.branches:
                case_block_ir = self._lift_block(
                    target_node, visited.copy(), stop_at=convergence_node, loop_ctx=loop_ctx
                )
                if edge_type.startswith("switch: case:"):
                    case_val = int(edge_type.split(":")[-1].strip())
                    cases[IRConst(self.code, IRConst.ConstType.INT, value=case_val)] = case_block_ir
                elif edge_type == "switch: default":
                    default_block = case_block_ir

            block.statements.append(IRSwitch(self.code, val_reg, cases, default_block))
            # See the Trap case below for why stop_at must be threaded through here.
            next_block_ir = self._lift_block(convergence_node, visited, stop_at=stop_at, loop_ctx=loop_ctx)
            block.statements.extend(next_block_ir.statements)

        elif last_op and last_op.op == "Trap":
            try_branch_node, catch_branch_node = None, None
            for branch_node, edge_type in node.branches:
                if edge_type == "fall-through":
                    try_branch_node = branch_node
                elif edge_type == "trap":
                    catch_branch_node = branch_node

            stop_nodes = {loop_ctx.header} if loop_ctx else set()
            allowed_nodes = loop_ctx.nodes if loop_ctx else None
            convergence_node = self._find_convergence_node(
                try_branch_node,
                catch_branch_node,
                allowed_nodes=allowed_nodes,
                stop_nodes=stop_nodes,
            )

            try_block_ir = self._lift_block(
                try_branch_node, visited.copy(), stop_at=convergence_node, loop_ctx=loop_ctx
            )
            catch_block_ir = self._lift_block(
                catch_branch_node, visited.copy(), stop_at=convergence_node, loop_ctx=loop_ctx
            )
            catch_local = self.locals[last_op.df["exc"].value]
            explicit_catch_type = (
                self._catch_has_explicit_type(catch_branch_node) if catch_branch_node is not None else False
            )
            block.statements.append(
                IRTryCatch(self.code, try_block_ir, catch_block_ir, catch_local, explicit_catch_type)
            )

            # Must bound this by the enclosing stop_at, like the conditional case
            # below does: when this Trap is itself inside a branch that was lifted
            # with stop_at == convergence_node (e.g. an enclosing if/else where one
            # side returns early and the other falls through into this try/catch),
            # omitting it would re-lift the shared tail past the try/catch here, and
            # the enclosing branch's own caller would *also* lift it as the
            # conditional's post-merge continuation — duplicating it.
            next_block_ir = self._lift_block(convergence_node, visited, stop_at=stop_at, loop_ctx=loop_ctx)
            block.statements.extend(next_block_ir.statements)

        elif last_op and last_op.op == "Ret":
            ret_type = self.func.regs[last_op.df["ret"].value].resolve(self.code)
            ret_val = self.locals[last_op.df["ret"].value] if not isinstance(ret_type.definition, Void) else None
            block.statements.append(IRReturn(self.code, ret_val))

        elif last_op and last_op.op in ("Throw", "Rethrow"):
            exc_local = self.locals[last_op.df["exc"].value]
            block.statements.append(IRThrow(self.code, exc_local))

        elif last_op and last_op.op == "EndTrap":
            if node.branches:
                successor_node, _ = node.branches[0]
                next_block_ir = self._lift_block(successor_node, visited, stop_at, loop_ctx=loop_ctx)
                block.statements.extend(next_block_ir.statements)

        elif last_op and (last_op.op == "JAlways" or not is_last_op_control_flow):
            # Handles both explicit unconditional jumps and implicit fall-through
            if node.branches:
                successor_node, _ = node.branches[0]
                if loop_ctx and successor_node == loop_ctx.header:
                    return block
                if loop_ctx and successor_node not in loop_ctx.nodes:
                    block.statements.append(IRBreak(self.code))
                else:
                    next_block_ir = self._lift_block(successor_node, visited, stop_at, loop_ctx=loop_ctx)
                    block.statements.extend(next_block_ir.statements)

        self._lift_cache[cache_key] = block
        return block

    def print(self) -> None:
        print(self.block.pprint())


class IRClass:
    """
    Intermediate representation of a class.
    """

    def __init__(self, code: Bytecode, obj: Obj, capture_layers: bool = False) -> None:
        self.code = code
        self.capture_layers = capture_layers
        self.dynamic: Optional[Obj] = None
        self.static: Optional[Obj] = None
        if obj.is_static:
            self.static = obj
            try:
                self.dynamic = obj.dynamic
            except (ValueError, AttributeError):
                self.dynamic = None
        else:
            self.dynamic = obj
            try:
                self.static = obj.static
            except (ValueError, AttributeError):
                self.static = None
        self.methods: List[IRFunction] = []
        self.static_methods: List[IRFunction] = []
        self.fields: List[Tuple[str, Type]] = []
        self.static_fields: List[Tuple[str, Type]] = []
        if self.dynamic is None and self.static is None:
            raise ValueError(
                "IRClass needs at least one valid Obj that has been preprocessed by `Bytecode.map_statics`!"
            )

        if self.dynamic:
            self.methods += self.gather_methods(self.dynamic)
            self.fields += self.gather_fields(self.dynamic)
        if self.static:
            self.static_methods += self.gather_methods(self.static)
            self.static_fields += self.gather_fields(self.static)

    def gather_methods(self, obj: Obj) -> List[IRFunction]:
        """
        Gathers all methods from an instance of Obj.
        """
        res: List[IRFunction] = []
        for proto in obj.protos:
            fn = proto.findex.resolve(self.code)
            assert isinstance(fn, Function), "Native protos aren't supported! Not even sure if this is possible tbh"
            res.append(IRFunction(self.code, fn, capture_layers=self.capture_layers))
        for binding in obj.bindings:
            fn = binding.findex.resolve(self.code)
            assert isinstance(fn, Function), "Native bindings aren't supported! Not even sure if this is possible tbh"
            # Avoid adding duplicates if a proto is also bound
            if fn not in [r.func for r in res]:
                res.append(IRFunction(self.code, fn, capture_layers=self.capture_layers))
        return res

    def gather_fields(self, obj: Obj) -> List[Tuple[str, Type]]:
        res: List[Tuple[str, Type]] = []
        binding_names: List[str] = []
        for binding in obj.bindings:
            binding_names.append(binding.field.resolve_obj(self.code, obj).name.resolve(self.code))
        for field in obj.fields:
            if not field.name.resolve(self.code) in binding_names:
                res.append((field.name.resolve(self.code), field.type.resolve(self.code)))
        return res

    def pseudo(self) -> str:
        """
        Generates Haxe pseudocode for the entire class.
        """
        from .. import pseudo

        return pseudo.class_pseudo(self)

    def print(self) -> None:
        """
        Prints the Haxe pseudocode for the entire class to the console.
        """
        print(self.pseudo())
