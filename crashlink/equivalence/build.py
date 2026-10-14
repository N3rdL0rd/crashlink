"""Execute a lifted function symbolically into a value graph.

Registers become SSA values (phis at joins, built on demand), memory is a single chain of effects,
and each opcode is classified:

- pure values (constants, arithmetic, conversions, loads) are shared by structure, so a `Mov`, a
  re-materialised constant or the order of independent pure computations leaves no trace;
- effects (calls, stores, allocations, and the checks that may throw) are ordered along the chain;
- loads read the chain as it stands, so they never move across a store.

Loads and stores dereference their object, which faults on null. That is an observable effect, so
it is recorded as a `nullcheck` guard unless the object is already known to be non-null on every
path (it was allocated, is a constant, or was checked before). `relaxed` mode drops the guards,
asserting equivalence only for executions in which no check fails.
"""

from __future__ import annotations

import struct
import sys
from typing import Dict, List, Optional, Set, Tuple, cast

from ..core import Bytecode, Enum, Fun, Function, Type
from .lift import Block, Lifted, Unsupported, liveness
from .names import FLOAT_KINDS, INT_KINDS, VOID_KIND, Namer
from .terms import Graph, Node, Var

MEM: Var = "mem"
START = -1
WIDTH = {3: 32, 4: 64}
"""Integer kinds whose arithmetic is folded, by bit width."""
OUT_ONLY = {("native", "std.itos"), ("native", "std.ftos")}
"""Natives whose second argument is an out-parameter."""
COMMUTES = {"Add", "Mul", "And", "Or", "Xor"}
ARITH = {"Add", "Sub", "Mul", "SDiv", "UDiv", "SMod", "UMod", "Shl", "SShr", "UShr", "And", "Or", "Xor"}
LOAD_GUARDED = {
    "Field",
    "EnumField",
    "EnumIndex",
    "GetArray",
    "ArraySize",
    "GetI8",
    "GetI16",
    "GetMem",
    "DynGet",
    "Unref",
}


def _is_pos_infos(desc: str) -> bool:
    """A `haxe.PosInfos` value, as the compiler builds it for an omitted `?pos` argument."""
    return (
        desc.startswith("virt{") and "fileName:" in desc and "lineNumber:" in desc and "methodName:" in desc
    )


_POS_FIELDS = frozenset({"fileName", "lineNumber", "className", "methodName"})


def _is_dynamic_pos_infos(fields: Dict[Tuple[str, object], Node]) -> bool:
    """A dynamic object with exactly the fields of a `haxe.PosInfos` (and nothing else but its extras)."""
    names = {key for how, key in fields if how == "dyn"}
    return all(how == "dyn" for how, _ in fields) and _POS_FIELDS <= names <= _POS_FIELDS | {"customParams"}


def _normal_int(value: int, kind: int) -> int:
    """An integer constant as the register holds it: -16 and 4294967280 are one I32 value."""
    if kind in WIDTH:
        return _wrap(value, WIDTH[kind])
    if kind == 1:
        return value & 0xFF
    if kind == 2:
        return value & 0xFFFF
    return value


def _wrap(value: int, width: int) -> int:
    value &= (1 << width) - 1
    return value - (1 << width) if value >> (width - 1) else value


class _Pending:
    """An object that has been allocated and filled in but not yet used."""

    def __init__(self, kind: str) -> None:
        self.kind = kind
        self.fields: Dict[Tuple[str, object], Node] = {}


class Built:
    """The result of building one function."""

    def __init__(self, graph: Graph, lifted: Lifted) -> None:
        self.graph = graph
        self.lifted = lifted
        self.exit_mem: List[Node] = []
        self.term_nodes: List[List[Node]] = []
        self.unstable = False


class Builder:
    def __init__(
        self,
        code: Bytecode,
        func: Function,
        lifted: Lifted,
        namer: Namer,
        strict: bool,
        ignore_positions: bool,
    ) -> None:
        self.code = code
        self.func = func
        self.lifted = lifted
        self.namer = namer
        self.strict = strict
        self.ignore_positions = ignore_positions
        self.g = Graph()
        self.nblocks = len(lifted.blocks)
        self.reg_desc = [namer.type_index(t.value) for t in func.regs]
        self.reg_kind = [namer.kind_of(t.value) for t in func.regs]
        self.cur: Dict[int, Dict[Var, Node]] = {START: {}}
        self.preds: List[List[int]] = [list(p) for p in lifted.preds]
        self.preds[0] = [START] + self.preds[0]
        self.sealed: Set[int] = set()
        self.incomplete: Dict[int, Dict[Var, Node]] = {}
        self.unprocessed_preds: List[int] = [len(p) for p in self.preds]
        self.facts_out: Dict[int, Set[int]] = {}
        self.facts: Set[int] = set()
        self.overrides: Dict[int, Dict[Var, Node]] = {}
        self.has_setglobal = any(op.op == "SetGlobal" for b in lifted.blocks for op in b.ops)
        self.cells: Dict[int, int] = {}
        self.pending: Dict[int, _Pending] = {}
        self.cell_pending: Dict[int, Node] = {}
        self.live_out = liveness(lifted)[1]
        self.exit_mem: List[Optional[Node]] = [None] * self.nblocks
        self.term_nodes: List[List[Node]] = [[] for _ in range(self.nblocks)]
        self.undef = self.g.pure("undef", ())
        self.enclosing: Dict[int, List[int]] = {}
        for trap_id, info in lifted.traps.items():
            for member in info.region:
                self.enclosing.setdefault(member, []).append(trap_id)
        self.trap_mems: Dict[int, List[Node]] = {trap_id: [] for trap_id in lifted.traps}
        self.trap_writes: Dict[int, Dict[int, List[Tuple[Node, Node]]]] = {
            trap_id: {r: [] for r in info.needed} for trap_id, info in lifted.traps.items()
        }
        self.processed: Set[int] = set()
        self.handler_of: Dict[int, int] = {
            block.term.succs[1]: trap_id
            for trap_id, block in enumerate(lifted.blocks)
            if block.term.kind == "trap"
        }
        self._find_cells()
        self._find_ref_reach()
        self._find_handlers()

    # -- setup -------------------------------------------------------------------------------

    def _find_cells(self) -> None:
        """Registers whose address is taken live in memory, not in SSA values."""
        for block in self.lifted.blocks:
            for op in block.ops:
                if op.op == "Ref":
                    reg = op.df["src"].value
                    if reg not in self.cells:
                        self.cells[reg] = len(self.cells)

    def _find_ref_reach(self) -> None:
        """For each block, the cells whose address was taken in it or in a block that reaches it:
        a reference to such a cell may exist, so what is stored in the cell is observable."""
        here: List[Set[int]] = [set() for _ in range(self.nblocks)]
        for i, block in enumerate(self.lifted.blocks):
            for op in block.ops:
                if op.op == "Ref":
                    here[i].add(self.cells[op.df["src"].value])
        reach = [set(s) for s in here]
        changed = True
        while changed:
            changed = False
            for i, block in enumerate(self.lifted.blocks):
                for s in block.term.succs:
                    if not reach[i] <= reach[s]:
                        reach[s] |= reach[i]
                        changed = True
        self.ref_reach = reach
        self.cell_reg = {cell: reg for reg, cell in self.cells.items()}

    def _find_handlers(self) -> None:
        for i, block in enumerate(self.lifted.blocks):
            if block.term.kind == "trap":
                handler = block.term.succs[1]
                if len(self.preds[handler]) != 1:
                    raise Unsupported("a catch handler with several entries")

    # -- SSA variable access (Braun et al., "Simple and Efficient Construction of SSA Form") ----

    def write(self, var: Var, block: int, node: Node) -> None:
        self.cur[block][var] = node

    def read(self, var: Var, block: int) -> Node:
        local = self.cur[block].get(var)
        if local is not None:
            return local
        return self._read_rec(var, block)

    def _var_ty(self, var: Var) -> str:
        return var if isinstance(var, str) else self.reg_desc[var]

    def _read_rec(self, var: Var, block: int) -> Node:
        if block == START:
            value = self.undef
        elif block not in self.sealed:
            phi = self.g.phi(block, var, self._var_ty(var))
            self.incomplete.setdefault(block, {})[var] = phi
            value = phi
        elif len(self.preds[block]) == 1:
            value = self.read(var, self.preds[block][0])
        else:
            phi = self.g.phi(block, var, self._var_ty(var))
            self.write(var, block, phi)
            self._fill(phi, var, block)
            value = phi
        self.write(var, block, value)
        return value

    def _fill(self, phi: Node, var: Var, block: int) -> None:
        phi.args = [self.read(var, p) for p in self.preds[block]]

    def seal(self, block: int) -> None:
        self.sealed.add(block)
        for var, phi in self.incomplete.pop(block, {}).items():
            self._fill(phi, var, block)

    # -- helpers used by opcode semantics ----------------------------------------------------------

    def reg(self, r: int, b: int, lazy_ok: bool = False) -> Node:
        if r in self.cells:
            if r in self.cell_pending:
                return self.cell_pending[r]
            return self.g.pure(
                "cellread", (self.cells[r], self.reg_desc[r]), self.read(MEM, b), ty=self.reg_desc[r]
            )
        node = self.g.find(self.read(r, b))
        if node.id in self.pending and not lazy_ok:
            return self.materialise(node, b)
        return node

    # -- objects that nothing has seen yet -------------------------------------------------------
    #
    # An allocation followed by stores into it is one value until something else uses it: when
    # the compiler allocates it, and in what order it fills it in, does not matter. So it is held
    # back (as a `lazy` node) and only emitted, as an allocation plus its stores, at its first use.
    # One that is never used again is dropped.

    def lazy(self, kind: str, attrs: Tuple[object, ...], ty: str) -> Node:
        node = self.g.effect("lazy", attrs, nonnull=True, ty=ty)
        self.pending[node.id] = _Pending(kind)
        return node

    def materialise(self, lazy: Node, b: int) -> Node:
        info = self.pending.pop(lazy.id)
        fields = dict(info.fields)
        if self.ignore_positions and _is_dynamic_pos_infos(fields):
            # `trace` builds its position as a dynamic object: where in the source it was written is
            # not behaviour, exactly as for a structured `haxe.PosInfos`.
            marker = self.g.pure("position", ())
            for key in (("dyn", "fileName"), ("dyn", "lineNumber")):
                fields[key] = marker
        real = self.effect(b, info.kind, lazy.attrs, nonnull=True, ty=lazy.ty)
        self.g.alias(lazy, real)
        self.facts.add(real.id)
        for (how, key), value in sorted(fields.items(), key=lambda kv: (kv[0][0], str(kv[0][1]))):
            attrs: Tuple[object, ...] = (key,) if how == "enum" or how == "dyn" else (key, lazy.ty)
            effect = {"enum": "SetEnumField", "dyn": "DynSet", "field": "SetField"}[how]
            self.effect(b, effect, attrs, real, value)
        return real

    def flush(self, b: int) -> None:
        """At the end of a block, emit the held-back objects and cell writes a later block can still see."""
        leaves = self.lifted.blocks[b].term.kind in ("ret", "throw", "rethrow")
        for r in sorted(self.cell_pending):
            # A reference to a register cannot outlive the function (it points into the stack), so a
            # value left in one as the function returns is never seen.
            if not leaves and (r in self.live_out[b] or self.cells[r] in self.ref_reach[b]):
                self.flush_cell(r, b)
        self.cell_pending.clear()
        live = self.live_out[b] | set(self.lifted.blocks[b].term.regs)
        for node_id in list(self.pending):
            node = self.g.nodes[node_id]
            holders = [r for r, v in self.cur[b].items() if isinstance(r, int) and self.g.find(v) is node]
            if any(r in live for r in holders):
                self.materialise(node, b)
            else:
                del self.pending[node_id]

    def put(self, r: int, b: int, node: Node) -> None:
        if r in self.cells:
            node = self.g.find(node)
            if node.id in self.pending:
                node = self.materialise(node, b)
            self.cell_pending[r] = node  # held back: only a reference to the cell can observe it
        else:
            enclosing = [t for t in self.enclosing.get(b, ()) if r in self.trap_writes[t]]
            if enclosing and self.g.find(node).id in self.pending:
                node = self.materialise(self.g.find(node), b)
            self.write(r, b, node)
            for trap_id in enclosing:
                self.trap_writes[trap_id][r].append((self.read(MEM, b), node))

    def effect(
        self, b: int, kind: str, attrs: Tuple[object, ...], *args: Node, nonnull: bool = False, ty: str = ""
    ) -> Node:
        if self.cell_pending and kind != "cellwrite":
            for arg in args:
                found = self.g.find(arg)
                if found.kind == "ref":
                    self.flush_cell(self.cell_reg[cast(int, found.attrs[0])], b)
        for trap_id in self.enclosing.get(b, ()):
            self.trap_mems[trap_id].append(self.read(MEM, b))  # an exception here is raised with this history
        node = self.g.effect(kind, attrs, self.read(MEM, b), *args, nonnull=nonnull, ty=ty)
        self.write(MEM, b, node)
        return node

    def flush_cell(self, r: int, b: int) -> None:
        pending = self.cell_pending.pop(r, None)
        if pending is not None:
            self.effect(b, "cellwrite", (self.cells[r],), pending)

    def known_nonnull(self, node: Node) -> bool:
        node = self.g.find(node)
        return node.nonnull or node.id in self.facts

    def guard(self, b: int, node: Node) -> None:
        if not self.strict or self.known_nonnull(node):
            return
        self.effect(b, "nullcheck", (), node)
        self.facts.add(self.g.find(node).id)

    def const_int(self, node: Node) -> Optional[int]:
        node = self.g.find(node)
        if node.kind == "int":
            value = node.attrs[1]
            return value if isinstance(value, int) else None
        return None

    def arith(self, name: str, kind: int, desc: str, a: Node, b: Node) -> Node:
        ca, cb = self.const_int(a), self.const_int(b)
        width = WIDTH.get(kind)
        if width is not None:
            linear = self.linear_arith(name, desc, width, a, b, ca, cb)
            if linear is not None:
                return linear
            if ca is not None and cb is not None:
                folded = self._fold(name, ca, cb, width)
                if folded is not None:
                    return self.g.pure("int", (desc, folded), ty=desc)
            zero_right = {"Add", "Sub", "Or", "Xor", "Shl", "SShr", "UShr"}
            if cb == 0 and name in zero_right:
                return a
            if ca == 0 and name in {"Add", "Or", "Xor"}:
                return b
            if cb == 1 and name == "Mul":
                return a
            if ca == 1 and name == "Mul":
                return b
        elif kind in INT_KINDS:
            if cb == 0 and name in {"Add", "Sub", "Or", "Xor"}:
                return a
        elif kind in FLOAT_KINDS:
            folded = self.fold_float(name, kind, desc, a, b)
            if folded is not None:
                return folded
        return self.g.pure(name, (desc,), a, b, ty=desc)

    def convert_const(
        self, name: str, src: Node, src_kind: int, dst_kind: int, dst_desc: str
    ) -> Optional[Node]:
        """Numeric conversions of constants."""
        if name in ("ToSFloat", "ToUFloat") and dst_kind in FLOAT_KINDS:
            value = self.const_int(src)
            if value is None:
                return None
            if name == "ToUFloat":
                value &= (1 << WIDTH.get(src_kind, 32)) - 1
            number = float(value)
            if dst_kind == 5:
                number = struct.unpack("f", struct.pack("f", number))[0]
            return self.g.pure("float", (dst_desc, repr(number)), ty=dst_desc)
        if name == "ToInt" and src_kind in FLOAT_KINDS and dst_kind in WIDTH:
            number = self.const_float(src)
            if number is not None and abs(number) < 2**31 and number == number:
                return self.g.pure("int", (dst_desc, int(number)), ty=dst_desc)
        return None

    def const_float(self, node: Node) -> Optional[float]:
        node = self.g.find(node)
        if node.kind == "float":
            return float(str(node.attrs[1]))
        return None

    def fold_float(self, name: str, kind: int, desc: str, a: Node, b: Optional[Node]) -> Optional[Node]:
        """Arithmetic on float constants, computed as the machine would (IEEE double, or single)."""
        x = self.const_float(a)
        y = self.const_float(b) if b is not None else None
        if x is None or (b is not None and y is None):
            return None
        try:
            if name == "Neg":
                value = -x
            elif y is None:
                return None
            elif name == "Add":
                value = x + y
            elif name == "Sub":
                value = x - y
            elif name == "Mul":
                value = x * y
            elif name == "SDiv":
                value = x / y
            else:
                return None
        except (ZeroDivisionError, OverflowError):
            return None
        if kind == 5:  # single precision rounds after every operation
            value = struct.unpack("f", struct.pack("f", value))[0]
        return self.g.pure("float", (desc, repr(float(value))), ty=desc)

    def _lin(self, node: Node, width: int) -> Tuple[int, Dict[int, int], Dict[int, Node]]:
        """`node` as constant + sum of coefficient * atom, in wrapping integer arithmetic."""
        node = self.g.find(node)
        const = self.const_int(node)
        if const is not None:
            return const, {}, {}
        if node.kind == "lin":
            base, coeffs = node.attrs[1], node.attrs[2]
            assert isinstance(base, int) and isinstance(coeffs, tuple)
            atoms = [self.g.find(x) for x in node.args]
            return base, {x.id: cast(int, c) for x, c in zip(atoms, coeffs)}, {x.id: x for x in atoms}
        return 0, {node.id: 1}, {node.id: node}

    def linear_arith(
        self, name: str, desc: str, width: int, a: Node, b: Node, ca: Optional[int], cb: Optional[int]
    ) -> Optional[Node]:
        """Add, Sub and multiplication or shift by a constant keep a value in the form
        `c + k1*x1 + k2*x2 ...`, so that `(x + 1 + 1) - (x + 1)` and `1` are the same value."""
        if name not in ("Add", "Sub", "Mul", "Shl"):
            return None
        if name == "Mul" and ca is None and cb is None:
            return None
        if name == "Shl" and not (cb is not None and 0 <= cb < width):
            return None
        const_a, coeffs_a, atoms_a = self._lin(a, width)
        const_b, coeffs_b, atoms_b = self._lin(b, width)
        if name == "Mul":
            scale, (const, coeffs, atoms) = (
                (ca, (const_b, coeffs_b, atoms_b)) if ca is not None else (cb, (const_a, coeffs_a, atoms_a))
            )
            assert scale is not None
            const, coeffs, atoms = const * scale, {k: v * scale for k, v in coeffs.items()}, dict(atoms)
        elif name == "Shl":
            assert cb is not None
            scale = 1 << cb
            const, coeffs, atoms = const_a * scale, {k: v * scale for k, v in coeffs_a.items()}, dict(atoms_a)
        else:
            sign = 1 if name == "Add" else -1
            const = const_a + sign * const_b
            coeffs = dict(coeffs_a)
            atoms = dict(atoms_a)
            for key, value in coeffs_b.items():
                coeffs[key] = coeffs.get(key, 0) + sign * value
                atoms[key] = atoms_b[key]
        const = _wrap(const, width)
        coeffs = {k: _wrap(v, width) for k, v in coeffs.items()}
        coeffs = {k: v for k, v in coeffs.items() if v != 0}
        if not coeffs:
            return self.g.pure("int", (desc, const), ty=desc)
        ordered = sorted(coeffs)
        if len(ordered) == 1 and const == 0 and coeffs[ordered[0]] == 1:
            return atoms[ordered[0]]
        return self.g.pure(
            "lin", (desc, const, tuple(coeffs[k] for k in ordered)), *(atoms[k] for k in ordered), ty=desc
        )

    @staticmethod
    def _fold(name: str, a: int, b: int, width: int) -> Optional[int]:
        if name == "Add":
            return _wrap(a + b, width)
        if name == "Sub":
            return _wrap(a - b, width)
        if name == "Mul":
            return _wrap(a * b, width)
        if name == "And":
            return _wrap(a & b, width)
        if name == "Or":
            return _wrap(a | b, width)
        if name == "Xor":
            return _wrap(a ^ b, width)
        if name in ("SDiv", "SMod", "UDiv", "UMod"):
            # HashLink defines division by zero (and the overflowing -1 case): the result is 0 / a * b
            if name in ("UDiv", "UMod"):
                x, y = a & ((1 << width) - 1), b & ((1 << width) - 1)
                if y == 0:
                    return 0
                return _wrap(x // y if name == "UDiv" else x % y, width)
            if b == 0:
                return 0
            if b == -1:
                return _wrap(a * b, width) if name == "SDiv" else 0
            quotient = abs(a) // abs(b) * (1 if (a < 0) == (b < 0) else -1)
            return _wrap(quotient if name == "SDiv" else a - quotient * b, width)
        if 0 <= b < width:
            if name == "Shl":
                return _wrap(a << b, width)
            if name == "SShr":
                return _wrap(a >> b, width)
            if name == "UShr":
                return _wrap((a & ((1 << width) - 1)) >> b, width)
        return None

    def _boxed_int(self, node: Node) -> Optional[Node]:
        """The int inside a value boxed from an I32 register."""
        found = self.g.find(node)
        if found.kind == "ToDyn" and found.attrs[0] == "I32":
            return found.args[0]
        return None

    def _text_of(self, text: Node, length: Node, desc: str) -> Optional[Node]:
        """`String.__alloc__(itos(n), len)`: the decimal text of `n`."""
        raw, size = self.g.find(text), self.g.find(length)
        if (
            raw.kind in ("itos", "ftos")
            and size.kind == raw.kind + "len"
            and self.g.find(raw.args[0]) is self.g.find(size.args[0])
        ):
            return self.to_text(raw.args[0], "int" if raw.kind == "itos" else "float", desc)
        return None

    def to_text(self, number: Node, kind: str, desc: str) -> Node:
        value = self.const_int(number) if kind == "int" else None
        if value is not None:
            return self.g.pure("str", (str(value),), nonnull=True, ty=desc)
        return self.g.pure("tostring", (kind,), number, nonnull=True, ty=desc)

    def concat(self, a: Node, b: Node, desc: str) -> Node:
        """`String.__add__` is a pure function that prints null as "null", so a chain of them is
        the concatenation of its parts and empty parts vanish (unless that would leave a bare
        operand, which still has to be turned into a string)."""
        parts: List[Node] = []
        for operand in (a, b):
            operand = self.g.find(operand)
            if operand.kind == "concat":
                parts.extend(operand.args)
            else:
                parts.append(operand)
        merged: List[Node] = []
        for part in parts:
            if merged and merged[-1].kind == "str" and part.kind == "str":
                joined = str(merged[-1].attrs[0]) + str(part.attrs[0])
                merged[-1] = self.g.pure("str", (joined,), nonnull=True, ty=desc)
            else:
                merged.append(part)
        kept = [p for p in merged if not (p.kind == "str" and p.attrs[0] == "")]
        if len(kept) == 0:
            return self.g.pure("str", ("",), nonnull=True, ty=desc)
        if len(kept) == 1:
            only = kept[0]
            if only.nonnull and only.ty == desc:
                return only
            return self.g.pure("concat", (), only, ty=desc)
        return self.g.pure("concat", (), *kept, ty=desc, nonnull=True)

    # -- one opcode ------------------------------------------------------------------------------

    def run_op(self, op, b: int) -> None:  # noqa: C901 - one case per opcode family
        g = self.g
        name = op.op
        df = op.df
        code = self.code
        regs = self.func.regs

        def R(field: str) -> Node:
            return self.reg(df[field].value, b)

        def dst_desc() -> str:
            return self.reg_desc[df["dst"].value]

        def set_dst(node: Node) -> None:
            self.put(df["dst"].value, b, node)

        def type_of(reg: int) -> Type:
            return regs[reg].resolve(code)

        if name == "Mov":
            set_dst(self.reg(df["src"].value, b, lazy_ok=True))
        elif name == "Int":
            value = _normal_int(df["ptr"].resolve(code).value, self.reg_kind[df["dst"].value])
            set_dst(g.pure("int", (dst_desc(), value), ty=dst_desc()))
        elif name == "Bool":
            set_dst(g.pure("int", (dst_desc(), int(df["value"].value)), ty=dst_desc()))
        elif name == "Float":
            value = df["ptr"].resolve(code).value
            set_dst(g.pure("float", (dst_desc(), repr(float(value))), ty=dst_desc()))
        elif name == "String":
            set_dst(g.pure("str", (df["ptr"].resolve(code),), nonnull=True, ty=dst_desc()))
        elif name == "Bytes":
            set_dst(g.pure("bytes", (df["ptr"].resolve(code),), nonnull=True, ty=dst_desc()))
        elif name == "Null":
            set_dst(g.pure("null", ()))
        elif name in ARITH:
            dst = df["dst"].value
            set_dst(self.arith(name, self.reg_kind[dst], self.reg_desc[dst], R("a"), R("b")))
        elif name in ("Incr", "Decr"):
            dst = df["dst"].value
            kind, desc = self.reg_kind[dst], self.reg_desc[dst]
            one = g.pure("int", (desc, 1), ty=desc)
            self.put(
                dst, b, self.arith("Add" if name == "Incr" else "Sub", kind, desc, self.reg(dst, b), one)
            )
        elif name == "Neg":
            dst = df["dst"].value
            kind, desc = self.reg_kind[dst], self.reg_desc[dst]
            src = R("src")
            if kind in WIDTH:
                set_dst(self.arith("Sub", kind, desc, g.pure("int", (desc, 0), ty=desc), src))
            else:
                folded = self.fold_float("Neg", kind, desc, src, None)
                set_dst(folded if folded is not None else g.pure("Neg", (desc,), src, ty=desc))
        elif name == "Not":
            src = R("src")
            src_f = g.find(src)
            if src_f.kind == "Not" and self.reg_kind[df["dst"].value] == 7:
                set_dst(src_f.args[0])
            else:
                set_dst(g.pure("Not", (), src, ty=dst_desc()))
        elif name in ("ToDyn", "ToSFloat", "ToUFloat", "ToInt", "ToVirtual"):
            src_reg = df["src"].value
            # Boxing gives the same dynamic value whether it is then typed Dyn or Null<T>.
            attrs = (self.reg_desc[src_reg],) if name == "ToDyn" else (self.reg_desc[src_reg], dst_desc())
            src_node = R("src")
            converted = self.convert_const(
                name, src_node, self.reg_kind[src_reg], self.reg_kind[df["dst"].value], dst_desc()
            )
            boxes_value = name == "ToDyn" and self.reg_kind[src_reg] in (1, 2, 3, 4, 5, 6, 7)
            set_dst(
                converted
                if converted is not None
                else g.pure(name, attrs, src_node, nonnull=boxes_value, ty=dst_desc())
            )
        elif name in ("SafeCast", "UnsafeCast"):
            src_reg = df["src"].value
            src, sdesc, ddesc = R("src"), self.reg_desc[src_reg], dst_desc()
            inner = g.find(src)
            if sdesc == ddesc:
                set_dst(src)
            elif inner.kind == "ToDyn" and inner.attrs[0] == ddesc:
                set_dst(inner.args[0])  # boxed and unboxed again
            elif name == "UnsafeCast" or not self.strict:
                set_dst(g.pure("cast", (name, sdesc, ddesc), src, ty=ddesc))
            else:
                set_dst(self.effect(b, "safecast", (sdesc, ddesc), src, ty=ddesc))
        elif name == "Type":
            set_dst(g.pure("type", (self.namer.type_index(df["ty"].value),), nonnull=True, ty=dst_desc()))
        elif name in ("GetType", "GetTID"):
            set_dst(g.pure(name, (), R("src"), ty=dst_desc()))
        elif name == "GetGlobal":
            ref = self.namer.global_(df["global"].value)
            if ref[0] == "str":
                set_dst(g.pure("str", (ref[1],), nonnull=True, ty=dst_desc()))
            elif self.has_setglobal:
                set_dst(g.pure("global", ref, self.read(MEM, b), ty=dst_desc()))
            else:
                set_dst(g.pure("global", ref, nonnull=True, ty=dst_desc()))
        elif name == "SetGlobal":
            self.effect(b, "SetGlobal", self.namer.global_(df["global"].value), R("src"))
        elif name in ("Field", "GetThis"):
            obj_reg = df["obj"].value if name == "Field" else 0
            obj = self.reg(obj_reg, b)
            self.guard(b, obj)
            fname = self.namer.field(type_of(obj_reg), df["field"].value)
            known = g.find(obj)
            if known.kind == "str" and fname == "length" and self.reg_desc[obj_reg] == "obj:String":
                # the length of a constant string, in UTF-16 units as HashLink counts them
                text = str(known.attrs[0])
                set_dst(
                    g.pure(
                        "int",
                        (dst_desc(), len(text.encode("utf-16-le", "surrogatepass")) // 2),
                        ty=dst_desc(),
                    )
                )
                return
            set_dst(
                g.pure(
                    "load",
                    ("Field", fname, self.reg_desc[obj_reg], dst_desc()),
                    obj,
                    self.read(MEM, b),
                    ty=dst_desc(),
                )
            )
        elif name in ("SetField", "SetThis"):
            obj_reg = df["obj"].value if name == "SetField" else 0
            obj = self.reg(obj_reg, b, lazy_ok=True)
            if obj.id not in self.pending:
                self.guard(b, obj)
            fname = self.namer.field(type_of(obj_reg), df["field"].value)
            value = R("src")
            if (
                self.ignore_positions
                and fname in ("fileName", "lineNumber")
                and _is_pos_infos(self.reg_desc[obj_reg])
            ):
                value = g.pure("position", ())  # where in the source it was written is not behaviour
            if obj.id in self.pending:
                self.pending[obj.id].fields[("field", fname)] = value
            else:
                self.effect(b, "SetField", (fname, self.reg_desc[obj_reg]), obj, value)
        elif name == "DynGet":
            obj = R("obj")
            self.guard(b, obj)
            set_dst(
                g.pure(
                    "load",
                    ("DynGet", df["field"].resolve(code), dst_desc()),
                    obj,
                    self.read(MEM, b),
                    ty=dst_desc(),
                )
            )
        elif name == "DynSet":
            obj = self.reg(df["obj"].value, b, lazy_ok=True)
            if obj.id in self.pending:
                self.pending[obj.id].fields[("dyn", df["field"].resolve(code))] = R("src")
            else:
                self.guard(b, obj)
                self.effect(b, "DynSet", (df["field"].resolve(code),), obj, R("src"))
        elif name in ("EnumField", "EnumIndex"):
            value = R("value")
            self.guard(b, value)
            attrs: Tuple[object, ...] = (name, dst_desc())
            if name == "EnumField":
                attrs += (self._construct(df["value"].value, df["construct"].value), df["field"].value)
            set_dst(g.pure("load", attrs, value, self.read(MEM, b), ty=dst_desc()))
        elif name == "SetEnumField":
            value = self.reg(df["value"].value, b, lazy_ok=True)
            if value.id in self.pending:
                self.pending[value.id].fields[("enum", df["field"].value)] = R("src")
            else:
                self.guard(b, value)
                self.effect(b, "SetEnumField", (df["field"].value,), value, R("src"))
        elif name in ("GetArray", "GetI8", "GetI16", "GetMem"):
            base = R("array") if name == "GetArray" else R("bytes")
            self.guard(b, base)
            set_dst(g.pure("load", (name, dst_desc()), base, R("index"), self.read(MEM, b), ty=dst_desc()))
        elif name in ("SetArray", "SetI8", "SetI16", "SetMem"):
            base = R("array") if name == "SetArray" else R("bytes")
            self.guard(b, base)
            self.effect(b, name, (), base, R("index"), R("src"))
        elif name == "ArraySize":
            array = R("array")
            self.guard(b, array)
            set_dst(g.pure("load", ("ArraySize", dst_desc()), array, self.read(MEM, b), ty=dst_desc()))
        elif name == "Ref":
            set_dst(g.pure("ref", (self.cells[df["src"].value],), nonnull=True, ty=dst_desc()))
        elif name == "Unref":
            ref = R("src")
            self.guard(b, ref)
            if g.find(ref).kind == "ref":
                self.flush_cell(self.cell_reg[cast(int, g.find(ref).attrs[0])], b)
            set_dst(g.pure("load", ("Unref", dst_desc()), ref, self.read(MEM, b), ty=dst_desc()))
        elif name == "Setref":
            ref = R("dst")
            self.guard(b, ref)
            self.effect(b, "Setref", (), ref, R("value"))
        elif name == "New":
            set_dst(self.lazy("new", (dst_desc(),), dst_desc()))
        elif name == "EnumAlloc":
            construct = self._construct(df["dst"].value, df["construct"].value)
            set_dst(self.lazy("enumalloc", (construct,), dst_desc()))
        elif name == "MakeEnum":
            construct = self._construct(df["dst"].value, df["construct"].value)
            args = [self.reg(r.value, b) for r in df["args"].value]
            set_dst(self.effect(b, "makeenum", (construct,), *args, nonnull=True, ty=dst_desc()))
        elif name in ("Call0", "Call1", "Call2", "Call3", "Call4", "CallN"):
            args = self._call_args(df, b)
            callee = self.namer.function(df["fun"].value)
            out = self.g.find(args[1]) if len(args) == 2 else None
            if callee in OUT_ONLY and out is not None and out.kind == "ref":
                # The number-to-text natives only write through the reference (the length of the text
                # they produced) and have no other effect, so the text and its length are values of the
                # number: the pair `itos` + `String.__alloc__` is one pure conversion.
                cell = self.cell_reg[cast(int, out.attrs[0])]
                shape = "itos" if callee[1] == "std.itos" else "ftos"
                number = args[0]
                self.cell_pending[cell] = self.g.pure(shape + "len", (), number, ty=self.reg_desc[cell])
                set_dst(self.g.pure(shape, (), number, nonnull=True, ty=dst_desc()))
            elif (
                callee == ("fn", "$String.__alloc__")
                and len(args) == 2
                and (text := self._text_of(args[0], args[1], dst_desc())) is not None
            ):
                set_dst(text)
            elif (
                callee == ("fn", "$Std.string")
                and len(args) == 1
                and (boxed := self._boxed_int(args[0])) is not None
            ):
                set_dst(self.to_text(boxed, "int", dst_desc()))
            elif callee == ("fn", "$String.__add__") and len(args) == 2:
                set_dst(self.concat(args[0], args[1], dst_desc()))
            else:
                set_dst(self.effect(b, "call", (callee,), *args, ty=dst_desc()))
        elif name in ("CallMethod", "CallThis"):
            args = self._call_args(df, b)
            if name == "CallThis":
                args = [self.reg(0, b)] + args
            obj_reg = df["args"].value[0].value if name == "CallMethod" else 0
            self.guard(b, args[0])
            direct = self.namer.devirtualise(type_of(obj_reg), df["field"].value)
            if direct is not None:
                set_dst(self.effect(b, "call", (direct,), *args, ty=dst_desc()))
            else:
                method = self.namer.method(type_of(obj_reg), df["field"].value)
                set_dst(self.effect(b, "callmethod", (method, self.reg_desc[obj_reg]), *args, ty=dst_desc()))
        elif name == "CallClosure":
            fun = R("fun")
            args = [self.reg(r.value, b) for r in df["args"].value]
            known = g.find(fun)
            if known.kind == "sclosure":  # calling a closure over a known function is calling it
                set_dst(self.effect(b, "call", (known.attrs[0],), *args, ty=dst_desc()))
            elif known.kind == "iclosure":
                set_dst(self.effect(b, "call", (known.attrs[0],), known.args[0], *args, ty=dst_desc()))
            else:
                self.guard(b, fun)
                set_dst(self.effect(b, "callclosure", (), fun, *args, ty=dst_desc()))
        elif name == "StaticClosure":
            set_dst(g.pure("sclosure", (self.namer.function(df["fun"].value),), nonnull=True, ty=dst_desc()))
        elif name == "InstanceClosure":
            set_dst(
                g.pure(
                    "iclosure", (self.namer.function(df["fun"].value),), R("obj"), nonnull=True, ty=dst_desc()
                )
            )
        elif name == "VirtualClosure":
            obj_reg = df["obj"].value
            obj = R("obj")
            self.guard(b, obj)
            method = self.namer.method(type_of(obj_reg), df["field"].value)
            set_dst(g.pure("vclosure", (method, self.reg_desc[obj_reg]), obj, nonnull=True, ty=dst_desc()))
        elif name == "NullCheck":
            self.guard(b, R("reg"))
        elif name == "Assert":
            self.effect(b, "assert", ())
        elif name in ("Throw", "Rethrow", "Ret", "Trap", "EndTrap", "Switch"):
            raise Unsupported(f"terminator {name} inside a block")
        else:
            raise Unsupported(f"opcode {name}")

    def _call_args(self, df, b: int) -> List[Node]:
        if "args" in df:
            return [self.reg(r.value, b) for r in df["args"].value]
        return [self.reg(df[f"arg{i}"].value, b) for i in range(5) if f"arg{i}" in df]

    def _construct(self, enum_reg: int, construct: int) -> Tuple[str, str]:
        enum_type = self.func.regs[enum_reg].resolve(self.code).definition
        if isinstance(enum_type, Enum):
            return (
                self.namer.type(self.func.regs[enum_reg].resolve(self.code)),
                enum_type.constructs[construct].name.resolve(self.code),
            )
        self.namer.unstable = True
        return ("?", str(construct))

    def _handler_state(self, trap_id: int) -> Dict[Var, Node]:
        """What the handler of a trap sees on entry: the exception, a history that is one of those
        the protected region can have when something is raised, and for each register the region
        writes that the handler reads, the value last written before that point."""
        info = self.lifted.traps[trap_id]
        if not info.region <= self.processed:
            raise Unsupported("a catch handler that runs before its protected block")
        g = self.g
        exc_reg = self.lifted.blocks[trap_id].term.regs[0]
        state: Dict[Var, Node] = {exc_reg: g.pure("exc", (trap_id,), nonnull=True, ty=self.reg_desc[exc_reg])}
        mems = list({g.find(m).id: g.find(m) for m in self.trap_mems[trap_id]}.values())
        state[MEM] = g.pure("catchmem", (trap_id,), *mems) if mems else g.pure("excmem", (trap_id,))
        for r in sorted(info.needed):
            pairs: List[Node] = []
            for mem, value in [(self.read(MEM, trap_id), self.read(r, trap_id))] + self.trap_writes[trap_id][
                r
            ]:
                pairs.extend((mem, value))
            state[r] = g.pure("catchval", (self.reg_desc[r],), *pairs, ty=self.reg_desc[r])
        return state

    # -- driving ----------------------------------------------------------------------------------

    def process(self, b: int) -> None:
        block: Block = self.lifted.blocks[b]
        if b in self.handler_of:
            self.overrides[b] = self._handler_state(self.handler_of[b])
        self.cur[b] = dict(self.overrides.get(b, {}))
        # A value that was non-null at the end of every predecessor already processed is non-null
        # here; the ones not processed yet are back edges, which only add to what the loop entry knew.
        known = [self.facts_out[p] for p in self.preds[b] if p in self.facts_out]
        self.facts = set.intersection(*known) if known else set()
        self.cell_pending = {}
        if b == 0:
            start = self.cur[START]
            for r in sorted(self.cells, key=lambda reg: self.cells[reg]):
                if r in start:
                    self.cell_pending[r] = start[r]
        for op in block.ops:
            self.run_op(op, b)
        term = block.term
        nodes: List[Node] = []
        if term.kind in ("ret", "throw", "rethrow"):
            reg = term.regs[0]
            if term.kind != "ret" or self.reg_kind[reg] != VOID_KIND:
                nodes.append(self.reg(reg, b))
        elif term.kind == "cond":
            nodes.extend(self.reg(r, b) for r in term.regs)
        elif term.kind == "switch":
            nodes.append(self.reg(term.regs[0], b))
        self.flush(b)
        self.exit_mem[b] = self.read(MEM, b)
        if term.kind in ("throw", "rethrow"):
            for trap_id in self.enclosing.get(b, ()):
                self.trap_mems[trap_id].append(self.read(MEM, b))
        self.processed.add(b)
        self.term_nodes[b] = nodes
        self.facts_out[b] = set(self.facts)
        for s in dict.fromkeys(term.succs):
            self.unprocessed_preds[s] -= 1
            if self.unprocessed_preds[s] == 0:
                self.seal(s)


def rpo(lifted: Lifted) -> List[int]:
    n = len(lifted.blocks)
    seen: Set[int] = set()
    post: List[int] = []
    stack: List[Tuple[int, int]] = [(0, 0)]
    seen.add(0)
    while stack:
        node, i = stack.pop()
        succs = lifted.blocks[node].term.succs
        if i < len(succs):
            stack.append((node, i + 1))
            s = succs[i]
            if s not in seen:
                seen.add(s)
                stack.append((s, 0))
        else:
            post.append(node)
    assert len(seen) <= n
    return post[::-1]


def processing_order(lifted: Lifted, order: List[int]) -> List[int]:
    """Blocks in an order where every block follows the predecessors that do not reach it by a back
    edge, and a catch handler follows every block of the region it protects."""
    position = {b: i for i, b in enumerate(order)}
    edges: Dict[int, Set[int]] = {b: set() for b in order}
    for b in order:
        for s in lifted.blocks[b].term.succs:
            if position[s] > position[b]:  # forward edges only
                edges[b].add(s)
    for trap_id, info in lifted.traps.items():
        handler = lifted.blocks[trap_id].term.succs[1]
        for member in info.region:
            if member != handler:
                edges[member].add(handler)
    indegree = {b: 0 for b in order}
    for b in order:
        for s in edges[b]:
            indegree[s] += 1
    ready = sorted((b for b in order if indegree[b] == 0), key=lambda x: position[x])
    result: List[int] = []
    while ready:
        b = ready.pop(0)
        result.append(b)
        for s in sorted(edges[b], key=lambda x: position[x]):  # type: ignore[arg-type]
            indegree[s] -= 1
            if indegree[s] == 0:
                ready.append(s)
                ready.sort(key=lambda x: position[x])
    if len(result) != len(order):
        raise Unsupported("a catch handler entangled with the block it protects")
    return result


def check_reducible(lifted: Lifted, order: List[int]) -> None:
    """Every edge that goes back in reverse post-order must lead to a block that dominates its
    source. The facts carried into a loop header (what is known non-null) are only valid then."""
    position = {b: i for i, b in enumerate(order)}
    idom: Dict[int, int] = {order[0]: order[0]}

    def intersect(a: int, b: int) -> int:
        while a != b:
            while position[a] > position[b]:
                a = idom[a]
            while position[b] > position[a]:
                b = idom[b]
        return a

    changed = True
    while changed:
        changed = False
        for b in order[1:]:
            done = [p for p in lifted.preds[b] if p in idom]
            if not done:
                continue
            new = done[0]
            for p in done[1:]:
                new = intersect(p, new)
            if idom.get(b) != new:
                idom[b] = new
                changed = True
    for b in order:
        for s in lifted.blocks[b].term.succs:
            if position[s] <= position[b]:
                walk = b
                while walk != s and walk != idom[walk]:
                    walk = idom[walk]
                if walk != s:
                    raise Unsupported("irreducible control flow")


def build(
    code: Bytecode, func: Function, lifted: Lifted, namer: Namer, strict: bool, ignore_positions: bool = True
) -> Built:
    old = sys.getrecursionlimit()
    sys.setrecursionlimit(max(old, 20000))
    try:
        builder = Builder(code, func, lifted, namer, strict, ignore_positions)
        g = builder.g
        # Entry state: parameters, then the memory chain.
        start = builder.cur[START]
        signature = func.type.resolve(code).definition
        nparams = len(signature.args) if isinstance(signature, Fun) else 0
        for i in range(nparams):
            start[i] = g.pure("param", (i, builder.reg_desc[i]), ty=builder.reg_desc[i])
        start[MEM] = g.pure("entrymem", ())
        builder.unprocessed_preds[0] -= 1  # the virtual start edge
        builder.facts_out[START] = set()
        if builder.unprocessed_preds[0] == 0:
            builder.seal(0)
        order = rpo(lifted)
        check_reducible(lifted, order)
        for b in processing_order(lifted, order):
            builder.process(b)
        g.simplify_phis()
        built = Built(g, lifted)
        built.exit_mem = [m for m in builder.exit_mem if m is not None]
        built.term_nodes = builder.term_nodes
        built.unstable = namer.unstable
        return built
    except RecursionError as exc:
        raise Unsupported("function too deeply nested") from exc
    finally:
        sys.setrecursionlimit(old)
