"""
Recovery of the interface a structurally typed value was declared as.

HL gives an interface's values the virtual type of its members, and the image keeps one copy
of each virtual: `interface A {}`, `interface B {}` and the anonymous `{}` are one type, so a
register's type alone can't name the interface. A conversion can. Every class keeps one
unnamed field per interface it implements, where a conversion of an instance to that
interface caches the wrapper it builds:

    JNotNull x; Null t; JAlways; Field t = x.<cache>; JNotNull t; ToVirtual t = x; SetField x.<cache> = t

A conversion to a structure (or anything not one of the class's interfaces) is a bare
`ToVirtual`, so source has to name the interface for the recompile to cache it again.

The cache slot names the interface the value was converted to. That name is carried along
where the value flows: moves, the parameters of the functions it's passed to, the fields it's
stored into and the returns it leaves by. A location is named only when everything stored
into it has that one name (a `null` aside): a value of another type there wouldn't convert
to the interface. Functions something else can stand in for (methods that are overridden,
satisfy a structure's member or are taken as closures) keep their declared signatures.
"""

import threading
import weakref
from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple, Union

from . import abstracts, typeinit
from .core import Bytecode, Function, Obj, Opcode, Reg, Regs, Virtual, is_static_name

Node = Tuple

# A location's sources: another location, the interface a cache slot names, or None for a
# value of unknown origin.
_Source = Union[Node, typeinit.Interface, None]


@dataclass
class _Result:
    #: Every location something is stored into: its interface, or None when it has none.
    named: Dict[Node, Optional[typeinit.Interface]]
    #: The functions with registers split into webs, by findex.
    webs: Dict[int, "_Webs"]
    #: Parameter counts, by findex.
    nargs: Dict[int, int]


_cache: Dict[int, Tuple["weakref.ReferenceType[Bytecode]", _Result]] = {}
_lock = threading.Lock()

_DST_READ = frozenset({"Setref", "Incr", "Decr"})


def _reads(op: Opcode) -> List[int]:
    regs: List[int] = []
    if op.op == "EndTrap":
        return regs
    for key, operand in op.df.items():
        if key == "dst" and op.op not in _DST_READ:
            continue
        if isinstance(operand, Reg):
            regs.append(operand.value)
        elif isinstance(operand, Regs):
            regs.extend(r.value for r in operand.value)
    return regs


def _writes(op: Opcode) -> Optional[int]:
    dst = op.df.get("dst")
    return dst.value if isinstance(dst, Reg) and op.op != "Setref" else None


_BRANCHES = frozenset({"Ret", "Throw", "Rethrow", "Switch", "JAlways"})


def _may_carry(ops: List[Opcode], i: int) -> bool:
    """Whether the value op `i` writes may be an interface's: a copy, a read, a call's result or a
    cached conversion."""
    name = ops[i].op or ""
    if name == "ToVirtual":
        return i + 1 < len(ops) and ops[i + 1].op in ("SetField", "SetThis")
    return name in ("Mov", "Field", "GetThis") or name.startswith("Call")


class _Webs:
    """A function's virtual registers, split where the compiler reuses a temporary: the
    definitions reaching a common read are one value (a web). Parameters, debug-named
    variables, registers whose address is taken and ones a try body writes stay whole, as
    the decompiler keeps them one local."""

    def __init__(self, func: Function, virtual: Set[int], nargs: int) -> None:
        self.findex = func.findex.value
        self.ops = func.ops
        ops = self.ops
        self.written = [_writes(op) for op in ops]
        self.writes: Dict[int, List[int]] = {}
        for i, w in enumerate(self.written):
            if w in virtual:
                self.writes.setdefault(w, []).append(i)
        self.split: Set[int] = set()
        self._parent: Dict[int, int] = {}
        self._use: Dict[Tuple[int, int], int] = {}
        candidates = {
            r
            for r, defs in self.writes.items()
            if len(defs) > 1 and r >= nargs and any(_may_carry(ops, d) for d in defs)
        }
        if not candidates:
            return
        whole: Set[int] = set()
        if func.has_debug and func.assigns:
            for assign in func.assigns:
                index = assign[1].value - 1
                named = self.written[index] if 0 <= index < len(ops) else None
                if named is not None:
                    whole.add(named)
        for i, op in enumerate(ops):
            if op.op == "Ref":
                whole.add(op.df["src"].value)
            elif op.op == "Trap":
                # What the try body writes, a throw can leave at any point: those stay whole,
                # so the rest reaches the handler as it was at the `Trap`.
                whole.add(op.df["exc"].value)
                end = min(i + op.df["offset"].value + 1, len(ops))
                whole.update(w for w in self.written[i + 1 : end] if w is not None)
        # Splitting a register only matters where some definition may carry a name.
        self.split = candidates - whole
        if self.split:
            self._solve()

    def _find(self, x: int) -> int:
        parent = self._parent
        parent.setdefault(x, x)
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != root:
            parent[x], x = root, parent[x]
        return root

    def _successors(self, i: int) -> List[int]:
        op = self.ops[i]
        if op.op in ("Ret", "Throw", "Rethrow"):
            return []
        found = [] if op.op == "JAlways" else [i + 1]
        for key, operand in op.df.items():
            if key in ("offset", "end"):
                found.append(i + operand.value + 1)
            elif key == "offsets":
                found.extend(i + offset.value + 1 for offset in operand.value)
        return [succ for succ in found if 0 <= succ < len(self.ops)]

    def _solve(self) -> None:
        """Reaching definitions of the split registers; the ones meeting at a read are joined."""
        ops, split = self.ops, self.split
        ends = {i: self._successors(i) for i, op in enumerate(ops) if op.op in _BRANCHES or "offset" in op.df}
        starts = {0} | {succ for found in ends.values() for succ in found} | {i + 1 for i in ends}
        leaders = sorted(start for start in starts if start < len(ops))
        blocks = {start: (start, end) for start, end in zip(leaders, leaders[1:] + [len(ops)])}
        successors = {
            start: ends[end - 1] if end - 1 in ends else ([end] if end < len(ops) else [])
            for start, (_, end) in blocks.items()
        }
        written = self.written
        gen: Dict[int, Dict[int, FrozenSet[int]]] = {}
        for start, (first, end) in blocks.items():
            # The last write of each register in the block wins.
            gen[start] = {
                w: frozenset((i,)) for i in range(first, end) if (w := written[i]) in split and w is not None
            }
        held: Dict[int, Dict[int, FrozenSet[int]]] = {0: {r: frozenset() for r in split}}
        pending = [0]
        while pending:
            start = pending.pop()
            out = {**held[start], **gen[start]}
            for succ in successors[start]:
                target = held.get(succ)
                if target is None:
                    held[succ] = dict(out)
                    pending.append(succ)
                    continue
                grew = False
                for r, defs in out.items():
                    if not defs <= target[r]:
                        target[r] = target[r] | defs
                        grew = True
                if grew:
                    pending.append(succ)
        for start, state in held.items():
            state = dict(state)
            for i in range(*blocks[start]):
                for r in _reads(ops[i]):
                    if r in split and state[r]:
                        first, *rest = sorted(state[r])
                        for other in rest:
                            a, b = self._find(first), self._find(other)
                            if a != b:
                                self._parent[max(a, b)] = min(a, b)
                        self._use[(i, r)] = first
                w = written[i]
                if w in split:
                    state[w] = frozenset((i,))

    def define(self, i: int) -> Node:
        """The location op `i` writes."""
        reg = self.written[i]
        if reg in self.split:
            return ("w", self.findex, self._find(i))
        return ("r", self.findex, reg)

    def use(self, i: int, reg: int) -> Node:
        """The location op `i` reads `reg` from."""
        if reg not in self.split:
            return ("r", self.findex, reg)
        first = self._use.get((i, reg))
        return ("w", self.findex, self._find(first) if first is not None else -1 - reg)

    def nodes(self, reg: int, defs: Optional[Iterable[int]]) -> Set[Node]:
        """The locations of a local of `reg` written by `defs` (default: all of its writes)."""
        if reg not in self.split:
            return {("r", self.findex, reg)}
        own = self.writes[reg]
        chosen = [d for d in defs if d in own] if defs is not None else []
        return {("w", self.findex, self._find(d)) for d in chosen or own}


def _chain(code: Bytecode, obj: Obj) -> List[Obj]:
    """`obj` and its ancestors, root first."""
    chain: List[Obj] = []
    current: Optional[Obj] = obj
    while current is not None and all(current is not seen for seen in chain):
        chain.append(current)
        if current.super.value < 0:
            break
        parent = current.super.resolve(code).definition
        current = parent if isinstance(parent, Obj) else None
    chain.reverse()
    return chain


def _owner_slot(code: Bytecode, obj: Obj, flat: int) -> Optional[Tuple[Obj, int]]:
    """The class that declares field `flat` of `obj` and the field's index among its own."""
    offset = 0
    for ancestor in _chain(code, obj):
        if flat < offset + len(ancestor.fields):
            return ancestor, flat - offset
        offset += len(ancestor.fields)
    return None


def _cache_slots(code: Bytecode, owner: Obj) -> Dict[int, typeinit.Interface]:
    """The interface each of `owner`'s own cache slots (unnamed virtual fields) holds.

    The compiler keeps one slot per type, so interfaces sharing their members share one: a
    conversion to any of them reads the same. Where they extend one another, the one they all
    extend is what each of them converts to; unrelated ones leave the slot unnamed."""
    implemented = typeinit.implemented(code, owner)
    found: Dict[int, typeinit.Interface] = {}
    for index, field in enumerate(owner.fields):
        virtual = field.type.resolve(code).definition
        if field.name.resolve(code) or not isinstance(virtual, Virtual):
            continue
        matches = [interface for interface in implemented if interface.virtual is virtual]
        widest = [
            interface
            for interface in matches
            if all(other is interface or interface in other.ancestors() for other in matches)
        ]
        if len(widest) == 1:
            found[index] = widest[0]
    return found


def _compute(code: Bytecode) -> _Result:
    if not typeinit.registry(code).interfaces:
        return _Result({}, {}, {})

    virtual_types = {i for i, typ in enumerate(code.types) if isinstance(typ.definition, Virtual)}

    def is_virtual(type_index: int) -> bool:
        return type_index in virtual_types

    slot_cache: Dict[int, Dict[int, typeinit.Interface]] = {}

    def cache_interface(obj_type: int, flat: int) -> Optional[typeinit.Interface]:
        owner = code.types[obj_type].definition
        if not isinstance(owner, Obj):
            return None
        found = _owner_slot(code, owner, flat)
        if found is None:
            return None
        declaring, slot = found
        if id(declaring) not in slot_cache:
            slot_cache[id(declaring)] = _cache_slots(code, declaring)
        return slot_cache[id(declaring)].get(slot)

    # Names a structure's member has: a method of that name has the member's signature.
    member_names: Set[str] = set()
    for typ in code.types:
        if isinstance(typ.definition, Virtual):
            member_names.update(field.name.resolve(code) for field in typ.definition.fields)

    # Functions whose own signature is the only one their calls go through.
    open_functions: Set[int] = set()
    for typ in code.types:
        obj = typ.definition
        if not isinstance(obj, Obj):
            continue
        inherited: Dict[str, int] = {}
        for ancestor in _chain(code, obj)[:-1]:
            for proto in ancestor.protos:
                inherited[proto.name.resolve(code)] = proto.findex.value
        for proto in obj.protos:
            name = proto.name.resolve(code)
            if name in member_names:
                open_functions.add(proto.findex.value)
            if name in inherited and inherited[name] != proto.findex.value:
                open_functions.update((proto.findex.value, inherited[name]))
        # A static half binds its static methods; an instance half, its `dynamic` ones.
        if not is_static_name(obj.name.resolve(code)):
            open_functions.update(binding.findex.value for binding in obj.bindings)
    nargs: Dict[int, int] = {}
    # An abstract's value is declared as the abstract: the `this` of its members and what its
    # constructor returns.
    abstract_values: List[Node] = []
    for func in code.functions:
        signature = func.type.resolve(code).definition
        nargs[func.findex.value] = len(getattr(signature, "args", []))
        abstract = abstracts.abstract_of_function(code, func)
        if abstract is not None and func.findex.value == abstract.constructor:
            abstract_values.append(("ret", func.findex.value))
        elif abstract is not None and func.findex.value in abstract.instance:
            abstract_values.append(("r", func.findex.value, 0))
        for op in func.ops:
            if op.op in ("StaticClosure", "InstanceClosure"):
                open_functions.add(op.df["fun"].value)
            elif op.op == "VirtualClosure":
                receiver = func.regs[op.df["obj"].value].resolve(code).definition
                if isinstance(receiver, Obj):
                    proto = code.proto_by_pindex(receiver, op.df["field"].value)
                    if proto is not None:
                        open_functions.add(proto.findex.value)

    sources: Dict[Node, List[_Source]] = {}

    def add(node: Node, source: _Source) -> None:
        sources.setdefault(node, []).append(source)

    for node in abstract_values:
        add(node, None)

    webs: Dict[int, _Webs] = {}
    for func in code.functions:
        findex = func.findex.value
        regs = [r.value for r in func.regs]
        ops = func.ops
        virtual = {r for r, t in enumerate(regs) if t in virtual_types}
        if not virtual:
            continue  # nothing structural to read, write or pass on
        web = webs[findex] = _Webs(func, virtual, nargs[findex])
        if findex in open_functions:
            for i in range(min(nargs[findex], len(regs))):
                if is_virtual(regs[i]):
                    add(("r", findex, i), None)
        for index, op in enumerate(ops):
            name, df = op.op, op.df
            if name == "Ret":
                reg = df["ret"].value
                if is_virtual(regs[reg]):
                    add(("ret", findex), web.use(index, reg) if findex not in open_functions else None)
                continue
            if name in ("SetField", "SetThis"):
                obj_reg = df["obj"].value if name == "SetField" else 0
                src = df["src"].value
                owner = code.types[regs[obj_reg]].definition
                if not is_virtual(regs[src]) or not isinstance(owner, Obj):
                    continue
                found = _owner_slot(code, owner, df["field"].value)
                if found is not None and found[0].fields[found[1]].name.resolve(code):
                    declaring, slot = found
                    add(("field", id(declaring), slot), web.use(index, src))
                continue
            if name is not None and name.startswith("Call"):
                args = _call_args(op)
                callee: Optional[int] = None
                if args is not None and name in ("CallMethod", "CallThis"):
                    receiver = code.types[regs[args[0]]].definition
                    if isinstance(receiver, Obj):
                        proto = code.proto_by_pindex(receiver, df["field"].value)
                        callee = proto.findex.value if proto is not None else None
                elif args is not None and "fun" in df:
                    callee = df["fun"].value
                if callee is not None and isinstance(code.fn(callee), Function):
                    for position, reg in enumerate(args or []):
                        add(("r", callee, position), web.use(index, reg) if is_virtual(regs[reg]) else None)
                if "dst" not in df or not is_virtual(regs[df["dst"].value]):
                    continue
                add(web.define(index), ("ret", callee) if callee is not None else None)
                continue
            if "dst" not in df or not is_virtual(regs[df["dst"].value]):
                continue
            dst = df["dst"].value
            node = web.define(index)
            if name == "Null":
                continue
            if name == "Mov":
                add(node, web.use(index, df["src"].value))
            elif name in ("Field", "GetThis"):
                obj_reg = df["obj"].value if name == "Field" else 0
                owner = code.types[regs[obj_reg]].definition
                found = _owner_slot(code, owner, df["field"].value) if isinstance(owner, Obj) else None
                if found is None:
                    add(node, None)
                elif found[0].fields[found[1]].name.resolve(code):
                    add(node, ("field", id(found[0]), found[1]))
                else:
                    add(node, cache_interface(regs[obj_reg], df["field"].value))
            elif name == "ToVirtual" and index + 1 < len(ops):
                # The conversion that fills a cache slot is to the slot's interface.
                store = ops[index + 1]
                src = df["src"].value
                stored = (
                    store.op == "SetField"
                    and store.df["obj"].value == src
                    or store.op == "SetThis"
                    and src == 0
                ) and store.df["src"].value == dst
                add(node, cache_interface(regs[src], store.df["field"].value) if stored else None)
            else:
                add(node, None)

    # A location takes the one name all its sources agree on. Solved optimistically first, so a
    # name goes round loops, then again with what stayed undecided taken as unnamed.
    unknown = object()
    conflict = object()

    def default(node: Node) -> object:
        return unknown if _neutral(node, nargs) else conflict

    value: Dict[Node, object] = {node: unknown for node in sources}
    users: Dict[Node, List[Node]] = {}
    for node, found_sources in sources.items():
        for source in found_sources:
            if isinstance(source, tuple):
                users.setdefault(source, []).append(node)

    def solve(pending: List[Node]) -> None:
        while pending:
            node = pending.pop()
            result: object = unknown
            for source in sources[node]:
                if isinstance(source, tuple):
                    current = value[source] if source in value else default(source)
                elif source is None:
                    current = conflict
                else:
                    current = source
                if current is unknown:
                    continue
                if result is unknown:
                    result = current
                elif result is not current:
                    result = conflict
                if result is conflict:
                    break
            if result is not value[node]:
                value[node] = result
                pending.extend(users.get(node, []))

    solve(list(sources))
    undecided = [node for node, found in value.items() if found is unknown]
    for node in undecided:
        value[node] = conflict
    solve([user for node in undecided for user in users.get(node, [])])
    named = {node: found if isinstance(found, typeinit.Interface) else None for node, found in value.items()}
    return _Result(named, {findex: web for findex, web in webs.items() if web.split}, nargs)


def _neutral(node: Node, nargs: Dict[int, int]) -> bool:
    """Whether a location nothing is stored into is no constraint: a register only ever null
    (or read before it's written) is; a field or return no one stores into, or a parameter no
    one passes, is unnamed."""
    return node[0] == "w" or node[0] == "r" and node[2] >= nargs.get(node[1], 0)


def _call_args(op: Opcode) -> Optional[List[int]]:
    """Argument registers of a call, receiver included."""
    name, df = op.op, op.df
    if name == "Call0":
        return []
    if name in ("Call1", "Call2", "Call3", "Call4"):
        return [df[f"arg{i}"].value for i in range(int(name[-1]))]
    if name in ("CallN", "CallMethod"):
        return [a.value for a in df["args"].value]
    if name == "CallThis":
        return [0] + [a.value for a in df["args"].value]
    return None


def _result(code: Bytecode) -> "_Result":
    key = id(code)
    with _lock:
        cached = _cache.get(key)
    if cached is None or cached[0]() is not code:
        cached = (weakref.ref(code), _compute(code))
        with _lock:
            _cache[key] = cached
    return cached[1]


def interface(code: Bytecode, node: Optional[Node]) -> Optional[typeinit.Interface]:
    """The interface the value at `node` was declared as: `("r", findex, reg)` for a parameter,
    `("ret", findex)` for a return, or a `mapargs.field_node`."""
    return _result(code).named.get(node) if node is not None else None


def local(
    code: Bytecode, findex: int, reg: int, defs: Optional[Iterable[int]] = None
) -> Optional[typeinit.Interface]:
    """The interface a local of register `reg` was declared as. `defs`, the indices of the ops
    writing the local, narrow it to a part of the register (by default, the whole of it)."""
    result = _result(code)
    web = result.webs.get(findex)
    nodes = web.nodes(reg, defs) if web is not None else {("r", findex, reg)}
    found: Optional[typeinit.Interface] = None
    for node in nodes:
        if node not in result.named:
            if _neutral(node, result.nargs):
                continue
            return None
        current = result.named[node]
        if current is None or found is not None and current is not found:
            return None
        found = current
    return found


def refine(annotation: str, code: Bytecode, node: Optional[Node]) -> str:
    """The declaration of the value at `node`: its interface, where one was recovered."""
    from . import disasm

    found = interface(code, node)
    return disasm.type_to_haxe(found.name) if found is not None else annotation
