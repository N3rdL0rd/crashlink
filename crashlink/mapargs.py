"""
Recovery of the value type of erased `haxe.ds` maps.

HL erases `Map<Int, String>` to `haxe.ds.IntMap`, whose value type is `Dyn` in every signature,
so a declaration renders `IntMap<Dynamic>`. The compiler still knows the value type at each use:

- `m.get(k)` is a `Dyn` that it converts with an `UnsafeCast` (a value of a type parameter
  already is the type, as far as the compiler is concerned) to the value type;
- `m.set(k, v)` boxes a basic value into a register of its own type before the call.

Where the map is declared `Dynamic` instead, `get` is an ordinary Dynamic read and gets a
`SafeCast`, which is what an unrecovered declaration recompiles to. The value type found at any
use is applied to everything the map flows through: locals, parameters, returns and fields.
"""

import threading
import weakref
from typing import Dict, List, Optional, Set, Tuple

from .core import Bytecode, Fun, Function, Null, Obj, Type

# Class name -> index of the value type among its (erased) type arguments.
MAP_VALUE_ARGUMENT = {
    "haxe.ds.IntMap": 0,
    "haxe.ds.StringMap": 0,
    "haxe.ds.ObjectMap": 1,
    "haxe.ds.EnumValueMap": 1,
}

Node = Tuple

_cache: Dict[int, Tuple["weakref.ReferenceType[Bytecode]", Dict[Node, str]]] = {}
_lock = threading.Lock()


def refine(annotation: str, value: Optional[str]) -> str:
    """The declaration of a map with its value type, where it was recovered."""
    if value is None:
        return annotation
    for name, position in MAP_VALUE_ARGUMENT.items():
        erased = f"{name}<Dynamic>" if position == 0 else f"{name}<Dynamic,Dynamic>"
        if annotation == erased:
            return f"{name}<{value}>" if position == 0 else f"{name}<Dynamic,{value}>"
    return annotation


def _call_args(op) -> Optional[List[int]]:  # type: ignore[no-untyped-def]
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


def _owner_slot(code: Bytecode, obj: Obj, flat: int) -> Optional[Tuple[int, int]]:
    """The class that declares field `flat` of `obj` and the field's index among its own."""
    chain: List[Obj] = []
    seen: Set[int] = set()
    current: Optional[Obj] = obj
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        if current.super.value < 0:
            break
        parent = current.super.resolve(code).definition
        current = parent if isinstance(parent, Obj) else None
    chain.reverse()
    offset = 0
    for ancestor in chain:
        if flat < offset + len(ancestor.fields):
            return (id(ancestor), flat - offset)
        offset += len(ancestor.fields)
    return None


def field_node(code: Bytecode, owner: Obj, name: str) -> Optional[Node]:
    for slot, field in enumerate(owner.fields):
        if field.name.resolve(code) == name:
            return ("field", id(owner), slot)
    return None


def _compute(code: Bytecode) -> Dict[Node, str]:
    from . import disasm

    map_types: Set[int] = set()
    for i, t in enumerate(code.types):
        definition = t.definition
        if isinstance(definition, Obj) and definition.name.resolve(code) in MAP_VALUE_ARGUMENT:
            map_types.add(i)
    if not map_types:
        return {}

    parent: Dict[Node, Node] = {}
    evidence: Dict[Node, Set[str]] = {}

    def find(n: Node) -> Node:
        parent.setdefault(n, n)
        while parent[n] != n:
            parent[n] = parent[parent[n]]
            n = parent[n]
        return n

    def union(a: Node, b: Node) -> None:
        parent[find(a)] = find(b)

    annotations: Dict[int, str] = {}
    # (map node, value node, erased annotation): the map holds maps, whose own value type
    # is only known once they are solved.
    nested: List[Tuple[Node, Node, str]] = []

    def value_name(type_index: int) -> Optional[str]:
        typ = code.types[type_index]
        if isinstance(typ.definition, Null):
            typ = typ.definition.type.resolve(code)
        if typ.kind.value == Type.Kind.DYN.value or typ.kind.value == Type.Kind.VOID.value:
            return None
        key = id(typ)
        if key not in annotations:
            annotations[key] = disasm._haxe_annotation(code, typ)
        return annotations[key]

    def note(node: Node, type_index: int, value_node: Optional[Node] = None) -> None:
        name = value_name(type_index)
        if name is None:
            return
        if value_node is not None and type_index in map_types:
            nested.append((node, value_node, name))
            return
        evidence.setdefault(node, set()).add(name)

    for func in code.functions:
        findex = func.findex.value
        regs = [r.value for r in func.regs]

        def is_map(reg: int) -> bool:
            return regs[reg] in map_types

        signature = func.type.resolve(code).definition
        ret_type = signature.ret.value if isinstance(signature, Fun) else -1
        for index, op in enumerate(func.ops):
            name, df = op.op, op.df
            if name == "Mov":
                if is_map(df["dst"].value) and is_map(df["src"].value):
                    union(("r", findex, df["dst"].value), ("r", findex, df["src"].value))
            elif name == "Ret":
                if ret_type in map_types:
                    union(("ret", findex), ("r", findex, df["ret"].value))
            elif name in ("Field", "GetThis", "SetField", "SetThis"):
                if name == "Field":
                    obj_reg, reg = df["obj"].value, df["dst"].value
                elif name == "GetThis":
                    obj_reg, reg = 0, df["dst"].value
                elif name == "SetField":
                    obj_reg, reg = df["obj"].value, df["src"].value
                else:
                    obj_reg, reg = 0, df["src"].value
                if not is_map(reg):
                    continue
                owner = code.types[regs[obj_reg]].definition
                if isinstance(owner, Obj):
                    slot = _owner_slot(code, owner, df["field"].value)
                    if slot is not None:
                        union(("field",) + slot, ("r", findex, reg))
            elif name is not None and name.startswith("Call"):
                args = _call_args(op)
                if args is None:
                    continue
                callee: Optional[int] = None
                if name in ("CallMethod", "CallThis"):
                    receiver = code.types[regs[args[0]]].definition
                    if isinstance(receiver, Obj):
                        proto = code.proto_by_pindex(receiver, df["field"].value)
                        callee = proto.findex.value if proto is not None else None
                else:
                    callee = df["fun"].value
                if callee is None:
                    continue
                target = code.fn(callee)
                if not isinstance(target, Function):
                    continue
                # The std's own map code serves every map: it joins none of them.
                if not code.full_func_name(target).startswith("haxe.ds."):
                    for position, reg in enumerate(args):
                        if is_map(reg):
                            union(("r", findex, reg), ("r", callee, position))
                    if "dst" in df and is_map(df["dst"].value):
                        union(("r", findex, df["dst"].value), ("ret", callee))
                if args and is_map(args[0]):
                    method = code.partial_func_name(target)
                    node = ("r", findex, args[0])
                    if method == "set" and len(args) == 3:
                        value = args[2]
                        if _boxed_by_to_dyn(func, index, value):
                            note(node, regs[value])
                        elif is_map(value):
                            note(node, regs[value], ("r", findex, value))
                    elif method == "get" and "dst" in df and index + 1 < len(func.ops):
                        follow = func.ops[index + 1]
                        if follow.op == "UnsafeCast" and follow.df["src"].value == df["dst"].value:
                            cast_dst = follow.df["dst"].value
                            note(node, regs[cast_dst], ("r", findex, cast_dst))

    def solve() -> Dict[Node, str]:
        solved: Dict[Node, Set[str]] = {}
        for node, names in evidence.items():
            solved.setdefault(find(node), set()).update(names)
        result: Dict[Node, str] = {}
        for node in list(parent):
            names = solved.get(find(node))
            if names is not None and len(names) == 1:
                result[node] = next(iter(names))
        return result

    result = solve()
    # A map of maps is typed by the maps it holds, which are typed by their own values.
    for node, value_node, erased in nested:
        evidence.setdefault(node, set()).add(erased)
        parent.setdefault(value_node, value_node)
    for _ in range(4):
        result = solve()
        changed = False
        for node, value_node, erased in nested:
            inner = result.get(value_node)
            refined = refine(erased, inner)
            names = evidence[node]
            if refined != erased and refined not in names:
                names.discard(erased)
                names.add(refined)
                changed = True
        if not changed:
            break
    return solve()


def _boxed_by_to_dyn(func: Function, index: int, reg: int) -> bool:
    for i in range(index - 1, -1, -1):
        dst = func.ops[i].df.get("dst")
        if dst is not None and dst.value == reg:
            return func.ops[i].op == "ToDyn"
    return False


def value_type(code: Bytecode, node: Optional[Node]) -> Optional[str]:
    """The recovered value type (a Haxe annotation) of the map at `node`: `("r", findex, reg)`
    for a register, `("ret", findex)` for a return, or a `field_node`."""
    if node is None:
        return None
    key = id(code)
    with _lock:
        cached = _cache.get(key)
        if cached is None or cached[0]() is not code:
            cached = (weakref.ref(code), _compute(code))
            _cache[key] = cached
    return cached[1].get(node)
