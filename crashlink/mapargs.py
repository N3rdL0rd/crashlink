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

import re
import threading
import weakref
from typing import Dict, List, Optional, Set, Tuple

from .core import Bytecode, Fun, Function, Null, Obj, Type, Virtual

# Class name -> index of the value type among its (erased) type arguments.
MAP_VALUE_ARGUMENT = {
    "haxe.ds.IntMap": 0,
    "haxe.ds.StringMap": 0,
    "haxe.ds.ObjectMap": 1,
    "haxe.ds.EnumValueMap": 1,
    "haxe.ds.List": 0,
}

# The members of `haxe.IMap` whose types do not mention its value type `V` structurally: the
# iterators are anonymous structures over `V`, which an `IMap<Dynamic, V>` would type differently.
_IMAP_MEMBERS = {"get", "set", "exists", "remove", "keys", "copy", "toString", "clear"}

Node = Tuple

_IMAP_ERASED = re.compile(r"(haxe\.(?:Constraints\.)?IMap)<Dynamic,\s*Dynamic>")

_cache: Dict[int, Tuple["weakref.ReferenceType[Bytecode]", Dict[Node, str]]] = {}
_lock = threading.Lock()


def refine(annotation: str, value: Optional[str]) -> str:
    """The declaration of a map with its value type, where it was recovered."""
    if value is None:
        return annotation
    imap = _IMAP_ERASED.fullmatch(annotation)
    if imap is not None:
        return f"{imap.group(1)}<Dynamic, {value}>"
    if annotation.startswith("Array<") and annotation.endswith(">"):
        inner = refine(annotation[6:-1], value)
        return f"Array<{inner}>"
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
    array_types: Set[int] = set()
    for i, t in enumerate(code.types):
        definition = t.definition
        if isinstance(definition, Obj) and definition.name.resolve(code) in (
            "hl.types.ArrayObj",
            "hl.types.ArrayDyn",
        ):
            array_types.add(i)
    imap_types: Set[int] = set()
    for i, t in enumerate(code.types):
        definition = t.definition
        if isinstance(definition, Virtual) and definition.fields:
            names = {f.name.resolve(code) for f in definition.fields}
            if names <= _IMAP_MEMBERS and names & {"get", "keys"}:
                imap_types.add(i)
    node_types: Set[int] = set()
    for i, t in enumerate(code.types):
        definition = t.definition
        if isinstance(definition, Obj) and definition.name.resolve(code) == "haxe.ds._List.ListNode":
            node_types.add(i)
    holders = map_types | array_types | imap_types | node_types

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
    nested: List[Tuple[Node, int, Node]] = []
    poisoned: List[Node] = []

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

    def note(node: Node, type_index: int) -> None:
        name = value_name(type_index)
        if name is not None:
            evidence.setdefault(node, set()).add(name)

    for func in code.functions:
        findex = func.findex.value
        regs = [r.value for r in func.regs]

        def _is_list(type_index: int) -> bool:
            definition = code.types[type_index].definition
            return isinstance(definition, Obj) and definition.name.resolve(code) == "haxe.ds.List"

        def is_map(reg: int) -> bool:
            return regs[reg] in holders

        signature = func.type.resolve(code).definition
        ret_type = signature.ret.value if isinstance(signature, Fun) else -1
        for index, op in enumerate(func.ops):
            name, df = op.op, op.df
            if name == "Mov":
                if is_map(df["dst"].value) and is_map(df["src"].value):
                    union(("r", findex, df["dst"].value), ("r", findex, df["src"].value))
            elif name == "Ret":
                if ret_type in holders:
                    union(("ret", findex), ("r", findex, df["ret"].value))
            elif name == "ToVirtual":
                if regs[df["dst"].value] in imap_types and regs[df["src"].value] in map_types:
                    union(("r", findex, df["dst"].value), ("r", findex, df["src"].value))
            elif name in ("GetArray", "SetArray"):
                # An array of maps is as much a map as its element: they share the value type. A
                # read comes out of the backing array as a Dynamic that is cast to the map.
                if name == "SetArray":
                    element = df["src"].value
                elif index + 1 < len(func.ops) and func.ops[index + 1].op == "UnsafeCast":
                    element = func.ops[index + 1].df["dst"].value
                else:
                    element = df["dst"].value
                if regs[element] in map_types:
                    union(("r", findex, df["array"].value), ("r", findex, element))
            elif name == "Field" and (regs[df["obj"].value] in node_types or _is_list(regs[df["obj"].value])):
                # A list's nodes share its element type, which a read of a node's item is cast to.
                owner = code.types[regs[df["obj"].value]].definition
                member = owner.fields[df["field"].value].name.resolve(code) if isinstance(owner, Obj) else ""
                if member == "item":
                    follow = func.ops[index + 1] if index + 1 < len(func.ops) else None
                    if (
                        follow is not None
                        and follow.op == "UnsafeCast"
                        and follow.df["src"].value == df["dst"].value
                    ):
                        note(("r", findex, df["obj"].value), regs[follow.df["dst"].value])
                elif regs[df["dst"].value] in node_types:
                    union(("r", findex, df["obj"].value), ("r", findex, df["dst"].value))
            elif name in ("Field", "GetThis", "SetField", "SetThis"):
                if name == "Field" and regs[df["obj"].value] in array_types:
                    union(("r", findex, df["obj"].value), ("r", findex, df["dst"].value))
                    continue
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
                if name == "Field" and not isinstance(owner, Obj):
                    # Read off a structure: its declared field type cannot be refined.
                    poisoned.append(("r", findex, reg))
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
                    if isinstance(receiver, Virtual) and regs[args[0]] in imap_types:
                        member = receiver.fields[df["field"].value].name.resolve(code)
                        follow = func.ops[index + 1] if index + 1 < len(func.ops) else None
                        if (
                            member == "get"
                            and follow is not None
                            and follow.op == "UnsafeCast"
                            and follow.df["src"].value == df["dst"].value
                        ):
                            note(("r", findex, args[0]), regs[follow.df["dst"].value])
                        continue
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
                if code.full_func_name(target).startswith("hl.types.Array") and regs[args[0]] in array_types:
                    for reg in [*args[1:], df["dst"].value if "dst" in df else args[0]]:
                        if regs[reg] in map_types:
                            union(("r", findex, args[0]), ("r", findex, reg))
                elif not code.full_func_name(target).startswith("haxe.ds."):
                    for position, reg in enumerate(args):
                        if is_map(reg):
                            union(("r", findex, reg), ("r", callee, position))
                    if "dst" in df and is_map(df["dst"].value):
                        union(("r", findex, df["dst"].value), ("ret", callee))
                if args and regs[args[0]] in map_types:
                    method = code.partial_func_name(target)
                    node = ("r", findex, args[0])
                    if method == "set" and len(args) == 3:
                        value = args[2]
                        if _boxed_by_to_dyn(func, index, value):
                            note(node, regs[value])
                    elif method == "get" and "dst" in df and index + 1 < len(func.ops):
                        follow = func.ops[index + 1]
                        if follow.op == "UnsafeCast" and follow.df["src"].value == df["dst"].value:
                            cast_reg = follow.df["dst"].value
                            if regs[cast_reg] in map_types:
                                # A map of maps: the inner map's own value type refines this one's.
                                nested.append((node, regs[cast_reg], ("r", findex, cast_reg)))
                            else:
                                note(node, regs[cast_reg])

    def solve(extra: List[Tuple[Node, str]]) -> Dict[Node, Set[str]]:
        solved: Dict[Node, Set[str]] = {}
        for node, names in evidence.items():
            solved.setdefault(find(node), set()).update(names)
        for node, name in extra:
            solved.setdefault(find(node), set()).add(name)
        return solved

    # Each map a `get` casts out of another is named with its own recovered value type; a use that
    # recovered none says nothing against the sites that did.
    extra: List[Tuple[Node, str]] = []
    for _ in range(4):
        solved = solve(extra)
        found: Dict[Node, Dict[bool, Set[str]]] = {}
        for node, type_index, inner in nested:
            names = solved.get(find(inner))
            annotation = value_name(type_index)
            if annotation is None:
                continue
            value = next(iter(names)) if names is not None and len(names) == 1 else None
            refined = refine(annotation, value)
            found.setdefault(node, {}).setdefault(refined != annotation, set()).add(refined)
        updated = [
            (node, name) for node, kinds in found.items() for name in kinds.get(True, kinds.get(False, set()))
        ]
        if sorted(updated) == sorted(extra):
            break
        extra = updated
    solved = solve(extra)
    unrefinable = {find(node) for node in poisoned}
    result: Dict[Node, str] = {}
    for node in list(parent):
        names = solved.get(find(node))
        if names is not None and len(names) == 1 and find(node) not in unrefinable:
            result[node] = next(iter(names))
    return result


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
