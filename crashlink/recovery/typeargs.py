"""Recovery of erased type arguments: a function's own, a class's, and those of `Array`, `Enum` and `haxe.ds` maps held in registers."""

import re
import threading
import weakref
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from ..core import Bytecode, Dyn, Enum, Fun, Function, Native, Null, Obj, Opcode, Type, Virtual, tIndex

# ============================================================================
# generics
#
# Recovery of a function's own type parameters.
#
# HL erases `function eq<T>(a:T, b:T)` to `(Dyn, Dyn)`, which is also what
# `function eq(a:Dynamic, b:Dynamic)` compiles to. They differ at a call: an argument for a
# `Dynamic` parameter is boxed into a `Dyn` register (a Dynamic expression passes as it is),
# while one for a parameter of the type variable `T`, once the call has fixed `T`, is boxed
# into (or cast to) a register of that type:
#
#     ToDyn  Null<Int> <- Int      f(1, ...)      Dyn parameter:  ToDyn Dyn <- Int
#     SafeCast Null<Int> <- Dyn    f(.., dynamic)                 no cast at all
#
# A parameter that any call feeds that way is a type variable; the parameters one call gives
# the same type at are the same variable.
# ============================================================================

# Per function: its parameter variables, the variable of its return (None if it doesn't return one),
# and the fields each variable's constraint `T:{var field:Type}` names: field name -> (type index, written).
_Variables = Tuple[Dict[int, int], Optional[int], Dict[int, Dict[str, Tuple[int, bool]]]]
_variables_cache: Dict[int, Tuple["weakref.ReferenceType[Bytecode]", Dict[int, _Variables]]] = {}
_variables_lock = threading.Lock()


def _call_args(op: Opcode) -> Optional[List[int]]:
    """Argument registers of a call, receiver included (`CallThis` reads it from register 0)."""
    name, df = op.op, op.df
    if name in ("Call0",):
        return []
    if name in ("Call1", "Call2", "Call3", "Call4"):
        return [df[f"arg{i}"].value for i in range(int(name[-1]))]
    if name in ("CallN", "CallMethod"):
        return [a.value for a in df["args"].value]
    if name == "CallThis":
        return [0] + [a.value for a in df["args"].value]
    return None


def _evidence(code: Bytecode, caller: Function, op_index: int, reg: int, array: bool) -> bool:
    """True if the register a call reads was filled by a conversion made for a type variable:
    a boxing or a cast, whose result isn't Dynamic. For an `Array<T>` parameter (an ArrayDyn)
    it is a cast of a typed array to it."""
    for i in range(op_index - 1, -1, -1):
        writer = caller.ops[i]
        dst = writer.df.get("dst")
        if dst is None or dst.value != reg:
            continue
        if array:
            return writer.op == "SafeCast" and _array_name(code, caller.regs[writer.df["src"].value]) in (
                "hl.types.ArrayObj",
                "hl.types.ArrayBytes_Int",
                "hl.types.ArrayBytes_Float",
                "hl.types.ArrayBytes_Bool",
                "hl.types.ArrayBytes_hl_F32",
                "hl.types.ArrayBytes_hl_UI16",
            )
        return writer.op in ("ToDyn", "SafeCast")
    return False


def _array_name(code: Bytecode, index: "tIndex") -> Optional[str]:
    definition = index.resolve(code).definition
    return definition.name.resolve(code) if isinstance(definition, Obj) else None


def _returned_parameter(func: Function, parameters: List[int]) -> Optional[int]:
    """The parameter every return of `func` returns unchanged, if it is one of `parameters`."""
    returned = {op.df["ret"].value for op in func.ops if op.op == "Ret"}
    if len(returned) != 1:
        return None
    (reg,) = returned
    if reg not in parameters or any(
        op.df.get("dst") is not None and op.df["dst"].value == reg for op in func.ops
    ):
        return None
    return reg


def _result_is_cast(caller: Function, op_index: int) -> bool:
    """True if the result of the call at `op_index` is cast straight away: the compiler casts the
    erased Dynamic result of a call that returns a type variable to the type the call fixed it at."""
    dst = caller.ops[op_index].df.get("dst")
    if dst is None or op_index + 1 >= len(caller.ops):
        return False
    following = caller.ops[op_index + 1]
    return following.op == "SafeCast" and following.df["src"].value == dst.value


def _result_is_unsafely_cast(caller: Function, op_index: int) -> bool:
    """True if the result of the call at `op_index` is cast without a check straight away: the
    compiler's cast of the erased result of an instance method that returns a type variable."""
    dst = caller.ops[op_index].df.get("dst")
    if dst is None or op_index + 1 >= len(caller.ops):
        return False
    following = caller.ops[op_index + 1]
    return following.op == "UnsafeCast" and following.df["src"].value == dst.value


def _constrained_fields(
    code: Bytecode, func: Function, params: List[int]
) -> Dict[int, Dict[str, Tuple[int, bool]]]:
    """The typed fields a body reads or writes on each of its Dynamic parameters. A field of a
    `Dynamic` is itself Dynamic; one that has a type is declared by a structural constraint
    (`T:{length:Int}`) on the parameter's type variable."""
    fields: Dict[int, Dict[str, Tuple[int, bool]]] = {}
    written = {op.df["dst"].value for op in func.ops if op.df.get("dst") is not None}
    for op in func.ops:
        if op.op == "DynGet":
            reg, typ, stored = op.df["obj"].value, func.regs[op.df["dst"].value], False
        elif op.op == "DynSet":
            reg, typ, stored = op.df["obj"].value, func.regs[op.df["src"].value], True
        else:
            continue
        if reg in params and reg not in written and typ.resolve(code).kind.value != Type.Kind.DYN.value:
            name = op.df["field"].resolve(code)
            known = fields.setdefault(reg, {}).get(name)
            fields[reg][name] = (typ.value, stored or known is not None and known[1])
    return fields


def _compute_variables(code: Bytecode) -> Dict[int, _Variables]:
    index = code.xref_index()
    dyn_kind = Type.Kind.DYN.value
    result: Dict[int, _Variables] = {}
    for func in code.functions:
        signature = func.type.resolve(code).definition
        # A constructor's type variables are its class's, not its own.
        if not isinstance(signature, Fun) or code.partial_func_name(func) == "__constructor__":
            continue
        arrays = {i for i, a in enumerate(signature.args) if _array_name(code, a) == "hl.types.ArrayDyn"}
        returns_dyn = signature.ret.resolve(code).kind.value == dyn_kind
        dyn_params = [
            i for i, a in enumerate(signature.args) if a.resolve(code).kind.value == dyn_kind or i in arrays
        ]
        if not dyn_params and not returns_dyn:
            continue
        parent = {i: i for i in dyn_params}

        def find(i: int) -> int:
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        evidenced: set = set()
        result_cast = False
        free_cast = False
        returned = (
            _returned_parameter(func, dyn_params)
            if signature.ret.resolve(code).kind.value == dyn_kind
            else None
        )
        for ref in index.callers_of(func.findex.value):
            caller = code.fn(ref.source_index, native=False)
            if ref.opcode_index is None or not isinstance(caller, Function):
                continue
            op = caller.ops[ref.opcode_index]
            args = _call_args(op)
            if args is None or len(args) != len(signature.args):
                continue

            def reg_type(p: int) -> int:
                return caller.regs[args[p]].value

            fed = [
                p
                for p in dyn_params
                if caller.regs[args[p]].resolve(code).kind.value != dyn_kind
                and _evidence(code, caller, ref.opcode_index, args[p], p in arrays)
            ]
            for p in fed:
                evidenced.add(p)
                for q in dyn_params:
                    if reg_type(q) == reg_type(p):
                        parent[find(q)] = find(p)
            result_cast = result_cast or returned is not None and _result_is_cast(caller, ref.opcode_index)
            free_cast = free_cast or returns_dyn and _result_is_unsafely_cast(caller, ref.opcode_index)
        constrained = _constrained_fields(code, func, dyn_params)
        evidenced.update(constrained)
        roots = {find(e) for e in evidenced}
        if result_cast and returned is not None:
            roots.add(find(returned))
        if not roots and not free_cast:
            continue
        groups: Dict[int, int] = {}
        numbered = {}
        for p in dyn_params:
            if find(p) in roots:
                numbered[p] = groups.setdefault(find(p), len(groups))
        if returned in numbered:
            returned_variable: Optional[int] = numbered[returned]
        elif free_cast and returned is None:
            # A result no parameter carries, cast unchecked where the call is: a variable of its own.
            returned_variable = len(groups)
        else:
            returned_variable = None
        constraints: Dict[int, Dict[str, Tuple[int, bool]]] = {}
        for p, named in constrained.items():
            constraints.setdefault(numbered[p], {}).update(named)
        result[func.findex.value] = (numbered, returned_variable, constraints)
    return result


def _variables(code: Bytecode, func: Function | Native) -> _Variables:
    key = id(code)
    with _variables_lock:
        cached = _variables_cache.get(key)
        if cached is None or cached[0]() is not code:
            cached = (weakref.ref(code), _compute_variables(code))
            _variables_cache[key] = cached
    return cached[1].get(func.findex.value, ({}, None, {}))


def type_variables(code: Bytecode, func: Function | Native) -> Dict[int, int]:
    """Map the index (into the function's argument types, receiver included) of each parameter
    that is a type variable to the number of its variable."""
    return _variables(code, func)[0]


def return_variable(code: Bytecode, func: Function | Native) -> Optional[int]:
    """The number of the type variable `func` returns, when it returns one of its parameters
    unchanged: `function alias<T>(t:T):T` erases to a Dynamic return of its parameter."""
    return _variables(code, func)[1]


def constraints(code: Bytecode, func: Function | Native) -> Dict[int, Dict[str, Tuple["tIndex", bool]]]:
    """For each type variable of `func` that its body uses typed fields of, those fields: name -> (type, written)."""
    return {
        number: {name: (tIndex(typ), written) for name, (typ, written) in named.items()}
        for number, named in _variables(code, func)[2].items()
    }


# ============================================================================
# enumparams
#
# Recovery of the parameters that hold an `Enum<T>`.
#
# Class objects of classes, abstracts and enums all share one HL type, `hl.BaseType`, so a
# parameter of it can't be declared from its type alone: `Enum<Dynamic>` would reject a class
# passed to it, `Dynamic` takes anything but is not the `Enum<T>` the source wrote. An enum's
# runtime object is the global typed with the enum's static class (`$Name`, which has no
# instance class); a parameter is an `Enum<T>` when every direct call of the function passes
# one.
# ============================================================================

_enum_cache: Dict[int, Tuple["weakref.ReferenceType[Bytecode]", Set[Tuple[int, int]]]] = {}
_enum_lock = threading.Lock()


def _is_enum_object(code: Bytecode, global_index: int, enum_names: Set[str]) -> bool:
    definition = code.global_types[global_index].resolve(code).definition
    if not isinstance(definition, Obj) or not definition.is_static:
        return False
    return definition.name.resolve(code).replace("$", "") in enum_names


def _enum_parameters(code: Bytecode) -> Set[Tuple[int, int]]:
    enum_names = {
        t.definition.name.resolve(code).replace("$", "") for t in code.types if isinstance(t.definition, Enum)
    }
    enum_args: Set[Tuple[int, int]] = set()
    other_args: Set[Tuple[int, int]] = set()
    for function in code.functions:
        last_def: Dict[int, Opcode] = {}
        for op in function.ops:
            name = op.op
            if name in ("Call1", "Call2", "Call3", "Call4"):
                args = [op.df[f"arg{i}"].value for i in range(int(name[-1]))]
            elif name == "CallN":
                args = [a.value for a in op.df["args"].value]
            else:
                args = None
            if args is not None:
                callee = op.df["fun"].value
                for position, reg in enumerate(args):
                    source = last_def.get(reg)
                    key = (callee, position)
                    if (
                        source is not None
                        and source.op == "GetGlobal"
                        and _is_enum_object(code, source.df["global"].value, enum_names)
                    ):
                        enum_args.add(key)
                    else:
                        other_args.add(key)
            dst = op.df.get("dst")
            if dst is not None:
                last_def[dst.value] = op
    return enum_args - other_args


def is_enum_parameter(code: Bytecode, findex: int, position: int) -> bool:
    """Whether every direct call of function `findex` passes an enum's runtime object as argument `position`."""
    key = id(code)
    with _enum_lock:
        cached = _enum_cache.get(key)
    if cached is None or cached[0]() is not code:
        cached = (weakref.ref(code), _enum_parameters(code))
        with _enum_lock:
            _enum_cache[key] = cached
    return (findex, position) in cached[1]


# ============================================================================
# arrayelems
#
# Recovery of the element type of an erased `Array<T>` held in a register.
#
# HL gives every `Array<T>` of an object type the one class `hl.types.ArrayObj`, so a register
# holding one says nothing about `T`, and rendering it `Array<Dynamic>` would make it an `ArrayDyn`
# (a cast, where the compiler made none). `T` survives where the compiler read an element out:
# `a[i]` loads the backing `array` field, reads the slot as a Dynamic and, being typed by the
# array's `T`, casts it unchecked:
#
#     Field array  <- a.array
#     GetArray     <- array[i]
#     UnsafeCast   T <- Dyn
#
# The type every such read of a register agrees on (reads through `Mov` copies count for both) is
# its element type.
# ============================================================================

_element_cache: Dict[int, Tuple["weakref.ReferenceType[Bytecode]", Dict[Tuple[int, int], str]]] = {}
_element_lock = threading.Lock()


def _is_array_obj(code: Bytecode, type_index: int) -> bool:
    definition = code.types[type_index].definition
    return isinstance(definition, Obj) and definition.name.resolve(code) == "hl.types.ArrayObj"


def _field_name(code: Bytecode, obj: Obj, flat: int) -> Optional[str]:
    """The name of field `flat` of `obj`, counting the fields of its super classes first."""
    chain: List[Obj] = []
    current: Optional[Obj] = obj
    while current is not None and len(chain) < 64:
        chain.append(current)
        parent = current.super.resolve(code).definition if current.super.value >= 0 else None
        current = parent if isinstance(parent, Obj) else None
    for ancestor in reversed(chain):
        if flat < len(ancestor.fields):
            return ancestor.fields[flat].name.resolve(code)
        flat -= len(ancestor.fields)
    return None


_CAST_OR_COPY = {"Mov", "SafeCast", "UnsafeCast"}


def _from_std_array_code(code: Bytecode, op: Opcode) -> bool:
    """True if `op` makes an array by the std's own code (`hl.types`, or its unnamed wrappers), which
    returns the element type its caller names, rather than reading one a declaration fixed."""
    if op.op in ("New", "Null", "Type"):
        return True
    if op.op is None or not op.op.startswith("Call") or "fun" not in op.df:
        return False
    callee = code.fn(op.df["fun"].value)
    if not isinstance(callee, Function):
        return True
    name = code.full_func_name(callee)
    return name.startswith("hl.types.") or name == "<none>"


def _compute_elements(code: Bytecode) -> Dict[Tuple[int, int], str]:
    from .. import disasm

    result: Dict[Tuple[int, int], str] = {}
    array_types = {i for i in range(len(code.types)) if _is_array_obj(code, i)}
    if not array_types:
        return result
    for func in code.functions:
        regs = [r.value for r in func.regs]
        if not any(r in array_types for r in regs):
            continue
        parent: Dict[int, int] = {}

        def find(r: int) -> int:
            parent.setdefault(r, r)
            while parent[r] != r:
                parent[r] = parent[parent[r]]
                r = parent[r]
            return r

        evidence: Dict[int, Set[str]] = {}
        nested: List[Tuple[int, int]] = []
        backing: Dict[int, int] = {}
        poisoned: Set[int] = set()
        ops = func.ops
        for index, op in enumerate(ops):
            name, df = op.op, op.df
            written = df.get("dst")
            if written is not None and regs[written.value] in array_types and name not in _CAST_OR_COPY:
                # A value read off a field, a global or a user function has the type that declares
                # it, which names no element type: a declaration naming one would not accept it.
                if not _from_std_array_code(code, op):
                    poisoned.add(written.value)
            if name == "Mov":
                if regs[df["dst"].value] in array_types and regs[df["src"].value] in array_types:
                    parent[find(df["dst"].value)] = find(df["src"].value)
            elif name == "Field" and regs[df["obj"].value] in array_types:
                owner = code.types[regs[df["obj"].value]].definition
                if isinstance(owner, Obj) and _field_name(code, owner, df["field"].value) == "array":
                    backing[df["dst"].value] = df["obj"].value
            elif name == "GetArray" and df["array"].value in backing and index + 1 < len(ops):
                follow = ops[index + 1]
                if follow.df.get("src") is None or follow.df["src"].value != df["dst"].value:
                    continue
                if follow.op == "SafeCast" and regs[follow.df["dst"].value] in array_types:
                    # An array of arrays: its element type is the inner array's, once that is known.
                    nested.append((backing[df["array"].value], follow.df["dst"].value))
                    continue
                if follow.op != "UnsafeCast":
                    continue
                element: Type = func.regs[follow.df["dst"].value].resolve(code)
                if element.kind.value == Type.Kind.DYN.value or not isinstance(element.definition, Obj):
                    continue
                evidence.setdefault(backing[df["array"].value], set()).add(
                    disasm._haxe_annotation(code, element)
                )

        def solve() -> Dict[int, Set[str]]:
            solved: Dict[int, Set[str]] = {}
            for reg, names in evidence.items():
                solved.setdefault(find(reg), set()).update(names)
            return solved

        solved = solve()
        unrefinable = {find(reg) for reg in poisoned}
        for _ in range(3):
            for outer, inner in nested:
                names = solved.get(find(inner))
                if names is not None and len(names) == 1:
                    evidence.setdefault(outer, set()).add(f"Array<{next(iter(names))}>")
            solved = solve()
        for reg in list(parent):
            names_here: Optional[Set[str]] = solved.get(find(reg))
            if (
                names_here is not None
                and len(names_here) == 1
                and regs[reg] in array_types
                and find(reg) not in unrefinable
            ):
                result[(func.findex.value, reg)] = next(iter(names_here))
    return result


def element_type(code: Bytecode, func: Function, reg: int) -> Optional[str]:
    """The annotation of the element type of the `ArrayObj` in register `reg` of `func`, if its reads agree on one."""
    key = id(code)
    with _element_lock:
        cached = _element_cache.get(key)
        if cached is None or cached[0]() is not code:
            cached = (weakref.ref(code), _compute_elements(code))
            _element_cache[key] = cached
    return cached[1].get((func.findex.value, reg))


_ERASED = re.compile(r"(Array<)+Dynamic>+")


def refine_array(annotation: str, element: Optional[str]) -> str:
    """`Array<Dynamic>` (what an `ArrayObj` renders as, with each array of arrays nested in it)
    with the element type recovered for it."""
    if element is None or _ERASED.fullmatch(annotation) is None:
        return annotation
    refined = f"Array<{element}>"
    return refined if refined.count("Array<") == annotation.count("Array<") else annotation


# ============================================================================
# mapargs
#
# Recovery of the value type of erased `haxe.ds` maps.
#
# HL erases `Map<Int, String>` to `haxe.ds.IntMap`, whose value type is `Dyn` in every signature,
# so a declaration renders `IntMap<Dynamic>`. The compiler still knows the value type at each use:
#
# - `m.get(k)` is a `Dyn` that it converts with an `UnsafeCast` (a value of a type parameter
#   already is the type, as far as the compiler is concerned) to the value type;
# - `m.set(k, v)` boxes a basic value into a register of its own type before the call.
#
# Where the map is declared `Dynamic` instead, `get` is an ordinary Dynamic read and gets a
# `SafeCast`, which is what an unrecovered declaration recompiles to. The value type found at any
# use is applied to everything the map flows through: locals, parameters, returns and fields.
# ============================================================================

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

_value_cache: Dict[int, Tuple["weakref.ReferenceType[Bytecode]", Dict[Node, str]]] = {}
_value_lock = threading.Lock()


def refine_map(annotation: str, value: Optional[str]) -> str:
    """The declaration of a map with its value type, where it was recovered."""
    if value is None:
        return annotation
    imap = _IMAP_ERASED.fullmatch(annotation)
    if imap is not None:
        return f"{imap.group(1)}<Dynamic, {value}>"
    if annotation.startswith("Array<") and annotation.endswith(">"):
        inner = refine_map(annotation[6:-1], value)
        return f"Array<{inner}>"
    for name, position in MAP_VALUE_ARGUMENT.items():
        erased = f"{name}<Dynamic>" if position == 0 else f"{name}<Dynamic,Dynamic>"
        if annotation == erased:
            return f"{name}<{value}>" if position == 0 else f"{name}<Dynamic,{value}>"
    return annotation


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
    for slot, member in enumerate(owner.fields):
        if member.name.resolve(code) == name:
            return ("field", id(owner), slot)
    return None


def _compute_values(code: Bytecode) -> Dict[Node, str]:
    from .. import disasm

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
            refined = refine_map(annotation, value)
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
    with _value_lock:
        cached = _value_cache.get(key)
        if cached is None or cached[0]() is not code:
            cached = (weakref.ref(code), _compute_values(code))
            _value_cache[key] = cached
    return cached[1].get(node)


# ============================================================================
# classgenerics
#
# Recovery of a class's type parameters.
#
# HL erases `class Box<T> { var v:T; function get():T ... }` to `Dyn` slots, which is also what
# `var v:Dynamic` compiles to. They differ where a slot is read at a known instantiation: the
# compiler trusts the type parameter and converts the read value with an *unchecked* cast,
#
#     Field     Dyn <- box.v      var s:String = box.v     (box:Box<String>)
#     UnsafeCast String <- Dyn
#
# where a `Dynamic` read is left alone (or, written `(cast box.v : String)`, cast with a checked
# `SafeCast`). An `UnsafeCast` of a field read or of a method's return is therefore a type
# parameter of the class that declares the slot, applied at the static type of the receiver: the
# view. An override narrowing a parameter the overridden method declares `Dynamic` is one too:
# Haxe only lets an override change a parameter's type through the class's type arguments.
#
# Each class declaring such slots gets one type parameter per group of slots whose views agree.
# A subclass either closes the parameters (`class B extends A<String>`: its own methods read the
# slots cast, and every view below it agrees) or forwards them (`class B<T> extends A<T>`).
# References to a generic class are written with the type arguments its views agree on; a
# parameter no read pins down is `Dynamic`. Slots whose reads at one view disagree (one class
# instantiated two ways) are left erased.
# ============================================================================

# ("field", id(owner), name) | ("ret", id(owner), method) | ("arg", id(owner), method, index)
Slot = Tuple[Any, ...]
# A type parameter's name, a concrete type argument, or None for Dynamic.
ScopeEntry = Union[str, Type, None]


@dataclass
class ClassGenerics:
    # id(obj) -> the type parameters it declares
    declared: Dict[int, List[int]] = field(default_factory=dict)
    # id(obj) -> what each type parameter in scope is in its body: a name, or the closed type
    scope: Dict[int, Dict[int, ScopeEntry]] = field(default_factory=dict)
    # id(obj) -> type arguments of its `extends` clause
    supers: Dict[int, List[ScopeEntry]] = field(default_factory=dict)
    # id(obj) -> type arguments of a reference to the (generic) class
    args: Dict[int, List[Optional[Type]]] = field(default_factory=dict)
    # slot -> type parameter
    slots: Dict[Slot, int] = field(default_factory=dict)
    names: Dict[int, str] = field(default_factory=dict)

    def params(self, obj: Optional[Obj]) -> List[str]:
        return [self.names[p] for p in self.declared.get(id(obj), ())] if obj is not None else []

    def slot_in(self, obj: Optional[Obj], slot: Slot) -> Optional[Tuple[ScopeEntry]]:
        """What the slot is inside `obj`'s body, wrapped in a tuple (None if it isn't a type parameter)."""
        pid = self.slots.get(slot)
        if pid is None or obj is None:
            return None
        scope = self.scope.get(id(obj))
        if scope is None or pid not in scope:
            return None
        return (scope[pid],)


def _name(number: int) -> str:
    return "T" if number == 0 else f"T{number}"


def _parent(code: Bytecode, obj: Obj) -> Optional[Obj]:
    if obj.super.value < 0:
        return None
    definition = obj.super.resolve(code).definition
    return definition if isinstance(definition, Obj) else None


def _chain(code: Bytecode, obj: Obj) -> List[Obj]:
    """`obj` and its ancestors, root first."""
    chain: List[Obj] = []
    current: Optional[Obj] = obj
    while current is not None and all(c is not current for c in chain):
        chain.append(current)
        current = _parent(code, current)
    return chain[::-1]


def _is_dyn(typ: Type) -> bool:
    return isinstance(typ.definition, Dyn)


def _method_types(code: Bytecode, obj: Obj, name: str) -> Optional[Fun]:
    """The signature (receiver included) of the method `obj` itself declares as `name`."""
    for proto in obj.protos:
        if proto.name.resolve(code) == name:
            fn = proto.findex.resolve(code)
            if isinstance(fn, Function):
                definition = fn.type.resolve(code).definition
                return definition if isinstance(definition, Fun) else None
    for binding in obj.bindings:
        member = obj.resolve_fields(code)[binding.field.value]
        if member.name.resolve(code) == name and member in obj.fields:
            fn = binding.findex.resolve(code)
            if isinstance(fn, Function):
                definition = fn.type.resolve(code).definition
                return definition if isinstance(definition, Fun) else None
    return None


def _declares_method(code: Bytecode, obj: Obj, name: str) -> bool:
    return any(p.name.resolve(code) == name for p in obj.protos) or any(
        f.name.resolve(code) == name and isinstance(f.type.resolve(code).definition, Fun) for f in obj.fields
    )


def method_root(code: Bytecode, obj: Obj, name: str) -> Optional[Obj]:
    """The topmost class of `obj`'s chain declaring the method `name`."""
    for candidate in _chain(code, obj):
        if _declares_method(code, candidate, name):
            return candidate
    return None


def _field_owner(code: Bytecode, obj: Obj, index: int) -> Optional[Obj]:
    seen = 0
    for candidate in _chain(code, obj):
        seen += len(candidate.fields)
        if index < seen:
            return candidate
    return None


def _user_classes(code: Bytecode) -> List[Obj]:
    from ..pseudo import _is_std_class_obj

    objs: List[Obj] = []
    for typ in code.types:
        obj = typ.definition
        if isinstance(obj, Obj) and not obj.name.resolve(code).split(".")[-1].startswith("$"):
            try:
                if obj.is_static:
                    continue
            except ValueError:
                pass
            if not _is_std_class_obj(code, obj):
                objs.append(obj)
    return objs


def _compute_class_generics(code: Bytecode) -> ClassGenerics:
    from ..pseudo import _method_registry

    users = _user_classes(code)
    user_ids = {id(o) for o in users}
    registry = _method_registry(code)
    owners: Dict[int, Obj] = {id(o): o for o in users}
    # slot -> [(view, type argument, read through `this`)]
    evidence: Dict[Slot, List[Tuple[Obj, Type, bool]]] = {}
    # (id(view), slot): a read through `this` that isn't cast
    uncast: Set[Tuple[int, Slot]] = set()
    roots: Dict[Tuple[int, str], Optional[Obj]] = {}

    def root_of(obj: Obj, name: str) -> Optional[Obj]:
        key = (id(obj), name)
        if key not in roots:
            roots[key] = method_root(code, obj, name)
        return roots[key]

    def read_slot(func: Function, op: Any) -> Optional[Tuple[Obj, Slot, int]]:
        """The class slot an op reads (view, slot, receiver register)."""
        name, df = op.op, op.df
        receiver: Optional[int] = None
        if name in ("Field", "GetThis"):
            receiver = df["obj"].value if name == "Field" else 0
            view = func.regs[receiver].resolve(code).definition
            if not isinstance(view, Obj) or id(view) not in user_ids:
                return None
            fields = view.resolve_fields(code)
            index = df["field"].value
            if index >= len(fields) or not _is_dyn(fields[index].type.resolve(code)):
                return None
            owner = _field_owner(code, view, index)
            if owner is None or id(owner) not in user_ids:
                return None
            return view, ("field", id(owner), fields[index].name.resolve(code)), receiver
        method: Optional[str] = None
        if name in ("Call1", "Call2", "Call3", "Call4", "CallN"):
            entry = registry.get(df["fun"].value)
            if entry is None or not entry[2]:
                return None
            receiver = (_call_args(op) or [None])[0]
            method = entry[1]
        elif name in ("CallMethod", "CallThis"):
            receiver = (_call_args(op) or [None])[0]
            if receiver is None:
                return None
            view = func.regs[receiver].resolve(code).definition
            if not isinstance(view, Obj):
                return None
            proto = code.proto_by_pindex(view, df["field"].value)
            if proto is None:
                return None
            method = proto.name.resolve(code)
        if method is None or receiver is None:
            return None
        view = func.regs[receiver].resolve(code).definition
        if not isinstance(view, Obj) or id(view) not in user_ids:
            return None
        root = root_of(view, method)
        if root is None or id(root) not in user_ids:
            return None
        signature = _method_types(code, root, method)
        if signature is None or not _is_dyn(signature.ret.resolve(code)):
            return None
        return view, ("ret", id(root), method), receiver

    def stored_slot(func: Function, op: Any, this_obj: Obj) -> Optional[Tuple[Slot, int]]:
        """The slot of its own class a method's op stores into (slot, source register)."""
        name, df = op.op, op.df
        if name == "SetThis" or (name == "SetField" and df["obj"].value == 0):
            fields = this_obj.resolve_fields(code)
            index = df["field"].value
            if index >= len(fields) or not _is_dyn(fields[index].type.resolve(code)):
                return None
            owner = _field_owner(code, this_obj, index)
            if owner is None or id(owner) not in user_ids:
                return None
            return ("field", id(owner), fields[index].name.resolve(code)), df["src"].value
        return None

    def is_foreign(func: Function, ops: List[Any], targets: Set[int], i: int, reg: int) -> bool:
        """True if the value a register holds at op `i` couldn't be of a type parameter: it is
        concrete, boxed from a concrete value, or an array's element (which the renderer types by
        the arrays its callers pass)."""
        if not _is_dyn(func.regs[reg].resolve(code)):
            return True
        j = i - 1
        while j >= 0 and j + 1 not in targets:
            writer = ops[j]
            dst = writer.df.get("dst")
            if dst is not None and dst.value == reg:
                if writer.op in ("ToDyn", "GetArray"):
                    return True
                args = _call_args(writer)
                if args:
                    receiver = func.regs[args[0]].resolve(code).definition
                    return isinstance(receiver, Obj) and receiver.name.resolve(code).startswith(
                        "hl.types.Array"
                    )
                return False
            j -= 1
        return False

    # (id(class), slot): a value a class's own methods store into a slot that a type parameter
    # couldn't hold. Such a slot isn't the parameter while the class declares it.
    foreign: Set[Tuple[int, Slot]] = set()
    # slot -> [(view, type)]: reads converted with a checked cast, which no read of a parameter
    # fixed to a reference type needs: that view instantiates the class another way.
    checked: Dict[Slot, List[Tuple[Obj, Type]]] = {}
    for func in code.functions:
        ops = func.ops
        targets: Set[int] = set()
        for i, op in enumerate(ops):
            if "offset" in op.df:
                targets.add(i + 1 + op.df["offset"].value)
            if op.op == "Switch":
                targets.update(i + 1 + o.value for o in op.df["offsets"].value)
        this_obj = func.regs[0].resolve(code).definition if func.regs else None
        entry = registry.get(func.findex.value)
        is_method = isinstance(this_obj, Obj) and entry is not None and entry[2] and entry[0] is this_obj
        # A constructor is bound on the static half, but its receiver is the instance too.
        owns_this = is_method or (
            isinstance(this_obj, Obj) and entry is not None and entry[1] == "__constructor__"
        )
        returned: Optional[Slot] = None
        if is_method and entry is not None and isinstance(this_obj, Obj):
            root = root_of(this_obj, entry[1])
            signature = func.type.resolve(code).definition
            if root is not None and isinstance(signature, Fun) and _is_dyn(signature.ret.resolve(code)):
                returned = ("ret", id(root), entry[1])
        for i, op in enumerate(ops):
            if owns_this and isinstance(this_obj, Obj):
                stored = stored_slot(func, op, this_obj)
                if stored is None and returned is not None and op.op == "Ret":
                    stored = returned, op.df["ret"].value
                if stored is not None and is_foreign(func, ops, targets, i, stored[1]):
                    foreign.add((id(this_obj), stored[0]))
            dst = op.df.get("dst")
            if dst is None:
                continue
            read = read_slot(func, op)
            if read is None:
                continue
            view, slot, receiver = read
            through_this = owns_this and receiver == 0
            cast: Optional[Tuple[str, Type]] = None
            for j in range(i + 1, len(ops)):
                if j in targets:
                    break
                later = ops[j]
                if later.op in ("UnsafeCast", "SafeCast") and later.df["src"].value == dst.value:
                    cast = later.op, func.regs[later.df["dst"].value].resolve(code)
                    break
                if later.df.get("dst") is not None and later.df["dst"].value == dst.value:
                    break
            if cast is not None and not _is_dyn(cast[1]):
                if cast[0] == "UnsafeCast":
                    evidence.setdefault(slot, []).append((view, cast[1], through_this))
                else:
                    checked.setdefault(slot, []).append((view, cast[1]))
            elif through_this:
                uncast.add((id(view), slot))

    # An override narrowing a parameter its root declares Dynamic.
    for obj in users:
        methods = [(p.name.resolve(code), p.findex.resolve(code)) for p in obj.protos]
        for binding in obj.bindings:
            methods.append(
                (
                    obj.resolve_fields(code)[binding.field.value].name.resolve(code),
                    binding.findex.resolve(code),
                )
            )
        for name, fn in methods:
            root = root_of(obj, name)
            if root is None or root is obj or id(root) not in user_ids or not isinstance(fn, Function):
                continue
            root_sig, own = _method_types(code, root, name), fn.type.resolve(code).definition
            if root_sig is None or not isinstance(own, Fun) or len(own.args) != len(root_sig.args):
                continue
            for index in range(1, len(own.args)):
                arg = own.args[index].resolve(code)
                if _is_dyn(root_sig.args[index].resolve(code)) and not _is_dyn(arg):
                    evidence.setdefault(("arg", id(root), name, index - 1), []).append((obj, arg, True))

    children: Dict[int, List[Obj]] = {}
    for obj in users:
        parent = _parent(code, obj)
        if parent is not None:
            children.setdefault(id(parent), []).append(obj)

    def subtree(obj: Obj) -> Set[int]:
        found, pending = set(), [obj]
        while pending:
            current = pending.pop()
            if id(current) not in found:
                found.add(id(current))
                pending.extend(children.get(id(current), ()))
        return found

    order = sorted(users, key=lambda o: len(_chain(code, o)))
    failed: Set[Slot] = set()
    while True:
        result = ClassGenerics()
        retry: Set[Slot] = set()
        # Group each owner's evidenced slots into type parameters.
        owned: Dict[int, List[Tuple[int, Dict[int, Type]]]] = {}
        pid_slots: Dict[int, List[Slot]] = {}
        for slot, items in evidence.items():
            if slot in failed or slot[1] not in owners:
                continue
            views: Dict[int, Type] = {}
            for view, typ, _ in items:
                if views.setdefault(id(view), typ) is not typ:
                    retry.add(slot)
            for view, typ in checked.get(slot, ()):
                if views.get(id(view), typ) is not typ:
                    retry.add(slot)
            if slot in retry:
                continue
            groups = owned.setdefault(slot[1], [])
            for pid, combined in groups:
                if all(combined.get(v, t) is t for v, t in views.items()):
                    combined.update(views)
                    pid_slots[pid].append(slot)
                    break
            else:
                pid = len(pid_slots)
                pid_slots[pid] = [slot]
                groups.append((pid, dict(views)))
        if retry:
            failed |= retry
            continue
        for pid, slots in pid_slots.items():
            for slot in slots:
                result.slots[slot] = pid

        def agreed(pid: int, among: Set[int]) -> Tuple[Optional[Type], bool]:
            value: Optional[Type] = None
            for slot in pid_slots[pid]:
                for view, typ, _ in evidence[slot]:
                    if id(view) in among:
                        if value is not None and value is not typ:
                            return None, False
                        value = typ
            return value, True

        for obj in order:
            parent = _parent(code, obj)
            inherited = result.declared.get(id(parent), []) if parent is not None else []
            scope: Dict[int, ScopeEntry] = (
                dict(result.scope.get(id(parent), {})) if parent is not None else {}
            )
            forwarded: List[int] = []
            if inherited:
                below = subtree(obj)
                closed: Dict[int, Optional[Type]] = {}
                needs_open = False
                for pid in inherited:
                    value, ok = agreed(pid, below)
                    closed[pid] = value
                    if not ok:
                        needs_open = True
                    elif value is not None and any(
                        (view, slot) in uncast for slot in pid_slots[pid] for view in below
                    ):
                        needs_open = True
                if needs_open:
                    forwarded = list(inherited)
                    result.supers[id(obj)] = [scope[pid] for pid in inherited]
                else:
                    result.supers[id(obj)] = [closed[pid] for pid in inherited]
                    scope.update(closed)
            own = [pid for pid, slots in pid_slots.items() if slots[0][1] == id(obj)]
            for k, pid in enumerate(own):
                result.names[pid] = _name(len(forwarded) + k)
                scope[pid] = result.names[pid]
            declared = forwarded + own
            result.scope[id(obj)] = scope
            for pid in declared:
                if any((id(obj), slot) in foreign for slot in pid_slots[pid]):
                    retry.update(pid_slots[pid])
            if declared:
                result.declared[id(obj)] = declared
                args: List[Optional[Type]] = []
                for pid in declared:
                    value, ok = agreed(pid, {id(obj)})
                    if not ok:
                        retry.update(pid_slots[pid])
                    args.append(value)
                result.args[id(obj)] = args
        if retry:
            failed |= retry
            continue
        return result


def class_generics(code: Bytecode) -> ClassGenerics:
    cached = code._class_generics
    if cached is None:
        cached = code._class_generics = _compute_class_generics(code)
    return cached
