"""
Recovery of the element type of an erased `Array<T>` held in a register.

HL gives every `Array<T>` of an object type the one class `hl.types.ArrayObj`, so a register
holding one says nothing about `T`, and rendering it `Array<Dynamic>` would make it an `ArrayDyn`
(a cast, where the compiler made none). `T` survives where the compiler read an element out:
`a[i]` loads the backing `array` field, reads the slot as a Dynamic and, being typed by the
array's `T`, casts it unchecked:

    Field array  <- a.array
    GetArray     <- array[i]
    UnsafeCast   T <- Dyn

The type every such read of a register agrees on (reads through `Mov` copies count for both) is
its element type.
"""

import re
import threading
import weakref
from typing import Dict, List, Optional, Set, Tuple

from .core import Bytecode, Function, Obj, Opcode, Type

_cache: Dict[int, Tuple["weakref.ReferenceType[Bytecode]", Dict[Tuple[int, int], str]]] = {}
_lock = threading.Lock()


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


def _compute(code: Bytecode) -> Dict[Tuple[int, int], str]:
    from . import disasm

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
    with _lock:
        cached = _cache.get(key)
        if cached is None or cached[0]() is not code:
            cached = (weakref.ref(code), _compute(code))
            _cache[key] = cached
    return cached[1].get((func.findex.value, reg))


_ERASED = re.compile(r"(Array<)+Dynamic>+")


def refine(annotation: str, element: Optional[str]) -> str:
    """`Array<Dynamic>` (what an `ArrayObj` renders as, with each array of arrays nested in it)
    with the element type recovered for it."""
    if element is None or _ERASED.fullmatch(annotation) is None:
        return annotation
    refined = f"Array<{element}>"
    return refined if refined.count("Array<") == annotation.count("Array<") else annotation
