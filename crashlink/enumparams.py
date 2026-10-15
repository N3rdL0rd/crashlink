"""
Recovery of the parameters that hold an `Enum<T>`.

Class objects of classes, abstracts and enums all share one HL type, `hl.BaseType`, so a
parameter of it can't be declared from its type alone: `Enum<Dynamic>` would reject a class
passed to it, `Dynamic` takes anything but is not the `Enum<T>` the source wrote. An enum's
runtime object is the global typed with the enum's static class (`$Name`, which has no
instance class); a parameter is an `Enum<T>` when every direct call of the function passes
one.
"""

import threading
import weakref
from typing import Dict, Set, Tuple

from .core import Bytecode, Enum, Obj, Opcode

_cache: Dict[int, Tuple["weakref.ReferenceType[Bytecode]", Set[Tuple[int, int]]]] = {}
_lock = threading.Lock()


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
    with _lock:
        cached = _cache.get(key)
    if cached is None or cached[0]() is not code:
        cached = (weakref.ref(code), _enum_parameters(code))
        with _lock:
            _cache[key] = cached
    return (findex, position) in cached[1]
