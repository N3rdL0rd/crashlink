"""
Recovery of a function's own type parameters.

HL erases `function eq<T>(a:T, b:T)` to `(Dyn, Dyn)`, which is also what
`function eq(a:Dynamic, b:Dynamic)` compiles to. They differ at a call: an argument for a
`Dynamic` parameter is boxed into a `Dyn` register (a Dynamic expression passes as it is),
while one for a parameter of the type variable `T`, once the call has fixed `T`, is boxed
into (or cast to) a register of that type:

    ToDyn  Null<Int> <- Int      f(1, ...)      Dyn parameter:  ToDyn Dyn <- Int
    SafeCast Null<Int> <- Dyn    f(.., dynamic)                 no cast at all

A parameter that any call feeds that way is a type variable; the parameters one call gives
the same type at are the same variable.
"""

import threading
import weakref
from typing import Dict, List, Optional, Tuple

from .core import Bytecode, Fun, Function, Native, Opcode, Type

_cache: Dict[int, Tuple["weakref.ReferenceType[Bytecode]", Dict[int, Dict[int, int]]]] = {}
_lock = threading.Lock()


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


def _evidence(caller: Function, op_index: int, reg: int) -> bool:
    """True if the register a call reads was filled by a conversion made for a type variable:
    a boxing or a cast, whose result isn't Dynamic."""
    for i in range(op_index - 1, -1, -1):
        dst = caller.ops[i].df.get("dst")
        if dst is not None and dst.value == reg:
            return caller.ops[i].op in ("ToDyn", "SafeCast")
    return False


def _compute(code: Bytecode) -> Dict[int, Dict[int, int]]:
    index = code.xref_index()
    dyn_kind = Type.Kind.DYN.value
    result: Dict[int, Dict[int, int]] = {}
    for func in code.functions:
        signature = func.type.resolve(code).definition
        if not isinstance(signature, Fun):
            continue
        dyn_params = [i for i, a in enumerate(signature.args) if a.resolve(code).kind.value == dyn_kind]
        if not dyn_params:
            continue
        parent = {i: i for i in dyn_params}

        def find(i: int) -> int:
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        evidenced: set = set()
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
                and _evidence(caller, ref.opcode_index, args[p])
            ]
            for p in fed:
                evidenced.add(p)
                for q in dyn_params:
                    if reg_type(q) == reg_type(p):
                        parent[find(q)] = find(p)
        if not evidenced:
            continue
        roots = {find(e) for e in evidenced}
        groups: Dict[int, int] = {}
        numbered = {}
        for p in dyn_params:
            if find(p) in roots:
                numbered[p] = groups.setdefault(find(p), len(groups))
        result[func.findex.value] = numbered
    return result


def type_variables(code: Bytecode, func: Function | Native) -> Dict[int, int]:
    """Map the index (into the function's argument types, receiver included) of each parameter
    that is a type variable to the number of its variable."""
    key = id(code)
    with _lock:
        cached = _cache.get(key)
        if cached is None or cached[0]() is not code:
            cached = (weakref.ref(code), _compute(code))
            _cache[key] = cached
    return cached[1].get(func.findex.value, {})
