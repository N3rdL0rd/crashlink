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

from .core import Bytecode, Fun, Function, Native, Obj, Opcode, Type, tIndex

# Per function: its parameter variables, and the variable of its return (None if it doesn't return one).
_Variables = Tuple[Dict[int, int], Optional[int]]
_cache: Dict[int, Tuple["weakref.ReferenceType[Bytecode]", Dict[int, _Variables]]] = {}
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


def _compute(code: Bytecode) -> Dict[int, _Variables]:
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
        result[func.findex.value] = (numbered, returned_variable)
    return result


def _variables(code: Bytecode, func: Function | Native) -> _Variables:
    key = id(code)
    with _lock:
        cached = _cache.get(key)
        if cached is None or cached[0]() is not code:
            cached = (weakref.ref(code), _compute(code))
            _cache[key] = cached
    return cached[1].get(func.findex.value, ({}, None))


def type_variables(code: Bytecode, func: Function | Native) -> Dict[int, int]:
    """Map the index (into the function's argument types, receiver included) of each parameter
    that is a type variable to the number of its variable."""
    return _variables(code, func)[0]


def return_variable(code: Bytecode, func: Function | Native) -> Optional[int]:
    """The number of the type variable `func` returns, when it returns one of its parameters
    unchanged: `function alias<T>(t:T):T` erases to a Dynamic return of its parameter."""
    return _variables(code, func)[1]
