"""
Core classes, handling, and casting for primitives.
"""

from dataclasses import dataclass
from enum import Enum
from types import CapsuleType
from typing import Any, Iterable, List, Tuple


from .globals import dbg_print, is_runtime

if is_runtime():
    from _pyhl import hl_getfield, hl_setfield # type: ignore[import-not-found]

class Type(Enum):
    """
    Type kind of an object.
    """

    VOID = 0
    U8 = 1
    U16 = 2
    I32 = 3
    I64 = 4
    F32 = 5
    F64 = 6
    BOOL = 7
    BYTES = 8
    DYN = 9
    FUN = 10
    OBJ = 11
    ARRAY = 12
    TYPETYPE = 13
    REF = 14
    VIRTUAL = 15
    DYNOBJ = 16
    ABSTRACT = 17
    ENUM = 18
    NULL = 19
    METHOD = 20
    STRUCT = 21
    PACKED = 22


class HlValue:
    """
    Value of some kind. ABC for all HL values.
    """

@dataclass
class HlPrim(HlValue):
    """
    Primitive object, stored as a castable Python object and a type kind.
    """

    obj: Any
    type: Type

class HlObj(HlValue):
    """
    Proxy to an instance of an HL class.
    """
    
    def __init__(self, ptr: CapsuleType):
        self.__ptr_impossible_to_overlap_this_name = ptr # HACK: yeah... sorry.
        
    def __getattr__(self, name: str) -> Any:
        if is_runtime():
            return hl_getfield(self.__ptr_impossible_to_overlap_this_name, name)
        raise NotImplementedError("Runtime access not implemented.")


class Args:
    """
    Represents intercepted arguments passed to a function.
    """

    def __init__(self, args: List[Any], fn_symbol: str, types: str):
        types_arr: List[Type] = [Type(int(typ)) for typ in types.split(",")]
        args_str: List[str] = []
        args_arr: List[HlValue] = []
        for i, arg in enumerate(args):
            args_str.append(f"arg{i}: {Type(types_arr[i])}={arg}")
            match types_arr[i]:
                case Type.OBJ:
                    args_arr.append(HlObj(arg))
                case _:
                    args_arr.append(HlPrim(arg, Type(types_arr[i])))
        dbg_print(f"{fn_symbol}({', '.join(args_str)})")
        self.args: List[HlValue] = args_arr

    def to_prims(self) -> List[Any|HlPrim]:
        return [arg.obj if isinstance(arg, HlPrim) else HlPrim(None, Type.VOID) for arg in self.args]

    def __getitem__(self, index: int) -> HlValue:
        return self.args[index]

    def __setitem__(self, index: int, value: HlValue) -> None:
        self.args[index] = value

    def __len__(self) -> int:
        return len(self.args)

    def __iter__(self) -> Iterable[HlValue]:
        return iter(self.args)

    def __repr__(self) -> str:
        return f"Args({self.args})"
