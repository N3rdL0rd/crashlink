"""
Core classes, handling, and casting for primitives.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, List, Tuple


from .globals import dbg_print


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


@dataclass
class HlPrim:
    """
    Primitive object, stored as a castable Python object and a type kind.
    """

    obj: Any
    type: Type


class Args:
    """
    Represents intercepted arguments passed to a function.
    """

    def __init__(self, args: List[Any], fn_symbol: str, types: str):
        types_arr: List[Type] = [Type(int(typ)) for typ in types.split(",")]
        args_str: List[str] = []
        args_arr: List[HlPrim] = []
        for i, arg in enumerate(args):
            args_str.append(f"arg{i}: {Type(types_arr[i])}={arg}")
            args_arr.append(HlPrim(arg, Type(types_arr[i])))
        dbg_print(f"{fn_symbol}({', '.join(args_str)})")
        self.args: List[HlPrim] = args_arr

    def to_hl(self) -> List[Any]:
        return [arg.obj for arg in self.args]

    def __getitem__(self, index: int) -> HlPrim:
        return self.args[index]

    def __setitem__(self, index: int, value: HlPrim) -> None:
        self.args[index] = value

    def __len__(self) -> int:
        return len(self.args)

    def __iter__(self) -> Iterable[HlPrim]:
        return iter(self.args)

    def __repr__(self) -> str:
        return f"Args({self.args})"
