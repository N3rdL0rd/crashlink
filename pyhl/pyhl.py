"""
Python side of the pyhl integration.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, List, Tuple


class Type(Enum):
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
class HlObj:
    obj: Any
    type: Type


def dbg_print(*args, **kwargs) -> None:
    global DEBUG
    try:
        if DEBUG:
            print("[pyhl] [py] ", end="")
            print(*args, **kwargs)
    except NameError:
        pass


class Args:
    def __init__(self, args: List[Any], fn_symbol: str, types: str):
        types_arr: List[Type] = [Type(int(typ)) for typ in types.split(",")]
        args_str: List[str] = []
        args_arr: List[HlObj] = []
        for i, arg in enumerate(args):
            args_str.append(f"arg{i}: {Type(types_arr[i])}={arg}")
            args_arr.append(HlObj(arg, Type(types_arr[i])))
        dbg_print(f"{fn_symbol}({', '.join(args_str)})")
        self.args: List[HlObj] = args_arr
