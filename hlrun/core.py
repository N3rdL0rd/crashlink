"""
Core classes, handling, and casting for primitives.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, List
from .globals import dbg_print, is_runtime

if is_runtime():
    from _pyhl import hl_obj_getfield, hl_obj_setfield, hl_obj_classname, hl_closure_call, hl_obj_field_type
    RUNTIME = True
else:
    RUNTIME = False

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


def _create_matching_obj(ptr: Any) -> HlObj:
    from .obj import OBJ_MAP
    name = hl_obj_classname(ptr)
    return OBJ_MAP[name](ptr) if name in OBJ_MAP else HlObj(ptr) # type: ignore[no-untyped-call]


def to_hlvalue(obj: Any, kind: Type|int) -> HlValue:
    """
    Convert a Capsule containing a pointer to an HL object to a HlValue.
    """
    kind = Type(kind) if isinstance(kind, int) else kind
    match kind:
        case Type.OBJ:
            return _create_matching_obj(obj)
        case Type.FUN:
            return HlClosure(obj)
        case _:
            return obj


class HlClosure(HlValue):
    """
    Proxy to a callable function, out-of-context of an object.
    """
    
    def __init__(self, ptr: Any) -> None:
        self.__ptr = ptr
    
    def __call__(self, *args: Any) -> Any:
        if RUNTIME:
            return hl_closure_call(self.__ptr, list(args))
        raise RuntimeError("This isn't the pyhl runtime!")


class HlObj(HlValue):
    """
    Proxy to an instance of an HL class.
    """
    
    def __getattr__(self, name: str) -> Any:
        if RUNTIME:
            if "__ptr_impossible_to_overlap_this_name" in self.__dict__:
                return to_hlvalue(hl_obj_getfield(self.__dict__["__ptr_impossible_to_overlap_this_name"], name), hl_obj_field_type(self.__dict__["__ptr_impossible_to_overlap_this_name"], name))
            else:
                raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")
        raise RuntimeError("This isn't the pyhl runtime!")
    
    def __setattr__(self, name: str, value: Any) -> None:
        if RUNTIME:
            if "__ptr_impossible_to_overlap_this_name" in self.__dict__:
                return hl_obj_setfield(self.__dict__["__ptr_impossible_to_overlap_this_name"], name, value)
            else:
                raise AttributeError("Cannot set attributes before initializing the object")
        raise RuntimeError("This isn't the pyhl runtime!")
        
    def _classname(self) -> str:
        """
        Get the class name of the object.
        """
        return hl_obj_classname(self.__dict__["__ptr_impossible_to_overlap_this_name"])

    def __init__(self, ptr): # type: ignore
        self.__dict__['__ptr_impossible_to_overlap_this_name'] = ptr # HACK: yeah... sorry.


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
            args_arr.append(to_hlvalue(arg, types_arr[i]))
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
