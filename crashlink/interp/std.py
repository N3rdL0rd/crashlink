# type: ignore
# ^ Currently flawed and not ready for typing. Ignore it for now, and fix it later.

"""
Port of HashLink's std C bindings to pure Python. Entirely functional due to the nature of the library and C bindings.
"""

from dataclasses import dataclass
from typing import Any, Callable, List

from ..core import Bytecode, Obj


@dataclass
class StdBinding:
    """
    Represents a binding between a Haxe/HashLink standard library function name and its Python implementation.
    """

    name: str
    lib: str
    func: Callable[..., Any]


BINDINGS: List[StdBinding] = []


def bind(name: str, lib: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator to bind a Python function to a Haxe/HashLink standard library function name.
    """

    def inner(func: Callable[..., Any]) -> Callable[..., Any]:
        BINDINGS.append(StdBinding(name, lib, func))
        return func

    return inner


@bind("hballoc", "std")
def hballoc(code: Bytecode, vm: "VM") -> "VMBytes":
    """
    Allocate a byte array.
    """
    from .vm import VMBytes  # deferred import, kill me

    return VMBytes(b"")


@bind("type_get_global", "std")
def type_get_global(code: Bytecode, vm: "VM", typ: "VMType") -> "VMPrim":
    """
    Get a global instance of an object type, if one is present.
    Does nothing when passed an Obj, only works with Structs and Enums.
    """
    match typ.value.kind.value:
        case 11:  # Obj - explicitly ignored
            pass
        case 21 | 18:  # Struct | Enum - both have the same attribute "_global" so they should be interchangable (?)
            if typ.value.definition._global and vm.globals[typ.value.definition._global.value]:
                return vm.globals[typ.value.definition._global.value]
            raise NameError(f"Global instance of {typ} not found.")
    return None


@bind("type_set_global", "std")
def type_set_global(code: Bytecode, vm: "VM", typ: "VMType", instance: "VMValue") -> "VMBool":
    """
    Set a global instance of an object type to the given instance or Obj (Dyn) - types are unchecked so be careful, YOLO!
    """
    from .vm import VMBool

    match typ.value.kind.value:
        case 11:  # Obj - explicitly ignored
            pass
        case 21 | 18:  # Struct | Enum
            if typ.value.definition._global:
                vm.globals[typ.value.definition._global.value] = instance
                return VMBool(True)
            raise NameError(f"Global instance of {typ} not found.")
    return VMBool(False)


@bind("alloc_obj", "std")
def alloc_obj(code: Bytecode, vm: "VM", typ: "VMType") -> "VMValue":
    """
    Allocate an empty Obj of the given type.
    """
    from .vm import VMObj

    obj = typ.value.definition
    assert isinstance(obj, Obj), "Not an Obj."
    return VMObj.create_empty(obj, code)


@bind("sys_print", "std")
def sys_print(code: Bytecode, vm: "VM", value: "VMValue") -> "VMVoid":
    """
    Print a value to the console.
    """
    from .vm import VMBytes

    assert isinstance(value, VMBytes), "Can only print bytes."
    print(value.value.decode("utf-8"), end="")
    return None
