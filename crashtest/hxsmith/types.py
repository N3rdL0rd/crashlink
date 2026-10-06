"""The slice of Haxe's type system the generator reasons about."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class Ty:
    """A Haxe type: a name and type arguments. Function types are named `->`
    with the parameter types followed by the return type as arguments."""

    name: str
    args: Tuple["Ty", ...] = ()

    def __str__(self) -> str:
        if self.name == "->":
            *params, ret = self.args
            return f"({', '.join(map(str, params))}) -> {ret}"
        if self.args:
            return f"{self.name}<{', '.join(map(str, self.args))}>"
        return self.name

    @property
    def is_fn(self) -> bool:
        return self.name == "->"

    @property
    def params(self) -> Tuple["Ty", ...]:
        return self.args[:-1]

    @property
    def ret(self) -> "Ty":
        return self.args[-1]

    def of(self, name: str) -> bool:
        return self.name == name


INT = Ty("Int")
FLOAT = Ty("Float")
BOOL = Ty("Bool")
STRING = Ty("String")
VOID = Ty("Void")
DYNAMIC = Ty("Dynamic")

SCALARS = (INT, FLOAT, BOOL, STRING)


def array_of(element: Ty) -> Ty:
    return Ty("Array", (element,))


def map_of(key: Ty, value: Ty) -> Ty:
    return Ty("Map", (key, value))


def null_of(inner: Ty) -> Ty:
    return Ty("Null", (inner,))


def fn_of(params: Tuple[Ty, ...], ret: Ty) -> Ty:
    return Ty("->", (*params, ret))
