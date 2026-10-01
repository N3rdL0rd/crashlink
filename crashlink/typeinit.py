"""
Type registration, read from the image's entry point.

Before `main` runs, the entry point registers every class and interface with the runtime:
`Type.initClass(staticHalf, instanceType, "pkg.Name")`, then for an interface
`registered.__implementedBy__ = [classes...]`. That is the only place the bytecode ties an
interface (a static half with no instance half) to the virtual type its values have, and
to the classes implementing it.
"""

import threading
import weakref
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .core import Bytecode, Function, Obj, Type, Virtual


@dataclass
class Interface:
    """An interface: its static half, the type its values have, and its implementors."""

    obj: Obj
    #: Name the registration gives (`pkg.Name`, or `pkg._Module.Name` when private).
    name: str
    #: The virtual type a value of the interface has: its members, inherited ones included.
    virtual: Virtual
    #: Instance halves of the classes registered as implementing it.
    implementors: List[Obj] = field(default_factory=list)
    #: Interfaces it extends (see `_link_parents`).
    parents: List["Interface"] = field(default_factory=list)

    def ancestors(self) -> List["Interface"]:
        """Every interface it extends, directly or not."""
        found: List[Interface] = []
        pending = list(self.parents)
        while pending:
            parent = pending.pop()
            if all(parent is not seen for seen in found):
                found.append(parent)
                pending.extend(parent.parents)
        return found


@dataclass
class Registry:
    #: Interfaces by `id()` of their static half.
    interfaces: Dict[int, Interface]
    #: Interfaces each class implements, by `id()` of the class's instance half.
    implements: Dict[int, List[Interface]]


# Keyed by id(code) with a weakref back to it, like `pseudo._method_registry`:
# a Bytecode isn't hashable.
_cache: Dict[int, Tuple["weakref.ReferenceType[Bytecode]", Registry]] = {}
_cache_lock = threading.Lock()


def registry(code: Bytecode) -> Registry:
    """The registrations of `code`, read once."""
    with _cache_lock:
        cached = _cache.get(id(code))
        if cached is not None and cached[0]() is code:
            return cached[1]
    result = _read(code)
    with _cache_lock:
        _cache[id(code)] = (weakref.ref(code), result)
    return result


def interface_of(code: Bytecode, obj: Optional[Obj]) -> Optional[Interface]:
    """The interface whose static half `obj` is."""
    return registry(code).interfaces.get(id(obj)) if obj is not None else None


def implemented(code: Bytecode, obj: Optional[Obj]) -> List[Interface]:
    """The interfaces the class whose instance half is `obj` is registered as implementing."""
    return registry(code).implements.get(id(obj), []) if obj is not None else []


def _read(code: Bytecode) -> Registry:
    interfaces: Dict[int, Interface] = {}
    implements: Dict[int, List[Interface]] = {}
    try:
        entry = code.fn(code.entrypoint.value)
    except Exception:
        entry = None
    if not isinstance(entry, Function):
        return Registry(interfaces, implements)
    types: Dict[int, Type] = {}
    strings: Dict[int, str] = {}
    registered: Dict[int, Interface] = {}
    arrays: Dict[int, List[Type]] = {}
    for op in entry.ops:
        df = op.df
        if op.op == "Type":
            types[df["dst"].value] = df["ty"].resolve(code)
        elif op.op == "String":
            strings[df["dst"].value] = df["ptr"].resolve(code)
        elif op.op == "Call3":
            callee = df["fun"].resolve(code)
            args = [df["arg0"].value, df["arg1"].value, df["arg2"].value]
            registered.pop(df["dst"].value, None)
            if not isinstance(callee, Function) or code.full_func_name(callee) != "$Type.initClass":
                continue
            static, instance, name = types.get(args[0]), types.get(args[1]), strings.get(args[2])
            if (
                static is not None
                and isinstance(static.definition, Obj)
                and instance is not None
                and isinstance(instance.definition, Virtual)
                and name is not None
            ):
                interface = Interface(static.definition, name, instance.definition)
                interfaces[id(static.definition)] = interface
                registered[df["dst"].value] = interface
        elif str(op.op).startswith("Call") and "dst" in df:
            arrays[df["dst"].value] = []
        elif op.op == "SetArray":
            element = types.get(df["src"].value)
            if element is not None and df["array"].value in arrays:
                arrays[df["array"].value].append(element)
        elif op.op == "SetField":
            interface = registered.get(df["obj"].value)
            if interface is None:
                continue
            target = entry.regs[df["obj"].value].resolve(code).definition
            if not isinstance(target, Obj):
                continue
            if df["field"].resolve_obj(code, target).name.resolve(code) != "__implementedBy__":
                continue
            for typ in arrays.get(df["src"].value, []):
                if isinstance(typ.definition, Obj):
                    interface.implementors.append(typ.definition)
                    implements.setdefault(id(typ.definition), []).append(interface)
    _link_parents(code, list(interfaces.values()))
    return Registry(interfaces, implements)


def _link_parents(code: Bytecode, interfaces: List[Interface]) -> None:
    """Infer which interfaces extend which. The registration lists a class under every
    interface it is one of, inherited ones included, and an interface's value type holds
    its inherited members: `B` extends `A` when every class implementing `B` implements `A`
    and `A`'s members are among `B`'s. Two interfaces that are each other's match are
    left unrelated: nothing tells which one extends the other."""
    members = {id(i): {f.name.resolve(code) for f in i.virtual.fields} for i in interfaces}
    classes = {id(i): {id(obj) for obj in i.implementors} for i in interfaces}
    candidates: Dict[int, List[Interface]] = {}
    for child in interfaces:
        if not child.implementors:
            continue
        candidates[id(child)] = [
            parent
            for parent in interfaces
            if parent is not child
            and members[id(parent)] <= members[id(child)]
            and classes[id(child)] <= classes[id(parent)]
            and (members[id(parent)] != members[id(child)] or classes[id(child)] != classes[id(parent)])
        ]
    for child in interfaces:
        found = candidates.get(id(child), [])
        # Direct parents only: drop one another candidate already extends.
        child.parents = [
            parent
            for parent in found
            if not any(parent in candidates.get(id(other), []) for other in found if other is not parent)
        ]
