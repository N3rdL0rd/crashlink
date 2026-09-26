"""
Recovery of Haxe abstracts.

Haxe erases an abstract to its underlying type and compiles its members to static
functions of a class `pkg._Module.Name_Impl_`:

- a method takes the value (`this`) as a leading argument, which debug info either
  leaves unnamed (one argument more than named parameters) or names `this`;
- the constructor is `_new`, which returns the value it built;
- `var x(get, set)` has its accessors `get_x`/`set_x`, and static members stay static.

Nothing else in the bytecode names the abstract: locals, fields and signatures all
carry the underlying type. So an abstract is declared with implicit casts from and to
that type (`abstract Name(T) from T to T`), which compile to no code, and each use
states the abstract where it's needed: `(x : Name).method()`.
"""

import threading
import weakref
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Optional, Tuple

from . import disasm
from .core import Bytecode, Fun, Function, Obj, Type, destaticify

IMPL_SUFFIX = "_Impl_"


@dataclass(frozen=True)
class Property:
    """A property of an abstract, read and written through its accessors."""

    name: str
    type: Type
    getter: Optional[int]
    setter: Optional[int]


@dataclass(frozen=True)
class Abstract:
    """One abstract of the image, from its `_Impl_` class."""

    #: The `$Name_Impl_` class holding the members.
    obj: Obj
    #: Path other code reaches the abstract by, in bytecode form (`pkg._Module.Name`;
    #: rendered `pkg.Module.Name`). The `_Impl_` class always carries the module that
    #: declares the abstract, which a secondary type of that module needs.
    path: str
    #: Name the declaration is written with, as `destaticify` gives a class's.
    declared: str
    #: The type the abstract wraps, or None when no member takes or builds one.
    underlying: Optional[Type]
    #: Methods taking the value as their leading argument, by findex.
    instance: FrozenSet[int]
    #: The constructor (`_new`), by findex.
    constructor: Optional[int]
    #: Instance properties by name.
    properties: Dict[str, Property] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.path.rsplit(".", 1)[-1]

    @property
    def module(self) -> str:
        """Source path of the module declaring the abstract (`pkg.Module`)."""
        prefix = self.path.rpartition(".")[0]
        package, _, module = prefix.rpartition(".")
        module = module.removeprefix("_")
        return f"{package}.{module}" if package else module

    def underlying_annotation(self, code: Bytecode) -> str:
        return disasm._haxe_annotation(code, self.underlying) if self.underlying is not None else "Dynamic"

    def header(self, code: Bytecode) -> str:
        """The declaration line, up to the opening brace."""
        underlying = self.underlying_annotation(code)
        return f"abstract {self.declared}({underlying}) from {underlying} to {underlying}"

    def accessor(self, findex: int) -> Optional[Tuple[Property, bool]]:
        """The property `findex` reads (False) or writes (True), if it's an accessor."""
        for prop in self.properties.values():
            if prop.getter == findex:
                return prop, False
            if prop.setter == findex:
                return prop, True
        return None


@dataclass
class _Index:
    by_obj: Dict[int, Abstract]
    by_findex: Dict[int, Abstract]


# Keyed by id(code) with a weakref back to it, like `pseudo._method_registry`:
# a Bytecode isn't hashable.
_cache: Dict[int, Tuple["weakref.ReferenceType[Bytecode]", _Index]] = {}
_cache_lock = threading.Lock()


def _takes_this(code: Bytecode, func: Function, arg_count: int) -> bool:
    """Whether a member's leading argument is the value (`this`). Older Haxe leaves
    it out of the debug names of the parameters, newer Haxe names it `this`, which a
    parameter can't be called otherwise."""
    if not func.has_debug or func.assigns is None or not arg_count:
        return False
    names = [assign[0].resolve(code) for assign in func.assigns if assign[1].value <= 0]
    if names and names[0] == "this":
        return True
    return len(set(names)) == arg_count - 1


def _abstract(code: Bytecode, obj: Obj) -> Optional[Abstract]:
    name = obj.name.resolve(code)
    # The members are bindings of the static half, `$Name_Impl_`.
    if not name.endswith(IMPL_SUFFIX) or not name.rpartition(".")[2].startswith("$"):
        return None
    functions = []
    for binding in obj.bindings:
        try:
            func = binding.findex.resolve(code)
        except Exception:
            continue
        if isinstance(func, Function):
            functions.append(func)
    # The std isn't recompiled from decompiled output; its abstracts keep their API.
    # With no members left there's nothing to declare either.
    if not functions or all(disasm.is_std(code, func) for func in functions):
        return None

    instance = set()
    constructor: Optional[int] = None
    underlying: Optional[Type] = None
    getters: Dict[str, Tuple[int, Type]] = {}
    setters: Dict[str, Tuple[int, Type]] = {}
    for func in functions:
        signature = func.type.resolve(code).definition
        if not isinstance(signature, Fun):
            continue
        method = code.partial_func_name(func)
        if method == "_new":
            constructor = func.findex.value
            underlying = signature.ret.resolve(code)
            continue
        if not _takes_this(code, func, len(signature.args)):
            continue
        instance.add(func.findex.value)
        if underlying is None:
            underlying = signature.args[0].resolve(code)
        if method.startswith("get_") and len(signature.args) == 1:
            getters[method[4:]] = (func.findex.value, signature.ret.resolve(code))
        elif method.startswith("set_") and len(signature.args) == 2:
            setters[method[4:]] = (func.findex.value, signature.args[1].resolve(code))

    properties = {}
    for prop in sorted(set(getters) | set(setters)):
        getter, setter = getters.get(prop), setters.get(prop)
        typ = getter[1] if getter is not None else setters[prop][1]
        if getter is not None and setter is not None and getter[1] is not setter[1]:
            continue  # accessors disagree on the type: not one property
        properties[prop] = Property(
            prop, typ, getter[0] if getter is not None else None, setter[0] if setter is not None else None
        )

    module, _, impl = name.rpartition(".")
    short = impl.lstrip("$")[: -len(IMPL_SUFFIX)]
    path = f"{module}.{short}" if module else short
    declared = destaticify(name)[: -len(IMPL_SUFFIX)]
    return Abstract(obj, path, declared, underlying, frozenset(instance), constructor, properties)


def _index(code: Bytecode) -> _Index:
    with _cache_lock:
        cached = _cache.get(id(code))
        if cached is not None and cached[0]() is code:
            return cached[1]
    by_obj: Dict[int, Abstract] = {}
    by_findex: Dict[int, Abstract] = {}
    for typ in code.types:
        obj = typ.definition
        if not isinstance(obj, Obj):
            continue
        found = _abstract(code, obj)
        if found is None:
            continue
        by_obj[id(obj)] = found
        try:
            dynamic = obj.dynamic
        except (ValueError, AttributeError):
            dynamic = None
        if isinstance(dynamic, Obj):
            by_obj[id(dynamic)] = found
        for binding in obj.bindings:
            by_findex[binding.findex.value] = found
    index = _Index(by_obj, by_findex)
    with _cache_lock:
        _cache[id(code)] = (weakref.ref(code), index)
    return index


def abstract_of(code: Bytecode, obj: Optional[Obj]) -> Optional[Abstract]:
    """The abstract whose `_Impl_` class (either half) `obj` is."""
    if obj is None:
        return None
    return _index(code).by_obj.get(id(obj))


def abstract_of_function(code: Bytecode, func: Function) -> Optional[Abstract]:
    """The abstract `func` is a member of."""
    return _index(code).by_findex.get(func.findex.value)
