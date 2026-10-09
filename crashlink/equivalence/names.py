"""Image-independent names for the things an opcode refers to.

Two bytecode images number their types, functions, globals and fields differently even when they
come from the same program. A signature can only be compared across images if every reference is
replaced by something that does not depend on the numbering: a name, or, where a thing has no
name, a description of what it is. Whenever no stable description exists the name carries the raw
index and is marked `unstable`; such a signature is only ever equal to one from an image that
numbers things the same way, which keeps the comparison sound.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable, Dict, Optional, Set, Tuple

from ..core import (
    Abstract,
    Bytecode,
    Enum,
    Fun,
    Function,
    Native,
    Null,
    Obj,
    Packed,
    Ref,
    Type,
    Virtual,
)

if TYPE_CHECKING:
    pass

# Kinds whose values are integers of some width, as opposed to floats, objects or dynamic values.
INT_KINDS = frozenset({1, 2, 3, 4, 7})  # U8 U16 I32 I64 Bool
FLOAT_KINDS = frozenset({5, 6})  # F32 F64
VOID_KIND = 0


class Namer:
    """Stable names for the references of one bytecode image."""

    def __init__(self, code: Bytecode, function_digest: Callable[[Function], str]):
        self.code = code
        self._function_digest = function_digest
        self._types: Dict[int, str] = {}
        self._active: Set[int] = set()
        self.unstable = False
        """Set when a name had to fall back to a raw index."""

    # -- types --------------------------------------------------------------------------------

    def type_index(self, index: int) -> str:
        cached = self._types.get(index)
        if cached is not None:
            return cached
        if index in self._active:
            return f"rec@{index}"
        self._active.add(index)
        try:
            text = self.type(self.code.types[index])
        finally:
            self._active.discard(index)
        self._types[index] = text
        return text

    def type(self, typ: Type) -> str:
        code = self.code
        defn = typ.definition
        kind = typ.kind.value
        if isinstance(defn, Obj):
            return f"obj:{defn.name.resolve(code)}"
        if isinstance(defn, Enum):
            return f"enum:{defn.name.resolve(code)}"
        if isinstance(defn, Abstract):
            return f"abs:{defn.name.resolve(code)}"
        if isinstance(defn, Fun):
            args = ",".join(self.type_index(a.value) for a in defn.args)
            return f"fun({args})->{self.type_index(defn.ret.value)}"
        if isinstance(defn, (Ref, Null)):
            return f"{type(defn).__name__}({self.type_index(defn.type.value)})"
        if isinstance(defn, Packed):
            return f"Packed({self.type_index(defn.inner.value)})"
        if isinstance(defn, Virtual):
            fields = sorted(f"{f.name.resolve(code)}:{self.type_index(f.type.value)}" for f in defn.fields)
            return "virt{" + ",".join(fields) + "}"
        return Type.TYPEDEFS[kind].__name__

    def kind_of(self, index: int) -> int:
        return self.code.types[index].kind.value

    # -- functions ----------------------------------------------------------------------------

    def function(self, findex: int) -> Tuple[str, ...]:
        """A callee: its name if it has one, else the signature of its body (a lifted closure)."""
        code = self.code
        target = code.get_findex_map().get(findex)
        if target is None:
            self.unstable = True
            return ("fn?", str(findex))
        if isinstance(target, Native):
            return ("native", code.full_func_name(target))
        name = code.full_func_name(target)
        if name != "<none>":
            return ("fn", name)
        return ("anon", self._function_digest(target))

    def method(self, obj_type: Type, field: int) -> str:
        """The name a CallMethod/CallThis `field` operand addresses on a receiver of `obj_type`."""
        defn = obj_type.definition
        if isinstance(defn, Obj):
            proto = self.code.proto_by_pindex(defn, field)
            if proto is not None:
                return proto.name.resolve(self.code)
        elif isinstance(defn, Virtual) and field < len(defn.fields):
            return defn.fields[field].name.resolve(self.code)
        self.unstable = True
        return f"field{field}"

    def field(self, obj_type: Type, field: int) -> str:
        defn = obj_type.definition
        if isinstance(defn, (Obj, Virtual)):
            try:
                return defn.resolve_fields(self.code)[field].name.resolve(self.code)
            except (IndexError, ValueError):
                pass
        self.unstable = True
        return f"field{field}"

    # -- globals ------------------------------------------------------------------------------

    def global_(self, gindex: int) -> Tuple[str, ...]:
        """A global: a string constant by its text, a constant object by its contents, a class or
        enum holder by its type (each type has one)."""
        code = self.code
        desc = self.type_index(code.global_types[gindex].value)
        initial = code.initialized_globals.get(gindex)
        defn = code.global_types[gindex].resolve(code).definition
        if initial is not None:
            if isinstance(defn, Obj) and defn.name.resolve(code) == "String":
                try:
                    return ("str", code.const_str(gindex))
                except (ValueError, TypeError):
                    pass
            try:
                items = sorted((str(k), _plain(v)) for k, v in initial.items())
                return ("const", desc, repr(items))
            except _Unplain:
                pass
        elif isinstance(defn, (Obj, Enum)):
            return ("global", desc)
        self.unstable = True
        return ("global?", desc, str(gindex))


class _Unplain(Exception):
    pass


def _plain(value: object) -> object:
    if value is None or isinstance(value, (bool, int, float, str, bytes)):
        return value
    inner = getattr(value, "value", None)
    if isinstance(inner, (bool, int, float, str, bytes)):
        return inner
    raise _Unplain


def reg_kind(namer: Namer, func: Function, reg: int) -> int:
    return namer.kind_of(func.regs[reg].value)


def is_int_like(kind: int) -> bool:
    return kind in INT_KINDS


def optional_name(code: Bytecode, func: Function) -> Optional[str]:
    name = code.full_func_name(func)
    return None if name == "<none>" else name
