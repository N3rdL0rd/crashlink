"""
Std/native naming helpers: class identification, method registries and std-member access.
"""

from __future__ import annotations

import functools
import re
import weakref
from typing import Optional, List, Dict, FrozenSet, Tuple
from ..core import Bytecode, Obj, Type, Function, Fun, Native, Struct, destaticify, gIndex
from .. import disasm
from ..errors import MalformedBytecode
from .. import abstracts, rtti_meta
from ..std_types import STD_TYPES
from ..decomp import IRFunction, IRExpression, IRConst, IRCall


_BASIC_TYPE_NAMES = {
    Type.Kind.I32.value: "Int",
    Type.Kind.F64.value: "Float",
    Type.Kind.BOOL.value: "Bool",
    Type.Kind.DYN.value: "Dynamic",
}


class _PseudoClass:
    """Lightweight stand-in for IRClass when pseudo() is called on a bare IRFunction."""

    __slots__ = ("dynamic", "static", "methods")

    def __init__(self, obj: Obj, methods: List[IRFunction]):
        # Bindings (e.g. a __constructor__ wrapper) are registered against the
        # *static* companion class, not the dynamic/instance one — if `obj`
        # is static, route it to its real dynamic counterpart so the actual
        # class hierarchy (super chain, instance fields) is visible.
        self.static: Optional[Obj] = None
        if obj.is_static and obj.dynamic is not None:
            self.dynamic = obj.dynamic
            self.static = obj
        else:
            self.dynamic = obj
        self.methods = methods


# Keyed by id(code), but the value carries a weakref back to `code` so a lookup
# can confirm the cached entry is still for *this* object. A plain id()-keyed
# dict without that check is a latent bug: once `code` is GC'd, a later,
# unrelated Bytecode can be allocated at the same address and silently get
# served someone else's stale registry. `Bytecode` (via Serialisable.__eq__)
# isn't hashable, so a WeakKeyDictionary keyed on `code` itself isn't an option.
_method_registry_cache: Dict[
    int, Tuple["weakref.ReferenceType[Bytecode]", Dict[int, Tuple[Obj, str, bool]]]
] = {}


def _method_registry(code: Bytecode) -> Dict[int, Tuple[Obj, str, bool]]:
    """Map findex -> (class Obj, method name, is_instance) using Obj protos/bindings."""
    cache_key = id(code)
    cached = _method_registry_cache.get(cache_key)
    if cached is not None and cached[0]() is code:
        return cached[1]
    registry: Dict[int, Tuple[Obj, str, bool]] = {}
    for t in code.types:
        if t.kind.value not in (Type.Kind.OBJ.value, Type.Kind.STRUCT.value):
            continue
        obj = t.definition
        if not isinstance(obj, Obj):
            continue
        for proto in obj.protos:
            fn = proto.findex.resolve(code)
            if isinstance(fn, Function):
                registry[fn.findex.value] = (obj, proto.name.resolve(code), True)
        for binding in obj.bindings:
            fn = binding.findex.resolve(code)
            if isinstance(fn, Function):
                field = binding.field.resolve_obj(code, obj)
                # Bound on the instance half: a `dynamic` method's default body.
                registry[fn.findex.value] = (obj, field.name.resolve(code), not obj.is_static)
    _method_registry_cache[cache_key] = (weakref.ref(code), registry)
    return registry


_BASIC_TYPE_NAMES = {
    Type.Kind.I32.value: "Int",
    Type.Kind.F64.value: "Float",
    Type.Kind.BOOL.value: "Bool",
    Type.Kind.DYN.value: "Dynamic",
}


_basic_type_globals_cache: Dict[int, Tuple["weakref.ReferenceType[Bytecode]", Dict[int, str]]] = {}


def _basic_type_globals(code: Bytecode) -> Dict[int, str]:
    """Map global index -> `Int`/`Float`/`Bool`/`Dynamic` for the globals holding those runtime types.

    HL has no class for them: the compiler's init code allocates a core type object, stores the
    primitive type in its `__type__` field and puts it in a global, which is what `Int` as a value
    (`Std.isOfType(v, Int)`) reads."""
    cached = _basic_type_globals_cache.get(id(code))
    if cached is not None and cached[0]() is code:
        return cached[1]
    found: Dict[int, str] = {}
    for func in code.functions:
        type_regs: Dict[int, str] = {}
        typed_objs: Dict[int, str] = {}
        for op in func.ops:
            df = op.df
            if op.op == "Type":
                basic = _BASIC_TYPE_NAMES.get(df["ty"].resolve(code).kind.value)
                if basic is not None:
                    type_regs[df["dst"].value] = basic
                else:
                    type_regs.pop(df["dst"].value, None)
            elif op.op == "New":
                typed_objs.pop(df["dst"].value, None)
            elif op.op == "SetField" and df["field"].value == 0 and df["src"].value in type_regs:
                typed_objs[df["obj"].value] = type_regs[df["src"].value]
            elif op.op == "SetGlobal" and df["src"].value in typed_objs:
                found[df["global"].value] = typed_objs[df["src"].value]
    _basic_type_globals_cache[id(code)] = (weakref.ref(code), found)
    return found


def _rtti_type_meta(code: Bytecode, name: str) -> str:
    """`@a @b(1) ` for the runtime metadata of the type registered as `name`."""
    meta = rtti_meta.for_type(code, destaticify(name).lstrip("$"))
    return rtti_meta.render_entries(meta.type) if meta is not None else ""


def _rtti_member_meta(code: Bytecode, owner: Optional[Obj], member: str, static: bool) -> str:
    """Runtime metadata of a field or method of the class `owner` (either half)."""
    if owner is None:
        return ""
    meta = rtti_meta.for_type(code, destaticify(owner.name.resolve(code)).lstrip("$"))
    if meta is None:
        return ""
    if not static and member in ("new", "__constructor__"):
        member = "_"  # the constructor's metadata is kept under `_`
    table = (meta.statics if static else meta.fields).get(member)
    return rtti_meta.render_entries(table) if table else ""


def _struct_meta(obj: Optional[Obj]) -> str:
    """`@:struct ` for a class the image stores as a struct (a plain pointer-free HL layout)."""
    return "@:struct " if isinstance(obj, Struct) else ""


def _containing_class_for(ir_func: IRFunction, code: Bytecode) -> Optional[_PseudoClass]:
    """Return a lightweight containing class for instance methods, or None."""
    info = _method_registry(code).get(ir_func.func.findex.value)
    if info is None:
        return None
    # Constructors are registered as bindings (is_instance=False in the
    # registry, since they aren't virtual/vtable methods), but they still
    # need their containing class attached — e.g. to detect a `super(...)`
    # delegation call to the parent's own constructor.
    if not info[2] and code.partial_func_name(ir_func.func) != "__constructor__":
        return None
    return _PseudoClass(info[0], [ir_func])


def _containing_class_name(ir_function: Optional[IRFunction], code: Bytecode) -> Optional[str]:
    """Return the de-staticified name of the class containing the current function."""
    if ir_function is None:
        return None
    containing = getattr(ir_function, "_containing_class", None)
    if not containing or not containing.dynamic:
        return None
    return destaticify(containing.dynamic.name.resolve(code))


def global_name(const: "IRConst") -> str:
    """Synthesized name for a raw HL global with no source-level name (see varN)."""
    assert isinstance(const.original_index, gIndex)
    return f"global{const.original_index.value}"


def _std_property_accessor_name(func: "Function", code: Bytecode, remaining_args: int) -> Optional[str]:
    """If func is a std-lib get_X()/set_X(v) property accessor, return X.

    The accessor method is private, so a decompiled direct call to it (as
    opposed to via the property it backs) fails to recompile. User-defined
    classes aren't affected here since their accessors are usually reachable
    (default Haxe visibility already allows same-class/subclass calls).
    """
    parts = _func_name_parts(func, code)
    if not parts:
        return None
    name = parts[-1]
    if name.startswith("get_") and remaining_args == 0:
        prop_name = name[4:]
    elif name.startswith("set_") and remaining_args == 1:
        prop_name = name[4:]
    else:
        return None
    if not prop_name or not _is_std_function(func, code):
        return None
    return prop_name


def _is_std_private_type(typ: "Type", code: Bytecode) -> bool:
    """True for a type the std declares `private` in another type's module: the bytecode
    names it `pkg._Module.Name`, and source outside that module can't name it."""
    name = disasm.type_name(code, typ)
    return name in STD_TYPES and bool(re.search(r"\._[^.]+\.[^.]+$", name))


def _is_std_call(expr: IRExpression) -> bool:
    """Whether `expr` calls a function of the standard library directly."""
    return (
        isinstance(expr, IRCall)
        and isinstance(expr.target, IRConst)
        and isinstance(expr.target.value, Function)
        and _is_std_function(expr.target.value, expr.code)
    )


def _is_std_function(func: "Function", code: Bytecode) -> bool:
    """Return True if the function originates from the Haxe standard library."""
    try:
        path = func.resolve_file(code)
    except (ValueError, IndexError, MalformedBytecode):
        # No debug info (ValueError) or a corrupt debug-file index: the origin
        # is not provably /std/.
        return False
    return "/std/" in path.replace("\\", "/")


def _std_private_access(
    rendered: str, owner: Obj, member: str, code: Bytecode, ir_function: Optional[IRFunction]
) -> str:
    """`rendered` (an access to `owner.member`), in `@:privateAccess` when that's a private
    member of a std type and the access isn't from inside the type."""
    owner_name = destaticify(owner.name.resolve(code))
    abstract = abstracts.abstract_of(code, owner)
    if abstract is not None and abstract.std:
        # The private static of a std abstract (an inlined `Int64.make` reads `MASK`).
        if _is_private_std_member(abstract.module, member):
            return f"(@:privateAccess {rendered})"
        return rendered
    if (
        _is_private_std_member(owner_name, member)
        and _containing_class_name(ir_function, code) != owner_name
        and _is_std_class_obj(code, owner)
    ):
        return f"(@:privateAccess {rendered})"
    return rendered


def _is_private_std_member(class_name: str, member_name: str) -> bool:
    """Return True if Haxe hides this std member from code outside its type."""
    if member_name.startswith("__"):
        return True  # compiler internals (`__alloc__`, `__constructor__`)
    members = _private_std_members(class_name.lstrip("$"))
    return members is not None and member_name in members


@functools.lru_cache(maxsize=None)
def _private_std_members(class_name: str) -> Optional[FrozenSet[str]]:
    """The private members of a std type by its bytecode name. Debug names are sometimes
    unqualified, and a secondary type (`hl.CoreType`) drops its module, so a name that isn't
    a path in the table matches by simple name; an HL specialisation of a generic class
    (`ArrayBytes_Int`) by the class it specialises."""
    from ..std_private import PRIVATE_STD_MEMBERS

    if class_name in PRIVATE_STD_MEMBERS:
        return PRIVATE_STD_MEMBERS[class_name]
    for name in (class_name.rsplit(".", 1)[-1], class_name.rsplit(".", 1)[-1].split("_", 1)[0]):
        matches = [
            members for path, members in PRIVATE_STD_MEMBERS.items() if path.rsplit(".", 1)[-1] == name
        ]
        if matches:
            return frozenset().union(*matches)
    return None


def _call_needs_private_access(func: "Function", code: Bytecode) -> bool:
    """Return True if a direct call to `func` has to be rendered inside an
    `@:privateAccess` expression to recompile."""
    if not _is_std_function(func, code):
        return False
    parts = _func_name_parts(func, code)
    if not parts:
        return False
    return _is_private_std_member(*parts)


def _func_name_parts(func: "Function", code: Bytecode) -> Optional[Tuple[str, str]]:
    """Return (class_name, method_name) for a function named like 'Class.method'."""
    name: Optional[str] = code.partial_func_name(func)
    if not name or name == "<none>":
        name = None
    if name and "." in name:
        class_name, method_name = name.rsplit(".", 1)
        return class_name, method_name
    # Static wrappers often drop the class from the partial name; use the full name.
    full = code.full_func_name(func)
    if full and full != "<none>.<none>" and "." in full:
        class_name, method_name = full.rsplit(".", 1)
        return destaticify(class_name), method_name
    return None


def _is_constructor_call(func: "Function", code: Bytecode) -> bool:
    """Return True if this function is a static __constructor__ wrapper."""
    parts = _func_name_parts(func, code)
    if not parts:
        return False
    return parts[1] == "__constructor__"


def _std_func_name(func: "Function", code: Bytecode) -> str:
    """Return a unique, valid Haxe identifier for a std library function."""
    base = code.partial_func_name(func) or "anon"
    if base == "<none>":
        base = "anon"
    base = base.replace("<", "").replace(">", "").replace(".", "_")
    return f"__std_{func.findex.value}_{base}"


def _std_call_name(func: "Function", code: Bytecode) -> Optional[str]:
    """Return a Haxe-qualified name like 'Std.random' for a std call, or None."""
    full = code.full_func_name(func)
    if not full or full == "<none>.<none>":
        return None
    if "." not in full:
        return None
    class_name, method_name = full.rsplit(".", 1)
    class_name = destaticify(class_name).lstrip("$")
    # Keep synthetic internal helpers as extern stubs.
    if method_name.startswith("__") and method_name != "__init__":
        return None
    return f"{class_name}.{method_name}"


def _is_arrayobj_alloc_call(func: "Function", call: "IRCall", code: Bytecode) -> bool:
    """Return True for anonymous ArrayObj factory calls like alloc(arr)."""
    try:
        path = func.resolve_file(code)
    except (ValueError, IndexError, MalformedBytecode):
        # No debug info (ValueError) or a corrupt debug-file index: not
        # provably the ArrayObj factory.
        return False
    if "ArrayObj.hx" not in path.replace("\\", "/"):
        return False
    fun_type = func.type.resolve(code).definition
    if not isinstance(fun_type, Fun):
        return False
    if len(fun_type.args) != 1 or len(call.args) != 1:
        return False
    ret_name = disasm.type_name(code, fun_type.ret.resolve(code))
    return "ArrayObj" in ret_name


def _is_string_alloc_call(func: "Function", call: "IRCall", code: Bytecode) -> bool:
    """Return True for String.__alloc__(bytes, length) factory calls."""
    try:
        path = func.resolve_file(code)
    except (ValueError, IndexError, MalformedBytecode):
        # No debug info (ValueError) or a corrupt debug-file index: not
        # provably the String factory.
        return False
    if "String.hx" not in path.replace("\\", "/"):
        return False
    if code.partial_func_name(func) != "__alloc__":
        return False
    fun_type = func.type.resolve(code).definition
    if not isinstance(fun_type, Fun):
        return False
    return len(fun_type.args) == 2 and len(call.args) == 2


def _call_renders_as_std_stub(func: "Function", call: "IRCall", code: Bytecode) -> bool:
    """Return True if this std call actually renders as a `StdFuncs.` stub.

    Calls that resolve to a Haxe-qualified name (Std.random, Math.random, ...)
    or that get folded away (String.__add__ -> `+`, String.__alloc__ -> the
    interpolated value) do not need an extern declaration.
    """
    # Resolves to a real Haxe name, e.g. Std.random / Math.random.
    if _std_call_name(func, code) is not None:
        return False
    # Anonymous ArrayObj alloc factory is rendered as `alloc(arr)`.
    if _is_arrayobj_alloc_call(func, call, code):
        return False
    partial = code.partial_func_name(func)
    # String.__add__(a, b) is rendered with the `+` operator.
    if partial == "__add__" and len(call.args) == 2:
        return False
    # String.__alloc__(bytes, length) is rendered as `__alloc__(...)` (or
    # `String.__alloc__(...)` outside the String class), so it never needs a stub.
    if partial == "__alloc__" and _is_string_alloc_call(func, call, code):
        return False
    return True


def _std_native_api(native: Native, code: Bytecode) -> Optional[Tuple[str, str, bool, bool]]:
    """The std method a native implements, as (type, method, is_static, is_public), if it's one."""
    from ..std_natives import STD_NATIVES

    return STD_NATIVES.get((native.lib.resolve(code), native.name.resolve(code)))


def _std_native_value(native: Native, code: Bytecode) -> Optional[str]:
    """A native used as a value, as its std API: only a static member is one without a receiver."""
    api = _std_native_api(native, code)
    if api is None or not api[2]:
        return None
    ref = f"{api[0]}.{api[1]}"
    return ref if api[3] else f"(@:privateAccess {ref})"


def _native_binding_name(native: Native, code: Bytecode) -> str:
    name = re.sub(r"[^A-Za-z0-9_]", "_", native.name.resolve(code))
    return f"n{native.findex.value}_{name}"


# Std classes that expose only static fields (no functions), so the file-path
# check below never sees them. Fields carry no source-path info in HL bytecode.
_FIELD_ONLY_STD_CLASSES = {"Math"}


def _is_std_class_obj(code: Bytecode, obj: Obj) -> bool:
    """
    True when the Obj (or its static/dynamic counterpart) has member functions
    and every one of them comes from a /std/ file — i.e. a standard-library
    class. Memberless classes are treated as user data classes (bytecode holds
    no source path to prove otherwise).
    """
    if destaticify(obj.name.resolve(code)) in _FIELD_ONLY_STD_CLASSES:
        return True
    objs = [obj]
    for attr in ("static", "dynamic"):
        try:
            other = getattr(obj, attr)
        except (ValueError, AttributeError):
            continue
        if isinstance(other, Obj):
            objs.append(other)
    has_members = False
    for o in objs:
        for member in list(o.protos) + list(o.bindings):
            try:
                fn = member.findex.resolve(code)
            except MalformedBytecode:
                # Corrupt bytecode: the member's findex is not in the map —
                # skip it.
                continue
            if isinstance(fn, Function):
                has_members = True
                try:
                    path = fn.resolve_file(code).replace("\\", "/")
                except (ValueError, IndexError, MalformedBytecode):
                    # A member's origin can't be resolved (no debug info or a
                    # corrupt index): not provably std — treat as user code.
                    return False
                if "/std/" not in path:
                    return False
    return has_members
