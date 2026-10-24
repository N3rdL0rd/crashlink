"""Recovery of what the compiler attaches to classes: `haxe.rtti.Meta` metadata and hxbit's `Serializable` rewrites."""

from __future__ import annotations

import weakref
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

from ..core import Bytecode, DynObj, Enum, Function, Native, Obj, Type, Virtual

# ============================================================================
# rtti_meta
#
# Recovery of runtime metadata (`@name(args)`, read back with `haxe.rtti.Meta`).
#
# Haxe keeps the metadata that has no `:` as an object in the `__meta__` field of the type's
# `hl.BaseType`: `{obj: {name: [args]}, fields: {field: {name: [args]}}, statics: {...}}`. The
# image's entry function registers each class (`f(staticType, type, "pack.Name")`) and builds
# the object with plain allocations and stores, so a small interpreter over its straight-line
# prefix reads them back.
# ============================================================================

_cache: Dict[int, Tuple["weakref.ReferenceType[Bytecode]", Dict[str, "Meta"]]] = {}


@dataclass
class Meta:
    """The metadata of one type, as `{name: [argument values]}` tables."""

    type: Dict[str, List[Any]] = field(default_factory=dict)
    fields: Dict[str, Dict[str, List[Any]]] = field(default_factory=dict)
    statics: Dict[str, Dict[str, List[Any]]] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.type or self.fields or self.statics)


class _Dyn(dict):
    """A dynamic object under construction."""


@dataclass
class _TypeRef:
    """A type constant (`Type` op), kept for the name an enum is registered under."""

    type: Any


def render_value(value: Any) -> str:
    """Haxe source of a metadata argument."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
        return f'"{escaped}"'
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, list):
        return "[" + ", ".join(render_value(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ", ".join(f"{k}: {render_value(v)}" for k, v in value.items()) + "}"
    raise TypeError(type(value).__name__)


def render_entries(entries: Dict[str, List[Any]]) -> str:
    """`@a @b(1, 2) ` for a `{name: args}` table (args None for a bare `@a`)."""
    parts = []
    for name, args in entries.items():
        parts.append(f"@{name}({', '.join(render_value(a) for a in args)}) " if args else f"@{name} ")
    return "".join(parts)


def _table(value: Any) -> Dict[str, List[Any]]:
    if not isinstance(value, dict):
        return {}
    return {name: (args if isinstance(args, list) else []) for name, args in value.items()}


def _meta_of(raw: Any) -> Meta:
    meta = Meta()
    if not isinstance(raw, dict):
        return meta
    meta.type = _table(raw.get("obj"))
    for key, target in (("fields", meta.fields), ("statics", meta.statics)):
        group = raw.get(key)
        if isinstance(group, dict):
            for name, entries in group.items():
                target[name] = _table(entries)
    return meta


def recover(code: Bytecode) -> Dict[str, Meta]:
    """Metadata by the registered type name (`pack.Name`), for every type that has some."""
    cached = _cache.get(id(code))
    if cached is not None and cached[0]() is code:
        return cached[1]
    found: Dict[str, Meta] = {}
    try:
        entry = code.entrypoint.resolve(code)
        if isinstance(entry, Function):
            found = _scan(code, entry)
    except Exception:
        found = {}
    _cache[id(code)] = (weakref.ref(code), found)
    return found


def _scan(code: Bytecode, entry: Function) -> Dict[str, Meta]:
    values: Dict[int, Any] = {}
    names: Dict[int, str] = {}  # register -> the type name it was registered under
    found: Dict[str, Meta] = {}
    constants: Dict[int, str] = {}
    try:
        for const in code.constants:
            if const.fields:
                gtype = code.global_types[const._global.value].resolve(code)
                if isinstance(gtype.definition, Obj) and gtype.definition.name.resolve(code) == "String":
                    constants[const._global.value] = code.strings.value[const.fields[0].value]
    except Exception:
        constants = {}
    for op in entry.ops:
        name = str(op.op)
        df = op.df
        if name in ("JTrue", "JFalse", "JAlways", "JNull", "JNotNull", "Ret", "Switch"):
            if name == "Ret":
                break
            continue  # initialisation blocks are straight-line; branches guard unrelated work
        dst = df["dst"].value if "dst" in df else -1
        if name == "String":
            values[dst] = df["ptr"].resolve(code)
        elif name in ("Int", "Float"):
            number = getattr(df["ptr"].resolve(code), "value", None)
            if name == "Int" and isinstance(number, int) and number >= 0x80000000:
                number -= 0x100000000  # the pool holds the 32-bit pattern
            values[dst] = number
        elif name == "Bool":
            values[dst] = bool(df["value"].value)
        elif name == "Type":
            values[dst] = _TypeRef(df["ty"].resolve(code))
        elif name == "Null":
            values[dst] = None
        elif name == "GetGlobal":
            g = df["global"].value
            if g in constants:
                values[dst] = constants[g]
            else:
                values.pop(dst, None)
        elif name == "New":
            typ = entry.regs[dst].resolve(code).definition
            if isinstance(typ, DynObj):
                values[dst] = _Dyn()
            else:
                values.pop(dst, None)
        elif name in ("Mov", "ToDyn", "ToSFloat", "ToUFloat", "ToInt", "SafeCast", "UnsafeCast"):
            src = df["src"].value
            if src in values:
                values[dst] = values[src]
            else:
                values.pop(dst, None)
        elif name == "Ref":
            values[dst] = values.get(df["src"].value)
        elif name in ("Call1", "Call2", "Call3", "Call4", "CallN"):
            args = (
                [a.value for a in df["args"].value]
                if name == "CallN"
                else [df[f"arg{i}"].value for i in range(int(name[-1]))]
            )
            target = df["fun"].resolve(code)
            if isinstance(target, Function):
                fname = code.full_func_name(target)
            elif isinstance(target, Native):
                fname = f"{target.lib.resolve(code)}.{target.name.resolve(code)}"
            else:
                fname = ""
            if name == "Call2" and fname == "$Type.initEnum":
                holder = values.get(args[1])
                if dst >= 0 and isinstance(holder, _TypeRef) and isinstance(holder.type.definition, Enum):
                    names[dst] = holder.type.definition.name.resolve(code)
                continue
            if name == "Call3" and fname in ("$Type.initClass", "$Type.initEnum"):
                if dst >= 0 and isinstance(values.get(args[2]), str):
                    names[dst] = values[args[2]]
                continue
            if dst < 0:
                continue
            if fname.endswith("alloc_array") and len(args) == 2 and isinstance(values.get(args[1]), int):
                values[dst] = [None] * values[args[1]]
            elif args and isinstance(values.get(args[0]), list):
                values[dst] = values[args[0]]  # an array wrapper (`ArrayDyn.alloc(arr, true)`)
            else:
                values.pop(dst, None)
        elif name == "SetArray":
            array = values.get(df["array"].value)
            index = values.get(df["index"].value)
            if isinstance(array, list) and isinstance(index, int) and 0 <= index < len(array):
                array[index] = values.get(df["src"].value)
        elif name in ("SetField", "DynSet"):
            obj = values.get(df["obj"].value)
            if name == "DynSet":
                field_name = df["field"].resolve(code)
            else:
                try:
                    holder = entry.regs[df["obj"].value].resolve(code).definition
                    field_name = df["field"].resolve_obj(code, holder).name.resolve(code)
                except Exception:
                    continue
            source = df["src"].value
            if isinstance(obj, _Dyn):
                obj[field_name] = values.get(source)
            elif field_name == "__meta__" and df["obj"].value in names:
                meta = _meta_of(values.get(source))
                if meta:
                    found[names[df["obj"].value]] = meta
        else:
            if dst >= 0:
                values.pop(dst, None)
    return found


def for_type(code: Bytecode, name: str) -> Optional[Meta]:
    return recover(code).get(name)


# ============================================================================
# hxbit
#
# Recognition of classes rewritten by hxbit's `Serializable` macro.
#
# The macro adds members a source file never contains: a class id (`__clid`,
# `getCLID`), a unique id (`__uid`, set at the start of the root constructor),
# the serialization methods themselves and a schema listing the `@:s` fields.
# Rendering those would declare members that recompiling through the macro
# generates again, so a serializable class is rendered the way it was written:
# `implements hxbit.Serializable` on the root class, `@:s` on the serialized
# fields, and none of the generated members.
# ============================================================================

if TYPE_CHECKING:
    from ..decomp.function import IRClass, IRFunction
    from ..decomp.ir import IRBlock, IRStatement

# Always generated: a class may not declare these itself.
_GENERATED_METHODS = frozenset(
    {"getCLID", "getSerializeSchema", "unserializeInit", "doSerialize", "doUnserialize"}
)
# Generated unless the class overrides them, in which case the macro splices its
# code in place of `super.serialize(ctx)`. Only the generated ones take `__ctx`.
_CTX_METHODS = frozenset({"serialize", "unserialize"})
_CTX_PARAM = "__ctx"
_SERIALIZABLE_MEMBERS = frozenset({"getCLID", "serialize", "unserialize"})


@dataclass
class SerializableClass:
    """What the macro did to one class."""

    root: bool  # no serializable ancestor: the class that declares `implements`
    fields: List[str] = field(default_factory=list)  # its own `@:s` fields, in schema order


def _protos(code: Bytecode, obj: Obj) -> Set[str]:
    return {proto.name.resolve(code) for proto in obj.protos}


def _super(code: Bytecode, obj: Obj) -> Optional[Obj]:
    if obj.super is None or obj.super.value < 0:
        return None
    parent = obj.super.resolve(code).definition
    return parent if isinstance(parent, Obj) else None


def is_serializable(code: Bytecode, obj: Optional[Obj]) -> bool:
    """Whether `obj` or an ancestor went through the macro (it adds `getCLID`)."""
    seen: Set[int] = set()
    while obj is not None and id(obj) not in seen:
        seen.add(id(obj))
        if "getCLID" in _protos(code, obj):
            return True
        obj = _super(code, obj)
    return False


def serializable_class(ir_class: "IRClass") -> Optional[SerializableClass]:
    code = ir_class.code
    obj = ir_class.dynamic
    if obj is None or not is_serializable(code, obj):
        return None
    info = SerializableClass(root=not is_serializable(code, _super(code, obj)))
    schema = next((m for m in ir_class.methods if _method_name(m) == "getSerializeSchema"), None)
    if schema is not None:
        info.fields = _schema_fields(schema)
    return info


def _method_name(ir_func: "IRFunction") -> str:
    return ir_func.code.partial_func_name(ir_func.func) or ""


def _schema_fields(schema: "IRFunction") -> List[str]:
    """Names `getSerializeSchema` pushes onto `schema.fieldsNames`."""
    from ..decomp.ir import IRCall, IRConst, IRField

    names: List[str] = []
    seen: Set[int] = set()
    pending: List["IRStatement"] = [schema.block]
    while pending:
        node = pending.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if (
            isinstance(node, IRCall)
            and len(node.args) == 2
            and isinstance(node.args[0], IRField)
            and node.args[0].field_name == "fieldsNames"
            and isinstance(node.args[1], IRConst)
            and isinstance(node.args[1].value, str)
        ):
            names.append(node.args[1].value)
        pending.extend(reversed(node.get_children()))
    return names


def is_generated_method(ir_func: "IRFunction") -> bool:
    """A member the macro adds. `serialize`/`unserialize` are the class's own
    only when it overrode them: the macro then renamed the context parameter
    `__ctx` and spliced its code in at the `super` call (see
    `restore_serialize_override`)."""
    name = _method_name(ir_func)
    if name in _GENERATED_METHODS:
        return True
    if name in _CTX_METHODS:
        return _source_ctx_name(ir_func) is None
    return False


def _source_ctx_name(ir_func: "IRFunction") -> Optional[str]:
    """The name the source gave the context parameter of an overridden
    `serialize`/`unserialize`, read from the debug assigns (the macro's own
    `__ctx` alias sits before the function, at op -1)."""
    func = ir_func.func
    if not func.has_debug or not func.assigns:
        return None
    for name_ref, op in func.assigns:
        name = name_ref.resolve(ir_func.code)
        if op.value == 0 and name != _CTX_PARAM:
            return name
    return None


def restore_serialize_override(ir_func: "IRFunction") -> None:
    """Undo the macro's splice into an overridden `serialize`/`unserialize`:
    drop the generated calls after `super.x(ctx)` and give the context back
    its source name."""
    from ..decomp.ir import IRCall, IRConst, IRLocal

    source = _source_ctx_name(ir_func)
    if source is None or _method_name(ir_func) not in _CTX_METHODS:
        return
    generated = {"doSerialize", "doUnserialize", "customSerialize", "customUnserialize"}

    def is_generated_call(stmt: "IRStatement") -> bool:
        if not isinstance(stmt, IRCall):
            return False
        target = stmt.target
        if isinstance(target, IRConst) and hasattr(target.value, "findex"):
            return ir_func.code.partial_func_name(target.value) in generated
        return getattr(target, "field_name", None) in generated

    ir_func.block.statements = [s for s in ir_func.block.statements if not is_generated_call(s)]
    for local in ir_func.all_locals:
        if isinstance(local, IRLocal) and local.name == _CTX_PARAM:
            local.name = source


def is_generated_field(code: Bytecode, name: str, typ: Type, static: bool) -> bool:
    """`__clid`, `__uid`, and the cache of the object as a `Serializable`."""
    if static:
        return name == "__clid"
    if name == "__uid":
        return True
    definition = typ.definition
    return isinstance(definition, Virtual) and is_serializable_virtual(code, definition)


def strip_uid_prologue(ctor: "IRFunction") -> None:
    """Drop `this.__uid = Serializer.SEQ << 24 | ++Serializer.UID` (however it
    was lowered) from a root constructor."""
    from ..decomp.ir import IRAssign, IRField, IRLocal

    block: "IRBlock" = ctor.block
    stmts = block.statements
    uid = next(
        (
            i
            for i, stmt in enumerate(stmts)
            if isinstance(stmt, IRAssign)
            and isinstance(stmt.target, IRField)
            and stmt.target.field_name == "__uid"
            and isinstance(stmt.target.target, IRLocal)
            and stmt.target.target.name == "this"
        ),
        None,
    )
    if uid is None:
        return
    start = uid
    while start > 0 and _feeds_uid(ctor.code, stmts[start - 1]):
        start -= 1
    block.statements = stmts[:start] + stmts[uid + 1 :]


def _feeds_uid(code: Bytecode, stmt: "IRStatement") -> bool:
    """A temp or `hxbit.Serializer` counter update computing the new id."""
    from ..decomp.ir import IRAssign, IRField, IRLocal

    if not isinstance(stmt, IRAssign):
        return False
    target = stmt.target
    if isinstance(target, IRLocal):
        return target.name.startswith("var") and target.name[3:].isdigit()
    return isinstance(target, IRField) and _is_serializer(code, target.target.get_type())


def _is_serializer(code: Bytecode, typ: Type) -> bool:
    definition = typ.definition
    return isinstance(definition, Obj) and definition.name.resolve(code) == "hxbit.$Serializer"


def is_serializable_virtual(code: Bytecode, definition: Virtual) -> bool:
    """The structure HL lays `hxbit.Serializable` out as (interfaces are erased)."""
    return _SERIALIZABLE_MEMBERS | {"__uid"} <= {f.name.resolve(code) for f in definition.fields}


def is_generated_class(name: str) -> bool:
    """Per-enum serializers the macro emits (`hxbit.enumSer.<Enum>`)."""
    return name.startswith("hxbit.enumSer.")
