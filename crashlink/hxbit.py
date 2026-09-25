"""
Recognition of classes rewritten by hxbit's `Serializable` macro.

The macro adds members a source file never contains: a class id (`__clid`,
`getCLID`), a unique id (`__uid`, set at the start of the root constructor),
the serialization methods themselves and a schema listing the `@:s` fields.
Rendering those would declare members that recompiling through the macro
generates again, so a serializable class is rendered the way it was written:
`implements hxbit.Serializable` on the root class, `@:s` on the serialized
fields, and none of the generated members.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, List, Optional, Set

from .core import Bytecode, Obj, Type, Virtual

if TYPE_CHECKING:
    from .decomp.function import IRClass, IRFunction
    from .decomp.ir import IRBlock, IRStatement

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
    from .decomp.ir import IRCall, IRConst, IRField

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
    from .decomp.ir import IRCall, IRConst, IRLocal

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
    from .decomp.ir import IRAssign, IRField, IRLocal

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
    from .decomp.ir import IRAssign, IRField, IRLocal

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
