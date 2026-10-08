"""Recovery of runtime metadata (`@name(args)`, read back with `haxe.rtti.Meta`).

Haxe keeps the metadata that has no `:` as an object in the `__meta__` field of the type's
`hl.BaseType`: `{obj: {name: [args]}, fields: {field: {name: [args]}}, statics: {...}}`. The
image's entry function registers each class (`f(staticType, type, "pack.Name")`) and builds
the object with plain allocations and stores, so a small interpreter over its straight-line
prefix reads them back.
"""

from __future__ import annotations

import weakref
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .core import Bytecode, DynObj, Enum, Function, Native, Obj

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
                if (
                    dst is not None
                    and isinstance(holder, _TypeRef)
                    and isinstance(holder.type.definition, Enum)
                ):
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
