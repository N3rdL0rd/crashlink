"""
Class member declaration helpers: fields, properties, interfaces and extern collection.
"""

from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from typing import Optional, List, Set, Dict, Tuple, Iterator
from ..core import Bytecode, Obj, Ref, Type, Function, Fun, Native, Enum, destaticify
from .. import disasm
from ..errors import MalformedBytecode
from .. import typeinit
from ..decomp import IRField, IRNew, IRStatement, IRLocal, IRConst, IRCall, IRTryCatch, IREnumConstruct
from .naming import (
    _std_func_name,
    _is_arrayobj_alloc_call,
    _call_renders_as_std_stub,
    _std_native_api,
    _std_native_value,
    _native_binding_name,
    _is_std_class_obj,
)
from .hierarchy import _ancestors, _chain, _obj_pair, _obj_fields


def _collect_natives(root: IRStatement, code: Bytecode) -> List[Native]:
    """
    Recursively collect the Native constants an IR tree renders through the `Native`
    extern: the ones not written as their std API (see `_std_native_value`).
    """
    natives: Dict[int, Native] = {}
    seen: Set[int] = set()

    def visit(stmt: IRStatement) -> None:
        if id(stmt) in seen:
            return
        seen.add(id(stmt))
        if (
            isinstance(stmt, IRCall)
            and isinstance(stmt.target, IRConst)
            and isinstance(stmt.target.value, Native)
        ):
            api = _std_native_api(stmt.target.value, code)
            if api is None or (not api[2] and not stmt.args):
                natives[id(stmt.target.value)] = stmt.target.value
            for arg in stmt.args:
                visit(arg)
            return
        if isinstance(stmt, IRConst) and isinstance(stmt.value, Native):
            if _std_native_value(stmt.value, code) is None:
                natives[id(stmt.value)] = stmt.value
        for child in stmt.get_children():
            visit(child)

    visit(root)
    return list(natives.values())


def _collect_function_externs(root: IRStatement, code: Bytecode) -> Dict[int, Tuple[str, int]]:
    """
    Collect Function constants that are used as call targets and are not defined
    in user code (i.e. they come from the HashLink std library). Returns a dict
    mapping findex to (valid Haxe identifier, max arity seen).
    """
    externs: Dict[int, Tuple[str, int]] = {}
    seen: Set[int] = set()

    def is_std_func(func: "Function") -> bool:
        try:
            path = func.resolve_file(code)
        except (ValueError, IndexError, MalformedBytecode):
            # No debug info (ValueError) or a corrupt debug-file index: the
            # origin is not provably /std/.
            return False
        return "/std/" in path.replace("\\", "/")

    def visit(stmt: IRStatement) -> None:
        if id(stmt) in seen:
            return
        seen.add(id(stmt))
        if (
            isinstance(stmt, IRCall)
            and isinstance(stmt.target, IRConst)
            and isinstance(stmt.target.value, Function)
        ):
            func = stmt.target.value
            if is_std_func(func) and _call_renders_as_std_stub(func, stmt, code):
                name = _std_func_name(func, code)
                arity = len(stmt.args)
                if func.findex.value in externs:
                    externs[func.findex.value] = (
                        name,
                        max(externs[func.findex.value][1], arity),
                    )
                else:
                    externs[func.findex.value] = (name, arity)
        for child in stmt.get_children():
            visit(child)

    visit(root)
    return externs


def _function_extern(externs: Dict[int, Tuple[str, int]], code: Bytecode) -> str:
    """
    Generate an extern class that declares std library functions called by the IR.
    Unsupported std signatures stay erased; callable slots retain their types.
    """
    if not externs:
        return ""

    lines = ["extern class StdFuncs {"]
    for findex, (name, arity) in sorted(externs.items()):
        func = next((func for func in code.functions if func.findex.value == findex), None)
        signature = func.type.resolve(code).definition if func is not None else None
        arg_types = ["Dynamic"] * arity
        ret = "Dynamic"
        if isinstance(signature, Fun) and len(signature.args) == arity:
            for i, index in enumerate(signature.args):
                typ = index.resolve(code)
                if isinstance(typ.definition, Fun):
                    arg_types[i] = disasm._haxe_annotation(code, typ)
            ret_type = signature.ret.resolve(code)
            if isinstance(ret_type.definition, Fun):
                ret = disasm._haxe_annotation(code, ret_type)
        params = ", ".join(f"arg{i}: {typ}" for i, typ in enumerate(arg_types))
        lines.append(f"    static function {name}({params}): {ret};")
    lines.append("}")
    return "\n".join(lines)


def _native_extern(natives: List[Native], code: Bytecode) -> str:
    """Declare real HashLink native bindings with their recovered signatures."""
    if not natives:
        return ""
    lines = ["extern class Native {"]
    emitted: Set[int] = set()
    for native in sorted(natives, key=lambda n: n.name.resolve(code)):
        if native.findex.value in emitted:
            continue
        emitted.add(native.findex.value)
        name = native.name.resolve(code)
        library = native.lib.resolve(code)
        fun = native.type.resolve(code).definition
        if not isinstance(fun, Fun):
            raise ValueError(f"Native {library}.{name} has no function signature")
        params = ", ".join(
            f"arg{i}: {disasm._haxe_annotation(code, arg.resolve(code), native=True)}"
            for i, arg in enumerate(fun.args)
        )
        ret = disasm._haxe_annotation(code, fun.ret.resolve(code), native=True)
        lines.append(f'    @:hlNative("{library}", "{name}")')
        lines.append(f"    public static function {_native_binding_name(native, code)}({params}): {ret};")
    lines.append("}")
    return "\n".join(lines)


def _annotation_dependencies(typ: Type, code: Bytecode, seen: Set[int]) -> Iterator[Type]:
    """Named types needed by signatures, including nested callable/enum payloads."""
    if id(typ) in seen:
        return
    seen.add(id(typ))
    definition = typ.definition
    if isinstance(definition, Fun):
        for index in [*definition.args, definition.ret]:
            yield from _annotation_dependencies(index.resolve(code), code, seen)
    elif isinstance(definition, Ref):
        yield from _annotation_dependencies(definition.type.resolve(code), code, seen)
    elif isinstance(definition, Enum):
        yield typ
        for constructor in definition.constructs:
            for index in constructor.params:
                yield from _annotation_dependencies(index.resolve(code), code, seen)
    elif isinstance(definition, Obj):
        name = definition.name.resolve(code)
        if disasm.type_to_haxe(name) == destaticify(name):
            yield typ


def _local_annotation_types(local: IRLocal) -> Iterator[Type]:
    yield local.get_type()
    if local.array_elem_type is not None:
        yield local.array_elem_type
    if local.native_elem_type is not None:
        yield local.native_elem_type


def _collect_referenced_user_classes(root: IRStatement, code: Bytecode, exclude: Set[str]) -> Set[str]:
    """
    Recursively collect names of user-defined (non-std) classes referenced in the
    IR via type constants, object allocation, field access, etc.
    """
    names: Set[str] = set()
    seen: Set[int] = set()
    seen_types: Set[int] = set()

    def is_user_type(typ: Type) -> bool:
        if not isinstance(typ.definition, Obj):
            return False
        try:
            return not _is_std_class_obj(code, typ.definition)
        except IndexError:
            # Corrupt bytecode: the class-name index is out of range — leave the
            # name out of the referenced set.
            return False

    def visit(stmt: IRStatement) -> None:
        if id(stmt) in seen:
            return
        seen.add(id(stmt))
        annotation_types: List[Type] = []
        if isinstance(stmt, IRLocal):
            annotation_types.extend(_local_annotation_types(stmt))
        elif isinstance(stmt, IRConst) and isinstance(stmt.value, (Function, Native)):
            annotation_types.append(stmt.value.type.resolve(code))
        for annotation in annotation_types:
            for typ in _annotation_dependencies(annotation, code, seen_types):
                if is_user_type(typ):
                    name = destaticify(disasm.type_name(code, typ))
                    if name not in exclude:
                        names.add(name)
        if (
            isinstance(stmt, IRConst)
            and isinstance(stmt.value, Type)
            and isinstance(stmt.value.definition, Obj)
        ):
            name = destaticify(stmt.value.definition.name.resolve(code))
            if name not in exclude and is_user_type(stmt.value):
                names.add(name)
        elif isinstance(stmt, IRConst) and isinstance(stmt.value, Function):
            # A call target's owning class (e.g. `Meter_Impl_.add(...)`) isn't
            # referenced via any Type/Field/New node, so it wouldn't otherwise
            # be pulled in as a class the recompiled output needs to compile.
            findex = stmt.value.findex.value
            owner_obj = None
            if code._proto_owner_map:
                owner_obj = code._proto_owner_map.get(findex)
            if owner_obj is None and code._field_owner_map:
                owner_obj = code._field_owner_map.get(findex)
            if owner_obj is not None:
                name = destaticify(owner_obj.name.resolve(code))
                if name not in exclude and not _is_std_class_obj(code, owner_obj):
                    names.add(name)
        elif isinstance(stmt, IRNew):
            new_type = stmt.get_type()
            if isinstance(new_type.definition, Obj):
                name = destaticify(disasm.type_name(code, new_type))
                if name not in exclude and is_user_type(new_type):
                    names.add(name)
        elif isinstance(stmt, IRField):
            target_type = stmt.target.get_type()
            if isinstance(target_type.definition, Obj):
                name = destaticify(target_type.definition.name.resolve(code))
                if name not in exclude and is_user_type(target_type):
                    names.add(name)
        elif isinstance(stmt, IRTryCatch):
            # Restored typed catches may bind a class that is never otherwise
            # referenced in the bodies (`catch (e:Unused)`); the clause types
            # still need to exist for recompilation.
            clause_locals = [stmt.catch_local] + [loc for loc, _ in stmt.extra_catches]
            for loc in clause_locals:
                if loc is None:
                    continue
                loc_type = loc.get_type()
                if isinstance(loc_type.definition, Obj):
                    name = destaticify(loc_type.definition.name.resolve(code))
                    if name not in exclude and is_user_type(loc_type):
                        names.add(name)
        for child in stmt.get_children():
            visit(child)

    visit(root)
    return names


def _collect_anonymous_functions(root: IRStatement, code: Bytecode) -> Dict[int, "Function"]:
    """
    Collect anonymous functions (closures and compiler adapters) referenced in the IR.
    These are emitted as private static helper methods so the decompiled output
    compiles cleanly.
    """
    funcs: Dict[int, "Function"] = {}
    seen: Set[int] = set()

    def visit(stmt: IRStatement) -> None:
        if id(stmt) in seen:
            return
        seen.add(id(stmt))
        if (
            isinstance(stmt, IRCall)
            and isinstance(stmt.target, IRConst)
            and isinstance(stmt.target.value, Function)
            and _is_arrayobj_alloc_call(stmt.target.value, stmt, code)
        ):
            # This call renders as ArrayObj.alloc, not an anonymous reference.
            for arg in stmt.args:
                visit(arg)
            return
        if isinstance(stmt, IRConst) and isinstance(stmt.value, Function):
            func = stmt.value
            name = code.partial_func_name(func)
            if not name or name == "<none>":
                funcs[func.findex.value] = func
        for child in stmt.get_children():
            visit(child)

    visit(root)
    return funcs


def _collect_referenced_enums(root: IRStatement, code: Bytecode) -> Dict[str, "Enum"]:
    """Collect enum types referenced in the IR.

    Keyed by the Enum *definition object*, not its display name: HashLink
    reuses name index 0 for anonymous/synthetic enum types (e.g. closure
    capture contexts), so distinct enum types can legitimately share a raw
    name. A name-keyed dict would silently drop one of them.
    """
    enums: Dict[int, "Enum"] = {}
    seen: Set[int] = set()
    seen_types: Set[int] = set()

    def add(definition: "Enum") -> None:
        enums[id(definition)] = definition

    def visit(stmt: IRStatement) -> None:
        if id(stmt) in seen:
            return
        seen.add(id(stmt))
        annotation_types: List[Type] = []
        if isinstance(stmt, IRLocal):
            annotation_types.extend(_local_annotation_types(stmt))
        elif isinstance(stmt, IRConst) and isinstance(stmt.value, (Function, Native)):
            annotation_types.append(stmt.value.type.resolve(code))
        for annotation in annotation_types:
            for typ in _annotation_dependencies(annotation, code, seen_types):
                if isinstance(typ.definition, Enum):
                    add(typ.definition)
        if (
            isinstance(stmt, IRConst)
            and isinstance(stmt.value, Type)
            and isinstance(stmt.value.definition, Enum)
        ):
            add(stmt.value.definition)
        elif isinstance(stmt, IRField):
            target_type = stmt.target.get_type()
            if isinstance(target_type.definition, Enum):
                add(target_type.definition)
        elif isinstance(stmt, IREnumConstruct):
            target_type = stmt.get_type()
            if isinstance(target_type.definition, Enum):
                add(target_type.definition)
        for child in stmt.get_children():
            visit(child)

    visit(root)
    return {destaticify(disasm._enum_name(code, definition)): definition for definition in enums.values()}


@dataclass
class ProjectExterns:
    """Natives and std functions the modules of a project call, declared once for all
    of them (`extern class Native`, `extern class StdFuncs` in the root package)."""

    natives: Dict[int, Native] = dc_field(default_factory=dict)
    functions: Dict[int, Tuple[str, int]] = dc_field(default_factory=dict)

    def declarations(self, code: Bytecode) -> Dict[str, str]:
        """Module name -> source of the extern classes, for the ones anything calls."""
        result = {}
        if self.natives:
            result["Native"] = _native_extern(list(self.natives.values()), code)
        if self.functions:
            result["StdFuncs"] = _function_extern(self.functions, code)
        return result


@dataclass
class ModuleDeclaration:
    """A class rendered as a declaration of a project module (see `crashlink.project`):
    under its short name, `private` when only its module may name it, and with the
    externs it calls collected in `externs` rather than declared before it."""

    name: str
    private: bool
    externs: ProjectExterns


def _implements_clause(code: Bytecode, dynamic: Optional[Obj]) -> str:
    """` implements I` for each interface the class is registered as implementing, but one
    another of them extends. hxbit's `Serializable` is left to `hxbit`: its macro
    regenerates the members it requires."""
    implemented = typeinit.implemented(code, dynamic)
    implied = {id(ancestor) for interface in implemented for ancestor in interface.ancestors()}
    return "".join(
        f" implements {disasm.type_to_haxe(interface.name)}"
        for interface in implemented
        if interface.name != "hxbit.Serializable" and id(interface) not in implied
    )


def _stored_property(code: Bytecode, dynamic: Optional[Obj], name: str) -> str:
    """The access of a field that is a property with storage (`@:isVar var x(get, set)`), or
    "". The bytecode keeps only the accessors beside the field; a structure over the
    property (`{ var x(get, set): T }`) is what shows the field is one, and a class's field
    can only be assigned to it if declared with the same access."""
    kinds = disasm.structure_property_kinds(code).get(name)
    if dynamic is None or kinds is None:
        return ""
    methods = {proto.name.resolve(code) for obj in _chain(code, dynamic) for proto in obj.protos}
    if f"get_{name}" not in methods:
        return ""
    return f"(get, {'set' if f'set_{name}' in methods else 'null'})"


def _field_declaration(
    code: Bytecode, dynamic: Optional[Obj], name: str, annotation: str, meta: str = ""
) -> str:
    access = _stored_property(code, dynamic, name)
    if access:
        return f"{meta}@:isVar public var {name}{access}: {annotation};"
    return f"{meta}public var {name}: {annotation};"


def _interface_properties(code: Bytecode, interface: typeinit.Interface) -> Dict[str, Tuple[bool, Type]]:
    """Fields of an interface that are properties without storage, `name -> (has a setter,
    type)`: no implementor has the field itself, only accessors. Fields an implementor
    stores are rendered plain, on both sides, like the class's own."""
    names = {member.name.resolve(code) for member in interface.virtual.fields}
    found = {}
    for member in interface.virtual.fields:
        name = member.name.resolve(code)
        member_type = member.type.resolve(code)
        if isinstance(member_type.definition, Fun) or not interface.implementors:
            continue
        stored = any(
            name in [field.name.resolve(code) for field in obj.fields]
            for implementor in interface.implementors
            for obj in _chain(code, implementor)
        )
        if not stored:
            found[name] = (f"set_{name}" in names, member_type)
    return found


def _implementation(code: Bytecode, interface: typeinit.Interface, name: str) -> Optional[Function]:
    """An implementor's method `name`, inherited ones included."""
    for implementor in interface.implementors:
        for obj in _chain(code, implementor):
            for proto in obj.protos:
                if proto.name.resolve(code) == name:
                    func = proto.findex.resolve(code)
                    if isinstance(func, Function):
                        return func
    return None


def _implemented_properties(code: Bytecode, dynamic: Optional[Obj]) -> List[str]:
    """Declarations of the storage-less properties a class's interfaces require (see
    `_interface_properties`), in the first class of the chain implementing them. An
    accessor the bytecode doesn't have (an `inline` one, inlined everywhere) is declared
    too, failing if called."""
    if dynamic is None:
        return []
    ancestors = list(_ancestors(code, dynamic))
    inherited = {id(interface) for obj in ancestors for interface in typeinit.implemented(code, obj)}
    methods = {proto.name.resolve(code) for obj in _chain(code, dynamic) for proto in obj.protos}
    lines = []
    declared: Set[str] = set()
    for interface in typeinit.implemented(code, dynamic):
        if id(interface) in inherited:
            continue
        for name, (setter, typ) in _interface_properties(code, interface).items():
            if name in declared:
                continue
            declared.add(name)
            annotation = disasm._haxe_annotation(code, typ)
            lines.append(f"public var {name}(get, {'set' if setter else 'never'}): {annotation};")
            if f"get_{name}" not in methods:
                lines.append(
                    f'function get_{name}(): {annotation} {{ throw "get_{name}: inline, not in the bytecode"; }}'
                )
    return lines


def _interface_dependencies(code: Bytecode, interface: typeinit.Interface) -> Set[str]:
    """User classes an interface's member types name."""
    names: Set[str] = set()
    seen: Set[int] = set()
    for member in interface.virtual.fields:
        for typ in _annotation_dependencies(member.type.resolve(code), code, seen):
            definition = typ.definition
            if isinstance(definition, Obj) and not _is_std_class_obj(code, definition):
                names.add(destaticify(definition.name.resolve(code)))
    return names


def class_field_lines(code: Bytecode, obj: Obj) -> List[str]:
    """Field declarations (unindented) for the class `obj` belongs to: static fields
    first, then instance fields, typed from the Obj alone (no decompilation)."""
    dynamic, static = _obj_pair(obj)
    lines = [
        f"public static var {name}: {disasm._haxe_annotation(code, typ)};"
        for name, typ in _obj_fields(code, static)
    ]
    lines.extend(
        _field_declaration(code, dynamic, name, disasm._haxe_annotation(code, typ))
        for name, typ in _obj_fields(code, dynamic)
    )
    return lines
