"""
Class hierarchy and member analysis: ancestors, overrides, fields and generic parameters.
"""

from __future__ import annotations

import weakref
from typing import Optional, List, Set, Dict, Tuple, Union, cast, Iterator, Iterable
from ..core import Bytecode, Obj, Type, Function, Fun, destaticify, tIndex, Dyn
from .. import disasm
from ..errors import MalformedBytecode
from .. import abstracts, generics, typeinit
from ..classgenerics import ScopeEntry, class_generics, method_root
from ..decomp import (
    IRClass,
    IRField,
    IRFunction,
    IRBlock,
    IRStatement,
    IRExpression,
    IRAssign,
    IRLocal,
    IRConst,
    IRCall,
    IRReturn,
)
from .naming import _PseudoClass, _containing_class_name, _func_name_parts


def _is_untyped_array_access_class(typ: "Type", code: Bytecode) -> bool:
    """True if `typ` is hl.types.ArrayBase/ArrayAccess — the type-erased base
    classes that back every concrete typed array (ArrayBytes_T, ArrayObj,
    ArrayDyn) but, unlike them, define no `@:arrayAccess` of their own."""
    name = disasm.type_name(code, typ)
    return name in ("hl.types.ArrayBase", "hl.types.ArrayAccess")


def _has_array_access(typ: "Type", code: Bytecode) -> bool:
    """True if `typ` is one of the concrete HL array classes, whose `get`/`set` are their `[]`.

    Any other receiver (a map, a class with its own `get`/`set`, a structure) has no
    array access in source, so a call of that name stays a call."""
    name = disasm.type_name(code, typ)
    return name.startswith("hl.types.Array") and not _is_untyped_array_access_class(typ, code)


def _instance_method(call: IRExpression, code: Bytecode) -> Optional[Function]:
    """The instance method a call invokes directly, if the call is one (its first argument is the receiver)."""
    if not (
        isinstance(call, IRCall)
        and isinstance(call.target, IRConst)
        and isinstance(call.target.value, Function)
        and call.call_type == IRCall.CallType.FUNC
    ):
        return None
    func = call.target.value
    abstract = abstracts.abstract_of_function(code, func)
    if _is_static_function(func, code) or (
        abstract is not None and func.findex.value not in abstract.instance
    ):
        return None
    return func


def _is_static_function(func: Function, code: Bytecode) -> bool:
    return (code.full_func_name(func) or "").rpartition(".")[0].rpartition(".")[2].startswith("$")


def _static_owner_path(code: Bytecode, obj: Obj, name: str, ir_function: Optional[IRFunction]) -> str:
    """How source names the class holding a static member: the abstract for an
    abstract's `_Impl_` class, which source can't name."""
    abstract = abstracts.abstract_of(code, obj)
    return _abstract_ref(abstract, code, ir_function) if abstract is not None else destaticify(name)


def _static_member_path(
    code: Bytecode, obj: Obj, name: str, field: str, ir_function: Optional[IRFunction]
) -> str:
    """`Owner.field`, or the bare field inside the owner when it is named like the class:
    `pkg.C.C` reads as the class itself, never the static `C`."""
    owner = _static_owner_path(code, obj, name, ir_function)
    if owner.rpartition(".")[2] == field and _containing_class_name(ir_function, code) == owner:
        return field
    return f"{owner}.{field}"


def _abstract_ref(abstract: abstracts.Abstract, code: Bytecode, ir_function: Optional[IRFunction]) -> str:
    """How code in `ir_function` names `abstract`: unqualified within its module (its
    own members, other abstracts of the module and the module's main class), qualified
    elsewhere."""
    if ir_function is not None and isinstance(ir_function.func, Function):
        caller = abstracts.abstract_of_function(code, ir_function.func)
        if caller is not None:
            module = caller.module
        else:
            module = destaticify(code.full_func_name(ir_function.func).rpartition(".")[0])
        if module == abstract.module:
            return abstract.name
    return abstract.path


#: Private abstracts of the std that source can't name, by the public property of their
#: module's main abstract that gives one: `new Access(xml).has` is the `HasAttribAccess`.
_PRIVATE_STD_ABSTRACT_PROPERTIES = {
    "haxe.xml._Access.NodeAccess": ("haxe.xml.Access", "node"),
    "haxe.xml._Access.AttribAccess": ("haxe.xml.Access", "att"),
    "haxe.xml._Access.HasAttribAccess": ("haxe.xml.Access", "has"),
    "haxe.xml._Access.HasNodeAccess": ("haxe.xml.Access", "hasNode"),
    "haxe.xml._Access.NodeListAccess": ("haxe.xml.Access", "nodes"),
}


def _abstract_constructor_body(ir_func: IRFunction, signature: Fun) -> None:
    """Rewrite the body of an abstract's `_new` into its constructor's. `_new` returns
    the value it built; source assigns it to `this`. When every return gives back the
    same local, that local is `this`; otherwise each returned value is assigned to it."""
    if getattr(ir_func, "_abstract_constructor", False):
        return
    setattr(ir_func, "_abstract_constructor", True)
    code = ir_func.code
    returns: List[Tuple[IRBlock, int]] = []
    seen: Set[int] = set()
    pending: List[IRStatement] = [ir_func.block]
    while pending:
        node = pending.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, IRBlock):
            returns.extend((node, i) for i, stmt in enumerate(node.statements) if isinstance(stmt, IRReturn))
        pending.extend(node.get_children())
    values = [cast(IRReturn, block.statements[i]).value for block, i in returns]
    registers = {value.reg_idx for value in values if isinstance(value, IRLocal)}
    if (
        values
        and all(isinstance(value, IRLocal) for value in values)
        and len(registers) == 1
        and next(iter(registers)) is not None
        and cast(int, next(iter(registers))) >= len(signature.args)
    ):
        register = next(iter(registers))
        for local in ir_func.all_locals:
            if local.reg_idx == register:
                local.name = "this"
        for block, i in returns:
            cast(IRReturn, block.statements[i]).value = None
        return
    this = IRLocal("this", signature.ret, code)
    # Splice from the back so earlier indices in the same block stay valid.
    for block, i in sorted(returns, key=lambda r: r[1], reverse=True):
        value = cast(IRReturn, block.statements[i]).value
        if value is not None:
            block.statements[i : i + 1] = [IRAssign(code, this, value), IRReturn(code, None)]


def _is_super_call(callee_class_name: str, ir_function: IRFunction, code: Bytecode) -> bool:
    """True if `callee_class_name` is a superclass of the function being rendered (i.e.
    this call is `super.foo()`, not a same-class `this.foo()`). The implementation `super`
    reaches is the nearest one up the chain, which needn't be the direct superclass's.
    Haxe rejects `super` inside a local function, so lambdas never report one."""
    if getattr(ir_function, "_rendered_as_lambda", False):
        return False
    containing = getattr(ir_function, "_containing_class", None)
    # A local function (or its lifted body) can't reach `super`: its `this` is a capture.
    if containing is None or getattr(ir_function, "_anon_name", None):
        return False
    primary_obj = containing.dynamic if containing.dynamic else containing.static
    return any(
        destaticify(parent.name.resolve(code)) == callee_class_name
        for parent in _ancestors(code, primary_obj)
    )


def _find_receiver_local(class_name: str, ir_function: IRFunction, code: Bytecode) -> Optional[str]:
    """Find a local variable of the given class type that is assigned in the function."""
    candidates: List[str] = []
    seen: Set[int] = set()

    def visit(stmt: IRStatement) -> None:
        if id(stmt) in seen:
            return
        seen.add(id(stmt))
        if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRLocal):
            tname = destaticify(disasm.type_name(code, stmt.target.get_type()))
            if tname == class_name:
                candidates.append(stmt.target.name)
        for child in stmt.get_children():
            visit(child)

    visit(ir_function.block)
    return candidates[0] if candidates else None


def _ancestors(code: Bytecode, obj: Optional[Obj]) -> Iterator[Obj]:
    """`obj`'s super class, then its super's, and so on."""
    seen: Set[int] = set()
    current = obj
    while current is not None and current.super and current.super.value > 0 and id(current) not in seen:
        seen.add(id(current))
        try:
            parent = current.super.resolve(code).definition
        except IndexError:
            # Corrupt bytecode: the superclass type index is out of range —
            # stop the ancestry walk.
            return
        if not isinstance(parent, Obj):
            return
        yield parent
        current = parent


def _is_ancestor(code: Bytecode, ancestor: Obj, obj: Obj) -> bool:
    return any(parent is ancestor for parent in _ancestors(code, obj))


def _ancestor_declares(code: Bytecode, obj: Optional[Obj], method_name: str) -> bool:
    """True if a class above `obj` declares `method_name`, as a method or a `dynamic` one.
    A class lists only the methods it declares or overrides, so the one to override can sit
    anywhere up the chain."""
    return any(method_name in _declared_methods(code, parent) for parent in _ancestors(code, obj))


def _declared_methods(code: Bytecode, obj: Obj) -> Set[str]:
    names = {proto.name.resolve(code) for proto in obj.protos}
    if not obj.is_static:
        names.update(binding.field.resolve_obj(code, obj).name.resolve(code) for binding in obj.bindings)
    return names


def _is_dynamic_method(code: Bytecode, obj: Optional[Obj], func: Function) -> bool:
    """Whether `func` is the default body of one of `obj`'s `dynamic` methods."""
    return (
        obj is not None
        and not obj.is_static
        and any(binding.findex.value == func.findex.value for binding in obj.bindings)
    )


_written_statics_cache: Dict[int, Tuple["weakref.ReferenceType[Bytecode]", Set[Tuple[int, str]]]] = {}


def _written_statics(code: Bytecode) -> Set[Tuple[int, str]]:
    """(`id()` of a static half, field name) of every static field some function assigns."""
    cached = _written_statics_cache.get(id(code))
    if cached is not None and cached[0]() is code:
        return cached[1]
    written: Set[Tuple[int, str]] = set()
    for func in code.functions:
        for op in func.ops:
            if op.op != "SetField":
                continue
            target = func.regs[op.df["obj"].value].resolve(code).definition
            if isinstance(target, Obj) and target.is_static:
                written.add((id(target), op.df["field"].resolve_obj(code, target).name.resolve(code)))
    _written_statics_cache[id(code)] = (weakref.ref(code), written)
    return written


def _is_static_dynamic_method(code: Bytecode, obj: Obj, func: Function, name: str) -> bool:
    """Whether `func` is the default body of a `static dynamic` method of the class whose statics are
    `obj`: a function is bound to its static field also when it is only kept, so the field has to be
    one the program assigns."""
    return any(binding.findex.value == func.findex.value for binding in obj.bindings) and (
        id(obj),
        name,
    ) in _written_statics(code)


def _method_overrides(method_name: str, ir_class: "Union[IRClass, _PseudoClass]", code: Bytecode) -> bool:
    """Return True if ir_class declares a method that overrides a superclass method."""
    primary_obj = ir_class.dynamic if ir_class.dynamic else ir_class.static
    return _ancestor_declares(code, primary_obj, method_name)


def _find_type_by_haxe_name(code: Bytecode, haxe_name: str) -> Optional[Type]:
    for t in code.types:
        if destaticify(disasm.type_name(code, t)) == haxe_name:
            return t
    return None


def _base_class_for_virtual_method(func: "Function", code: Bytecode) -> Optional[str]:
    """If `func` is an overridden virtual method, return the Haxe name of the
    superclass that originally declared it."""
    try:
        parts = _func_name_parts(func, code)
        if not parts:
            return None
        class_name, method_name = parts
        typ = _find_type_by_haxe_name(code, class_name)
        if typ is None:
            return None
        obj = typ.definition
        if not isinstance(obj, Obj):
            return None
        if obj.is_static:
            obj = obj.dynamic
        if obj is None:
            return None
        super_idx = obj.super
        while super_idx is not None and super_idx.value >= 0:
            super_type = super_idx.resolve(code)
            super_obj = super_type.definition
            if not isinstance(super_obj, Obj):
                break
            check_obj = super_obj
            if check_obj.is_static:
                check_obj = check_obj.dynamic
            if check_obj is not None:
                for proto in check_obj.protos:
                    if proto.name.resolve(code) == method_name:
                        return destaticify(disasm.type_name(code, super_type))
            super_idx = super_obj.super
    except (IndexError, ValueError):
        # Corrupt bytecode: a type/name index is out of range, or a static half
        # has no dynamic counterpart — no provable declaring base class.
        pass
    return None


def _virtual_receiver_static_types(ir_function: IRFunction, code: Bytecode) -> Dict[str, str]:
    """Map receiver local names to the static superclass type implied by virtual
    dispatch (e.g. myObject -> Base when myObject is used as a Base closure)."""
    result: Dict[str, str] = {}
    seen: Set[int] = set()

    def visit(stmt: IRStatement) -> None:
        if id(stmt) in seen:
            return
        seen.add(id(stmt))
        # Only a *captured* function constant (the StaticClosure lift shape,
        # `dst_local = IRConst(Function)` — i.e. `var f = SomeClass.method;`)
        # implies anything about the receiver's static type: the closure is
        # invoked later through `dst_local`, separately from this assignment,
        # so its virtual-dispatch behavior depends on the receiver's
        # *declared* type at that later point, not its concrete one here.
        # An IRConst(Function) used directly as an IRCall's target (a normal
        # `obj.method(...)` call) carries no such implication — the call
        # already resolves to a specific, possibly-overridden implementation
        # regardless of how `obj` is declared, so widening obj's type here
        # would be both unnecessary and wrong.
        if (
            isinstance(stmt, IRAssign)
            and isinstance(stmt.expr, IRConst)
            and isinstance(stmt.expr.value, Function)
        ):
            func = stmt.expr.value
            parts = _func_name_parts(func, code)
            if parts is not None:
                class_name, _ = parts
                base = _base_class_for_virtual_method(func, code)
                if base is not None:
                    receiver = _find_receiver_local(class_name, ir_function, code)
                    if receiver is not None:
                        result[receiver] = base
        if (
            isinstance(stmt, IRField)
            and stmt.virtual_dispatch_fun is not None
            and isinstance(stmt.target, IRLocal)
        ):
            base = _base_class_for_virtual_method(stmt.virtual_dispatch_fun, code)
            if base is not None:
                result[stmt.target.name] = base
        for child in stmt.get_children():
            visit(child)

    visit(ir_function.block)
    return result


def _chain(code: Bytecode, obj: Obj) -> List[Obj]:
    return [obj, *_ancestors(code, obj)]


def _method_body(code: Bytecode, chain: Iterable[Obj], name: str) -> Optional[Function]:
    """The body of method `name` along `chain`: the first class in it that declares the method."""
    for obj in chain:
        for proto in obj.protos:
            func = proto.findex.resolve(code)
            if proto.name.resolve(code) == name and isinstance(func, Function):
                return func
    return None


def _narrowed_parameters(code: Bytecode, interface: typeinit.Interface, name: str) -> Dict[int, str]:
    """The parameters of an interface's method `name` that its values declare `Dynamic` but every
    implementor types one concrete way (the generic `T` of `interface I<T>`, erased in the bytecode):
    index -> Haxe type. Only a leaf interface qualifies, one neither extending nor extended, so
    that its implementors are exactly the classes registered against it. A body that only throws
    (the stub Haxe generates for an abstract base) takes no part in the agreement."""
    member = next((f for f in interface.virtual.fields if f.name.resolve(code) == name), None)
    if member is None or interface.parents:
        return {}
    signature = member.type.resolve(code).definition
    if not isinstance(signature, Fun):
        return {}
    if any(interface in other.parents for other in typeinit.registry(code).interfaces.values()):
        return {}
    erased = [i for i, arg in enumerate(signature.args) if isinstance(arg.resolve(code).definition, Dyn)]
    types: Dict[int, Set[str]] = {i: set() for i in erased}
    for implementor in interface.implementors:
        # The body the implementor's values run is its own, or else the one a subclass overrides it with.
        funcs = [_method_body(code, _chain(code, implementor), name)]
        funcs += [_method_body(code, [obj], name) for obj in _subclasses(code, implementor)]
        for func in funcs:
            if func is None:
                continue
            fun_def = func.type.resolve(code).definition
            if not isinstance(fun_def, Fun) or len(fun_def.args) != len(signature.args) + 1:
                return {}
            if {op.op for op in func.ops} <= {"Null", "Throw"}:
                continue
            for i in erased:
                types[i].add(disasm._haxe_annotation(code, fun_def.args[i + 1].resolve(code)))
    return {i: next(iter(found)) for i, found in types.items() if len(found) == 1 and "Dynamic" not in found}


def _subclasses(code: Bytecode, obj: Obj) -> List[Obj]:
    """Every class that extends `obj`, directly or through a chain of super classes."""
    return [
        definition
        for t in code.types
        if isinstance(definition := t.definition, Obj)
        and definition is not obj
        and any(ancestor is obj for ancestor in _chain(code, definition))
    ]


def _narrowed_method_parameters(code: Bytecode, dynamic: Optional[Obj], method_name: str) -> Dict[int, str]:
    """`_narrowed_parameters` over every interface `dynamic` or its super classes implement. A
    parameter two interfaces narrow differently is left erased."""
    narrowed: Dict[int, str] = {}
    conflicts: Set[int] = set()
    if dynamic is None:
        return narrowed
    for obj in _chain(code, dynamic):
        for interface in typeinit.implemented(code, obj):
            for i, typ in _narrowed_parameters(code, interface, method_name).items():
                if narrowed.setdefault(i, typ) != typ:
                    conflicts.add(i)
    return {i: typ for i, typ in narrowed.items() if i not in conflicts}


def _find_constructor(code: Bytecode, obj: Obj) -> Optional[Function]:
    """The `__constructor__` function of a class, searching the protos and bindings of
    both halves (it's bound on the static one)."""
    entries = [
        entry
        for half in _obj_pair(obj)
        if half is not None
        for entry in list(getattr(half, "protos", [])) + list(getattr(half, "bindings", []))
    ]
    for entry in entries:
        try:
            fn = entry.findex.resolve(code)
        except MalformedBytecode:
            # Corrupt bytecode: the entry's findex is not in the map — skip it.
            continue
        if isinstance(fn, Function) and code.partial_func_name(fn) == "__constructor__":
            return fn
    return None


def _obj_pair(obj: Obj) -> Tuple[Optional[Obj], Optional[Obj]]:
    """(dynamic, static) halves of a class from either one (needs map_statics)."""
    dynamic: Optional[Obj]
    static: Optional[Obj]
    if obj.is_static:
        static = obj
        try:
            dynamic = obj.dynamic
        except (ValueError, AttributeError):
            dynamic = None
    else:
        dynamic = obj
        try:
            static = obj.static
        except (ValueError, AttributeError):
            static = None
    return dynamic, static


def _obj_functions(code: Bytecode, obj: Optional[Obj]) -> List[Function]:
    """Non-native functions bound to a class half (protos + bindings), deduped."""
    if obj is None:
        return []
    res: List[Function] = []
    seen: Set[int] = set()
    for entry in list(getattr(obj, "protos", [])) + list(getattr(obj, "bindings", [])):
        try:
            fn = entry.findex.resolve(code)
        except MalformedBytecode:
            # Corrupt bytecode: the entry's findex is not in the map — skip it.
            continue
        if isinstance(fn, Function) and fn.findex.value not in seen:
            seen.add(fn.findex.value)
            res.append(fn)
    return res


def _obj_fields(code: Bytecode, obj: Optional[Obj]) -> List[Tuple[str, Type]]:
    """Data fields of a class half (mirrors IRClass.gather_fields, no lifting)."""
    if obj is None:
        return []
    binding_names: Set[str] = set()
    for binding in getattr(obj, "bindings", []):
        try:
            binding_names.add(binding.field.resolve_obj(code, obj).name.resolve(code))
        except (IndexError, ValueError):
            # Corrupt bytecode: a field/superclass index is out of range or the
            # hierarchy is cyclic/invalid — skip this binding's name.
            pass
    res: List[Tuple[str, Type]] = []
    for field in getattr(obj, "fields", []):
        try:
            name = field.name.resolve(code)
            # Unnamed slots are compiler padding: source can't declare or name them.
            if name and name not in binding_names:
                res.append((name, field.type.resolve(code)))
        except IndexError:
            # Corrupt bytecode: the field's name/type index is out of range —
            # skip the field.
            pass
    return res


def _scope_text(code: Bytecode, entry: ScopeEntry) -> str:
    """A class type parameter as written in a class body: its name, or the type a super class closed it with."""
    if entry is None:
        return "Dynamic"
    if isinstance(entry, str):
        return entry
    return disasm._haxe_annotation(code, entry)


def _method_slot_text(code: Bytecode, obj: Optional[Obj], name: str, *index: int) -> Optional[str]:
    """How a method of `obj` declares its return (no `index`) or parameter `index` when the class
    that first declares the method types it with a class type parameter (see `classgenerics`)."""
    if obj is None:
        return None
    root = method_root(code, obj, name)
    if root is None:
        return None
    key = ("arg", id(root), name, index[0]) if index else ("ret", id(root), name)
    slot = class_generics(code).slot_in(obj, key)
    return _scope_text(code, slot[0]) if slot is not None else None


def _constraint_text(code: Bytecode, fields: "Optional[Dict[str, Tuple[tIndex, bool]]]") -> str:
    """`:{ var name: Type; ... }`, the structural constraint of a type variable whose body uses typed
    fields of it. A field only read is read-only, which also admits `String.length`."""
    if not fields:
        return ""
    members = " ".join(
        f"var {name}{'' if written else '(default, null)'}: {disasm._haxe_annotation(code, typ.resolve(code))};"
        for name, (typ, written) in fields.items()
    )
    return f":{{ {members} }}"


def _type_variable_name(number: int) -> str:
    return "T" if number == 0 else f"T{number}"


def _own_type_variables(
    code: Bytecode,
    func: Function,
    containing: "Union[IRClass, _PseudoClass, None]",
    name: str,
    is_instance: bool,
) -> Tuple[Dict[int, int], Optional[int]]:
    """The parameters of `func` that are its type variables, and the variable of its return (see
    `generics`). A method that overrides or is overridden keeps every parameter Dynamic: Haxe
    requires the overriding method to declare the same type parameters."""
    variables = generics.type_variables(code, func)
    returned = generics.return_variable(code, func)
    if not variables or not is_instance:
        return variables, returned
    obj = containing.dynamic if containing is not None else None
    if obj is None:
        return {}, None
    if _ancestor_declares(code, obj, name):
        return {}, None
    for t in code.types:
        sub = t.definition
        if isinstance(sub, Obj) and sub is not obj and name in _declared_methods(code, sub):
            if _is_ancestor(code, obj, sub):
                return {}, None
    return variables, returned


def _erased_parameters(
    code: Bytecode, dynamic: Optional[Obj], method_name: str
) -> Tuple[Set[int], Dict[int, str]]:
    """Parameters of a method that an interface its class (or a super class) implements
    declares `Dynamic`: an interface with type parameters is erased to `Dynamic` there,
    while the implementation has the concrete type. Haxe matches the two parameter lists
    exactly, so they are declared `Dynamic` on the implementation as well. The same goes
    for a method overriding one of a generic class, whose parameters were erased there.
    A parameter every implementor of a leaf interface types one concrete way is not erased:
    it is returned with that type instead (see `_narrowed_parameters`)."""
    erased: Set[int] = set()
    if dynamic is None:
        return erased, {}
    for parent in _ancestors(code, dynamic):
        signatures = [
            (proto.findex.resolve(code).type.resolve(code).definition, 1)
            for proto in parent.protos
            if proto.name.resolve(code) == method_name and isinstance(proto.findex.resolve(code), Function)
        ] + [
            (field.type.resolve(code).definition, 0)
            for field in parent.fields
            if field.name.resolve(code) == method_name
        ]
        for signature, skip in signatures:
            if isinstance(signature, Fun):
                erased.update(
                    i
                    for i, arg in enumerate(signature.args[skip:])
                    if isinstance(arg.resolve(code).definition, Dyn)
                )
    narrowed = {
        i: typ
        for i, typ in _narrowed_method_parameters(code, dynamic, method_name).items()
        if i not in erased
    }
    for obj in _chain(code, dynamic):
        for interface in typeinit.implemented(code, obj):
            for iface in [interface, *interface.ancestors()]:
                for member in iface.virtual.fields:
                    signature = member.type.resolve(code).definition
                    if member.name.resolve(code) != method_name or not isinstance(signature, Fun):
                        continue
                    erased.update(
                        i
                        for i, arg in enumerate(signature.args)
                        if isinstance(arg.resolve(code).definition, Dyn) and i not in narrowed
                    )
    return erased, narrowed


def _overrides_super(code: Bytecode, dynamic: Optional[Obj], method_name: str) -> bool:
    """True if `method_name` is declared by a super class (needs `override`)."""
    return _ancestor_declares(code, dynamic, method_name)
