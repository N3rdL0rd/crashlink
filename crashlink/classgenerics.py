"""
Recovery of a class's type parameters.

HL erases `class Box<T> { var v:T; function get():T ... }` to `Dyn` slots, which is also what
`var v:Dynamic` compiles to. They differ where a slot is read at a known instantiation: the
compiler trusts the type parameter and converts the read value with an *unchecked* cast,

    Field     Dyn <- box.v      var s:String = box.v     (box:Box<String>)
    UnsafeCast String <- Dyn

where a `Dynamic` read is left alone (or, written `(cast box.v : String)`, cast with a checked
`SafeCast`). An `UnsafeCast` of a field read or of a method's return is therefore a type
parameter of the class that declares the slot, applied at the static type of the receiver: the
view. An override narrowing a parameter the overridden method declares `Dynamic` is one too:
Haxe only lets an override change a parameter's type through the class's type arguments.

Each class declaring such slots gets one type parameter per group of slots whose views agree.
A subclass either closes the parameters (`class B extends A<String>`: its own methods read the
slots cast, and every view below it agrees) or forwards them (`class B<T> extends A<T>`).
References to a generic class are written with the type arguments its views agree on; a
parameter no read pins down is `Dynamic`. Slots whose reads at one view disagree (one class
instantiated two ways) are left erased.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .core import Bytecode, Dyn, Fun, Function, Obj, Type
from .generics import _call_args

# ("field", id(owner), name) | ("ret", id(owner), method) | ("arg", id(owner), method, index)
Slot = Tuple[Any, ...]
# A type parameter's name, a concrete type argument, or None for Dynamic.
ScopeEntry = Union[str, Type, None]


@dataclass
class ClassGenerics:
    # id(obj) -> the type parameters it declares
    declared: Dict[int, List[int]] = field(default_factory=dict)
    # id(obj) -> what each type parameter in scope is in its body: a name, or the closed type
    scope: Dict[int, Dict[int, ScopeEntry]] = field(default_factory=dict)
    # id(obj) -> type arguments of its `extends` clause
    supers: Dict[int, List[ScopeEntry]] = field(default_factory=dict)
    # id(obj) -> type arguments of a reference to the (generic) class
    args: Dict[int, List[Optional[Type]]] = field(default_factory=dict)
    # slot -> type parameter
    slots: Dict[Slot, int] = field(default_factory=dict)
    names: Dict[int, str] = field(default_factory=dict)

    def params(self, obj: Optional[Obj]) -> List[str]:
        return [self.names[p] for p in self.declared.get(id(obj), ())] if obj is not None else []

    def slot_in(self, obj: Optional[Obj], slot: Slot) -> Optional[Tuple[ScopeEntry]]:
        """What the slot is inside `obj`'s body, wrapped in a tuple (None if it isn't a type parameter)."""
        pid = self.slots.get(slot)
        if pid is None or obj is None:
            return None
        scope = self.scope.get(id(obj))
        if scope is None or pid not in scope:
            return None
        return (scope[pid],)


def _name(number: int) -> str:
    return "T" if number == 0 else f"T{number}"


def _parent(code: Bytecode, obj: Obj) -> Optional[Obj]:
    if obj.super.value < 0:
        return None
    definition = obj.super.resolve(code).definition
    return definition if isinstance(definition, Obj) else None


def _chain(code: Bytecode, obj: Obj) -> List[Obj]:
    """`obj` and its ancestors, root first."""
    chain: List[Obj] = []
    current: Optional[Obj] = obj
    while current is not None and all(c is not current for c in chain):
        chain.append(current)
        current = _parent(code, current)
    return chain[::-1]


def _is_dyn(typ: Type) -> bool:
    return isinstance(typ.definition, Dyn)


def _method_types(code: Bytecode, obj: Obj, name: str) -> Optional[Fun]:
    """The signature (receiver included) of the method `obj` itself declares as `name`."""
    for proto in obj.protos:
        if proto.name.resolve(code) == name:
            fn = proto.findex.resolve(code)
            if isinstance(fn, Function):
                definition = fn.type.resolve(code).definition
                return definition if isinstance(definition, Fun) else None
    for binding in obj.bindings:
        member = obj.resolve_fields(code)[binding.field.value]
        if member.name.resolve(code) == name and member in obj.fields:
            fn = binding.findex.resolve(code)
            if isinstance(fn, Function):
                definition = fn.type.resolve(code).definition
                return definition if isinstance(definition, Fun) else None
    return None


def _declares_method(code: Bytecode, obj: Obj, name: str) -> bool:
    return any(p.name.resolve(code) == name for p in obj.protos) or any(
        f.name.resolve(code) == name and isinstance(f.type.resolve(code).definition, Fun) for f in obj.fields
    )


def method_root(code: Bytecode, obj: Obj, name: str) -> Optional[Obj]:
    """The topmost class of `obj`'s chain declaring the method `name`."""
    for candidate in _chain(code, obj):
        if _declares_method(code, candidate, name):
            return candidate
    return None


def _field_owner(code: Bytecode, obj: Obj, index: int) -> Optional[Obj]:
    seen = 0
    for candidate in _chain(code, obj):
        seen += len(candidate.fields)
        if index < seen:
            return candidate
    return None


def _user_classes(code: Bytecode) -> List[Obj]:
    from .pseudo import _is_std_class_obj  # the renderer's notion of a class it declares

    objs: List[Obj] = []
    for typ in code.types:
        obj = typ.definition
        if isinstance(obj, Obj) and not obj.name.resolve(code).split(".")[-1].startswith("$"):
            try:
                if obj.is_static:
                    continue
            except ValueError:
                pass
            if not _is_std_class_obj(code, obj):
                objs.append(obj)
    return objs


def _compute(code: Bytecode) -> ClassGenerics:
    from .pseudo import _method_registry

    users = _user_classes(code)
    user_ids = {id(o) for o in users}
    registry = _method_registry(code)
    owners: Dict[int, Obj] = {id(o): o for o in users}
    # slot -> [(view, type argument, read through `this`)]
    evidence: Dict[Slot, List[Tuple[Obj, Type, bool]]] = {}
    # (id(view), slot): a read through `this` that isn't cast
    uncast: Set[Tuple[int, Slot]] = set()
    roots: Dict[Tuple[int, str], Optional[Obj]] = {}

    def root_of(obj: Obj, name: str) -> Optional[Obj]:
        key = (id(obj), name)
        if key not in roots:
            roots[key] = method_root(code, obj, name)
        return roots[key]

    def read_slot(func: Function, op: Any) -> Optional[Tuple[Obj, Slot, int]]:
        """The class slot an op reads (view, slot, receiver register)."""
        name, df = op.op, op.df
        receiver: Optional[int] = None
        if name in ("Field", "GetThis"):
            receiver = df["obj"].value if name == "Field" else 0
            view = func.regs[receiver].resolve(code).definition
            if not isinstance(view, Obj) or id(view) not in user_ids:
                return None
            fields = view.resolve_fields(code)
            index = df["field"].value
            if index >= len(fields) or not _is_dyn(fields[index].type.resolve(code)):
                return None
            owner = _field_owner(code, view, index)
            if owner is None or id(owner) not in user_ids:
                return None
            return view, ("field", id(owner), fields[index].name.resolve(code)), receiver
        method: Optional[str] = None
        if name in ("Call1", "Call2", "Call3", "Call4", "CallN"):
            entry = registry.get(df["fun"].value)
            if entry is None or not entry[2]:
                return None
            receiver = (_call_args(op) or [None])[0]
            method = entry[1]
        elif name in ("CallMethod", "CallThis"):
            receiver = (_call_args(op) or [None])[0]
            if receiver is None:
                return None
            view = func.regs[receiver].resolve(code).definition
            if not isinstance(view, Obj):
                return None
            proto = code.proto_by_pindex(view, df["field"].value)
            if proto is None:
                return None
            method = proto.name.resolve(code)
        if method is None or receiver is None:
            return None
        view = func.regs[receiver].resolve(code).definition
        if not isinstance(view, Obj) or id(view) not in user_ids:
            return None
        root = root_of(view, method)
        if root is None or id(root) not in user_ids:
            return None
        signature = _method_types(code, root, method)
        if signature is None or not _is_dyn(signature.ret.resolve(code)):
            return None
        return view, ("ret", id(root), method), receiver

    def stored_slot(func: Function, op: Any, this_obj: Obj) -> Optional[Tuple[Slot, int]]:
        """The slot of its own class a method's op stores into (slot, source register)."""
        name, df = op.op, op.df
        if name == "SetThis" or (name == "SetField" and df["obj"].value == 0):
            fields = this_obj.resolve_fields(code)
            index = df["field"].value
            if index >= len(fields) or not _is_dyn(fields[index].type.resolve(code)):
                return None
            owner = _field_owner(code, this_obj, index)
            if owner is None or id(owner) not in user_ids:
                return None
            return ("field", id(owner), fields[index].name.resolve(code)), df["src"].value
        return None

    def is_foreign(func: Function, ops: List[Any], targets: Set[int], i: int, reg: int) -> bool:
        """True if the value a register holds at op `i` couldn't be of a type parameter: it is
        concrete, boxed from a concrete value, or an array's element (which the renderer types by
        the arrays its callers pass)."""
        if not _is_dyn(func.regs[reg].resolve(code)):
            return True
        j = i - 1
        while j >= 0 and j + 1 not in targets:
            writer = ops[j]
            dst = writer.df.get("dst")
            if dst is not None and dst.value == reg:
                if writer.op in ("ToDyn", "GetArray"):
                    return True
                args = _call_args(writer)
                if args:
                    receiver = func.regs[args[0]].resolve(code).definition
                    return isinstance(receiver, Obj) and receiver.name.resolve(code).startswith(
                        "hl.types.Array"
                    )
                return False
            j -= 1
        return False

    # (id(class), slot): a value a class's own methods store into a slot that a type parameter
    # couldn't hold. Such a slot isn't the parameter while the class declares it.
    foreign: Set[Tuple[int, Slot]] = set()
    # slot -> [(view, type)]: reads converted with a checked cast, which no read of a parameter
    # fixed to a reference type needs: that view instantiates the class another way.
    checked: Dict[Slot, List[Tuple[Obj, Type]]] = {}
    for func in code.functions:
        ops = func.ops
        targets: Set[int] = set()
        for i, op in enumerate(ops):
            if "offset" in op.df:
                targets.add(i + 1 + op.df["offset"].value)
            if op.op == "Switch":
                targets.update(i + 1 + o.value for o in op.df["offsets"].value)
        this_obj = func.regs[0].resolve(code).definition if func.regs else None
        entry = registry.get(func.findex.value)
        is_method = isinstance(this_obj, Obj) and entry is not None and entry[2] and entry[0] is this_obj
        # A constructor is bound on the static half, but its receiver is the instance too.
        owns_this = is_method or (
            isinstance(this_obj, Obj) and entry is not None and entry[1] == "__constructor__"
        )
        returned: Optional[Slot] = None
        if is_method and entry is not None and isinstance(this_obj, Obj):
            root = root_of(this_obj, entry[1])
            signature = func.type.resolve(code).definition
            if root is not None and isinstance(signature, Fun) and _is_dyn(signature.ret.resolve(code)):
                returned = ("ret", id(root), entry[1])
        for i, op in enumerate(ops):
            if owns_this and isinstance(this_obj, Obj):
                stored = stored_slot(func, op, this_obj)
                if stored is None and returned is not None and op.op == "Ret":
                    stored = returned, op.df["ret"].value
                if stored is not None and is_foreign(func, ops, targets, i, stored[1]):
                    foreign.add((id(this_obj), stored[0]))
            dst = op.df.get("dst")
            if dst is None:
                continue
            read = read_slot(func, op)
            if read is None:
                continue
            view, slot, receiver = read
            through_this = owns_this and receiver == 0
            cast: Optional[Tuple[str, Type]] = None
            for j in range(i + 1, len(ops)):
                if j in targets:
                    break
                later = ops[j]
                if later.op in ("UnsafeCast", "SafeCast") and later.df["src"].value == dst.value:
                    cast = later.op, func.regs[later.df["dst"].value].resolve(code)
                    break
                if later.df.get("dst") is not None and later.df["dst"].value == dst.value:
                    break
            if cast is not None and not _is_dyn(cast[1]):
                if cast[0] == "UnsafeCast":
                    evidence.setdefault(slot, []).append((view, cast[1], through_this))
                else:
                    checked.setdefault(slot, []).append((view, cast[1]))
            elif through_this:
                uncast.add((id(view), slot))

    # An override narrowing a parameter its root declares Dynamic.
    for obj in users:
        methods = [(p.name.resolve(code), p.findex.resolve(code)) for p in obj.protos]
        for binding in obj.bindings:
            methods.append(
                (
                    obj.resolve_fields(code)[binding.field.value].name.resolve(code),
                    binding.findex.resolve(code),
                )
            )
        for name, fn in methods:
            root = root_of(obj, name)
            if root is None or root is obj or id(root) not in user_ids or not isinstance(fn, Function):
                continue
            root_sig, own = _method_types(code, root, name), fn.type.resolve(code).definition
            if root_sig is None or not isinstance(own, Fun) or len(own.args) != len(root_sig.args):
                continue
            for index in range(1, len(own.args)):
                arg = own.args[index].resolve(code)
                if _is_dyn(root_sig.args[index].resolve(code)) and not _is_dyn(arg):
                    evidence.setdefault(("arg", id(root), name, index - 1), []).append((obj, arg, True))

    children: Dict[int, List[Obj]] = {}
    for obj in users:
        parent = _parent(code, obj)
        if parent is not None:
            children.setdefault(id(parent), []).append(obj)

    def subtree(obj: Obj) -> Set[int]:
        found, pending = set(), [obj]
        while pending:
            current = pending.pop()
            if id(current) not in found:
                found.add(id(current))
                pending.extend(children.get(id(current), ()))
        return found

    order = sorted(users, key=lambda o: len(_chain(code, o)))
    failed: Set[Slot] = set()
    while True:
        result = ClassGenerics()
        retry: Set[Slot] = set()
        # Group each owner's evidenced slots into type parameters.
        owned: Dict[int, List[Tuple[int, Dict[int, Type]]]] = {}
        pid_slots: Dict[int, List[Slot]] = {}
        for slot, items in evidence.items():
            if slot in failed or slot[1] not in owners:
                continue
            views: Dict[int, Type] = {}
            for view, typ, _ in items:
                if views.setdefault(id(view), typ) is not typ:
                    retry.add(slot)
            for view, typ in checked.get(slot, ()):
                if views.get(id(view), typ) is not typ:
                    retry.add(slot)
            if slot in retry:
                continue
            groups = owned.setdefault(slot[1], [])
            for pid, combined in groups:
                if all(combined.get(v, t) is t for v, t in views.items()):
                    combined.update(views)
                    pid_slots[pid].append(slot)
                    break
            else:
                pid = len(pid_slots)
                pid_slots[pid] = [slot]
                groups.append((pid, dict(views)))
        if retry:
            failed |= retry
            continue
        for pid, slots in pid_slots.items():
            for slot in slots:
                result.slots[slot] = pid

        def agreed(pid: int, among: Set[int]) -> Tuple[Optional[Type], bool]:
            value: Optional[Type] = None
            for slot in pid_slots[pid]:
                for view, typ, _ in evidence[slot]:
                    if id(view) in among:
                        if value is not None and value is not typ:
                            return None, False
                        value = typ
            return value, True

        for obj in order:
            parent = _parent(code, obj)
            inherited = result.declared.get(id(parent), []) if parent is not None else []
            scope: Dict[int, ScopeEntry] = (
                dict(result.scope.get(id(parent), {})) if parent is not None else {}
            )
            forwarded: List[int] = []
            if inherited:
                below = subtree(obj)
                closed: Dict[int, Optional[Type]] = {}
                needs_open = False
                for pid in inherited:
                    value, ok = agreed(pid, below)
                    closed[pid] = value
                    if not ok:
                        needs_open = True
                    elif value is not None and any(
                        (view, slot) in uncast for slot in pid_slots[pid] for view in below
                    ):
                        needs_open = True
                if needs_open:
                    forwarded = list(inherited)
                    result.supers[id(obj)] = [scope[pid] for pid in inherited]
                else:
                    result.supers[id(obj)] = [closed[pid] for pid in inherited]
                    scope.update(closed)
            own = [pid for pid, slots in pid_slots.items() if slots[0][1] == id(obj)]
            for k, pid in enumerate(own):
                result.names[pid] = _name(len(forwarded) + k)
                scope[pid] = result.names[pid]
            declared = forwarded + own
            result.scope[id(obj)] = scope
            for pid in declared:
                if any((id(obj), slot) in foreign for slot in pid_slots[pid]):
                    retry.update(pid_slots[pid])
            if declared:
                result.declared[id(obj)] = declared
                args: List[Optional[Type]] = []
                for pid in declared:
                    value, ok = agreed(pid, {id(obj)})
                    if not ok:
                        retry.update(pid_slots[pid])
                    args.append(value)
                result.args[id(obj)] = args
        if retry:
            failed |= retry
            continue
        return result


def class_generics(code: Bytecode) -> ClassGenerics:
    cached = code._class_generics
    if cached is None:
        cached = code._class_generics = _compute(code)
    return cached
