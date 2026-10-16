"""
Class, interface and enum rendering: class bodies, closure bodies and property adapters.
"""

from __future__ import annotations

import re
from typing import Optional, List, Set, Dict, Tuple
from .doc import strip
from ..core import Bytecode, Obj, Function, Fun, Native, Enum, Packed, destaticify, Virtual
from .. import disasm
from ..errors import MalformedBytecode
from .. import abstracts, ifacenames, mapargs, rtti_meta, hxbit, hxsl, typeinit
from ..classgenerics import class_generics
from ..std_types import STD_TYPES
from ..decomp import (
    STATIC_INIT_UNRECOVERABLE,
    IRClass,
    IRBoundClosure,
    IRPostIncrement,
    IRFunction,
    IRBlock,
    IRStatement,
    IRAssign,
    IRLocal,
    IRConst,
    IRBoolExpr,
    IRConditional,
    IRTrace,
    IRArrayAccess,
    IRArrayLiteral,
    IRReturn,
    IRThrow,
)
from ..decomp.opt.arraytypes import recover_closure_param_elem_types
from ..decomp.opt.clean import default_arg_regs, default_arg_value
from ..decomp.opt.inliner import IRTempAssignmentInliner
from ..decomp.inline_calls import inline_index
from .naming import _rtti_type_meta, _rtti_member_meta, _struct_meta, _is_std_class_obj
from .closures import (
    _walk_ir,
    _hoist_closure_contexts,
    _void_return_adapter,
    _optional_ref_adapter,
    _function_header,
    _split_params,
    _closure_adapter,
)
from .hierarchy import _narrowed_parameters, _scope_text
from .strings import _indent_str
from .locals import _count_local_reads_and_writes, _collect_locals
from .members import (
    _collect_natives,
    _collect_function_externs,
    _function_extern,
    _native_extern,
    _annotation_dependencies,
    _collect_referenced_user_classes,
    _collect_anonymous_functions,
    _collect_referenced_enums,
    ModuleDeclaration,
    _implements_clause,
    _stored_property,
    _field_declaration,
    _interface_properties,
    _implementation,
    _implemented_properties,
    _interface_dependencies,
)
from .render import (
    _resolve_array_access,
    _expression_to_haxe,
    _generate_statements,
    _generate_function_pseudo,
)


def _closure_context_body(helper_ir: IRFunction) -> Optional[Tuple[List[str], str]]:
    """Like `_closure_inline_body`, for a closure whose first parameter is an anonymous capture
    context (several captured variables travel in one enum value). The body reads each capture
    through the context's parameters; those reads render as `_CTX_MARK<index>_CTX_MARK`
    placeholders for the creating function to replace with the captured expressions. A body of
    several statements is kept as a block: `() -> { ... }`."""
    signature = helper_ir.func.type.resolve(helper_ir.code).definition
    if not isinstance(signature, Fun) or not signature.args or not helper_ir.locals:
        return None
    ctx_type = signature.args[0].resolve(helper_ir.code).definition
    if not isinstance(ctx_type, Enum) or ctx_type.name.value != 0:
        return None
    ctx_name = helper_ir.locals[0].name
    setattr(helper_ir, "_ctx_param", ctx_name)
    try:
        entry = _closure_inline_body(helper_ir)
        if entry is None:
            entry = _closure_block_body(helper_ir)
    finally:
        setattr(helper_ir, "_ctx_param", None)
    if entry is None or re.search(rf"\b{re.escape(ctx_name)}\b", entry[1]):
        return None  # the context itself is used, not just read
    return entry


def _closure_block_body(helper_ir: IRFunction) -> Optional[Tuple[List[str], str]]:
    """(parameter names, block body) for an anonymous function of several statements, as the
    `() -> { ... }` lambda it came from. The first parameter (the context) is not named; the
    caller substitutes the captures for its reads. Rendered with `_ctx_param` set."""
    signature = helper_ir.func.type.resolve(helper_ir.code).definition
    if not isinstance(signature, Fun) or not signature.args:
        return None
    if any(
        disasm._is_pos_infos(helper_ir.code, arg.resolve(helper_ir.code).definition)
        for arg in signature.args[1:]
    ):
        return None  # a position parameter is filled in by the compiler; a lambda cannot declare it
    text = _generate_function_pseudo(helper_ir)
    lines = text.splitlines()
    open_at = next(
        (i for i, line in enumerate(lines) if line.rstrip().endswith("{") and "function " in line), None
    )
    if open_at is None or not lines[-1].strip() == "}":
        return None
    header = _function_header(lines[open_at])
    if header is None:
        return None
    parts = [part.strip() for part in _split_params(header.group(1))]
    declared = [part.split(":")[0].strip() for part in parts]
    if len(declared) != len(signature.args):
        return None
    base = len(lines[open_at]) - len(lines[open_at].lstrip()) + 4
    body = [line[base:] if line.startswith(" " * base) else line.lstrip() for line in lines[open_at + 1 : -1]]
    indented = "\n".join(("    " + line) if line else line for line in body)
    return declared, "{\n" + indented + "\n}"


def _collapse_adapter_guards(ir_func: IRFunction) -> None:
    """`t = f == null ? null : adapter(f)` is `t = f`.

    Converting a function value to a function type that differs only in a return or Dynamic
    argument type wraps it in an adapter helper, guarded by a null test; the source passed `f`
    and the compiler adds both again."""
    code = ir_func.code
    for block in [n for n in _walk_ir(ir_func.block) if isinstance(n, IRBlock)]:
        for idx, stmt in enumerate(block.statements):
            if not (
                isinstance(stmt, IRConditional)
                and isinstance(stmt.condition, IRBoolExpr)
                and stmt.condition.op == IRBoolExpr.CompareType.NULL
                and isinstance(stmt.condition.left, IRLocal)
                and len(stmt.true_block.statements) == 1
                and len(stmt.false_block.statements) == 1
            ):
                continue
            null_branch, call_branch = stmt.true_block.statements[0], stmt.false_block.statements[0]
            if not (
                isinstance(null_branch, IRAssign)
                and isinstance(call_branch, IRAssign)
                and null_branch.target == call_branch.target
                and isinstance(null_branch.expr, IRConst)
                and null_branch.expr.const_type == IRConst.ConstType.NULL
                and isinstance(call_branch.expr, IRBoundClosure)
                and call_branch.expr.obj == stmt.condition.left
            ):
                continue
            if call_branch.expr.fun.findex.value not in getattr(ir_func, "_return_adapters", ()):
                continue  # an adapter of argument types was written as a plain copy of the function
            function = _expression_to_haxe(stmt.condition.left, code, ir_func)
            if _closure_adapter(call_branch.expr, function, code, ir_func) != function:
                continue
            # Assigned to a temporary of the adapted function type, `f` would not type-check
            # (`Void -> Void` is not `Void -> Dynamic`); where the compiler adapts it is the
            # call it is passed to, so the temporary has to go.
            target = call_branch.target
            if not (isinstance(target, IRLocal) and idx + 1 < len(block.statements)):
                continue
            mentions = sum(
                1
                for node in _walk_ir(ir_func.block)
                if isinstance(node, IRLocal) and node.name == target.name
            )
            # Two writes (the guard's branches) and the one read in the next statement, nothing else.
            if mentions != 3 or _count_local_reads_and_writes(ir_func.block, target.name) != (1, 2):
                continue
            if IRTempAssignmentInliner(ir_func)._substitute_in_statement(
                block.statements[idx + 1], target, call_branch.expr
            ):
                del block.statements[idx]
                return _collapse_adapter_guards(ir_func)


def _capture_box_uses(
    root: IRStatement, name: str, code: Bytecode, ir_function: Optional[IRFunction]
) -> Tuple[int, int, int, int, List[IRBoundClosure]]:
    """How the local `name` is used in a tree: (all uses, uses that are part of a capture box,
    box definitions, element writes, closures it is the environment of).

    A capture box is the one-element array the compiler wraps a captured variable in: it is
    created from a one-element literal, read and written only as element 0, and otherwise only
    handed to closures as their environment."""
    total = accounted = defs = writes = 0
    consumers: List[IRBoundClosure] = []

    def count(node: IRStatement) -> int:
        here = 1 if isinstance(node, IRLocal) and node.name == name else 0
        return here + sum(count(child) for child in node.get_children())

    def element(node: IRStatement) -> bool:
        if not isinstance(node, IRArrayAccess):
            return False
        try:
            arr_str, idx_str, kind = _resolve_array_access(node, code, ir_function)
        except (KeyError, IndexError, ValueError, MalformedBytecode):
            # Corrupt bytecode (a table index out of range) while probing: not a
            # provable element write.
            return False
        return strip(arr_str) == name and idx_str == "0" and kind is None

    def walk(node: IRStatement, written: bool = False) -> None:
        nonlocal total, accounted, defs, writes
        if isinstance(node, IRAssign):
            target = node.target
            if isinstance(target, IRLocal) and target.name == name:
                total += 1
                if isinstance(node.expr, IRArrayLiteral) and len(node.expr.elements) == 1:
                    defs += 1
                    accounted += 1
                walk(node.expr)
                return
            walk(target, True)
            walk(node.expr)
            return
        if isinstance(node, IRPostIncrement) and element(node.target):
            inside = count(node)
            total += inside
            accounted += inside
            writes += 1
            return
        if element(node):
            inside = count(node)
            total += inside
            accounted += inside
            writes += 1 if written else 0
            return
        if isinstance(node, IRBoundClosure) and isinstance(node.obj, IRLocal) and node.obj.name == name:
            total += 1
            accounted += 1
            consumers.append(node)
            return
        if isinstance(node, IRLocal) and node.name == name:
            total += 1
            return
        for child in node.get_children():
            walk(child)

    walk(root)
    return total, accounted, defs, writes, consumers


def _find_capture_boxes(
    ir_func: IRFunction,
    helper_irs: Dict[int, IRFunction],
) -> Dict[str, List[IRFunction]]:
    """Capture boxes of `ir_func`, with the closure helpers sharing each.

    The compiler boxes a variable that a closure captures and that is assigned, so source
    wrote a plain variable and the closure reads it by name. Only a box every closure
    receiving it renders as a lambda can go: a lifted helper bound to the value would
    capture a copy."""
    code = ir_func.code
    candidates: Dict[str, IRArrayLiteral] = {}
    pending: List[IRStatement] = [ir_func.block]
    while pending:
        node = pending.pop()
        if (
            isinstance(node, IRAssign)
            and isinstance(node.target, IRLocal)
            and isinstance(node.expr, IRArrayLiteral)
            and len(node.expr.elements) == 1
        ):
            candidates.setdefault(node.target.name, node.expr)
        pending.extend(node.get_children())
    boxes: Dict[str, List[IRFunction]] = {}
    local_types = _collect_locals(ir_func.block) if candidates else {}
    for name, literal in candidates.items():
        if not re.fullmatch(r"Array<.+>", local_types.get(name, "")):
            continue
        total, accounted, defs, writes, consumers = _capture_box_uses(ir_func.block, name, code, ir_func)
        if total != accounted or defs != 1 or not consumers:
            continue
        helpers: List[IRFunction] = []
        for closure in consumers:
            findex = closure.fun.findex.value
            helper = helper_irs.get(findex)
            if helper is None or not helper.locals or helper.locals[0].name != name:
                break
            h_total, h_accounted, h_defs, h_writes, h_consumers = _capture_box_uses(
                helper.block, name, code, helper
            )
            if h_total != h_accounted or h_defs or h_consumers or helper in helpers:
                break
            helpers.append(helper)
            writes += h_writes
        else:
            if writes:
                boxes[name] = helpers
                setattr(
                    ir_func, "_unboxed_literals", getattr(ir_func, "_unboxed_literals", set()) | {id(literal)}
                )
    return boxes


def _closure_inline_body(helper_ir: IRFunction) -> Optional[Tuple[List[str], str]]:
    """(parameter names, rendered body) for an anonymous function, if it is a
    single expression that can stand in expression position."""
    statements = list(helper_ir.block.statements)
    if statements and isinstance(statements[-1], IRReturn) and statements[-1].value is None:
        statements = statements[:-1]
    if len(statements) != 1 or isinstance(statements[0], IRThrow):
        return None  # `() -> throw x` is typed as returning Dynamic, not as the Void function it was
    signature = helper_ir.func.type.resolve(helper_ir.code).definition
    if not isinstance(signature, Fun):
        return None
    names = [local.name for local in helper_ir.locals[: len(signature.args)]]
    if len(names) != len(signature.args):
        return None
    if names and disasm._is_pos_infos(helper_ir.code, signature.args[-1].resolve(helper_ir.code).definition):
        names[-1] = "?" + names[-1]  # the compiler fills a position parameter in at each call
    helper_ir._rendered_as_lambda = True
    for index, (value, const) in helper_ir.default_args.items():
        if index < len(names):
            # The body reads the parameter through the local that holds its value.
            names[index] = f"{value.name} = {_expression_to_haxe(const, helper_ir.code, helper_ir)}"
    rendered = _generate_statements([statements[0]], helper_ir.code, helper_ir, 0, set())
    if len(rendered) != 1:
        return None
    body = rendered[0].strip()
    if isinstance(statements[0], IRTrace):
        # The statement form ends in a position comment, which would swallow the rest of the line.
        body = body.rsplit(" // {", 1)[0].rstrip()
    body = body.rstrip(";")
    if not body or "\n" in body:
        return None
    if isinstance(statements[0], IRReturn) and body.startswith("return "):
        body = body[len("return ") :]
    return names, body


def _enum_pseudo(enum_def: "Enum", code: Bytecode, name: Optional[str] = None, private: str = "") -> str:
    """Generate a Haxe enum declaration from a HashLink Enum definition."""
    if name is None:
        name = destaticify(disasm._enum_name(code, enum_def))
    enum_meta = rtti_meta.for_type(code, enum_def.name.resolve(code)) if enum_def.name.value else None
    type_meta = rtti_meta.render_entries(enum_meta.type) if enum_meta is not None else ""
    lines = [f"{type_meta}{private}enum {name} {{"]
    for index, construct in enumerate(enum_def.constructs):
        cname = disasm.enum_construct_name(code, enum_def, index)
        member_meta = (
            rtti_meta.render_entries(enum_meta.fields[cname])
            if enum_meta is not None and enum_meta.fields.get(cname)
            else ""
        )
        params = []
        for i, pidx in enumerate(construct.params):
            ptype = pidx.resolve(code)
            # An erased `Array<T>` parameter, typed by the arrays the image builds the constructor with.
            elem = disasm.erased_array_slots(code).get(("enum", id(enum_def), index, i))
            ptype_name = (
                f"Array<{disasm._haxe_annotation(code, elem)}>"
                if elem is not None
                else disasm._haxe_annotation(code, ptype)
            )
            params.append(f"arg{i}: {ptype_name}")
        if params:
            lines.append(f"    {member_meta}{cname}({', '.join(params)});")
        else:
            lines.append(f"    {member_meta}{cname};")
    lines.append("}")
    return "\n".join(lines)


def class_pseudo(ir_class: "IRClass", max_classes: Optional[int] = None) -> str:
    """
    Generates Haxe pseudocode for an entire IRClass, including any user-defined
    super classes or other referenced classes needed for recompilation.

    `max_classes` caps how many classes (the target class plus transitively
    referenced ones) are emitted before recursion stops; `None` (the default)
    is unbounded, which is required for compile-roundtrip use (the output must
    be self-contained to recompile). A class that is referenced from - or
    references - a large fraction of a big codebase can otherwise pull in
    thousands of classes transitively; callers that only want to look at one
    class (e.g. an interactive/agent-facing tool) should pass a small bound.
    """
    return "\n\n".join(_class_pseudo_recursive(ir_class, set(), max_classes=max_classes))


def _interface_pseudo(code: Bytecode, interface: typeinit.Interface, name: str, private: str = "") -> str:
    """An interface declaration from the type its values have: a member per field,
    methods for function-typed ones. `private` prefixes the declaration. A parameter an
    implementation gives a default has it here too (`a: T = v`), which is how Haxe matches
    the two: HL passes an optional basic value by reference."""
    properties = _interface_properties(code, interface)
    dynamic = typeinit.dynamic_members(code, interface.virtual)
    inherited = {
        member.name.resolve(code) for parent in interface.parents for member in parent.virtual.fields
    }
    extends = "".join(f" extends {disasm.type_to_haxe(parent.name)}" for parent in interface.parents)
    lines = [f"{_rtti_type_meta(code, interface.name)}{private}interface {name}{extends} {{"]
    for member in interface.virtual.fields:
        member_name = member.name.resolve(code)
        if member_name in inherited:
            continue
        member_type = member.type.resolve(code)
        signature = member_type.definition
        lines_before = len(lines)
        if isinstance(signature, Fun):
            implementation = _implementation(code, interface, member_name)
            defaults = default_arg_regs(code, implementation) if implementation is not None else {}
            narrowed = _narrowed_parameters(code, interface, member_name)
            params = []
            for i, arg in enumerate(signature.args):
                load = defaults.get(i + 1)
                if load is not None and implementation is not None:
                    value_type = implementation.regs[load.df["dst"].value].resolve(code)
                    default = _expression_to_haxe(default_arg_value(code, load), code, None)
                    params.append(f"a{i}: {disasm._haxe_annotation(code, value_type)} = {default}")
                else:
                    annotation = narrowed.get(i) or disasm._haxe_annotation(code, arg.resolve(code))
                    params.append(f"a{i}: {annotation}")
            ret = disasm._haxe_annotation(code, signature.ret.resolve(code))
            kw = "dynamic " if member_name in dynamic else ""
            lines.append(f"    {kw}function {member_name}({', '.join(params)}): {ret};")
        elif member_name in properties:
            setter = "set" if properties[member_name][0] else "never"
            lines.append(
                f"    var {member_name}(get, {setter}): {disasm._haxe_annotation(code, member_type)};"
            )
        elif access := next(
            (a for imp in interface.implementors if (a := _stored_property(code, imp, member_name))), ""
        ):
            lines.append(f"    var {member_name}{access}: {disasm._haxe_annotation(code, member_type)};")
        else:
            lines.append(f"    var {member_name}: {disasm._haxe_annotation(code, member_type)};")
        member_meta = _rtti_member_meta(code, interface.obj, member_name, False)
        if member_meta and len(lines) > lines_before:
            lines[lines_before] = f"    {member_meta}{lines[lines_before].lstrip()}"
    lines.append("}")
    return disasm.source_paths("\n".join(lines))


def _class_body(
    ir_class: "IRClass", emitted_enums: Optional[Set[int]] = None, module: Optional[ModuleDeclaration] = None
) -> Tuple[str, Set[str], Optional[str]]:
    """Render one class's own body — header, static + instance fields, methods and
    anonymous-closure helpers — with no cross-file recursion.

    Returns (source, referenced_class_names, super_name). This is the single place
    class bodies are rendered: `class_pseudo` wraps it with recursive emission of
    referenced classes (for single-class recompilation), `decompile_file` calls it
    flat per class for a whole-file dump, and `crashlink.project` with `module` for
    a declaration of a project module.
    """
    code: Bytecode = ir_class.code
    primary_obj = ir_class.dynamic if ir_class.dynamic else ir_class.static
    if not primary_obj:
        return "// Error: IRClass contains no valid Obj definitions.", set(), None

    class_name = destaticify(primary_obj.name.resolve(code))
    declared = class_name if module is None else module.name
    private = "private " if module is not None and module.private else ""

    interface = typeinit.interface_of(code, primary_obj)
    if interface is not None:
        return (
            _interface_pseudo(code, interface, declared, private),
            _interface_dependencies(code, interface),
            None,
        )

    # If this class is an hxsl shader, its real source is the serialized ShaderData
    # (the bytecode only holds generated uniform-plumbing). Recover and render it.
    try:
        shader = hxsl.shader_for_class(code, class_name)
        if shader is not None:
            return hxsl.render_shader(shader), set(), "hxsl.Shader"
    except (KeyError, IndexError, TypeError, ValueError, AttributeError):
        # Corrupt serialized shader blob: never let shader recovery break normal
        # decompilation.
        pass
    output_lines: List[str] = []
    indent_str = _indent_str(1)

    header = f"{_rtti_type_meta(code, primary_obj.name.resolve(code)) if primary_obj is not None else ''}{_struct_meta(primary_obj)}{private}class {declared}"
    generic = class_generics(code)
    params = generic.params(ir_class.dynamic)
    if params:
        header += f"<{', '.join(params)}>"
    abstract = abstracts.abstract_of(code, primary_obj)
    if abstract is not None:
        header = private + abstract.header(code, declared if module is not None else None)
    super_name: Optional[str] = None
    if ir_class.dynamic and ir_class.dynamic.super and ir_class.dynamic.super.value > 0:
        super_type = ir_class.dynamic.super.resolve(code)
        if isinstance(super_type.definition, Obj):
            super_name = destaticify(super_type.definition.name.resolve(code))
            super_args = generic.supers.get(id(ir_class.dynamic))
            header += f" extends {super_name}"
            if super_args:
                header += f"<{', '.join(_scope_text(code, arg) for arg in super_args)}>"
    # A class hxbit's `Serializable` macro rewrote is rendered as written:
    # without the members the macro generates again on recompile.
    serializable = hxbit.serializable_class(ir_class)
    static_methods = ir_class.static_methods
    methods = ir_class.methods
    static_fields = ir_class.static_fields
    fields = ir_class.fields
    header += _implements_clause(code, ir_class.dynamic)
    # An unnamed virtual-typed slot caches the object as one of its interfaces:
    # the compiler adds it, source never declares it.
    fields = [
        (name, typ)
        for name, typ in fields
        if not (name.startswith("__hidden") and isinstance(typ.definition, Virtual))
    ]
    if serializable is not None:
        if serializable.root:
            header += " implements hxbit.Serializable"
        static_methods = [m for m in static_methods if not hxbit.is_generated_method(m)]
        methods = [m for m in methods if not hxbit.is_generated_method(m)]
        static_fields = [f for f in static_fields if not hxbit.is_generated_field(code, f[0], f[1], True)]
        fields = [f for f in fields if not hxbit.is_generated_field(code, f[0], f[1], False)]
        for method in static_methods + methods:
            hxbit.restore_serialize_override(method)
            if serializable.root and code.partial_func_name(method.func) == "__constructor__":
                hxbit.strip_uid_prologue(method)
    header += " {"

    anon_funcs: Dict[int, "Function"] = {}
    for ir_func in static_methods + methods:
        anon_funcs.update(_collect_anonymous_functions(ir_func.block, code))
    # Static-init recovery renders anonymous closures as bare `__anon_<findex>`
    # identifiers (see _collect_static_field_inits); pull those in too.
    for init in getattr(ir_class, "static_field_inits", {}).values():
        for m in re.finditer(r"__anon_(\d+)", init):
            findex = int(m.group(1))
            if findex not in anon_funcs:
                func = next((f for f in code.functions if f.findex.value == findex), None)
                if func is not None:
                    anon_funcs[findex] = func
    helper_irs: Dict[int, IRFunction] = {}
    pending = list(anon_funcs.values())
    while pending:
        func = pending.pop()
        findex = func.findex.value
        if findex in helper_irs:
            continue
        helper_ir = IRFunction(code, func)
        recover_closure_param_elem_types(helper_ir)
        helper_irs[findex] = helper_ir
        pending.extend(_collect_anonymous_functions(helper_ir.block, code).values())
    all_methods = static_methods + methods + list(helper_irs.values())

    # Closures whose body is a single expression are rendered at the point they
    # are created; the rest stay lifted helpers. Which ones actually got
    # inlined is only known after the methods render, so the helper emission
    # below consults `inlined`.
    inline_bodies: Dict[int, Tuple[List[str], str]] = {}
    optional_adapters: Dict[int, List[bool]] = {}
    return_adapters: Set[int] = set()
    ctx_bodies: Dict[int, Tuple[List[str], str]] = {}
    inlined: Set[int] = set()
    for ir_func in static_methods + methods + list(helper_irs.values()):
        setattr(ir_func, "_inline_closure_bodies", inline_bodies)
        setattr(ir_func, "_helper_irs", helper_irs)
        setattr(ir_func, "_optional_adapters", optional_adapters)
        setattr(ir_func, "_return_adapters", return_adapters)
        setattr(ir_func, "_inlined_closures", inlined)
        setattr(ir_func, "_ctx_closure_bodies", ctx_bodies)
    # A closure is created inside the one that encloses it and so has the higher findex; rendering
    # the inner ones first lets the outer body embed them as lambdas too.
    for findex, helper_ir in sorted(helper_irs.items(), reverse=True):
        setattr(helper_ir, "_containing_class", ir_class)
        setattr(helper_ir, "_force_static", True)
        setattr(helper_ir, "_anon_name", f"__anon_{findex}")
        helper_sig = helper_ir.func.type.resolve(code).definition
        if isinstance(helper_sig, Fun) and helper_sig.args and helper_ir.locals:
            first = helper_sig.args[0].resolve(code).definition
            if isinstance(first, Enum) and first.name.value == 0:
                setattr(helper_ir, "_ctx_param_name", helper_ir.locals[0].name)
        # A closure nested in this one that captured the same variables is bound to them first, so
        # that this body reads as the lambda it came from.
        _collapse_adapter_guards(helper_ir)
        _hoist_closure_contexts(helper_ir, ctx_bodies)
        ctx_body = _closure_context_body(helper_ir)
        if ctx_body is not None:
            ctx_bodies[findex] = ctx_body
        body = _closure_inline_body(helper_ir)
        optional = _optional_ref_adapter(helper_ir) if body is None else None
        if optional is not None:
            optional_adapters[findex] = optional
        elif body is None and _void_return_adapter(helper_ir):
            return_adapters.add(findex)
        if body is not None:
            inline_bodies[findex] = body
    for ir_func in static_methods + methods:
        for name, helpers in _find_capture_boxes(ir_func, helper_irs).items():
            setattr(ir_func, "_unboxed_captures", getattr(ir_func, "_unboxed_captures", frozenset()) | {name})
            for helper_ir in helpers:
                setattr(helper_ir, "_unboxed_captures", frozenset({name}))
                body = _closure_inline_body(helper_ir)
                if body is not None:
                    inline_bodies[helper_ir.func.findex.value] = body
    for ir_func in static_methods + methods:
        _collapse_adapter_guards(ir_func)
        _hoist_closure_contexts(ir_func, ctx_bodies)

    # Collect natives, std functions, referenced classes and referenced enums.
    natives: List[Native] = []
    func_externs: Dict[int, Tuple[str, int]] = {}
    referenced_classes: Set[str] = set()
    referenced_enums: Dict[str, Enum] = {}
    annotation_types = [typ for _, typ in static_fields + fields]
    annotation_types.extend(getattr(ir_class, "field_elem_types", {}).values())
    annotation_types.extend(method.func.type.resolve(code) for method in all_methods)
    seen_types: Set[int] = set()
    for annotation in annotation_types:
        for typ in _annotation_dependencies(annotation, code, seen_types):
            definition = typ.definition
            if isinstance(definition, Obj) and not _is_std_class_obj(code, definition):
                name = destaticify(definition.name.resolve(code))
                if name != class_name:
                    referenced_classes.add(name)
            elif isinstance(definition, Enum):
                referenced_enums[destaticify(disasm._enum_name(code, definition))] = definition
    for ir_func in all_methods:
        natives.extend(_collect_natives(ir_func.block, code))
        func_externs.update(_collect_function_externs(ir_func.block, code))
        referenced_classes.update(_collect_referenced_user_classes(ir_func.block, code, {class_name}))
        referenced_enums.update(_collect_referenced_enums(ir_func.block, code))
    for ref_set in getattr(ir_class, "static_field_init_refs", {}).values():
        referenced_classes.update(ref_set - {class_name})
    for implemented in typeinit.implemented(code, ir_class.dynamic):
        if implemented.name not in STD_TYPES and implemented.name != "hxbit.Serializable":
            referenced_classes.add(destaticify(implemented.obj.name.resolve(code)))
    if module is not None:
        # A project declares every named enum in its own module, and the natives and
        # std externs once for all modules. A closure's capture context is the class's.
        module.externs.natives.update((native.findex.value, native) for native in natives)
        module.externs.functions.update(func_externs)
        referenced_enums = {name: enum for name, enum in referenced_enums.items() if not enum.name.value}
    native_extern = _native_extern(natives, code) if module is None else ""
    func_extern = _function_extern(func_externs, code) if module is None else ""
    if native_extern:
        output_lines.append(native_extern)
        output_lines.append("")
    if func_extern:
        output_lines.append(func_extern)
        output_lines.append("")
    deferred_enums: List[Tuple[str, Enum]] = []
    for enum_name in sorted(referenced_enums):
        definition = referenced_enums[enum_name]
        if emitted_enums is not None and id(definition) in emitted_enums:
            continue
        if not definition.name.value:
            # A capture context is declared only if the rendered body still uses it; a
            # lambda that was inlined does not need one (see the end of this function).
            deferred_enums.append((enum_name, definition))
            continue
        if emitted_enums is not None:
            emitted_enums.add(id(definition))
        output_lines.append(_enum_pseudo(definition, code, name=enum_name))
        output_lines.append("")
    header_index = len(output_lines)
    output_lines.append(header)

    if static_fields:
        for field_name, field_type in static_fields:
            field_type_haxe = disasm._haxe_annotation(code, field_type)
            if ir_class.static is not None:
                field_type_haxe = mapargs.refine(
                    field_type_haxe,
                    mapargs.value_type(code, mapargs.field_node(code, ir_class.static, field_name)),
                )
                field_type_haxe = ifacenames.refine(
                    field_type_haxe, code, mapargs.field_node(code, ir_class.static, field_name)
                )
            if field_type_haxe == "Array<Dynamic>":
                elem_types = getattr(ir_class, "field_elem_types", {})
                if field_name in elem_types:
                    elem_haxe = disasm._haxe_annotation(code, elem_types[field_name])
                    field_type_haxe = f"Array<{elem_haxe}>"
            init = getattr(ir_class, "static_field_inits", {}).get(field_name)
            if init == STATIC_INIT_UNRECOVERABLE:
                init_str = ""
                comment = "  // initializer not recovered"
            else:
                if (
                    init is not None
                    and strip(init).startswith("(__anon_")
                    and field_type_haxe.startswith("Array<")
                ):
                    # The initializer's helper returns the erased array.
                    init = f"cast {init}"
                init_str = f" = {init}" if init is not None else ""
                comment = ""
            output_lines.append(
                f"{indent_str}{_rtti_member_meta(code, ir_class.dynamic, field_name, True)}public static var {field_name}: {field_type_haxe}{init_str};{comment}"
            )
        output_lines.append("")

    if fields:
        for field_name, field_type in fields:
            field_type_haxe = disasm._haxe_annotation(code, field_type)
            if ir_class.dynamic is not None:
                field_type_haxe = mapargs.refine(
                    field_type_haxe,
                    mapargs.value_type(code, mapargs.field_node(code, ir_class.dynamic, field_name)),
                )
                field_type_haxe = ifacenames.refine(
                    field_type_haxe, code, mapargs.field_node(code, ir_class.dynamic, field_name)
                )
            if field_type_haxe == "Array<Dynamic>":
                elem_types = getattr(ir_class, "field_elem_types", {})
                if field_name in elem_types:
                    elem_haxe = disasm._haxe_annotation(code, elem_types[field_name])
                    field_type_haxe = f"Array<{elem_haxe}>"
            slot = generic.slot_in(ir_class.dynamic, ("field", id(ir_class.dynamic), field_name))
            if slot is not None:
                field_type_haxe = _scope_text(code, slot[0])
            meta = "@:s " if serializable is not None and field_name in serializable.fields else ""
            meta += _rtti_member_meta(code, ir_class.dynamic, field_name, False)
            if isinstance(field_type.definition, Packed):
                meta += "@:packed "
            output_lines.append(
                f"{indent_str}{_field_declaration(code, ir_class.dynamic, field_name, field_type_haxe, meta)}"
            )
        output_lines.append("")

    properties = _implemented_properties(code, ir_class.dynamic)
    if properties:
        output_lines.extend(f"{indent_str}{line}" for line in properties)
        output_lines.append("")

    if abstract is not None and abstract.properties:
        for prop in abstract.properties.values():
            read = "get" if prop.getter is not None else "never"
            write = "set" if prop.setter is not None else "never"
            prop_type = disasm._haxe_annotation(code, prop.type)
            output_lines.append(f"{indent_str}public var {prop.name}({read}, {write}): {prop_type};")
        output_lines.append("")

    for ir_func in static_methods:
        setattr(ir_func, "_containing_class", ir_class)
        func_str = _generate_function_pseudo(ir_func)
        for line in func_str.split("\n"):
            output_lines.append(f"{indent_str}{line}")
        output_lines.append("")

    for ir_func in methods:
        setattr(ir_func, "_containing_class", ir_class)
        func_str = _generate_function_pseudo(ir_func)
        for line in func_str.split("\n"):
            output_lines.append(f"{indent_str}{line}")
        output_lines.append("")

    # Inline functions no longer in the bytecode, rebuilt from their copies.
    for declaration in rebuilt_inline_declarations(code, primary_obj):
        output_lines.extend(f"{indent_str}{line}" for line in declaration.splitlines())
        output_lines.append("")

    # Emit any anonymous closures referenced by this class as private helpers,
    # except the ones already rendered inline at their creation site.
    # A helper rendered here can inline another one into its body, so render them all before deciding
    # which are emitted.
    rendered_helpers: Dict[int, str] = {}
    for findex, helper_ir in sorted(helper_irs.items()):
        if findex in inlined:
            continue
        setattr(helper_ir, "_containing_class", ir_class)
        setattr(helper_ir, "_force_static", True)
        setattr(helper_ir, "_anon_name", f"__anon_{findex}")
        rendered_helpers[findex] = _generate_function_pseudo(helper_ir)
    for findex, func_str in sorted(rendered_helpers.items()):
        if findex in inlined:
            continue
        for line in func_str.split("\n"):
            output_lines.append(f"{indent_str}{line}")
        output_lines.append("")

    if output_lines and output_lines[-1] == "":
        output_lines.pop()

    rendered = "\n".join(output_lines[header_index:])
    declared: List[str] = []
    for enum_name, definition in deferred_enums:
        if not re.search(rf"\b{re.escape(enum_name)}\b", rendered):
            continue
        if emitted_enums is not None:
            emitted_enums.add(id(definition))
        declared.extend([_enum_pseudo(definition, code, name=enum_name), ""])
    output_lines[header_index:header_index] = declared
    output_lines.append("}")
    return disasm.source_paths("\n".join(output_lines)), referenced_classes, super_name


def rebuilt_inline_declarations(code: Bytecode, obj: Obj) -> List[str]:
    """Declarations of the inline functions of `obj` rebuilt from their copies
    (see `decomp.inline_calls`), which the bytecode no longer holds."""
    declarations = []
    for template in inline_index(code).rebuilt.get(id(obj), ()):
        if template.ambiguous or template.expression is None:
            continue
        params = ", ".join(
            f"v{i}: {disasm._haxe_annotation(code, typ)}" for i, typ in enumerate(template.param_types)
        )
        ret = disasm._haxe_annotation(code, template.expression.get_type())
        body = _expression_to_haxe(template.expression, code, None)
        declarations.append(
            f"public static inline function {template.name}({params}): {ret} {{\n{_indent_str(1)}return {body};\n}}"
        )
    return declarations


def _class_pseudo_recursive(
    ir_class: "IRClass",
    emitted: Set[str],
    max_classes: Optional[int] = None,
    emitted_enums: Optional[Set[int]] = None,
) -> List[str]:
    """
    Recursive helper for class_pseudo. Returns a list of class source strings:
    the class itself plus its super and referenced user classes (for recompile-
    ability), each emitted once.
    """
    code: Bytecode = ir_class.code
    if emitted_enums is None:
        emitted_enums = set()

    primary_obj = ir_class.dynamic if ir_class.dynamic else ir_class.static
    if not primary_obj:
        return ["// Error: IRClass contains no valid Obj definitions."]

    class_name = destaticify(primary_obj.name.resolve(code))
    if class_name in emitted:
        return []
    emitted.add(class_name)

    body, referenced_classes, super_name = _class_body(ir_class, emitted_enums)
    result = [body]

    # Recursively emit the super class and any other referenced user classes.
    to_emit: Set[str] = set(referenced_classes)
    if super_name and super_name != class_name:
        to_emit.add(super_name)

    for other_name in sorted(to_emit):
        if max_classes is not None and len(emitted) >= max_classes:
            result.append(
                f"// ... {len(to_emit - emitted)} more referenced class(es) omitted "
                f"(max_classes={max_classes} reached)"
            )
            break
        if other_name in emitted:
            continue
        try:
            other_obj = code.get_test_obj(other_name)
        except (ValueError, IndexError):
            # No class by that name in the image (ValueError) or a corrupt name
            # index while scanning: fall back to a stub.
            result.append(f"class {other_name} {{}}")
            emitted.add(other_name)
            continue
        # Std classes (e.g. a user exception's `extends haxe.Exception`) are
        # referenced by path in the header, never inlined.
        if _is_std_class_obj(code, other_obj):
            emitted.add(other_name)
            continue
        try:
            other_ir = IRClass(code, other_obj)
            result.extend(
                _class_pseudo_recursive(
                    other_ir, emitted, max_classes=max_classes, emitted_enums=emitted_enums
                )
            )
        except (KeyError, IndexError, ValueError, MalformedBytecode):
            # Corrupt bytecode while decompiling a referenced class: fall back
            # to a stub so one bad class does not lose the rest.
            result.append(f"class {other_name} {{}}")
            emitted.add(other_name)

    return result
