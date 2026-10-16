"""
Public entry points: function pseudocode, whole-file decompilation and stub generation.
"""

from __future__ import annotations

import os
from typing import Optional, List, Set, Dict, Tuple, Any
from .doc import RenderedSource, marked, render_marked
from ..core import Bytecode, Obj, Type, Function, Fun, Native, destaticify
from .. import disasm
from .. import abstracts, typeinit
from ..decomp import IRClass, IRFunction
from ..decomp.opt.clean import default_arg_regs, default_arg_value, overriding_default_arg_regs
from .naming import _method_registry, _rtti_type_meta, _struct_meta
from .casts import _return_annotation
from .hierarchy import (
    _ancestors,
    _is_dynamic_method,
    _find_constructor,
    _obj_pair,
    _obj_functions,
    _erased_parameters,
    _overrides_super,
)
from .members import ModuleDeclaration, _implements_clause, _implemented_properties, class_field_lines
from .render import _expression_to_haxe, _generate_function_pseudo_mapped
from .classes import _interface_pseudo, _class_body


def pseudo(ir_func: IRFunction) -> str:
    """
    Generates Haxe pseudocode from a given IRFunction, wrapped in a class for context.
    """
    return pseudo_oplines(ir_func)[0]


def pseudo_oplines(ir_func: IRFunction) -> Tuple[str, Dict[int, int]]:
    """pseudo() plus a body-relative opcode→line map.

    Line indices match the function body as shown after the class wrapper is
    stripped (the map is partial — optimizer-created statements have no src op).
    """
    text, op_to_line, _ = _pseudo_wrapped(ir_func)
    return text, op_to_line


def _pseudo_wrapped(ir_func: IRFunction) -> Tuple[str, Dict[int, int], int]:
    """The wrapped text, the opcode→line map, and how many lines of the text the wrapper
    takes before the function body starts (its last line closes the wrapper)."""
    function_body_str, op_to_line = _generate_function_pseudo_mapped(ir_func)

    full_name = ir_func.code.full_func_name(ir_func.func)
    class_name_suggestion = "DecompiledClass"
    if "." in full_name and full_name != "<none>.<none>":
        class_name_part = full_name.rsplit(".", 1)[0]
        if class_name_part and class_name_part != "<none>":
            class_name_suggestion = class_name_part.lstrip("$")
    elif not isinstance(ir_func.func, Native):
        # No proto/field registration at all to get a name from (see the
        # matching fallback in _generate_function_pseudo) — fall back to the
        # first argument's type if it looks like a `this` receiver.
        core_fun_type = ir_func.func.type.resolve(ir_func.code).definition
        if isinstance(core_fun_type, Fun) and core_fun_type.args:
            first_arg_type = core_fun_type.args[0].resolve(ir_func.code)
            if isinstance(first_arg_type.definition, Obj):
                class_name_suggestion = destaticify(disasm.type_name(ir_func.code, first_arg_type))

    abstract = (
        abstracts.abstract_of_function(ir_func.code, ir_func.func)
        if isinstance(ir_func.func, Function)
        else None
    )
    header = (
        disasm.source_paths(abstract.header(ir_func.code))
        if abstract is not None
        else f"class {class_name_suggestion}"
    )
    final_output = [f"{header} {{"]
    body_start = final_output[0].count("\n") + 1
    final_output.extend(["    " + line for line in function_body_str.split("\n")])
    final_output.append("}")

    return "\n".join(final_output), op_to_line, body_start


def pseudo_spans(ir_func: IRFunction, types: bool = False) -> RenderedSource:
    """`pseudo_oplines()` plus the symbol each token names: the same text, with a
    `SymbolSpan` for every local, field, method, type and enum construct in it. With
    `types`, every expression also gets a `TypeSpan`: the type it produces."""
    with marked(types) as table:
        text, oplines, body_start = _pseudo_wrapped(ir_func)
    rendered = render_marked(text, table)
    rendered.oplines = oplines
    rendered.body_start = body_start
    return rendered


def decompile_file(code: Bytecode, needle: str) -> Optional[str]:
    """Decompile every class/function of a debug source file into one dump.

    The single source of by-file decompilation, shared by the CLI (`df`) and GUI.
    Classes are grouped and ordered by `disasm.file_class_map` (the one place file
    ordering lives) and each is rendered once via `_class_body` — no cross-file
    recursion, so the dump stays scoped to the file. `needle` matches a debug file
    by full path, path suffix, or basename. Returns None if nothing matches.
    """
    fmap = disasm.file_class_map(code)
    keys = [k for k in fmap if k == needle or k.endswith(needle) or os.path.basename(k) == needle]
    if not keys:
        return None

    reg = _method_registry(code)
    findex_map = code.get_findex_map()
    chunks: List[str] = []
    emitted: Set[str] = set()
    emitted_enums: Set[int] = set()

    for key in keys:
        for entry in fmap[key]:
            if entry.canonical_name == "(standalone)":
                for m in entry.methods:
                    fn = findex_map.get(m.findex)
                    if fn is None or isinstance(fn, Native):
                        continue
                    try:
                        chunks.append(pseudo(IRFunction(code, fn)))
                    except Exception as e:
                        # Deliberately broad: one bad function must not lose the
                        # rest of the file; the failure is surfaced in the output.
                        chunks.append(f"// f@{m.findex}: decompilation failed: {e}")
                continue
            if entry.canonical_name in emitted:
                continue
            emitted.add(entry.canonical_name)
            reg_entry = reg.get(entry.methods[0].findex) if entry.methods else None
            if reg_entry is None:
                continue
            try:
                chunks.append(_class_body(IRClass(code, reg_entry[0]), emitted_enums)[0])
            except Exception as e:
                # Deliberately broad: one bad class must not lose the rest of the
                # file; the failure is surfaced in the output.
                chunks.append(f"// class {entry.canonical_name}: decompilation failed: {e}")

    return "\n\n".join(chunks)


# --- stub generation -------------------------------------------------------
#
# For large decompilation projects: emit a whole file as a *compilable stub* —
# every class with its fields and its methods' exact signatures (names, argument
# types, return types), but with bodies replaced by a type-correct placeholder.
# Other files that reference this one compile against a faithful API surface,
# while the un-decompiled bodies fail loudly if actually called.


def _stub_default(typ: Type) -> str:
    """A type-correct default *expression* for a stub value of `typ`."""
    k = typ.kind.value
    K = Type.Kind
    if k in (K.U8.value, K.U16.value, K.I32.value, K.I64.value):
        return "0"
    if k in (K.F32.value, K.F64.value):
        return "0.0"
    if k == K.BOOL.value:
        return "false"
    return "null"


def _stub_method(code: Bytecode, func: Function, is_instance: bool, dynamic: Optional[Obj]) -> Optional[str]:
    """One method rendered as a compilable stub from its type alone (no decompile)."""
    if isinstance(func, Native):
        return None

    raw = code.partial_func_name(func)
    is_ctor = raw == "__constructor__"
    name = "new" if is_ctor else (raw if raw and raw != "<none>" else f"f{func.findex.value}")
    if is_ctor:
        is_instance = True
    abstract = abstracts.abstract_of_function(code, func)
    if abstract is not None:
        is_instance = func.findex.value in abstract.instance
        if func.findex.value == abstract.constructor:
            fun = func.type.resolve(code).definition
            if not isinstance(fun, Fun):
                return None
            params = ", ".join(
                f"arg{i}: {disasm._haxe_annotation(code, a.resolve(code))}" for i, a in enumerate(fun.args)
            )
            return f"public function new({params}) {{\n    this = {_stub_default(fun.ret.resolve(code))};\n}}"

    fun_def = func.type.resolve(code).definition
    params: List[str] = []
    ret_type: Optional[Type] = None
    if isinstance(fun_def, Fun):
        start = 1 if is_instance else 0
        defaults = {reg: (func, load) for reg, load in default_arg_regs(code, func).items()}
        for reg, found in overriding_default_arg_regs(code, func).items():
            defaults.setdefault(reg, found)
        erased, narrowed = (
            _erased_parameters(code, dynamic, name) if is_instance and not is_ctor else (set(), {})
        )
        for i, arg_idx in enumerate(fun_def.args[start:]):
            t = (
                narrowed[i]
                if i in narrowed
                else "Dynamic"
                if i in erased
                else disasm._haxe_annotation(code, arg_idx.resolve(code))
            )
            found = defaults.get(start + i)
            if found is not None:
                owner, load = found
                value_type = disasm._haxe_annotation(code, owner.regs[load.df["dst"].value].resolve(code))
                default = _expression_to_haxe(default_arg_value(code, load), code, None)
                params.append(f"arg{i}: {value_type} = {default}")
                continue
            optional = "?" if id(fun_def) in disasm._trace_signature_types(code)[1] and start + i == 1 else ""
            params.append(f"{optional}arg{i}: {t}" if t else f"{optional}arg{i}")
        ret_type = fun_def.ret.resolve(code)
    ret_name = _return_annotation(code, func, ret_type) if ret_type is not None else "Void"

    static_kw = "" if is_instance else "static "
    override_kw = (
        "override " if (is_instance and not is_ctor and _overrides_super(code, dynamic, name)) else ""
    )
    if is_instance and not is_ctor and _is_dynamic_method(code, dynamic, func):
        override_kw += "dynamic "
    ret_decl = "" if is_ctor else (f": {ret_name}" if ret_name else "")
    header = f"public {static_kw}{override_kw}function {name}({', '.join(params)}){ret_decl} {{"

    body: Optional[str] = None
    if is_ctor:
        # A derived class must call super(); supply type-correct default args so
        # the stub compiles even when we don't reproduce the real constructor.
        # The nearest ancestor's constructor is the one `super()` calls; with none,
        # Haxe rejects the call.
        pctor = (
            next(
                (
                    ctor
                    for parent in _ancestors(code, dynamic)
                    if (ctor := _find_constructor(code, parent)) is not None
                ),
                None,
            )
            if dynamic is not None
            else None
        )
        if pctor is not None:
            super_args = ""
            pfun = pctor.type.resolve(code).definition
            if isinstance(pfun, Fun) and len(pfun.args) > 1:
                # A parameter with a default takes it: its declared type may not be nullable.
                pdefaults = default_arg_regs(code, pctor)
                super_args = ", ".join(
                    _expression_to_haxe(default_arg_value(code, pdefaults[k]), code, None)
                    if k in pdefaults
                    else _stub_default(a.resolve(code))
                    for k, a in enumerate(pfun.args[1:], 1)
                )
            body = f"    super({super_args});"
    elif ret_type is not None and ret_type.kind.value != Type.Kind.VOID.value:
        # `throw` type-checks against any return type — the standard stub body.
        body = f'    throw "stub: {name} not decompiled";'

    return f"{header}\n{body}\n}}" if body else f"{header}\n}}"


def _stub_class(code: Bytecode, primary: Obj, module: Optional[ModuleDeclaration] = None) -> str:
    """A class rendered as a compilable stub straight from its Obj: fields + method
    signatures, no decompilation (so it's fast and can't crash on hard bodies).
    `module` declares it in a project module (see `_class_body`)."""
    dynamic, static = _obj_pair(primary)
    named = dynamic if dynamic is not None else static
    assert named is not None
    # Short name only: the package is declared once per file (a dotted name in a
    # `class` declaration isn't valid Haxe). `extends`/type refs stay qualified.
    class_name = destaticify(named.name.resolve(code)).rsplit(".", 1)[-1]
    if module is not None:
        class_name = module.name
    private = "private " if module is not None and module.private else ""
    interface = typeinit.interface_of(code, static)
    if interface is not None:
        return _interface_pseudo(code, interface, class_name, private)

    lines: List[str] = []
    header = f"{_rtti_type_meta(code, dynamic.name.resolve(code)) if dynamic is not None else ''}{_struct_meta(dynamic)}{private}class {class_name}"
    if dynamic is not None and dynamic.super and dynamic.super.value > 0:
        super_def = dynamic.super.resolve(code).definition
        if isinstance(super_def, Obj):
            header += f" extends {destaticify(super_def.name.resolve(code))}"
    header += _implements_clause(code, dynamic)
    abstract = abstracts.abstract_of(code, primary)
    if abstract is not None:
        underlying = abstract.underlying_annotation(code)
        header = f"{private}abstract {class_name if module is not None else abstract.name}({underlying}) from {underlying} to {underlying}"
    header += " {"
    lines.append(header)
    if abstract is not None and abstract.properties:
        for prop in abstract.properties.values():
            read = "get" if prop.getter is not None else "never"
            write = "set" if prop.setter is not None else "never"
            lines.append(
                f"    public var {prop.name}({read}, {write}): {disasm._haxe_annotation(code, prop.type)};"
            )
        lines.append("")

    fields = class_field_lines(code, primary) + _implemented_properties(code, dynamic)
    lines.extend(f"    {field}" for field in fields)
    if fields:
        lines.append("")

    # Static methods (from the static half) then instance methods, deduped by findex.
    seen: Set[int] = set()
    ordered: List[Tuple[Function, bool]] = []
    for func in _obj_functions(code, static):
        seen.add(func.findex.value)
        ordered.append((func, False))
    for func in _obj_functions(code, dynamic):
        if func.findex.value not in seen:
            seen.add(func.findex.value)
            ordered.append((func, True))

    for func, is_instance in ordered:
        stub = _stub_method(code, func, is_instance, dynamic)
        if stub is None:
            continue
        for line in stub.split("\n"):
            lines.append(f"    {line}")
        lines.append("")

    if lines and lines[-1] == "":
        lines.pop()
    lines.append("}")
    return "\n".join(lines)


def stub_file(code: Bytecode, needle: str) -> Optional[str]:
    """Emit a compilable stub of a whole debug file: every class with its fields
    and exact method signatures, bodies replaced by type-correct placeholders.

    For large decompilation projects — stub the files you haven't reached yet so
    the project keeps compiling and the API surface other files see stays faithful.
    `needle` matches a debug file by full path, suffix, or basename; None if no
    match. Classes are ordered by `disasm.file_class_map`.
    """
    fmap = disasm.file_class_map(code)
    keys = [k for k in fmap if k == needle or k.endswith(needle) or os.path.basename(k) == needle]
    if not keys:
        return None

    reg = _method_registry(code)
    return _stub_from_entries(code, reg, [e for k in keys for e in fmap[k]])


def _stub_from_entries(code: Bytecode, reg: Dict[int, Any], entries: List[Any]) -> str:
    """Render a stub for one file's ClassEntry list, straight from each class's Obj
    (no decompilation, so it's fast and can't crash on a hard-to-lift body)."""
    chunks: List[str] = []
    emitted: Set[str] = set()
    package = ""
    for entry in entries:
        if entry.canonical_name == "(standalone)" or entry.canonical_name in emitted:
            continue
        emitted.add(entry.canonical_name)
        reg_entry = reg.get(entry.methods[0].findex) if entry.methods else None
        if reg_entry is None:
            continue
        if not package and "." in entry.canonical_name:
            package = entry.canonical_name.rsplit(".", 1)[0]
        try:
            chunks.append(_stub_class(code, reg_entry[0]))
        except Exception as e:
            # Deliberately broad: one bad class must not lose the rest of the
            # file; the failure is surfaced in the output.
            chunks.append(f"// class {entry.canonical_name}: stub failed: {e}")
    body = "\n\n".join(chunks)
    # A packaged file needs a matching `package` declaration to compile under its
    # directory on the classpath.
    return f"package {package};\n\n{body}" if package else body
