"""
Human-readable disassembly of opcodes and utilities to work at a relatively low level with HashLink bytecode.
"""

from ast import literal_eval
from typing import List, Optional, Dict

try:
    from tqdm import tqdm

    USE_TQDM = True
except ImportError:
    USE_TQDM = False


from .core import (
    Bytecode,
    Fun,
    Function,
    Native,
    Obj,
    Opcode,
    Reg,
    Type,
    Virtual,
    Void,
    fileRef,
    full_func_name,
    partial_func_name,
    tIndex,
)
from .opcodes import opcodes


def type_name(code: Bytecode, typ: Type) -> str:
    """
    Generates a human-readable name for a type.
    """
    typedef = type(typ.definition)
    defn = typ.definition

    if typedef == Obj and isinstance(defn, Obj):
        return defn.name.resolve(code)
    elif typedef == Virtual and isinstance(defn, Virtual):
        fields = []
        for field in defn.fields:
            fields.append(field.name.resolve(code))
        return f"Virtual[{', '.join(fields)}]"
    return typedef.__name__


def type_to_haxe(type: str) -> str:
    """
    Maps internal HashLink type names to Haxe type names.
    """
    mapping = {
        "I32": "Int",
        "F64": "Float",
        "Bytes": "hl.Bytes",
        "Dyn": "Dynamic",
        "Fun": "Function",
    }
    return mapping.get(type, type)


def func_header(code: Bytecode, func: Function | Native) -> str:
    """
    Generates a human-readable header for a function.
    """
    if isinstance(func, Native):
        return native_header(code, func)
    assert isinstance(func, Function)
    name = full_func_name(code, func)
    fun_type = func.type.resolve(code).definition
    if isinstance(fun_type, Fun):
        fun: Fun = fun_type
        return f"f@{func.findex.value} {'static ' if is_static(code, func) else ''}{name} ({', '.join([type_name(code, arg.resolve(code)) for arg in fun.args])}) -> {type_name(code, fun.ret.resolve(code))} (from {func.resolve_file(code)})"
    return f"f@{func.findex.value} {name} (no fun found!)"


def func_header_html(code: Bytecode, func: Function | Native) -> str:
    """
    Generates a human-readable header for a function in HTML format.
    """
    if isinstance(func, Native):
        return native_header(code, func)
    assert isinstance(func, Function)
    name = partial_func_name(code, func)
    fun_type = func.type.resolve(code).definition
    if isinstance(fun_type, Fun):
        fun: Fun = fun_type
        return f"f@{func.findex.value} {'static ' if is_static(code, func) else ''}<code>{name} ({', '.join([type_name(code, arg.resolve(code)) for arg in fun.args])})</code> Returns <code>{type_name(code, fun.ret.resolve(code))}</code>"
    return f"f@{func.findex.value} <code>{name}</code> (no fun found!)"


def native_header(code: Bytecode, native: Native) -> str:
    """
    Generates a human-readable header for a native function.
    """
    fun_type = native.type.resolve(code).definition
    if isinstance(fun_type, Fun):
        fun: Fun = fun_type
        return f"f@{native.findex.value} {native.lib.resolve(code)}.{native.name.resolve(code)} [native] ({', '.join([type_name(code, arg.resolve(code)) for arg in fun.args])}) -> {type_name(code, fun.ret.resolve(code))} (from {native.lib.resolve(code)})"
    return f"f@{native.findex.value} {native.lib.resolve(code)}.{native.name.resolve(code)} [native] (no fun found!)"


def is_std(code: Bytecode, func: Function | Native) -> bool:
    """
    Checks if a function is from the standard library. This is a heuristic and is a bit broken still.
    """
    if isinstance(func, Native):
        return True
    try:
        if "std" in func.resolve_file(code):
            return True
    except ValueError:
        pass
    return False


def is_static(code: Bytecode, func: Function) -> bool:
    """
    Checks if a function is static.
    """
    # bindings are static functions, protos are dynamic
    for type in code.types:
        if type.kind.value == Type.TYPEDEFS.index(Obj):
            if not isinstance(type.definition, Obj):
                raise TypeError(f"Expected Obj, got {type.definition}")
            definition: Obj = type.definition
            for binding in definition.bindings:
                if binding.findex.value == func.findex.value:
                    return True
    return False


def pseudo_from_op(
    op: Opcode,
    idx: int,
    regs: List[Reg] | List[tIndex],
    code: Bytecode,
    terse: bool = False,
    func: Optional[Function] = None,
) -> str:
    """
    Generates pseudocode disassembly from an opcode.
    """
    match op.op:
        # Constants
        case "Int" | "Float":
            return f"reg{op.df['dst']} = {op.df['ptr'].resolve(code)}"
        case "Bool":
            return f"reg{op.df['dst']} = {op.df['value'].value}"
        case "String":
            return f'reg{op.df["dst"]} = "{op.df["ptr"].resolve(code)}"'
        case "Null":
            return f"reg{op.df['dst']} = null"

        # Control Flow
        case "Label":
            return "label"
        case "JAlways":
            return f"jump to {idx + (op.df['offset'].value + 1)}"
        case "JEq" | "JSEq":
            return f"if reg{op.df['a']} == reg{op.df['b']}: jump to {idx + (op.df['offset'].value + 1)}"
        case "JNull":
            return f"if reg{op.df['reg']} is null: jump to {idx + (op.df['offset'].value + 1)}"
        case "JFalse":
            return f"if reg{op.df['cond']} is false: jump to {idx + (op.df['offset'].value + 1)}"
        case "JTrue":
            return f"if reg{op.df['cond']} is true: jump to {idx + (op.df['offset'].value + 1)}"
        case "JSGte":
            return f"if reg{op.df['a']} >= reg{op.df['b']}: jump to {idx + (op.df['offset'].value + 1)}"
        case "JULt" | "JSLt":
            return f"if reg{op.df['a']} < reg{op.df['b']}: jump to {idx + (op.df['offset'].value + 1)}"
        case "JNotLt":
            return f"if reg{op.df['a']} >= reg{op.df['b']}: jump to {idx + (op.df['offset'].value + 1)}"
        case "JNotEq":
            return f"if reg{op.df['a']} != reg{op.df['b']}: jump to {idx + (op.df['offset'].value + 1)}"
        case "JSGt":
            return f"if reg{op.df['a']} > reg{op.df['b']}: jump to {idx + (op.df['offset'].value + 1)}"
        case "JNotNull":
            return f"if reg{op.df['reg']} is not null: jump to {idx + (op.df['offset'].value + 1)}"

        # Arithmetic
        case "Mul":
            return f"reg{op.df['dst']} = reg{op.df['a']} * reg{op.df['b']}"
        case "SDiv":
            return f"reg{op.df['dst']} = reg{op.df['a']} / reg{op.df['b']}"
        case "Incr":
            return f"reg{op.df['dst']}++"
        case "Decr":
            return f"reg{op.df['dst']}--"
        case "Sub":
            return f"reg{op.df['dst']} = reg{op.df['a']} - reg{op.df['b']}"
        case "Add":
            return f"reg{op.df['dst']} = reg{op.df['a']} + reg{op.df['b']}"
        case "Shl":
            return f"reg{op.df['dst']} = reg{op.df['a']} << reg{op.df['b']}"
        case "SMod":
            return f"reg{op.df['dst']} = reg{op.df['a']} % reg{op.df['b']}"
        case "Xor":
            return f"reg{op.df['dst']} = reg{op.df['a']} ^ reg{op.df['b']}"

        # Memory/Object Operations
        case "GetThis":
            this = None
            for reg in regs:
                # find first Obj reg
                if type(reg.resolve(code).definition) == Obj:
                    this = reg.resolve(code)
                    break
            if this:
                return (
                    f"reg{op.df['dst']} = this.{op.df['field'].resolve_obj(code, this.definition).name.resolve(code)}"
                )
            return f"reg{op.df['dst']} = this.f@{op.df['field'].value} (this not found!)"
        case "GetGlobal":
            glob = type_name(code, op.df["global"].resolve(code))
            return f"reg{op.df['dst']} = {glob} (g@{op.df['global']})"
        case "Field":
            field = op.df["field"].resolve_obj(code, regs[op.df["obj"].value].resolve(code).definition)
            return f"reg{op.df['dst']} = reg{op.df['obj']}.{field.name.resolve(code)}"
        case "SetField":
            field = op.df["field"].resolve_obj(code, regs[op.df["obj"].value].resolve(code).definition)
            return f"reg{op.df['obj']}.{field.name.resolve(code)} = reg{op.df['src']}"
        case "Mov":
            return f"reg{op.df['dst']} = reg{op.df['src']}"
        case "SetArray":
            return f"reg{op.df['array']}[reg{op.df['index']}] = reg{op.df['src']})"
        case "ArraySize":
            return f"reg{op.df['dst']} = len(reg{op.df['array']})"
        case "New":
            typ = regs[op.df["dst"].value].resolve(code)
            return f"reg{op.df['dst']} = new {type_name(code, typ)}"
        case "DynSet":
            return f"reg{op.df['obj']}.{op.df['field'].resolve(code)} = reg{op.df['src']}"
        case "GetThis":
            if not func:
                return f"reg{op.df['dst']} = this.field{op.df['field']}"
            obj = func.regs[0].resolve(code)
            assert isinstance(obj.definition, Obj), "reg0 should be an Obj of the type of this (is this static?)"
            fields = obj.definition.resolve_fields(code)
            field = fields[op.df["field"].value]
            return f"reg{op.df['dst']} = this.{field.name.resolve(code)}"
        case "SetThis":
            if not func:
                return f"this.field{op.df['field']} = reg{op.df['src']}"
            obj = func.regs[0].resolve(code)
            assert isinstance(obj.definition, Obj), "reg0 should be an Obj of the type of this (is this static?)"
            fields = obj.definition.resolve_fields(code)
            field = fields[op.df["field"].value]
            return f"this.{field.name.resolve(code)} = reg{op.df['src']}"
        case "InstanceClosure":
            return f"reg{op.df['dst']} = f@{op.df['fun']} (as method of reg{op.df['obj']})"

        # Type Conversions
        case "ToSFloat":
            return f"reg{op.df['dst']} = SFloat(reg{op.df['src']})"
        case "ToVirtual":
            return f"reg{op.df['dst']} = Virtual(reg{op.df['src']})"
        case "Ref":
            return f"reg{op.df['dst']} = &reg{op.df['src']}"
        case "SetMem":
            return f"reg{op.df['bytes']}[reg{op.df['index']}] = reg{op.df['src']}"
        case "GetMem":
            return f"reg{op.df['dst']} = reg{op.df['bytes']}[reg{op.df['index']}]"
        case "SafeCast":
            return f"reg{op.df['dst']} = reg{op.df['src']} as {type_name(code, regs[op.df['dst'].value].resolve(code))}"
        case "UnsafeCast":
            return f"reg{op.df['dst']} = reg{op.df['src']} unsafely as {type_name(code, regs[op.df['dst'].value].resolve(code))}"

        # Function Calls
        case "CallClosure":
            args = ", ".join([f"reg{arg}" for arg in op.df["args"].value])
            if type(regs[op.df["dst"].value].resolve(code).definition) == Void:
                return f"reg{op.df['fun']}({args})"
            return f"reg{op.df['dst']} = reg{op.df['fun']}({args})"
        case "Call0":
            return f"reg{op.df['dst']} = f@{op.df['fun']}()"
        case "Call1":
            return f"reg{op.df['dst']} = f@{op.df['fun']}(reg{op.df['arg0']})"
        case "Call2":
            fun = full_func_name(code, code.fn(op.df["fun"].value))
            return (
                f"reg{op.df['dst']} = f@{op.df['fun']}({', '.join([f'reg{op.df[arg]}' for arg in ['arg0', 'arg1']])})"
            )
        case "Call3":
            return f"reg{op.df['dst']} = f@{op.df['fun']}({', '.join([f'reg{op.df[arg]}' for arg in ['arg0', 'arg1', 'arg2']])})"
        case "Call4":
            return f"reg{op.df['dst']} = f@{op.df['fun']}({', '.join([f'reg{op.df[arg]}' for arg in ['arg0', 'arg1', 'arg2', 'arg3']])})"
        case "CallN":
            return f"reg{op.df['dst']} = f@{op.df['fun']}({', '.join([f'reg{arg}' for arg in op.df['args'].value])})"
        case "CallThis":
            if not func:
                return f"reg{op.df['dst']} = this.field{op.df['field']}({', '.join([f'reg{arg}' for arg in op.df['args'].value])})"
            obj = func.regs[0].resolve(code)
            assert isinstance(obj.definition, Obj), "reg0 should be an Obj of the type of this (is this static?)"
            fields = obj.definition.resolve_fields(code)
            field = fields[op.df["field"].value]
            return f"reg{op.df['dst']} = this.{field.name.resolve(code)}({', '.join([f'reg{arg}' for arg in op.df['args'].value])})"

        # Error Handling
        case "NullCheck":
            return f"if reg{op.df['reg']} is null: error"
        case "Trap":
            return f"trap to reg{op.df['exc']} (end: {idx + (op.df['offset'].value)})"
        case "EndTrap":
            return f"end trap to reg{op.df['exc']}"

        # Switch
        case "Switch":
            reg = op.df["reg"]
            offsets = op.df["offsets"].value
            offset_mappings = []
            cases = []
            for i, offset in enumerate(offsets):
                if offset.value != 0:
                    case_num = str(i)
                    target = str(idx + (offset.value + 1))
                    offset_mappings.append(f"if {case_num} jump {target}")
                    cases.append(case_num)
            if not terse:
                return f"switch reg{reg} [{', '.join(offset_mappings)}] (end: {idx + (op.df['end'].value)})"
            return f"switch reg{reg} [{', '.join(cases)}] (end: {idx + (op.df['end'].value)})"

        # Return
        case "Ret":
            if type(regs[op.df["ret"].value].resolve(code).definition) == Void:
                return "return"
            return f"return reg{op.df['ret']}"

        # Unknown
        case _:
            return f"unknown operation {op.op}"


def fmt_op(
    code: Bytecode,
    regs: List[Reg] | List[tIndex],
    op: Opcode,
    idx: int,
    width: int = 15,
    debug: Optional[List[fileRef]] = None,
    func: Optional[Function] = None,
) -> str:
    """
    Formats an opcode into a table row.
    """
    defn = op.df
    file_info = ""
    if debug:
        file = debug[idx].resolve_pretty(code)  # str: "file:line"
        file_info = f"[{file}] "

    return f"{file_info}{idx:>3}. {op.op:<{width}} {str(defn):<{48}} {pseudo_from_op(op, idx, regs, code, func=func):<{width}}"


def func(code: Bytecode, func: Function | Native) -> str:
    """
    Generates a human-readable printout and disassembly of a function or native.
    """
    if isinstance(func, Native):
        return native_header(code, func)
    res = ""
    res += func_header(code, func) + "\n"
    res += "Reg types:\n"
    for i, reg in enumerate(func.regs):
        res += f"  {i}. {type_name(code, reg.resolve(code))}\n"
    if func.has_debug and func.assigns and func.version and func.version >= 3:
        res += "\nAssigns:\n"
        for assign in func.assigns:
            res += f"Op {assign[1].value - 1}: {assign[0].resolve(code)}\n"
    res += "\nOps:\n"
    for i, op in enumerate(func.ops):
        res += (
            fmt_op(
                code,
                func.regs,
                op,
                i,
                debug=func.debuginfo.value if func.debuginfo else None,
                func=func,
            )
            + "\n"
        )
    res += "\nCalls:\n"
    for i, call in enumerate(func.calls):
        res += f"  {i}. {func_header(code, call.resolve(code))}\n"
    res += "\nXrefs:\n"
    for i, caller in enumerate(func.called_by(code)):
        res += f"  {i}. {func_header(code, caller.resolve(code))}\n"
    return res


def to_asm(ops: List[Opcode]) -> str:
    """
    Dumps a list of opcodes to a human-readable(-ish) assembly format.

    Eg.:
    ```txt
    Int. 0. 0
    Int. 2. 1
    GetGlobal. 3. 3
    Add. 4. 0. 2
    Sub. 5. 0. 2
    Mul. 6. 0. 2
    ToSFloat. 8. 0
    ToSFloat. 9. 2
    SDiv. 8. 8. 9
    SMod. 7. 0. 2
    Shl. 10. 0. 2
    JSLt. 0. 2. 2
    Bool. 11. False
    JAlways. 1
    Bool. 11. True
    JSLt. 0. 2. 2
    Bool. 12. False
    JAlways. 1
    Bool. 12. True
    Ret. 1
    ```
    """
    res = ""
    for op in ops:
        res += f"{op.op}. {'. '.join([str(arg) for arg in op.df.values()])}\n"
    return res


def from_asm(asm: str) -> List[Opcode]:
    """
    Reads and parses a list of opcodes from a human-readable(-ish) assembly format. See `to_asm`.
    """
    ops = []
    for line in asm.split("\n"):
        parts = line.split(". ")
        op = parts[0]
        args = parts[1:]
        if not op:
            continue
        new_opcode = Opcode()
        new_opcode.op = op
        new_opcode.df = {}
        # find defn types for this op
        opargs = opcodes[op]
        for name, type in opargs.items():
            new_value = Opcode.TYPE_MAP[type]()
            new_value.value = literal_eval(args.pop(0))
            new_opcode.df[name] = new_value
        ops.append(new_opcode)
    return ops


def gen_docs_for_obj(code: Bytecode, obj: Obj) -> str:
    """
    Generates HTML documentation for an Obj. Returns the HTML string.
    """
    res = "<!DOCTYPE html><html lang='en'><head>"
    res += "<meta charset='UTF-8'>"
    res += "<link rel='stylesheet' href='https://cdn.jsdelivr.net/gh/N3rdL0rd/holiday.css/dist/holiday.min.css'>"
    res += f"<title>{obj.name.resolve(code)} (crashlink auto API docs)</title></head><body>"
    res += f"<main><h1><code>{obj.name.resolve(code)}</code>"
    if obj.super.value > 0:
        superobj = obj.super.resolve(code)
        assert isinstance(superobj.definition, Obj), "super should be an Obj"
        res += f" <small>(inherits from <code>{superobj.definition.name.resolve(code)}</code>)</small>"
    res += "</h1>"
    res += "<h2>Fields</h2><ul>"
    for field in obj.fields:
        res += f"<li><code>{field.name.resolve(code)}</code>: <code>{type_name(code, field.type.resolve(code))}</code></li>"
    res += "</ul>"
    res += "<h2>Protos</h2><ul>"
    for proto in obj.protos:
        res += f"<li>{func_header_html(code, proto.findex.resolve(code))}</li>"
    res += "</ul>"
    res += "<h2>Bindings</h2><ul>"
    for binding in obj.bindings:
        res += f"<li>{func_header_html(code, binding.findex.resolve(code))}</li>"
    res += "</ul></main><footer>Generated by crashlink</footer></body></html>"
    return res


def gen_docs(code: Bytecode) -> Dict[str, str]:
    """
    Generates a set of HTML documentation pages for all Objects in the bytecode. Returns Dict[path, html].
    """
    res = {}
    kind = Type.TYPEDEFS.index(Obj)
    try:
        if not USE_TQDM:
            for obj in code.types:
                if obj.kind.value == kind:
                    if not isinstance(obj.definition, Obj):
                        raise TypeError(f"Expected Obj, got {obj.definition}")
                    defn: Obj = obj.definition
                    res[defn.name.resolve(code) + ".html"] = gen_docs_for_obj(code, defn)
        else:
            for obj in tqdm(code.types):
                if obj.kind.value == kind:
                    if not isinstance(obj.definition, Obj):
                        raise TypeError(f"Expected Obj, got {obj.definition}")
                    defin: Obj = obj.definition
                    res[defin.name.resolve(code) + ".html"] = gen_docs_for_obj(code, defin)
    except KeyboardInterrupt:
        print("Aborted.")
    return res


__all__ = [
    "type_name",
    "type_to_haxe",
    "func_header",
    "native_header",
    "is_std",
    "is_static",
    "pseudo_from_op",
    "fmt_op",
    "func",
    "to_asm",
    "from_asm",
]
