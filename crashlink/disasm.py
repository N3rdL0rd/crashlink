"""
Human-readable disassembly of opcodes and utilities to work at a relatively low level with HashLink bytecode.
"""

from __future__ import annotations

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
    tIndex,
    Enum,
    destaticify,
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
    elif typedef == Enum and isinstance(defn, Enum):
        return defn.name.resolve(code)
    return typedef.__name__


def type_to_haxe(type: str) -> str:
    """
    Maps internal HashLink type names to Haxe type names.
    """
    mapping = {
        "I32": "Int",
        "F64": "Float",
        "F32": "Single",
        "U16": "hl.UI16",
        "UI16": "hl.UI16",
        "Bytes": "hl.Bytes",
        "Dyn": "Dynamic",
        "DynObj": "Dynamic",
        "Fun": "Dynamic",
        "TypeType": "hl.Type",
    }
    if type.startswith("hl.types.ArrayBytes_"):
        suffix = type[len("hl.types.ArrayBytes_") :]
        element_map = {
            "Int": "Int",
            "Float": "Float",
            "Bool": "Bool",
            "hl_F32": "Single",
            "hl_UI16": "hl.UI16",
        }
        return f"Array<{element_map.get(suffix, 'Dynamic')}>"
    if type in ("hl.types.ArrayObj", "hl.types.ArrayDyn"):
        return "Array<Dynamic>"
    if type == "Array":
        return "Array<Dynamic>"
    if type in ("Function", "Native"):
        return "Dynamic"
    if type == "Null":
        return "Dynamic"
    if type.startswith("Virtual["):
        return "Dynamic"
    return destaticify(mapping.get(type, type))


def func_header(code: Bytecode, func: Function | Native) -> str:
    """
    Generates a human-readable header for a function.
    """
    if isinstance(func, Native):
        return native_header(code, func)
    assert isinstance(func, Function)
    name = code.full_func_name(func)
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
    name = code.partial_func_name(func)
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
    return func.findex.value in code.get_field_map()


def _method_name_for_field(code: Bytecode, obj_type: "Type", field_idx: int) -> str:
    """Resolve the method name addressed by a CallMethod/CallThis `field` operand.

    On an ``Obj`` the operand indexes the virtual method table (by proto
    ``pindex``), not the data fields; on a ``Virtual`` it indexes the
    method-typed data fields directly. Falls back to ``field<n>`` when the
    target cannot be resolved.
    """
    defn = obj_type.definition
    if isinstance(defn, Obj):
        proto = code.proto_by_pindex(defn, field_idx)
        if proto is not None:
            return proto.name.resolve(code)
    elif isinstance(defn, Virtual) and field_idx < len(defn.fields):
        return defn.fields[field_idx].name.resolve(code)
    return f"field{field_idx}"


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
        case "Bytes":
            return f"reg{op.df['dst']} = bytes@{op.df['ptr'].resolve(code)}"
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
        case "JSLte":
            return f"if reg{op.df['a']} <= reg{op.df['b']}: jump to {idx + (op.df['offset'].value + 1)}"
        case "JULt" | "JSLt":
            return f"if reg{op.df['a']} < reg{op.df['b']}: jump to {idx + (op.df['offset'].value + 1)}"
        case "JUGte":
            return f"if reg{op.df['a']} >=u reg{op.df['b']}: jump to {idx + (op.df['offset'].value + 1)}"
        case "JNotLt":
            return f"if reg{op.df['a']} >= reg{op.df['b']}: jump to {idx + (op.df['offset'].value + 1)}"
        case "JNotGte":
            return f"if reg{op.df['a']} < reg{op.df['b']}: jump to {idx + (op.df['offset'].value + 1)}"
        case "JNotEq":
            return f"if reg{op.df['a']} != reg{op.df['b']}: jump to {idx + (op.df['offset'].value + 1)}"
        case "JSGt":
            return f"if reg{op.df['a']} > reg{op.df['b']}: jump to {idx + (op.df['offset'].value + 1)}"
        case "JNotNull":
            return f"if reg{op.df['reg']} is not null: jump to {idx + (op.df['offset'].value + 1)}"

        # Arithmetic
        case "Mul":
            return f"reg{op.df['dst']} = reg{op.df['a']} * reg{op.df['b']}"
        case "UDiv":
            return f"reg{op.df['dst']} = reg{op.df['a']} /u reg{op.df['b']}"
        case "SDiv":
            return f"reg{op.df['dst']} = reg{op.df['a']} / reg{op.df['b']}"
        case "UMod":
            return f"reg{op.df['dst']} = reg{op.df['a']} %u reg{op.df['b']}"
        case "SMod":
            return f"reg{op.df['dst']} = reg{op.df['a']} % reg{op.df['b']}"
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
        case "SShr":
            return f"reg{op.df['dst']} = reg{op.df['a']} >> reg{op.df['b']}"
        case "UShr":
            return f"reg{op.df['dst']} = reg{op.df['a']} >>> reg{op.df['b']}"
        case "And":
            return f"reg{op.df['dst']} = reg{op.df['a']} & reg{op.df['b']}"
        case "Or":
            return f"reg{op.df['dst']} = reg{op.df['a']} | reg{op.df['b']}"
        case "Xor":
            return f"reg{op.df['dst']} = reg{op.df['a']} ^ reg{op.df['b']}"
        case "Neg":
            return f"reg{op.df['dst']} = -reg{op.df['src']}"
        case "Not":
            return f"reg{op.df['dst']} = !reg{op.df['src']}"

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
        case "SetGlobal":
            glob = type_name(code, op.df["global"].resolve(code))
            return f"{glob} (g@{op.df['global']}) = reg{op.df['src']}"
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
        case "DynGet":
            return f"reg{op.df['dst']} = reg{op.df['obj']}.{op.df['field'].resolve(code)}"
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
        case "StaticClosure":
            return f"reg{op.df['dst']} = f@{op.df['fun']} (static closure)"
        case "VirtualClosure":
            return f"reg{op.df['dst']} = reg{op.df['obj']}.field{op.df['field']} (virtual closure)"

        # Type Conversions
        case "ToSFloat":
            return f"reg{op.df['dst']} = SFloat(reg{op.df['src']})"
        case "ToUFloat":
            return f"reg{op.df['dst']} = UFloat(reg{op.df['src']})"
        case "ToInt":
            return f"reg{op.df['dst']} = Int(reg{op.df['src']})"
        case "ToDyn":
            return f"reg{op.df['dst']} = Dyn(reg{op.df['src']})"
        case "ToVirtual":
            return f"reg{op.df['dst']} = Virtual(reg{op.df['src']})"
        case "Type":
            return f"reg{op.df['dst']} = type {type_name(code, op.df['ty'].resolve(code))}"
        case "GetType":
            return f"reg{op.df['dst']} = type(reg{op.df['src']})"
        case "GetTID":
            return f"reg{op.df['dst']} = tid(reg{op.df['src']})"
        case "Ref":
            return f"reg{op.df['dst']} = &reg{op.df['src']}"
        case "Unref":
            return f"reg{op.df['dst']} = *reg{op.df['src']}"
        case "Setref":
            return f"*reg{op.df['dst']} = reg{op.df['value']}"
        case "RefData":
            return f"reg{op.df['dst']} = data(reg{op.df['src']})"
        case "RefOffset":
            return f"reg{op.df['dst']} = reg{op.df['reg']} + reg{op.df['offset']}"
        case "GetArray":
            return f"reg{op.df['dst']} = reg{op.df['array']}[reg{op.df['index']}]"
        case "GetMem":
            return f"reg{op.df['dst']} = reg{op.df['bytes']}[reg{op.df['index']}]"
        case "GetI8":
            return f"reg{op.df['dst']} = reg{op.df['bytes']}[reg{op.df['index']}] (i8)"
        case "GetI16":
            return f"reg{op.df['dst']} = reg{op.df['bytes']}[reg{op.df['index']}] (i16)"
        case "SetMem":
            return f"reg{op.df['bytes']}[reg{op.df['index']}] = reg{op.df['src']}"
        case "SetI8":
            return f"reg{op.df['bytes']}[reg{op.df['index']}] = reg{op.df['src']} (i8)"
        case "SetI16":
            return f"reg{op.df['bytes']}[reg{op.df['index']}] = reg{op.df['src']} (i16)"
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
            fun = code.full_func_name(code.fn(op.df["fun"].value))
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
            args = ", ".join([f"reg{arg}" for arg in op.df["args"].value])
            if not func:
                return f"reg{op.df['dst']} = this.field{op.df['field']}({args})"
            method = _method_name_for_field(code, func.regs[0].resolve(code), op.df["field"].value)
            return f"reg{op.df['dst']} = this.{method}({args})"
        case "CallMethod":
            method_args = op.df["args"].value
            obj_reg = method_args[0].value if method_args else None
            rest = ", ".join([f"reg{arg}" for arg in method_args[1:]])
            if func is not None and obj_reg is not None:
                method = _method_name_for_field(code, func.regs[obj_reg].resolve(code), op.df["field"].value)
                return f"reg{op.df['dst']} = reg{obj_reg}.{method}({rest})"
            return f"reg{op.df['dst']} = reg{obj_reg}.field{op.df['field']}({rest})"

        # Error Handling
        case "NullCheck":
            return f"if reg{op.df['reg']} is null: error"
        case "Throw":
            return f"throw reg{op.df['exc']}"
        case "Rethrow":
            return f"rethrow reg{op.df['exc']}"
        case "Trap":
            return f"trap to reg{op.df['exc']} (end: {idx + (op.df['offset'].value)})"
        case "EndTrap":
            return f"end trap to reg{op.df['exc']}"
        case "Catch":
            return f"catch to reg{op.df['global']}"

        # Enums
        case "MakeEnum":
            args = ", ".join([f"reg{arg}" for arg in op.df["args"].value])
            return f"reg{op.df['dst']} = construct{op.df['construct']}({args})"
        case "EnumAlloc":
            return f"reg{op.df['dst']} = alloc construct{op.df['construct']}"
        case "EnumIndex":
            return f"reg{op.df['dst']} = index(reg{op.df['value']})"
        case "EnumField":
            return f"reg{op.df['dst']} = reg{op.df['value']}.field{op.df['field']} (construct{op.df['construct']})"
        case "SetEnumField":
            return f"reg{op.df['value']}.field{op.df['field']} = reg{op.df['src']}"

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

        # Other
        case "Assert":
            return "assert"
        case "Nop":
            return "nop"

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
        res += f"  {i}. {type_name(code, reg.resolve(code))} (t@{reg.value})\n"
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


def gen_docs_for_obj(code: Bytecode, obj: Obj, static_obj: Optional[Obj] = None) -> str:
    """
    Generates HTML documentation for an Obj (and its static counterpart if provided).
    Static members from static_obj are rendered inline, marked as static.
    """
    name = obj.name.resolve(code)
    res = "<!DOCTYPE html><html lang='en'><head>"
    res += "<meta charset='UTF-8'>"
    res += "<link rel='stylesheet' href='https://cdn.jsdelivr.net/gh/N3rdL0rd/holiday.css/dist/holiday.min.css'>"
    res += f"<title>{name} (crashlink auto API docs)</title></head><body>"
    res += f"<main><h1><code>{name}</code>"
    if obj.super.value > 0:
        superobj = obj.super.resolve(code)
        assert isinstance(superobj.definition, Obj), "super should be an Obj"
        super_name = superobj.definition.name.resolve(code)
        # Link to the dynamic (non-$) counterpart's page
        page_name = destaticify(super_name)
        res += f" <small>(inherits from <a href='{page_name}.html'><code>{super_name}</code></a>)</small>"
    res += "</h1>"

    res += "<h2>Fields</h2><ul>"
    for field in obj.fields:
        res += f"<li><code>{field.name.resolve(code)}</code>: <code>{type_name(code, field.type.resolve(code))}</code></li>"
    if static_obj:
        for field in static_obj.fields:
            res += f"<li><em>static</em> <code>{field.name.resolve(code)}</code>: <code>{type_name(code, field.type.resolve(code))}</code></li>"
    res += "</ul>"

    res += "<h2>Protos</h2><ul>"
    for proto in obj.protos:
        res += f"<li>{func_header_html(code, proto.findex.resolve(code))}</li>"
    if static_obj:
        for proto in static_obj.protos:
            res += f"<li><em>static</em> {func_header_html(code, proto.findex.resolve(code))}</li>"
    res += "</ul>"

    res += "<h2>Bindings</h2><ul>"
    for binding in obj.bindings:
        res += f"<li>{func_header_html(code, binding.findex.resolve(code))}</li>"
    if static_obj:
        for binding in static_obj.bindings:
            res += f"<li><em>static</em> {func_header_html(code, binding.findex.resolve(code))}</li>"
    res += "</ul></main><footer>Generated by crashlink</footer></body></html>"
    return res


def gen_docs(code: Bytecode) -> Dict[str, str]:
    """
    Generates a set of HTML documentation pages for all Objects in the bytecode. Returns Dict[path, html].
    Dynamic/static class pairs are merged into a single page named after the dynamic class.
    Static-only classes (no dynamic counterpart) get their own page.
    """
    res = {}
    kind = Type.TYPEDEFS.index(Obj)

    def _process(defn: Obj) -> None:
        is_static = getattr(defn, "_is_static", None)
        # Static classes with a dynamic counterpart are rendered as part of that page — skip them.
        if is_static is True and getattr(defn, "_dynamic", None) is not None:
            return
        static_obj: Optional[Obj] = getattr(defn, "_static", None) if is_static is False else None
        page_name = destaticify(defn.name.resolve(code))
        res[page_name + ".html"] = gen_docs_for_obj(code, defn, static_obj)

    try:
        if not USE_TQDM:
            for obj in code.types:
                if obj.kind.value == kind:
                    if not isinstance(obj.definition, Obj):
                        raise TypeError(f"Expected Obj, got {obj.definition}")
                    _process(obj.definition)
        else:
            for obj in tqdm(code.types):  # pyright: ignore[reportPossiblyUnboundVariable]
                if obj.kind.value == kind:
                    if not isinstance(obj.definition, Obj):
                        raise TypeError(f"Expected Obj, got {obj.definition}")
                    _process(obj.definition)
    except KeyboardInterrupt:
        print("Aborted.")
    return res


def _class_md_path(name: str) -> str:
    """docs-relative path for a class page. name must already be destaticified."""
    return name.replace(".", "/") + ".md"


def _rel_path(from_path: str, to_path: str) -> str:
    """Compute a relative path from from_path to to_path (both docs-relative, forward slashes)."""
    from_parts = from_path.replace("\\", "/").split("/")[:-1]
    to_parts = to_path.replace("\\", "/").split("/")
    common = 0
    for i in range(min(len(from_parts), len(to_parts))):
        if from_parts[i] == to_parts[i]:
            common += 1
        else:
            break
    ups = len(from_parts) - common
    rel_parts = [".."] * ups + to_parts[common:]
    return "/".join(rel_parts) if rel_parts else to_parts[-1]


def func_header_md(code: Bytecode, func: Function | Native) -> str:
    """Generates a Markdown-safe one-line function signature."""
    if isinstance(func, Native):
        fun_type = func.type.resolve(code).definition
        lib = func.lib.resolve(code)
        name = func.name.resolve(code)
        if isinstance(fun_type, Fun):
            args = ", ".join(type_name(code, a.resolve(code)) for a in fun_type.args)
            ret = type_name(code, fun_type.ret.resolve(code))
            return f"`f@{func.findex.value}` `{lib}.{name}` \\[native\\] `({args}) → {ret}`"
        return f"`f@{func.findex.value}` `{lib}.{name}` \\[native\\]"
    assert isinstance(func, Function)
    fname = code.partial_func_name(func)
    fun_type = func.type.resolve(code).definition
    if isinstance(fun_type, Fun):
        args = ", ".join(type_name(code, a.resolve(code)) for a in fun_type.args)
        ret = type_name(code, fun_type.ret.resolve(code))
        return f"`f@{func.findex.value}` `{fname}({args}) → {ret}`"
    return f"`f@{func.findex.value}` `{fname}`"


def gen_mkdocs_for_obj(code: Bytecode, obj: Obj, static_obj: Optional[Obj] = None) -> str:
    """Generates a Starlight-compatible Markdown page for an Obj pair."""
    name = obj.name.resolve(code)
    page_path = _class_md_path(destaticify(name))
    escaped = name.replace('"', '\\"')
    lines: List[str] = ["---", f'title: "{escaped}"', "---", "", f"# `{name}`", ""]

    if obj.super.value > 0:
        superobj = obj.super.resolve(code)
        if isinstance(superobj.definition, Obj):
            super_name = superobj.definition.name.resolve(code)
            super_page_path = _class_md_path(destaticify(super_name))
            rel = _rel_path(page_path, super_page_path)
            lines += [f"**Inherits from:** [`{super_name}`]({rel})", ""]

    lines += ["## Fields", ""]
    instance_fields = obj.fields
    static_fields = static_obj.fields if static_obj else []
    if instance_fields or static_fields:
        lines += ["| | Name | Type |", "|---|------|------|"]
        for field in instance_fields:
            lines.append(f"| | `{field.name.resolve(code)}` | `{type_name(code, field.type.resolve(code))}` |")
        for field in static_fields:
            lines.append(f"| *static* | `{field.name.resolve(code)}` | `{type_name(code, field.type.resolve(code))}` |")
    else:
        lines.append("*No fields.*")
    lines.append("")

    lines += ["## Protos", ""]
    instance_protos = obj.protos
    static_protos = static_obj.protos if static_obj else []
    if instance_protos or static_protos:
        for proto in instance_protos:
            lines.append(f"- {func_header_md(code, proto.findex.resolve(code))}")
        for proto in static_protos:
            lines.append(f"- *static* {func_header_md(code, proto.findex.resolve(code))}")
    else:
        lines.append("*No protos.*")
    lines.append("")

    lines += ["## Bindings", ""]
    instance_bindings = obj.bindings
    static_bindings = static_obj.bindings if static_obj else []
    if instance_bindings or static_bindings:
        for binding in instance_bindings:
            lines.append(f"- {func_header_md(code, binding.findex.resolve(code))}")
        for binding in static_bindings:
            lines.append(f"- *static* {func_header_md(code, binding.findex.resolve(code))}")
    else:
        lines.append("*No bindings.*")

    return "\n".join(lines)


def gen_mkdocs(code: Bytecode, site_name: str = "API Reference") -> Dict[str, str]:
    """
    Generates a complete MkDocs + Material project for the bytecode's API.
    Returns Dict[relative_path, content]. Dynamic/static pairs are merged into one page.
    """
    res: Dict[str, str] = {}
    kind = Type.TYPEDEFS.index(Obj)
    num_classes = 0

    def _process(defn: Obj) -> None:
        nonlocal num_classes
        if getattr(defn, "_is_static", None) is True and getattr(defn, "_dynamic", None) is not None:
            return
        static_obj: Optional[Obj] = (
            getattr(defn, "_static", None) if getattr(defn, "_is_static", None) is False else None
        )
        page_name = destaticify(defn.name.resolve(code))
        res["src/content/docs/" + _class_md_path(page_name)] = gen_mkdocs_for_obj(code, defn, static_obj)
        num_classes += 1

    try:
        if not USE_TQDM:
            for obj in code.types:
                if obj.kind.value == kind:
                    if not isinstance(obj.definition, Obj):
                        raise TypeError(f"Expected Obj, got {obj.definition}")
                    _process(obj.definition)
        else:
            for obj in tqdm(code.types):  # pyright: ignore[reportPossiblyUnboundVariable]
                if obj.kind.value == kind:
                    if not isinstance(obj.definition, Obj):
                        raise TypeError(f"Expected Obj, got {obj.definition}")
                    _process(obj.definition)
    except KeyboardInterrupt:
        print("Aborted.")

    res["src/content/docs/index.md"] = (
        f'---\ntitle: "{site_name}"\n---\n\n'
        f"# {site_name}\n\n"
        f"Auto-generated from HashLink bytecode using [crashlink](https://github.com/N3rdL0rd/crashlink).\n\n"
        f"{num_classes} classes documented.\n"
    )

    # Derive sidebar structure from generated pages
    dirs: set[str] = set()
    top_files: List[str] = []
    prefix = "src/content/docs/"
    for path in res:
        if not path.startswith(prefix) or path == prefix + "index.md":
            continue
        rel = path[len(prefix) :]
        if "/" in rel:
            dirs.add(rel.split("/")[0])
        else:
            top_files.append(rel[:-3])  # strip .md

    sidebar_lines = ["        sidebar: ["]
    if top_files:
        sidebar_lines += [
            "          { label: 'Top-level', collapsed: true, items: [",
        ]
        for name in sorted(top_files):
            safe = name.replace("'", "\\'")
            sidebar_lines.append(f"            {{ label: '{safe}', link: '{safe}' }},")
        sidebar_lines.append("          ] },")
    for d in sorted(dirs):
        safe = d.replace("'", "\\'")
        sidebar_lines.append(
            f"          {{ label: '{safe}', autogenerate: {{ directory: '{safe}' }}, collapsed: true }},"
        )
    sidebar_lines.append("        ],")
    sidebar_str = "\n".join(sidebar_lines)

    res["astro.config.mjs"] = (
        "import { defineConfig } from 'astro/config';\n"
        "import starlight from '@astrojs/starlight';\n\n"
        "export default defineConfig({\n"
        "  integrations: [\n"
        "    starlight({\n"
        f"      title: '{site_name}',\n"
        "      pagination: false,\n"
        "      lastUpdated: false,\n"
        f"{sidebar_str}\n"
        "    }),\n"
        "  ],\n"
        "});\n"
    )

    res["package.json"] = (
        "{\n"
        '  "name": "api-reference",\n'
        '  "type": "module",\n'
        '  "scripts": {\n'
        '    "dev": "astro dev",\n'
        '    "build": "astro build",\n'
        '    "preview": "astro preview"\n'
        "  },\n"
        '  "dependencies": {\n'
        '    "@astrojs/starlight": "^0.32.0",\n'
        '    "astro": "^5.0.0"\n'
        "  }\n"
        "}\n"
    )

    res["tsconfig.json"] = '{\n  "extends": "astro/tsconfigs/strict"\n}\n'

    res[".github/workflows/deploy.yml"] = (
        "name: Deploy to GitHub Pages\n\n"
        "on:\n"
        "  push:\n"
        "    branches: [main]\n"
        "  workflow_dispatch:\n\n"
        "permissions:\n"
        "  contents: read\n"
        "  pages: write\n"
        "  id-token: write\n\n"
        "concurrency:\n"
        "  group: pages\n"
        "  cancel-in-progress: false\n\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: actions/setup-node@v4\n"
        "        with:\n"
        "          node-version: 20\n"
        "      - run: npm ci\n"
        "      - run: npm run build\n"
        "      - uses: actions/upload-pages-artifact@v3\n"
        "        with:\n"
        "          path: dist/\n\n"
        "  deploy:\n"
        "    needs: build\n"
        "    runs-on: ubuntu-latest\n"
        "    environment:\n"
        "      name: github-pages\n"
        "      url: ${{ steps.deployment.outputs.page_url }}\n"
        "    steps:\n"
        "      - id: deployment\n"
        "        uses: actions/deploy-pages@v4\n"
    )

    res["src/content.config.ts"] = (
        "import { defineCollection } from 'astro:content';\n"
        "import { docsLoader } from '@astrojs/starlight/loaders';\n"
        "import { docsSchema } from '@astrojs/starlight/schema';\n\n"
        "export const collections = {\n"
        "  docs: defineCollection({ loader: docsLoader(), schema: docsSchema() }),\n"
        "};\n"
    )

    return res


from dataclasses import dataclass, field as dc_field


@dataclass
class MethodEntry:
    findex: int
    method_name: str
    first_line: int


@dataclass
class ClassEntry:
    canonical_name: str
    first_line: int
    methods: List[MethodEntry] = dc_field(default_factory=list)


def file_class_map(code: Bytecode) -> Dict[str, List[ClassEntry]]:
    """Return source-file → ordered class list with per-method line info.

    Heuristic: for each function with debug info, take the minimum
    non-zero line number across all its opcodes as its "start line".
    Classes are identified via the pseudo method registry (static + instance
    unified by destaticify).  Within each file, classes are sorted by their
    earliest start line; methods within each class are sorted the same way.
    Functions not registered to any class appear under the synthetic class
    name "(standalone)".

    Returns {} if the bytecode has no debug info.
    """
    from .pseudo import _method_registry
    from .core import destaticify

    if not code.has_debug_info:
        return {}

    reg = _method_registry(code)
    fmap = code.get_findex_map()

    # (file_path, canonical_class) -> list of MethodEntry
    _groups: Dict[tuple, List[MethodEntry]] = {}

    for findex, func in fmap.items():
        if isinstance(func, Native):
            continue
        if not func.has_debug or not func.debuginfo or not func.debuginfo.value:
            continue

        # Minimum non-zero line across all ops = best proxy for declaration line
        lines = [ref.line for ref in func.debuginfo.value if ref.line > 0]
        if not lines:
            continue
        first_line = min(lines)

        try:
            file_path = func.resolve_file(code)
        except Exception:
            continue

        if findex in reg:
            obj, method_name, _ = reg[findex]
            canonical = destaticify(obj.name.resolve(code))
        else:
            method_name = full_func_name_str(code, func)
            canonical = "(standalone)"

        key = (file_path, canonical)
        _groups.setdefault(key, []).append(
            MethodEntry(findex=findex, method_name=method_name, first_line=first_line)
        )

    # Sort methods within each class by first_line
    for entries in _groups.values():
        entries.sort(key=lambda e: e.first_line)

    # Group by file, then build ClassEntry list sorted by earliest method line
    file_map: Dict[str, Dict[str, ClassEntry]] = {}
    for (file_path, canonical), entries in _groups.items():
        class_first_line = entries[0].first_line
        if file_path not in file_map:
            file_map[file_path] = {}
        if canonical not in file_map[file_path]:
            file_map[file_path][canonical] = ClassEntry(
                canonical_name=canonical,
                first_line=class_first_line,
                methods=entries,
            )
        else:
            # Merge if the same class appears in the same file (static + instance split)
            existing = file_map[file_path][canonical]
            existing.methods.extend(entries)
            existing.methods.sort(key=lambda e: e.first_line)
            existing.first_line = min(existing.first_line, class_first_line)

    # Sort classes within each file by first_line
    return {
        fp: sorted(classes.values(), key=lambda c: c.first_line)
        for fp, classes in sorted(file_map.items())
    }


def full_func_name_str(code: Bytecode, func: Function) -> str:
    """Safe full_func_name that never raises."""
    try:
        name = code.full_func_name(func)
        return name if name else f"f@{func.findex.value}"
    except Exception:
        return f"f@{func.findex.value}"


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
    "gen_mkdocs",
    "file_class_map",
    "MethodEntry",
    "ClassEntry",
    "full_func_name_str",
]
