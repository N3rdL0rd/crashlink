"""
Human-readable disassembly of opcodes and utilities to work at a relatively low level with HashLink bytecode.
"""

from ast import literal_eval
from typing import List, Optional

from .core import *
from .opcodes import opcodes


def get_proto_for(code: Bytecode, idx: int) -> Optional[Proto]:
    """
    Gets the proto for a standalone function index.
    """
    for type in code.types:
        if type.kind.value == Type.TYPEDEFS.index(Obj):
            if not isinstance(type.definition, Obj):
                raise TypeError(f"Expected Obj, got {type.definition}")
            definition: Obj = type.definition
            for proto in definition.protos:
                if proto.findex.value == idx:
                    return proto
    return None


def get_field_for(code: Bytecode, idx: int) -> Optional[Field]:
    """
    Gets the field for a standalone function index.
    """
    for type in code.types:
        if type.kind.value == Type.TYPEDEFS.index(Obj):
            if not isinstance(type.definition, Obj):
                raise TypeError(f"Expected Obj, got {type.definition}")
            definition: Obj = type.definition
            fields = definition.resolve_fields(code)
            for binding in definition.bindings:  # binding binds a field to a function
                if binding.findex.value == idx:
                    return fields[binding.field.value]
    return None


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


def full_func_name(code: Bytecode, func: Function | Native) -> str:
    """
    Generates a human-readable name for a function or native.
    """
    proto = get_proto_for(code, func.findex.value)
    if proto:
        name = proto.name.resolve(code)
        for type in code.types:
            if type.kind.value == Type.TYPEDEFS.index(Obj):
                if not isinstance(type.definition, Obj):
                    continue
                obj_def: Obj = type.definition
                for fun in obj_def.protos:
                    if fun.findex.value == func.findex.value:
                        return f"{obj_def.name.resolve(code)}.{name}"
    else:
        name = "<none>"
        field = get_field_for(code, func.findex.value)
        if field:
            name = field.name.resolve(code)
            for type in code.types:
                if type.kind.value == Type.TYPEDEFS.index(Obj):
                    if not isinstance(type.definition, Obj):
                        continue
                    _obj_def: Obj = type.definition
                    fields = _obj_def.resolve_fields(code)
                    for binding in _obj_def.bindings:
                        if binding.findex.value == func.findex.value:
                            return f"{_obj_def.name.resolve(code)}.{name}"
    return name


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


def func_header(code: Bytecode, func: Function) -> str:
    """
    Generates a human-readable header for a function.
    """
    name = full_func_name(code, func)
    fun_type = func.type.resolve(code).definition
    if isinstance(fun_type, Fun):
        fun: Fun = fun_type
        return f"f@{func.findex.value} {'static ' if is_static(code, func) else ''}{name} ({', '.join([type_name(code, arg.resolve(code)) for arg in fun.args])}) -> {type_name(code, fun.ret.resolve(code))} (from {func.resolve_file(code)})"
    return f"f@{func.findex.value} {name} (no fun found, this is a bug!)"


def native_header(code: Bytecode, native: Native) -> str:
    """
    Generates a human-readable header for a native function.
    """
    fun_type = native.type.resolve(code).definition
    if isinstance(fun_type, Fun):
        fun: Fun = fun_type
        return f"f@{native.findex.value} {native.lib.resolve(code)}.{native.name.resolve(code)} [native] ({', '.join([type_name(code, arg.resolve(code)) for arg in fun.args])}) -> {type_name(code, fun.ret.resolve(code))} (from {native.lib.resolve(code)})"
    return f"f@{native.findex.value} {native.lib.resolve(code)}.{native.name.resolve(code)} [native] (no fun found, this is a bug!)"


def is_std(code: Bytecode, func: Function | Native) -> bool:
    """
    Checks if a function is from the standard library. This is a heuristic and is a bit broken still.
    """
    if isinstance(func, Native):
        return True
    if "std" in func.resolve_file(code):
        return True
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
) -> str:
    """
    Generates pseudocode disassembly from an opcode.
    """
    match op.op:
        # Constants
        case "Int" | "Float":
            return f"reg{op.definition['dst']} = {op.definition['ptr'].resolve(code)}"
        case "Bool":
            return f"reg{op.definition['dst']} = {op.definition['value'].value}"
        case "String":
            return f"reg{op.definition['dst']} = \"{op.definition['ptr'].resolve(code)}\""
        case "Null":
            return f"reg{op.definition['dst']} = null"

        # Control Flow
        case "Label":
            return "label"
        case "JAlways":
            return f"jump to {idx + (op.definition['offset'].value + 1)}"
        case "JEq" | "JSEq":
            return f"if reg{op.definition['a']} == reg{op.definition['b']}: jump to {idx + (op.definition['offset'].value + 1)}"
        case "JNull":
            return f"if reg{op.definition['reg']} is null: jump to {idx + (op.definition['offset'].value + 1)}"
        case "JFalse":
            return f"if reg{op.definition['cond']} is false: jump to {idx + (op.definition['offset'].value + 1)}"
        case "JTrue":
            return f"if reg{op.definition['cond']} is true: jump to {idx + (op.definition['offset'].value + 1)}"
        case "JSGte":
            return f"if reg{op.definition['a']} >= reg{op.definition['b']}: jump to {idx + (op.definition['offset'].value + 1)}"
        case "JULt" | "JSLt":
            return f"if reg{op.definition['a']} < reg{op.definition['b']}: jump to {idx + (op.definition['offset'].value + 1)}"
        case "JNotLt":
            return f"if reg{op.definition['a']} >= reg{op.definition['b']}: jump to {idx + (op.definition['offset'].value + 1)}"
        case "JNotEq":
            return f"if reg{op.definition['a']} != reg{op.definition['b']}: jump to {idx + (op.definition['offset'].value + 1)}"
        case "JSGt":
            return f"if reg{op.definition['a']} > reg{op.definition['b']}: jump to {idx + (op.definition['offset'].value + 1)}"

        # Arithmetic
        case "Mul":
            return f"reg{op.definition['dst']} = reg{op.definition['a']} * reg{op.definition['b']}"
        case "SDiv":
            return f"reg{op.definition['dst']} = reg{op.definition['a']} / reg{op.definition['b']}"
        case "Incr":
            return f"reg{op.definition['dst']}++"
        case "Decr":
            return f"reg{op.definition['dst']}--"
        case "Sub":
            return f"reg{op.definition['dst']} = reg{op.definition['a']} - reg{op.definition['b']}"
        case "Add":
            return f"reg{op.definition['dst']} = reg{op.definition['a']} + reg{op.definition['b']}"
        case "Shl":
            return f"reg{op.definition['dst']} = reg{op.definition['a']} << reg{op.definition['b']}"
        case "SMod":
            return f"reg{op.definition['dst']} = reg{op.definition['a']} % reg{op.definition['b']}"
        case "Xor":
            return f"reg{op.definition['dst']} = reg{op.definition['a']} ^ reg{op.definition['b']}"

        # Memory/Object Operations
        case "GetThis":
            this = None
            for reg in regs:
                # find first Obj reg
                if type(reg.resolve(code).definition) == Obj:
                    this = reg.resolve(code)
                    break
            if this:
                return f"reg{op.definition['dst']} = this.{op.definition['field'].resolve_obj(code, this.definition).name.resolve(code)}"
            return f"reg{op.definition['dst']} = this.f@{op.definition['field'].value} (this not found!)"
        case "GetGlobal":
            glob = type_name(code, op.definition["global"].resolve(code))
            return f"reg{op.definition['dst']} = {glob} (g@{op.definition['global']})"
        case "Field":
            field = op.definition["field"].resolve_obj(code, regs[op.definition["obj"].value].resolve(code).definition)
            return f"reg{op.definition['dst']} = reg{op.definition['obj']}.{field.name.resolve(code)}"
        case "SetField":
            field = op.definition["field"].resolve_obj(code, regs[op.definition["obj"].value].resolve(code).definition)
            return f"reg{op.definition['obj']}.{field.name.resolve(code)} = reg{op.definition['src']}"
        case "Mov":
            return f"reg{op.definition['dst']} = reg{op.definition['src']}"
        case "SetArray":
            return f"reg{op.definition['array']}[reg{op.definition['index']}] = reg{op.definition['src']})"
        case "ArraySize":
            return f"reg{op.definition['dst']} = len(reg{op.definition['array']})"
        case "New":
            typ = regs[op.definition["dst"].value].resolve(code)
            return f"reg{op.definition['dst']} = new {type_name(code, typ)}"
        case "DynSet":
            return f"reg{op.definition['obj']}.{op.definition['field'].resolve(code)} = reg{op.definition['src']}"

        # Type Conversions
        case "ToSFloat":
            return f"reg{op.definition['dst']} = SFloat(reg{op.definition['src']})"
        case "ToVirtual":
            return f"reg{op.definition['dst']} = Virtual(reg{op.definition['src']})"
        case "Ref":
            return f"reg{op.definition['dst']} = &reg{op.definition['src']}"
        case "SetMem":
            return f"reg{op.definition['bytes']}[reg{op.definition['index']}] = reg{op.definition['src']}"
        case "GetMem":
            return f"reg{op.definition['dst']} = reg{op.definition['bytes']}[reg{op.definition['index']}]"
        case "SafeCast":
            return f"reg{op.definition['dst']} = reg{op.definition['src']} as {type_name(code, regs[op.definition['dst'].value].resolve(code))}"
        case "UnsafeCast":
            return f"reg{op.definition['dst']} = reg{op.definition['src']} unsafely as {type_name(code, regs[op.definition['dst'].value].resolve(code))}"

        # Function Calls
        case "CallClosure":
            args = ", ".join([f"reg{arg}" for arg in op.definition["args"].value])
            if type(regs[op.definition["dst"].value].resolve(code).definition) == Void:
                return f"reg{op.definition['fun']}({args})"
            return f"reg{op.definition['dst']} = reg{op.definition['fun']}({args})"
        case "Call0":
            return f"reg{op.definition['dst']} = f@{op.definition['fun']}()"
        case "Call1":
            return f"reg{op.definition['dst']} = f@{op.definition['fun']}(reg{op.definition['arg0']})"
        case "Call2":
            fun = full_func_name(code, code.fn(op.definition["fun"].value))
            return f"reg{op.definition['dst']} = f@{op.definition['fun']}({', '.join([f'reg{op.definition[arg]}' for arg in ['arg0', 'arg1']])})"
        case "Call3":
            return f"reg{op.definition['dst']} = f@{op.definition['fun']}({', '.join([f'reg{op.definition[arg]}' for arg in ['arg0', 'arg1', 'arg2']])})"
        case "CallN":
            return f"reg{op.definition['dst']} = f@{op.definition['fun']}({', '.join([f'reg{arg}' for arg in op.definition['args'].value])})"

        # Error Handling
        case "NullCheck":
            return f"if reg{op.definition['reg']} is null: error"
        case "Trap":
            return f"trap to reg{op.definition['exc']} (end: {idx + (op.definition['offset'].value)})"
        case "EndTrap":
            return f"end trap to reg{op.definition['exc']}"

        # Switch
        case "Switch":
            reg = op.definition["reg"]
            offsets = op.definition["offsets"].value
            offset_mappings = []
            cases = []
            for i, offset in enumerate(offsets):
                if offset.value != 0:
                    case_num = str(i)
                    target = str(idx + (offset.value + 1))
                    offset_mappings.append(f"if {case_num} jump {target}")
                    cases.append(case_num)
            if not terse:
                return f"switch reg{reg} [{', '.join(offset_mappings)}] (end: {idx + (op.definition['end'].value)})"
            return f"switch reg{reg} [{', '.join(cases)}] (end: {idx + (op.definition['end'].value)})"

        # Return
        case "Ret":
            if type(regs[op.definition["ret"].value].resolve(code).definition) == Void:
                return "return"
            return f"return reg{op.definition['ret']}"

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
) -> str:
    """
    Formats an opcode into a table row.
    """
    defn = op.definition
    file_info = ""
    if debug:
        file = debug[idx].resolve_pretty(code)  # str: "file:line"
        file_info = f"[{file}] "

    return f"{file_info}{idx:>3}. {op.op:<{width}} {str(defn):<{48}} {pseudo_from_op(op, idx, regs, code):<{width}}"


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
        res += fmt_op(code, func.regs, op, i, debug=func.debuginfo.value if func.debuginfo else None) + "\n"
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
        res += f"{op.op}. {'. '.join([str(arg) for arg in op.definition.values()])}\n"
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
        new_opcode.definition = {}
        # find defn types for this op
        opargs = opcodes[op]
        for name, type in opargs.items():
            new_value = Opcode.TYPE_MAP[type]()
            new_value.value = literal_eval(args.pop(0))  # FIXME: unsafe?
            new_opcode.definition[name] = new_value
        ops.append(new_opcode)
    return ops
