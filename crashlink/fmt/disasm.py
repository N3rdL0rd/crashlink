from ..core import *

from typing import Optional
from enum import Enum, auto


def get_proto_for(code: Bytecode, idx: int) -> Optional[Proto]:
    for type in code.types:
        if type.kind.value == Type.TYPEDEFS.index(Obj):
            definition: Obj = type.definition
            for proto in definition.protos:
                if proto.findex.value == idx:
                    return proto
    return None


def get_field_for(code: Bytecode, idx: int) -> Optional[Field]:
    for type in code.types:
        if type.kind.value == Type.TYPEDEFS.index(Obj):
            definition: Obj = type.definition
            fields = definition.resolve_fields(code)
            for binding in definition.bindings:  # binding binds a field to a function
                if binding.findex.value == idx:
                    return fields[binding.field.value]
    return None


def type_name(code: Bytecode, typ: Type):
    typedef = type(typ.definition)
    defn = typ.definition
    if typedef == Obj:
        defn: Obj = defn
        return defn.name.resolve(code)
    elif typedef == Virtual:
        defn: Virtual = defn
        fields = []
        for field in defn.fields:
            fields.append(field.name.resolve(code))
        return f"Virtual[{', '.join(fields)}]"
    return typedef.__name__


def full_func_name(code: Bytecode, func: Function):
    proto = get_proto_for(code, func.findex.value)
    if proto:
        name = proto.name.resolve(code)
        for type in code.types:
            if type.kind.value == Type.TYPEDEFS.index(Obj):
                definition: Obj = type.definition
                for fun in definition.protos:
                    if fun.findex.value == func.findex.value:
                        return f"{definition.name.resolve(code)}.{name}"
    else:
        name = "<none>"
        field = get_field_for(code, func.findex.value)
        if field:
            name = field.name.resolve(code)
            for type in code.types:
                if type.kind.value == Type.TYPEDEFS.index(Obj):
                    definition: Obj = type.definition
                    fields = definition.resolve_fields(code)
                    for binding in definition.bindings:
                        if binding.findex.value == func.findex.value:
                            return f"{definition.name.resolve(code)}.{name}"
        else:
            name = "<none>"
    return name


def type_to_haxe(type: str):
    mapping = {
        "I32": "Int",
        "F64": "Float",
        "Bytes": "hl.Bytes",
        "Dyn": "Dynamic",
        "Fun": "Function",
    }
    return mapping.get(type, type)


def func_header(code: Bytecode, func: Function):
    name = full_func_name(code, func)
    try:
        fun: Fun = func.type.resolve(code).definition
    except:
        fun = None
    if fun:
        return f"f@{func.findex.value} {'static ' if is_static(code, func) else ''}{name} ({', '.join([type_name(code, arg.resolve(code)) for arg in fun.args])}) -> {type_name(code, fun.ret.resolve(code))}"
    return f"f@{func.findex.value} {name} (no fun found, this is a bug!)"


def native_header(code: Bytecode, native: Native):
    try:
        fun: Fun = native.type.resolve(code).definition
    except:
        fun = None
    if fun:
        return f"f@{native.findex.value} {native.lib.resolve(code)}.{native.name.resolve(code)} [native] ({', '.join([type_name(code, arg.resolve(code)) for arg in fun.args])}) -> {type_name(code, fun.ret.resolve(code))}"
    return f"f@{native.findex.value} {native.lib.resolve(code)}.{native.name.resolve(code)} [native] (no fun found, this is a bug!)"


def is_std(code: Bytecode, func: Function | Native):
    if isinstance(func, Native):
        return True
    name = full_func_name(code, func)
    prefixes = [
        "hl.",
        "haxe.",
        "std.",
        "?std.",
        "Std.",
        "$Std.",
        "Date.",
        "$Date.",
        "String.",
        "$String.",
        "StringBuf.",
        "$StringBuf.",
        "$SysError.",
        "SysError.",
        "Sys.",
        "$Sys.",
        "$Type.",
        "Type.",
    ]
    for prefix in prefixes:
        if name.startswith(prefix):
            return True
    return False

def is_static(code: Bytecode, func: Function):
    # bindings are static functions, protos are dynamic
    for type in code.types:
        if type.kind.value == Type.TYPEDEFS.index(Obj):
            definition: Obj = type.definition
            for binding in definition.bindings:
                if binding.findex.value == func.findex.value:
                    return True
    return False

def pseudo_from_op(op: Opcode, idx: int, regs: List[Reg], code: Bytecode):
    if op.op == "Int":
        return f"reg{op.definition['dst']} = {op.definition['ptr'].resolve(code)}"
    elif op.op == "Float":
        return f"reg{op.definition['dst']} = {op.definition['ptr'].resolve(code)}"
    elif op.op == "Label":
        return "label"
    elif op.op == "Mov":
        return f"reg{op.definition['dst']} = reg{op.definition['src']}"
    elif op.op == "JSGte": # jump signed greater than or equal
        return f"if reg{op.definition['a']} >= reg{op.definition['b']}: jump to {idx + (op.definition['offset'].value + 1)}"
    elif op.op == "JNotLt": # jump not less than
        return f"if reg{op.definition['a']} >= reg{op.definition['b']}: jump to {idx + (op.definition['offset'].value + 1)}"
    elif op.op == "Mul":
        return f"reg{op.definition['dst']} = reg{op.definition['a']} * reg{op.definition['b']}"
    elif op.op == "SDiv": # signed division
        return f"reg{op.definition['dst']} = reg{op.definition['a']} / reg{op.definition['b']}"
    elif op.op == "Decr":
        return f"reg{op.definition['dst']}--"
    elif op.op == "GetGlobal":
        glob = type_name(code, op.definition['global'].resolve(code)) # TODO: resolve constants
        return f"reg{op.definition['dst']} = {glob} (g@{op.definition['global']})"
    elif op.op == "Field":
        field = op.definition['field'].resolve(code, regs[op.definition['obj'].value].resolve(code).definition).name.resolve(code)
        return f"reg{op.definition['dst']} = reg{op.definition['obj']}.{field}"
    elif op.op == "NullCheck":
        return f"if reg{op.definition['reg']} is null: error"
    elif op.op == "New":
        # no type specified since regs are typed, so it can only be the type of the reg
        typ = regs[op.definition['dst'].value].resolve(code)
        return f"reg{op.definition['dst']} = new {type_name(code, typ)}"
    elif op.op == "DynSet":
        return f"reg{op.definition['obj']}.{op.definition['field'].resolve(code)} = reg{op.definition['src']}"
    elif op.op == "ToVirtual":
        return f"reg{op.definition['dst']} = Virtual(reg{op.definition['src']})"
    elif op.op == "CallClosure":
        if type(regs[op.definition['dst'].value].resolve(code).definition) == Void:
            return f"reg{op.definition['fun']}({', '.join([f'reg{arg}' for arg in op.definition['args'].value])})"
        return f"reg{op.definition['dst']} = reg{op.definition['fun']}({', '.join([f'reg{arg}' for arg in op.definition['args'].value])})"
    elif op.op == "JAlways":
        return f"jump to {idx + (op.definition['offset'].value + 1)}"
    elif op.op == "Ret":
        if type(regs[op.definition['ret'].value].resolve(code).definition) == Void:
            return "return"
        return f"return reg{op.definition['ret']}"
    return ""

def fmt_op(code: Bytecode, regs: List[Reg], op: Opcode, idx: int, width: int = 15):
    defn = op.definition
    return f"{idx:>3}. {op.op:<{width}} {str(defn):<{48}} {pseudo_from_op(op, idx, regs, code):<{width}}"

def func(code: Bytecode, func: Function):
    if type(func) == Native:
        return native_header(code, func)
    res = ""
    res += func_header(code, func) + "\n"
    res += "Reg types:\n"
    for i, reg in enumerate(func.regs):
        res += f"  {i}. {type_name(code, reg.resolve(code))}\n"
    if func.has_debug:
        res += "\nAssigns:\n"
        for assign in func.assigns:
            res += f"Op {assign[1].value - 1}: {assign[0].resolve(code)}\n"
    res += "\nOps:\n"
    for i, op in enumerate(func.ops):
        res += fmt_op(code, func.regs, op, i) + "\n"
    return res

def func_ir(code: Bytecode, func: Function) -> str:
    return "\n".join([pseudo_from_op(op, i, func.regs, code) for i, op in enumerate(func.ops)])