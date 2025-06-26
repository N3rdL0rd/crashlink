# hlc.py

"""
Handler and translation layer to HL/C (Hashlink/C) for crashlink. Designed to arbitrarily convert already-compiled JIT bytecode to AOT C that you can port to other platforms very easily.
"""

from typing import List, Set
from .core import F32, U16, Bytecode, Function, Obj, Opcode, Ref, Type, I32, I64, Bytes, Null, Bool, VarInt, Virtual, Void, F64, DynObj, tIndex
from .disasm import full_func_name
from .globals import VERSION

unimplemented_opcodes: Set[str] = set()
unimplemented_types: Set[str] = set()

def op_to_c(code: Bytecode, op: Opcode, regs: List[tIndex], fn: int, i: int, indent: int | None = 0) -> str:
    """
    Convert an opcode to a line of C code.
    """
    def _get_jmp_target() -> int:
        if isinstance(op.df.get('offset'), int):
            return i + (op.df['offset'] + 1)
        elif isinstance(op.df.get('offset'), VarInt):
            return i + (op.df['offset'].value + 1)
        else:
            raise ValueError(f"Invalid offset type in opcode {op.op}")

    def _get_field_name(typ_idx: int, field_idx: int) -> str:
        obj_def = code.types[typ_idx].definition
        assert isinstance(obj_def, (Obj, Virtual)), "This should only be called for object types"
        return "field_" + obj_def.resolve_fields(code)[field_idx].name.resolve(code)

    def _get_chlc_value_wrapper(reg_idx: int) -> str:
        reg_type = regs[reg_idx].resolve(code).definition
        if isinstance(reg_type, I32): return f"chlc_value_from_i32(reg{reg_idx})"
        if isinstance(reg_type, F64): return f"chlc_value_from_f64(reg{reg_idx})"
        if isinstance(reg_type, Bool): return f"chlc_value_from_bool(reg{reg_idx})"
        return f"chlc_value_from_ptr(reg{reg_idx})"

    def _get_chlc_value_unwrapper(reg_idx: int) -> str:
        reg_type = regs[reg_idx].resolve(code).definition
        if isinstance(reg_type, I32): return ".data.i"
        if isinstance(reg_type, F64): return ".data.f"
        if isinstance(reg_type, Bool): return ".data.b"
        return ".data.p"

    res = f"// Unknown opcode {op.op}"
    match op.op:
        case "Mov": res = f"reg{op.df['dst']} = reg{op.df['src']};"
        case "Int": res = f"reg{op.df['dst']} = int${op.df['ptr']};"
        case "Float": res = f"reg{op.df['dst']} = float${op.df['ptr']};"
        case "Bool": res = f"reg{op.df['dst']} = {str(op.df['value']).lower()};"
        case "Null": res = f"reg{op.df['dst']} = NULL;"
        case "ToSFloat": res = f"reg{op.df['dst']} = (double)reg{op.df['src']};"
        case "ToUFloat": res = f"reg{op.df['dst']} = (float)reg{op.df['src']};"
        case "Label": res = f"// Label Op_{i}"
        case "Add" | "Sub" | "Mul" | "SDiv" | "SMod" | "Shl" | "Shr" | "SShr" | "SShl":
            op_map = {"Add": "+","Sub": "-","Mul": "*","SDiv": "/","SMod": "%","Shl": "<<","Shr": ">>","SShr": ">>","SShl": "<<"}
            res = f"reg{op.df['dst']} = reg{op.df['a']} {op_map[op.op]} reg{op.df['b']};"
        case "Incr" | "Decr":
            res = f"reg{op.df['dst']}{'++' if op.op == 'Incr' else '--'};"
        case "And": res = f"reg{op.df['dst']} = reg{op.df['a']} & reg{op.df['b']};"
        case "ToInt": res = f"reg{op.df['dst']} = (int)reg{op.df['src']};"
        case "JSLt" | "JSGt" | "JEq" | "JSGte" | "JNotEq" | "JUGte" | "JULt":
            op_map = {"JSLt": "<", "JSGt": ">", "JEq": "==", "JSGte": ">=", "JNotEq": "!=", "JUGte": ">=", "JULt": "<"}
            res = f"if (reg{op.df['a']} {op_map[op.op]} reg{op.df['b']}) goto Op_{_get_jmp_target()};"
        case "JAlways": res = f"goto Op_{_get_jmp_target()};"
        case "JNotNull" | "JNull":
            res = f"if (reg{op.df['reg']} {'!=' if op.op == 'JNotNull' else '=='} NULL) goto Op_{_get_jmp_target()};"
        case "JFalse" | "JTrue":
            res = f"if ({'!' if op.op == 'JFalse' else ''}reg{op.df['cond']}) goto Op_{_get_jmp_target()};"
        case "NullCheck": res = f"if (reg{op.df['reg']} == NULL) {{ printf(\"Failed null check at f@{fn}:{i}\\n\"); exit(1); }}"
        case "Ref": res = f"reg{op.df['dst']} = &reg{op.df['src']};"
        case "Unref": res = f"reg{op.df['dst']} = *reg{op.df['src']};"
        case "Setref": res = f"*reg{op.df['dst']} = reg{op.df['src']};"
        case "Call0" | "Call1" | "Call2" | "Call3" | "Call4" | "CallN":
            args_list = []
            if op.op == "CallN":
                args_list = [f"reg{r.value}" for r in op.df['args'].value]
            else:
                n = int(op.op[4:])
                args_list = [f"reg{op.df[f'arg{i}']}" for i in range(n)]
            args = ", ".join(args_list)
            res = f"fAt_{op.df['fun'].value}({args}); /* {full_func_name(code, op.df['fun'].resolve(code))} */"
        case "Ret":
            res = f"return reg{op.df['ret']};" if not isinstance(regs[op.df['ret'].value].resolve(code).definition, Void) else "return;"
        case "GetThis": res = f"reg{op.df['dst']} = reg0->{_get_field_name(regs[0].value, op.df['field'].value)};"
        case "SetThis": res = f"reg0->{_get_field_name(regs[0].value, op.df['field'].value)} = reg{op.df['src']};"
        case "Field":
            res = f"reg{op.df['dst']} = reg{op.df['obj']}->{_get_field_name(regs[op.df['obj'].value].value, op.df['field'].value)};"
        case "SetField":
            res = f"reg{op.df['obj']}->{_get_field_name(regs[op.df['obj'].value].value, op.df['field'].value)} = reg{op.df['src']};"
        case "GetGlobal": res = f"reg{op.df['dst']} = global_var_{op.df['global']};"
        case "SetGlobal": res = f"global_var_{op.df['global']} = reg{op.df['src']};"
        case "New":
            type_idx = regs[op.df['dst'].value].value
            type_definition = code.types[type_idx].definition
            if isinstance(type_definition, DynObj):
                res = f"reg{op.df['dst']} = chlc_dynobj_new();"
            else:
                res = f"reg{op.df['dst']} = (t${type_idx})malloc(sizeof(struct _t${type_idx}));"
        case "DynGet":
            unwrapper = _get_chlc_value_unwrapper(op.df['dst'].value)
            res = f"reg{op.df['dst']} = chlc_dynobj_get(reg{op.df['obj']}, string${op.df['field'].value}){unwrapper};"
        case "DynSet":
            wrapped_value = _get_chlc_value_wrapper(op.df['src'].value)
            res = f"chlc_dynobj_set(reg{op.df['obj']}, string${op.df['field'].value}, {wrapped_value});"
        case "Throw":
            res = f"chlc_throw(\"Throwing error from f@{fn}:{i}\");"
        case "Type":
            res = f"reg{op.df['dst']} = NULL;"
        case _:
            assert op.op is not None
            unimplemented_opcodes.add(op.op)
            res = f"// Unsupported opcode {op.op}"
    return f"{' ' * (indent or 0)}Op_{i}: {res}"

def typ_to_c(code: Bytecode, typ: Type, idx: int) -> str:
    res = "void *"
    dfn = typ.definition
    if isinstance(dfn, I32): res = "int"
    elif isinstance(dfn, I64): res = "int64_t"
    elif isinstance(dfn, U16): res = "uint16_t"
    elif isinstance(dfn, Bytes): res = "vbyte*"
    elif isinstance(dfn, Null): res = "void*"
    elif isinstance(dfn, Bool): res = "bool"
    elif isinstance(dfn, F64): res = "double"
    elif isinstance(dfn, F32): res = "float"
    elif isinstance(dfn, Void): res = f"/* void type */"
    elif isinstance(dfn, Obj) or isinstance(dfn, Virtual): res = f"t${idx}"
    elif isinstance(dfn, Ref): res = f"{typ_to_c(code, dfn.type.resolve(code), dfn.type.value)}*"
    elif isinstance(dfn, DynObj): res = "struct _HlcDynobj*"
    else:
        unimplemented_types.add(type(dfn).__name__)
        res = f"/* Unsupported type {dfn} */ void*"
    return res

def fn_to_c(code: Bytecode, fn: Function) -> str:
    args = fn.regs[:fn.resolve_nargs(code)]
    non_args = fn.regs[fn.resolve_nargs(code):]
    res = f"void fAt_{fn.findex.value}("
    arg_decls = []
    for i, reg in enumerate(args):
        typ = typ_to_c(code, reg.resolve(code), reg.value)
        if typ != "/* void type */":
            arg_decls.append(f"{typ} reg{i}")
    res += ", ".join(arg_decls)
    res += f") {{ // {full_func_name(code, fn)}\n"
    for i, reg in enumerate(non_args, start=len(args)):
        typ = typ_to_c(code, reg.resolve(code), reg.value)
        if typ != "/* void type */":
            res += f"    {typ} reg{i};\n"
    for i, op in enumerate(fn.ops):
        res += op_to_c(code, op, fn.regs, fn.findex.value, i, indent=4) + "\n"
    res += "}\n"
    return res

def generate_types(code: Bytecode) -> str:
    forward_decls, struct_defs = "", ""
    for i, typ in enumerate(code.types):
        dfn_name = type(typ.definition).__name__
        if dfn_name in {"I32", "I64", "F32", "F64", "Bytes", "Null", "Bool", "Void", "U8", "U16", "Ref", "DynObj", "Array", "TypeType"}:
             forward_decls += f"/* t@{i} {typ.str_resolve(code)} - primitive-like type {dfn_name} */\n"
        elif dfn_name in {"Obj", "Virtual"}:
            assert isinstance(typ.definition, (Obj, Virtual))
            forward_decls += f"/* t@{i} {typ.str_resolve(code)} */\n"
            forward_decls += f"typedef struct _t${i} *t${i};\n\n"
            fields = typ.definition.resolve_fields(code)
            if not fields:
                struct_defs += f"struct _t${i} {{ int _unused; }}; // empty struct\n\n"
            else:
                struct_defs += f"struct _t${i} {{\n"
                for field in fields:
                    field_type = typ_to_c(code, field.type.resolve(code), field.type.value)
                    struct_defs += f"    {field_type} field_{field.name.resolve(code)};\n"
                struct_defs += f"}};\n\n"
        else:
            unimplemented_types.add(dfn_name)
            forward_decls += f"/* t@{i} {typ.str_resolve(code)} - unsupported type {typ.definition} */\n"
    return forward_decls + struct_defs

def generate_global_initializers(code: Bytecode) -> str:
    res = "void chlc_init_globals() {\n"
    for i, global_tidx in enumerate(code.global_types):
        global_type = global_tidx.resolve(code)
        if isinstance(global_type.definition, Obj):
            res += f"    global_var_{i} = (t${global_tidx.value})malloc(sizeof(struct _t${global_tidx.value}));\n"
            if i in code.initialized_globals:
                for field_name, value in code.initialized_globals[i].items():
                    field_assignment = ""
                    if isinstance(value, str):
                        try:
                            str_idx = code.strings.value.index(value)
                            field_assignment = f"string${str_idx}"
                        except ValueError:
                            field_assignment = f"\"ERROR_STR_NOT_FOUND\""
                    elif isinstance(value, bool):
                        field_assignment = str(value).lower()
                    else: # int, float
                        field_assignment = str(value)
                    res += f"    global_var_{i}->field_{field_name} = {field_assignment};\n"
    res += "}\n\n"
    return res

def generate_natives(code: Bytecode) -> str:
    res = ""
    for native in code.natives:
        res += f"// Native function {native.name.resolve(code)} not implemented\n"
    res += "\n"
    return res

def code_to_c(code: Bytecode) -> str:
    global unimplemented_opcodes, unimplemented_types
    unimplemented_opcodes.clear()
    unimplemented_types.clear()
    

    res = f"// Generated by crashlink HL/C (cHL/C) -> crashlink {VERSION} (code ver {code.version.value})\n\n"
    res += "#include <stdio.h>\n#include <stdlib.h>\n#include <stdint.h>\n#include <stdbool.h>\n"
    res += "\n#include <hlc.h>\n\n"

    res += "// Types\n"
    res += generate_types(code)
    
    res += "// Natives\n"
    res += generate_natives(code)
    
    res += "// Globals\n"
    for i, global_tidx in enumerate(code.global_types):
        c_type = typ_to_c(code, global_tidx.resolve(code), global_tidx.value)
        res += f"static {c_type} global_var_{i};\n"
    for i, st in enumerate(code.strings.value):
        c_str = st.replace('\\', '\\\\').replace('"', '\\"')
        res += f"static vbyte* string${i} = \"{c_str}\";\n"
    for i, _int in enumerate(code.ints):
        res += f"static int int${i} = {_int.value};\n"
    for i, _float in enumerate(code.floats):
        res += f"static double float${i} = {_float.value};\n"
    res += "\n\n// Global Initializers\n"
    res += generate_global_initializers(code)

    res += "// Functions\n"
    for fn in code.functions:
        res += fn_to_c(code, fn) + "\n"
        
    res += "// Main Entrypoint\n"
    res += f"int main(int argc, char** argv) {{\n"
    res += f"    chlc_init_globals();\n"
    res += f"    fAt_{code.entrypoint.value}();\n"
    res += f"    return 0;\n"
    res += f"}}\n"
    
    for op in ["GetGlobal", "SetGlobal", "DynGet", "DynSet"]:
        if op in unimplemented_opcodes: unimplemented_opcodes.remove(op)

    if unimplemented_opcodes:
        print(f"Warning: Found {len(unimplemented_opcodes)} unimplemented opcodes: {', '.join(sorted(unimplemented_opcodes))}")
    if unimplemented_types:
        print(f"Warning: Found {len(unimplemented_types)} unimplemented types: {', '.join(sorted(unimplemented_types))}")
    
    return res