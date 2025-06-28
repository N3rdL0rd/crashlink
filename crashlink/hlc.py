"""
Handler and translation layer to HL/C (Hashlink/C) for crashlink. Designed to arbitrarily convert already-compiled JIT bytecode to AOT C that you can port to other platforms very easily.
"""

from typing import List, Set, Tuple
from .core import (
    F32, U16, U8, Bytecode, Function, Obj, Opcode, Ref, Type, I32, I64, Bytes, Null, Bool, 
    VarInt, Virtual, Void, F64, DynObj, tIndex, Array, TypeType, Fun, Method, 
    Packed, Struct, Abstract, Enum, Dyn
)
from .disasm import full_func_name
from .globals import VERSION

unimplemented_opcodes: Set[str] = set()
unimplemented_types: Set[str] = set()

# --- Hashing and Naming ---

def hl_hash(s: str) -> int:
    """
    Replicates the HashLink string hashing algorithm (from hlcode.ml).
    """
    h = 0
    for b in s.encode('utf-8'):
        h = (h * 223) + b
        h &= 0xFFFFFFFF  # Emulate 32-bit overflow
    # Convert to signed 32-bit
    if h & 0x80000000:
        h -= 0x100000000
    return h

def get_c_name(name: str) -> str:
    """Creates a valid C identifier from a Haxe path-like name."""
    keywords = {
        "auto", "bool", "break", "case", "char", "const", "continue", "default", "do", "double",
        "else", "enum", "extern", "float", "for", "goto", "if", "int", "long", "register",
        "return", "short", "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
        "unsigned", "void", "volatile", "while", "NULL", "true", "false", "t"
    }
    c_name = ''.join(c if c.isalnum() else '_' for c in name.replace("::", "_").replace(".", "_"))
    if c_name in keywords or c_name.startswith("__"):
        return "hx_" + c_name
    return c_name

def get_c_type_name(code: Bytecode, typ: Type) -> str:
    """Generates a C-style name for a given HashLink type, used for typedefs."""
    dfn = typ.definition
    name = ""
    if isinstance(dfn, (Obj, Struct)):
        name = dfn.name.resolve(code)
    elif isinstance(dfn, Enum):
        name = dfn.name.resolve(code)
    elif isinstance(dfn, Abstract):
        name = dfn.name.resolve(code)
    else:
        try:
            return f"Type_{code.types.index(typ)}"
        except ValueError:
            return f"Type_unfound_{id(typ)}"
    return get_c_name(name)

def get_c_hl_type_var_name(code: Bytecode, typ: Type) -> str:
    """Gets the C name for the global hl_type variable for a given type."""
    dfn = typ.definition
    if isinstance(dfn, (Obj, Struct)):
        name = get_c_name(dfn.name.resolve(code))
        return f"t_{name}"
    if isinstance(dfn, Enum):
        name = get_c_name(dfn.name.resolve(code))
        return f"t_{name}"
    if isinstance(dfn, Abstract):
        name = get_c_name(dfn.name.resolve(code))
        return f"t_{name}"
    
    kind_map = {
        0: "hlt_void", 1: "hlt_ui8", 2: "hlt_ui16", 3: "hlt_i32", 4: "hlt_i64",
        5: "hlt_f32", 6: "hlt_f64", 7: "hlt_bool", 8: "hlt_bytes", 9: "hlt_dyn",
        10: "hlt_fun", 11: "hlt_obj", 12: "hlt_array", 13: "hlt_type", 14: "hlt_ref",
        15: "hlt_virtual", 16: "hlt_dynobj", 17: "hlt_abstract", 18: "hlt_enum",
        19: "hlt_null", 20: "hlt_method", 21: "hlt_struct", 22: "hlt_packed"
    }
    return kind_map.get(typ.kind.value, f"hlt_unknown_{typ.kind.value}")

def ctype_no_ptr(code: Bytecode, typ: Type) -> Tuple[str, int]:
    dfn = typ.definition
    if isinstance(dfn, Void): return "void", 0
    if isinstance(dfn, U8): return "unsigned char", 0
    if isinstance(dfn, U16): return "unsigned short", 0
    if isinstance(dfn, I32): return "int", 0
    if isinstance(dfn, I64): return "int64_t", 0
    if isinstance(dfn, F32): return "float", 0
    if isinstance(dfn, F64): return "double", 0
    if isinstance(dfn, Bool): return "bool", 0
    if isinstance(dfn, Bytes): return "vbyte", 1
    if isinstance(dfn, Dyn): return "vdynamic", 1
    if isinstance(dfn, (Fun, Method)): return "vclosure", 1
    if isinstance(dfn, (Obj, Struct)): return get_c_type_name(code, typ), 0
    if isinstance(dfn, Array): return "varray", 1
    if isinstance(dfn, TypeType): return "hl_type", 1
    if isinstance(dfn, Ref):
        s, i = ctype_no_ptr(code, dfn.type.resolve(code))
        return s, i + 1
    if isinstance(dfn, Virtual): return "vvirtual", 1
    if isinstance(dfn, DynObj): return "vdynobj", 1
    if isinstance(dfn, Abstract): return get_c_name(dfn.name.resolve(code)), 1
    if isinstance(dfn, Enum): return "venum", 1
    if isinstance(dfn, Null): return "vdynamic", 1
    if isinstance(dfn, Packed):
        s, v = ctype_no_ptr(code, dfn.inner.resolve(code))
        return f"struct _{s}", v
    unimplemented_types.add(type(dfn).__name__)
    return "void", 1

def typ_to_c(code: Bytecode, typ: Type) -> str:
    base, ptr_level = ctype_no_ptr(code, typ)
    return base + "*" * ptr_level

def is_gc_ptr(typ: Type) -> bool:
    return not isinstance(typ.definition, (Void, U8, U16, I32, I64, F32, F64, Bool, Ref))

def op_to_c(code: Bytecode, op: Opcode, regs: List[tIndex], fn_idx: int, op_idx: int, indent: int) -> str:
    def r(reg_idx: int) -> str: return f"r{reg_idx}"
    def jmp(offset: VarInt) -> str: return f"Op_{op_idx + offset.value + 1}"
    def field_access(obj_reg_idx: int, field_idx: int) -> str:
        obj_type = regs[obj_reg_idx].resolve(code)
        obj_def = obj_type.definition
        assert isinstance(obj_def, (Obj, Virtual, Struct))
        field = obj_def.resolve_fields(code)[field_idx]
        return f"{r(obj_reg_idx)}->{get_c_name(field.name.resolve(code))}"
    
    res = f"// Unsupported opcode {op.op}"
    df = op.df
    op_name = op.op

    match op_name:
        case "Mov": res = f"{r(df['dst'].value)} = {r(df['src'].value)};"
        case "Int": res = f"{r(df['dst'].value)} = {df['ptr'].resolve(code).value};"
        case "Float": res = f"{r(df['dst'].value)} = {df['ptr'].resolve(code).value};"
        case "Bool": res = f"{r(df['dst'].value)} = {'true' if df['value'].value else 'false'};"
        case "Bytes": res = f"{r(df['dst'].value)} = bytes${df['ptr'].value};"
        case "String": res = f"{r(df['dst'].value)} = string${df['ptr'].value};"
        case "Null": res = f"{r(df['dst'].value)} = NULL;"
        case "Add" | "Sub" | "Mul" | "SDiv" | "SMod" | "Shl" | "SShr" | "And" | "Or" | "Xor":
            op_map = {"Add":"+","Sub":"-","Mul":"*","SDiv":"/","SMod":"%","Shl":"<<","SShr":">>","And":"&","Or":"|","Xor":"^"}
            res = f"{r(df['dst'].value)} = {r(df['a'].value)} {op_map[op_name]} {r(df['b'].value)};"
        case "UShr": res = f"{r(df['dst'].value)} = ((unsigned){r(df['a'].value)}) >> {r(df['b'].value)};"
        case "Neg": res = f"{r(df['dst'].value)} = -{r(df['src'].value)};"
        case "Not": res = f"{r(df['dst'].value)} = !{r(df['src'].value)};"
        case "Incr": res = f"++{r(df['dst'].value)};"
        case "Decr": res = f"--{r(df['dst'].value)};"
        case "JTrue" | "JFalse": res = f"if( {'!' if op_name == 'JFalse' else ''}{r(df['cond'].value)} ) goto {jmp(df['offset'])};"
        case "JNull" | "JNotNull": res = f"if( {r(df['reg'].value)} {'==' if op_name == 'JNull' else '!='} NULL ) goto {jmp(df['offset'])};"
        case "JEq" | "JNotEq" | "JSLt" | "JSGte" | "JSGt" | "JSLte" | "JULt" | "JUGte":
            op_map = {"JEq":"==","JNotEq":"!=","JSLt":"<","JSGte":">=","JSGt":">","JSLte":"<=","JULt":"<","JUGte":">="}
            a_val, b_val = r(df['a'].value), r(df['b'].value)
            cond = f"{a_val} {op_map[op_name]} {b_val}"
            if "U" in op_name: cond = f"((unsigned){a_val}) {op_map[op_name]} ((unsigned){b_val})"
            res = f"if( {cond} ) goto {jmp(df['offset'])};"
        case "JAlways": res = f"goto {jmp(df['offset'])};"
        case "Ret":
            ret_reg_idx = df['ret'].value
            if isinstance(regs[ret_reg_idx].resolve(code).definition, Void):
                res = "return;"
            else:
                res = f"return {r(ret_reg_idx)};"
        case "GetGlobal": res = f"{r(df['dst'].value)} = g_{df['global'].value};"
        case "SetGlobal": res = f"g_{df['global'].value} = {r(df['src'].value)};"
        case "Field": res = f"{r(df['dst'].value)} = {field_access(df['obj'].value, df['field'].value)};"
        case "SetField": res = f"{field_access(df['obj'].value, df['field'].value)} = {r(df['src'].value)};"
        case "GetThis": res = f"{r(df['dst'].value)} = {field_access(0, df['field'].value)};"
        case "SetThis": res = f"{field_access(0, df['field'].value)} = {r(df['src'].value)};"
        case "New":
            type_of_reg = regs[df['dst'].value].resolve(code)
            hl_type_var = get_c_hl_type_var_name(code, type_of_reg)
            res = f"{r(df['dst'].value)} = ({typ_to_c(code, type_of_reg)})hl_alloc_obj(&{hl_type_var});"
        case "SafeCast":
            dst_type = regs[df['dst'].value].resolve(code)
            hl_type_var = get_c_hl_type_var_name(code, dst_type)
            res = f"{r(df['dst'].value)} = ({typ_to_c(code, dst_type)})hl_safe_cast({r(df['src'].value)}, &{hl_type_var});"
        case "UnsafeCast": res = f"{r(df['dst'].value)} = ({typ_to_c(code, regs[df['dst'].value].resolve(code))}){r(df['src'].value)};"
        case "ToSFloat": res = f"{r(df['dst'].value)} = (double){r(df['src'].value)};"
        case "ToInt": res = f"{r(df['dst'].value)} = (int){r(df['src'].value)};"
        case "Call0" | "Call1" | "Call2" | "Call3" | "Call4" | "CallN":
            dst, fun_fidx = r(df['dst'].value), df['fun'].value
            args_list = [r(reg.value) for reg in df['args'].value] if op_name == "CallN" else [r(df[f'arg{i}'].value) for i in range(int(op_name[4:]))]
            call_str = f"f_{fun_fidx}({', '.join(args_list)})"
            
            is_void_ret = False
            try:
                target_fn = code.fn(fun_fidx)
                fun_type_def = target_fn.type.resolve(code).definition
                if isinstance(fun_type_def, Fun) and isinstance(fun_type_def.ret.resolve(code).definition, Void):
                    is_void_ret = True
            except Exception:
                if isinstance(regs[df['dst'].value].resolve(code).definition, Void):
                    is_void_ret = True
            res = f"{call_str};" if is_void_ret else f"{dst} = {call_str};"
        case "DynGet":
            field_idx = df['field'].value
            field_name = code.strings.value[field_idx]
            hash_val = hl_hash(field_name)
            res = f"{r(df['dst'].value)} = ({typ_to_c(code, regs[df['dst'].value].resolve(code))})hl_dyn_get({r(df['obj'].value)}, {hash_val}, &{get_c_hl_type_var_name(code, regs[df['dst'].value].resolve(code))});"
        case "DynSet":
            field_idx = df['field'].value
            field_name = code.strings.value[field_idx]
            hash_val = hl_hash(field_name)
            res = f"hl_dyn_set({r(df['obj'].value)}, {hash_val}, &{get_c_hl_type_var_name(code, regs[df['src'].value].resolve(code))}, {r(df['src'].value)});"
        case "Throw": res = f"hl_throw({r(df['exc'].value)});"
        case "Trap": res = f"hl_trap(&trap, {r(df['exc'].value)}, {jmp(df['offset'])});"
        case "EndTrap": res = "hl_endtrap();"
        case "NullCheck": res = f"if( {r(df['reg'].value)} == NULL ) hl_null_access();"
        case "Switch":
            res = f"switch({r(df['reg'].value)}) {{\n"
            if df['offsets'].value:
                for i, offset in enumerate(df['offsets'].value):
                    if offset.value != 0:
                        res += f"{' ' * (indent+2)}case {i}: goto {jmp(offset)};\n"
            res += f"{' ' * (indent+2)}default: goto {jmp(df['end'])};\n{' ' * indent}}}"
        case "Label": res = ""
        case _:
            if op_name: unimplemented_opcodes.add(op_name)

    return f"{' ' * indent}Op_{op_idx}: {res}"

def fn_to_c(code: Bytecode, fn: Function) -> Tuple[str, str]:
    fn_name = f"f_{fn.findex.value}"
    fn_sig = fn.type.resolve(code).definition
    
    if not isinstance(fn_sig, Fun):
        proto = f"// ERROR: f_{fn.findex.value} has non-function type {type(fn_sig).__name__}"
        return proto, proto

    ret_type = typ_to_c(code, fn_sig.ret.resolve(code))
    nargs = fn.resolve_nargs(code)
    args = fn.regs[:nargs]
    arg_decls = [f"{typ_to_c(code, reg.resolve(code))} r{i}" for i, reg in enumerate(args)]
    
    proto = f"{ret_type} {fn_name}({', '.join(arg_decls) or 'void'}); // {full_func_name(code, fn)}"
    impl = f"{ret_type} {fn_name}({', '.join(arg_decls) or 'void'}) {{\n"
    
    for i, reg_tidx in enumerate(fn.regs[nargs:], start=nargs):
        reg_type = reg_tidx.resolve(code)
        if not isinstance(reg_type.definition, Void):
            impl += f"    {typ_to_c(code, reg_type)} r{i};\n"
    impl += "\n"
    
    for i, op in enumerate(fn.ops):
        impl += op_to_c(code, op, fn.regs, fn.findex.value, i, indent=4) + "\n"
    
    impl += "}\n"
    return proto, impl

def generate_types(code: Bytecode) -> Tuple[str, str, str]:
    """Generates forward declarations, struct definitions, and hl_type var definitions."""
    forward_decls, struct_defs, type_vars = [], [], []
    
    for i, typ in enumerate(code.types):
        dfn = typ.definition
        if isinstance(dfn, (Obj, Struct)):
            c_name = get_c_type_name(code, typ)
            forward_decls.append(f"typedef struct _{c_name} *{c_name};")

    for i, typ in enumerate(code.types):
        hl_type_var_name = get_c_hl_type_var_name(code, typ)
        type_vars.append(f"hl_type {hl_type_var_name};")
        
        dfn = typ.definition
        if isinstance(dfn, (Obj, Struct)):
            c_name = get_c_type_name(code, typ)
            struct_defs.append(f"struct _{c_name} {{")
            if isinstance(dfn, Obj):
                struct_defs.append(f"    hl_type *_{get_c_name(dfn.name.resolve(code))}__$type;")
            
            fields = dfn.resolve_fields(code)
            for field in fields:
                field_c_type = typ_to_c(code, field.type.resolve(code))
                field_c_name = get_c_name(field.name.resolve(code))
                struct_defs.append(f"    {field_c_type} {field_c_name};")
            struct_defs.append("};")
        elif type(dfn).__name__ not in ('Void', 'U8', 'U16', 'I32', 'I64', 'F32', 'F64', 'Bool', 'Bytes', 'Dyn', 'Fun', 'Array', 'TypeType', 'Ref', 'Virtual', 'DynObj', 'Abstract', 'Null', 'Method', 'Packed', 'Enum'):
            unimplemented_types.add(type(dfn).__name__)

    return "\n".join(forward_decls), "\n\n".join(struct_defs), "\n".join(type_vars)

def generate_natives(code: Bytecode) -> str:
    """Generates C prototypes for native functions."""
    protos = []
    for native in code.natives:
        fun_type_def = native.type.resolve(code).definition
        if isinstance(fun_type_def, Fun):
            ret_type = typ_to_c(code, fun_type_def.ret.resolve(code))
            arg_types = [typ_to_c(code, arg.resolve(code)) for arg in fun_type_def.args]
            arg_str = ", ".join(arg_types) if arg_types else "void"
            native_name = get_c_name(f"{native.lib.resolve(code)}_{native.name.resolve(code)}")
            protos.append(f"HL_API {ret_type} {native_name}({arg_str});")
    return "\n".join(protos)

def generate_init_types(code: Bytecode) -> str:
    """Generates the hl_init_types function and its required static data."""
    body = []
    static_data = []

    for i, typ in enumerate(code.types):
        hl_type_var = get_c_hl_type_var_name(code, typ)
        dfn = typ.definition
        
        body.append(f"    {hl_type_var}.kind = {typ.kind.value};")

        if isinstance(dfn, (Obj, Struct)):
            c_name = get_c_type_name(code, typ)
            fields = dfn.resolve_fields(code)
            
            field_data = []
            for f in fields:
                field_name = f.name.resolve(code)
                hash_val = hl_hash(field_name)
                field_data.append(f"{{ &string${f.name.value}, &{get_c_hl_type_var_name(code, f.type.resolve(code))}, {hash_val}/*{field_name}*/ }}")
            if fields:
                static_data.append(f"static hl_obj_field obj_fields_{c_name}[] = {{ {', '.join(field_data)} }};")
            
            body.append(f"    {hl_type_var}.obj = &obj_props_{c_name};")
            body.append(f"    obj_props_{c_name}.name = (uchar*)string${dfn.name.value};")
            body.append(f"    obj_props_{c_name}.nfields = {len(fields)};")
            if fields: body.append(f"    obj_props_{c_name}.fields = obj_fields_{c_name};")
            
            if isinstance(dfn, Obj): # Structs don't have GC info
                bytes_offsets = [f"(int)(intptr_t)&(({c_name})0)->{get_c_name(f.name.resolve(code))}" for f in fields if is_gc_ptr(f.type.resolve(code))]
                if bytes_offsets:
                    static_data.append(f"static int obj_bytes_offset_{c_name}[] = {{ {', '.join(bytes_offsets)}, -1 }};")
                    body.append(f"    obj_props_{c_name}.bytes_offset = obj_bytes_offset_{c_name};")

                if dfn.super.value >= 0:
                    super_type = dfn.super.resolve(code)
                    if super_type.definition and isinstance(super_type.definition, Obj):
                        body.append(f"    obj_props_{c_name}.super = &({get_c_hl_type_var_name(code, super_type)}.obj);")
            
            static_data.append(f"static hl_type_obj obj_props_{c_name};")

    init_func = "void hl_init_types() {\n" + "\n".join(body) + "\n}"
    return "\n".join(static_data) + "\n\n" + init_func

def code_to_c(code: Bytecode) -> str:
    """The main function to transpile a Bytecode object to a C source file string."""
    global unimplemented_opcodes, unimplemented_types
    unimplemented_opcodes.clear()
    unimplemented_types.clear()
    
    c_parts = [
        f"// Generated by crashlink HL/C (cHL/C) -> crashlink {VERSION} (bytecode ver {code.version.value})",
        "#include <stdio.h>", "#include <stdlib.h>", "#include <stdint.h>", "#include <stdbool.h>",
        "#include <string.h>", '#include "hlc.h"'
    ]
    
    type_fwd, type_defs, type_vars = generate_types(code)
    c_parts.append("\n// --- Type Forward Declarations ---")
    c_parts.append(type_fwd)
    c_parts.append("\n// --- Type Definitions ---")
    c_parts.append(type_defs)
    c_parts.append("\n// --- HL Type Variables ---")
    c_parts.append(type_vars)
    
    c_parts.append("\n// --- Globals and Constants ---")
    c_parts.append("static hl_bytes_map *g___types__ = NULL;")
    for i, g_tidx in enumerate(code.global_types):
        c_parts.append(f"static {typ_to_c(code, g_tidx.resolve(code))} g_{i};")
    for i, s in enumerate(code.strings.value):
        c_str = s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
        c_parts.append(f'static vbyte string${i}[] = "{c_str}";')
    for i, val in enumerate(code.ints):
        c_parts.append(f"static int int${i} = {val.value};")
    for i, val in enumerate(code.floats):
        c_parts.append(f"static double float${i} = {val.value};")
    if code.bytes:
        for i, val in enumerate(code.bytes.value):
            byte_vals = ", ".join(str(b) for b in val)
            c_parts.append(f"static vbyte bytes${i}[] = {{{byte_vals}}};")
        
    c_parts.append("\n// --- Function Prototypes ---")
    fn_protos = [fn_to_c(code, fn)[0] for fn in code.functions]
    c_parts.append("\n".join(fn_protos))
    c_parts.append(generate_natives(code))

    c_parts.append("\n// --- Type Initializer ---")
    c_parts.append(generate_init_types(code))

    c_parts.append("\n// --- Global Initializer ---")
    init_body = []
    if code.constants:
        for const in code.constants:
            g_idx = const._global.value
            g_type = code.global_types[g_idx].resolve(code)
            if isinstance(g_type.definition, Obj):
                c_type_name = typ_to_c(code, g_type)
                hl_type_var = get_c_hl_type_var_name(code, g_type)
                init_body.append(f"    g_{g_idx} = ({c_type_name})hl_alloc_obj(&{hl_type_var});")
                if g_idx in code.initialized_globals:
                    for field_name, value in code.initialized_globals[g_idx].items():
                        field_assignment = f"{value}"
                        if isinstance(value, str): field_assignment = f'(vbyte*)"{value}"'
                        init_body.append(f"    g_{g_idx}->{get_c_name(field_name)} = {field_assignment};")
    c_parts.append("void chlc_init_globals() {\n" + "\n".join(init_body) + "\n}")
    
    c_parts.append("\n// --- Function Implementations ---")
    fn_impls = [fn_to_c(code, fn)[1] for fn in code.functions]
    c_parts.append("\n".join(fn_impls))
    
    c_parts.append("\n// --- Main Entrypoint ---")
    c_parts.append("int main(int argc, char** argv) {")
    c_parts.append("    hl_global_init();")
    c_parts.append("    hl_register_thread(&main_thread);")
    c_parts.append("    if( g___types__ ) return 0;")
    c_parts.append("    g___types__ = hl_hballoc();")
    c_parts.append("    hl_init_types();")
    c_parts.append("    chlc_init_globals();")
    c_parts.append(f"    f_{code.entrypoint.value}();")
    c_parts.append("    return 0;")
    c_parts.append("}")

    if unimplemented_opcodes:
        print(f"Warning: Found {len(unimplemented_opcodes)} unimplemented opcodes: {', '.join(sorted(list(unimplemented_opcodes)))}")
    if unimplemented_types:
        print(f"Warning: Found {len(unimplemented_types)} unimplemented types: {', '.join(sorted(list(unimplemented_types)))}")
        
    return "\n\n".join(c_parts)