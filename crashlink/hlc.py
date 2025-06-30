from __future__ import annotations

import enum
from typing import Any, Callable, List, Literal, Optional, Dict, Tuple, reveal_type

from crashlink.errors import MalformedBytecode

from .core import *


KEYWORDS = {
    "auto",
    "bool",
    "break",
    "case",
    "char",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extern",
    "float",
    "for",
    "goto",
    "if",
    "int",
    "long",
    "register",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "struct",
    "switch",
    "typedef",
    "union",
    "unsigned",
    "void",
    "volatile",
    "while",
    # C99/C11 keywords
    "inline",
    "restrict",
    "_Alignas",
    "_Alignof",
    "_Atomic",
    "_Bool",
    "_Complex",
    "_Generic",
    "_Imaginary",
    "_Noreturn",
    "_Static_assert",
    "_Thread_local",
    "_Pragma",
    # Common values/macros
    "NULL",
    "true",
    "false",
    # GCC/MSVC specifics and other reserved names
    "asm",
    "typeof",
    "__declspec",
    "dllimport",
    "dllexport",
    "naked",
    "thread",
    # Reserved by HLC itself
    "t",
}


def sanitize_ident(name: str) -> str:
    """
    Sanitizes a Haxe identifier to ensure it's a valid C identifier.
    If the name is a C keyword or starts with '__', it's prefixed with '_hx_'.
    """
    if name in KEYWORDS or name.startswith("__"):
        return "_hx_" + name
    return name


# --- Hashing ---


def hl_hash_utf8(name: str) -> int:
    """Hash UTF-8 string until null terminator"""
    h = 0
    for char in name:
        char_val = ord(char)
        if char_val == 0:
            break
        h = (223 * h + char_val) & 0xFFFFFFFF
    h = h % 0x1FFFFF7B
    return h if h < 0x7FFFFFFF else h - 0x100000000


def hl_hash(name: bytes) -> int:
    """General hash function - processes until null terminator"""
    h = 0
    for byte_val in name:
        if byte_val == 0:
            break
        h = (223 * h + byte_val) & 0xFFFFFFFF
    h = h % 0x1FFFFF7B
    return h if h < 0x7FFFFFFF else h - 0x100000000


def hash_string(s: str) -> int:
    """Hash a string by encoding it as UTF-8 bytes"""
    return hl_hash(s.encode("utf-8"))


def _ctype_no_ptr(code: Bytecode, typ: Type, i: int) -> Tuple[str, int]:
    """
    Internal helper to get the base C type name and pointer level.
    Returns: A tuple of (base_c_name: str, pointer_level: int).
    """
    defn = typ.definition
    if defn is None:
        raise ValueError(f"Type t@{i} has no definition, cannot determine C type.")

    if isinstance(defn, Void):
        return "void", 0
    if isinstance(defn, U8):
        return "unsigned char", 0
    if isinstance(defn, U16):
        return "unsigned short", 0
    if isinstance(defn, I32):
        return "int", 0
    if isinstance(defn, I64):
        return "int64", 0
    if isinstance(defn, F32):
        return "float", 0
    if isinstance(defn, F64):
        return "double", 0
    if isinstance(defn, Bool):
        return "bool", 0
    if isinstance(defn, Bytes):
        return "vbyte", 1
    if isinstance(defn, Dyn):
        return "vdynamic", 1
    if isinstance(defn, Fun):
        return "vclosure", 1
    if isinstance(defn, Array):
        return "varray", 1
    if isinstance(defn, TypeType):
        return "hl_type", 1
    if isinstance(defn, Virtual):
        return "vvirtual", 1
    if isinstance(defn, DynObj):
        return "vdynobj", 1
    if isinstance(defn, Enum):
        return "venum", 1
    if isinstance(defn, Null):
        return "vdynamic", 1
    if isinstance(defn, Method):
        return "void", 1
    if isinstance(defn, Obj) or isinstance(defn, Struct):
        return f"obj${i}", 0

    if isinstance(defn, Abstract):
        # AN ABSTRACT'S NAME BECOMES A C TYPE, SO IT MUST BE SANITIZED.
        c_name = sanitize_ident(defn.name.resolve(code))
        return c_name, 1

    if isinstance(defn, Ref):
        inner_type = defn.type.resolve(code)
        base_name, ptr_level = _ctype_no_ptr(code, inner_type, defn.type.value)
        return base_name, ptr_level + 1

    if isinstance(defn, Packed):
        inner_type = defn.inner.resolve(code)
        base_name, ptr_level = _ctype_no_ptr(code, inner_type, defn.inner.value)
        return f"struct _{base_name}", ptr_level

    raise NotImplementedError(f"C type conversion not implemented for type definition: {type(defn).__name__}")


def ctype(code: Bytecode, typ: Type, i: int) -> str:
    """Converts a Type object into a C type string representation, including pointers."""
    base_name, ptr_level = _ctype_no_ptr(code, typ, i)
    return base_name + ("*" * ptr_level) if ptr_level > 0 else base_name


def ctype_no_ptr(code: Bytecode, typ: Type, i: int) -> str:
    """Converts a Type object into a C type string representation, excluding pointers."""
    base_name, _ = _ctype_no_ptr(code, typ, i)
    return base_name


class Indenter:
    """A context manager for dynamically handling indentation levels."""

    indent_char: str
    level: int
    current_indent: str

    def __init__(self, indent_char: str = "    ") -> None:
        self.indent_char = indent_char
        self.level = 0
        self.current_indent = ""

    def __enter__(self) -> "Indenter":
        self.level += 1
        self.current_indent = self.indent_char * self.level
        return self

    def __exit__(self, exc_type: Optional[Any], exc_val: Optional[Any], exc_tb: Optional[Any]) -> Literal[False]:
        self.level -= 1
        self.current_indent = self.indent_char * self.level
        return False


KIND_SHELLS = {
    0: "HVOID",
    1: "HUI8",
    2: "HUI16",
    3: "HI32",
    4: "HI64",
    5: "HF32",
    6: "HF64",
    7: "HBOOL",
    8: "HBYTES",
    9: "HDYN",
    10: "HFUN",
    11: "HOBJ",
    12: "HARRAY",
    13: "HTYPE",
    14: "HREF",
    15: "HVIRTUAL",
    16: "HDYNOBJ",
    17: "HABSTRACT",
    18: "HENUM",
    19: "HNULL",
    20: "HMETHOD",
    21: "HSTRUCT",
    22: "HPACKED",
    23: "HGUID",
    24: "HLAST",
}


def generate_natives(code: Bytecode) -> List[str]:
    """Generates forward declarations for abstract types and native function prototypes."""
    res = []
    indent = Indenter()

    def line(*args: Any) -> None:
        res.append(indent.current_indent + " ".join(str(arg) for arg in args))

    line("// Abstract type forward declarations")
    all_types = code.gather_types()
    abstract_names = set()
    for typ in all_types:
        if isinstance(typ.definition, Abstract):
            name = typ.definition.name.resolve(code)
            if name not in {"hl_tls", "hl_mutex", "hl_thread"}:
                abstract_names.add(sanitize_ident(name))

    for name in sorted(list(abstract_names)):
        line(f"typedef struct _{name} {name};")

    res.append("")

    line("// Native function prototypes")
    sorted_natives = sorted(code.natives, key=lambda n: (n.lib.resolve(code), n.name.resolve(code)))

    for native in sorted_natives:
        func_type = native.type.resolve(code)
        if not isinstance(func_type.definition, Fun):
            continue
        fun_def = func_type.definition

        lib_name = native.lib.resolve(code).lstrip("?")
        c_func_name = f"{'hl' if lib_name == 'std' else lib_name}_{native.name.resolve(code)}"
        ret_type_str = ctype(code, fun_def.ret.resolve(code), fun_def.ret.value)
        arg_types = [ctype(code, arg.resolve(code), arg.value) for arg in fun_def.args]
        args_str = ", ".join(arg_types) if arg_types else "void"

        if c_func_name not in {"hl_tls_set"}:  # filter out built-ins we don't want to redefine
            line(f"HL_API {ret_type_str} {c_func_name}({args_str});")
    return res


def generate_structs(code: Bytecode) -> List[str]:
    """Generates C struct forward declarations and definitions for Haxe classes."""
    res = []
    indent = Indenter()

    def line(*args: Any) -> None:
        res.append(indent.current_indent + " ".join(str(arg) for arg in args))

    types = code.gather_types()
    struct_map = {i: t for i, t in enumerate(types) if isinstance(t.definition, (Struct, Obj))}
    if not struct_map:
        return res

    line("// Class/Struct forward definitions")
    for i in sorted(struct_map.keys()):
        dfn = struct_map[i].definition
        assert isinstance(dfn, (Obj, Struct)), f"Expected definition to be Obj or Struct, got {type(dfn).__name__}."
        line(f"typedef struct _obj${i} *obj${i}; /* {dfn.name.resolve(code)} */")
    res.append("")

    line("// Class/Struct definitions")
    for i, typ in sorted(struct_map.items()):
        df = typ.definition
        assert isinstance(df, (Obj, Struct)), f"Expected definition to be Obj or Struct, got {type(df).__name__}."
        line(f"struct _obj${i} {{ /* {df.name.resolve(code)} */")
        with indent:
            line("hl_type *$type;")
            for f in df.resolve_fields(code):
                field_type = ctype(code, f.type.resolve(code), f.type.value)
                # A STRUCT FIELD IS A C IDENTIFIER, SO IT MUST BE SANITIZED.
                field_name = sanitize_ident(f.name.resolve(code))
                line(f"{field_type} {field_name};")
        line("};")
    return res


def generate_types(code: Bytecode) -> List[str]:
    """Generates the C data and initializers for all hl_type instances."""
    res = []
    indent = Indenter()

    def line(*args: Any) -> None:
        res.append(indent.current_indent + " ".join(str(arg) for arg in args))

    types = code.gather_types()

    line("// Type shells")
    for i, typ in enumerate(types):
        line(f"hl_type t${i} = {{ {KIND_SHELLS[typ.kind.value]} }};")

    line("\n// Type data")
    for i, typ in enumerate(types):
        df = typ.definition
        if isinstance(df, (Obj, Struct)):
            if df.fields:
                vals = ", ".join(
                    f'{{(const uchar*)USTR("{f.name.resolve(code)}"), &t${f.type.value}, {hl_hash_utf8(f.name.resolve(code))}}}'
                    for f in df.fields
                )
                line(f"static hl_obj_field fieldst${i}[] = {{{vals}}};")
            if df.protos:
                vals = ", ".join(
                    f'{{(const uchar*)USTR("{p.name.resolve(code)}"), {p.findex.value}, {p.pindex.value}, {hl_hash_utf8(p.name.resolve(code))}}}'
                    for p in df.protos
                )
                line(f"static hl_obj_proto protot${i}[] = {{{vals}}};")
            if df.bindings:
                bindings = ", ".join(f"{b.field.value}, {b.findex.value}" for b in df.bindings)
                line(f"static int bindingst${i}[] = {{{bindings}}};")
            line(f"static hl_type_obj objt${i} = {{")
            with indent:
                line(f"{df.nfields}, {df.nprotos}, {df.nbindings},")
                line(f'(const uchar*)USTR("{df.name.resolve(code)}"),')
                line(f"&t${df.super.value}," if df.super.value >= 0 else "NULL,")
                line(f"fieldst${i}," if df.fields else "NULL,")
                line(f"protot${i}," if df.protos else "NULL,")
                line(f"bindingst${i}," if df.bindings else "NULL,")
            line("};")
        elif isinstance(df, Fun):
            if df.args:
                line(f"static hl_type *fargst${i}[] = {{{', '.join(f'&t${arg.value}' for arg in df.args)}}};")
                line(f"static hl_type_fun tfunt${i} = {{fargst${i}, &t${df.ret.value}, {df.nargs}}};")
            else:
                line(f"static hl_type_fun tfunt${i} = {{NULL, &t${df.ret.value}, 0}};")
        elif isinstance(df, Virtual):
            if df.fields:
                vals = ", ".join(
                    f'{{(const uchar*)USTR("{f.name.resolve(code)}"), &t${f.type.value}, {hl_hash_utf8(f.name.resolve(code))}}}'
                    for f in df.fields
                )
                line(f"static hl_obj_field vfieldst${i}[] = {{{vals}}};")
                line(f"static hl_type_virtual virtt${i} = {{vfieldst${i}, {df.nfields}}};")
            else:
                line(f"static hl_type_virtual virtt${i} = {{NULL, 0}};")
        elif isinstance(df, Enum):
            # TODO enum
            pass

    line("\n// Type initializer")
    line("void hl_init_types( hl_module_context *ctx ) {")
    with indent:
        for j, typ in enumerate(types):
            df = typ.definition
            if isinstance(df, (Obj, Struct)):
                line(f"objt${j}.m = ctx;")
                if df._global and df._global.value:
                    line(
                        f"objt${j}.global_value = (void**)&g${df._global.value - 1};"
                    )  # FIXME: don't know if -1 is correct?
                line(f"t${j}.obj = &objt${j};")
            elif isinstance(df, Fun):
                line(f"t${j}.fun = &tfunt${j};")
            elif isinstance(df, Virtual):
                line(f"t${j}.virt = &virtt${j};")
                line(f"hl_init_virtual(&t${j},ctx);")
            elif isinstance(df, Enum):
                # TODO enum
                pass
            elif isinstance(df, (Null, Ref)):
                line(f"t${j}.tparam = &t${df.type.value};")
    line("}\n")
    return res


def is_gc_ptr(typ: Type) -> bool:
    """Checks if a type is a pointer that the GC needs to track."""
    NON_GC_POINTER_KINDS = {
        Type.Kind.VOID.value,
        Type.Kind.U8.value,
        Type.Kind.U16.value,
        Type.Kind.I32.value,
        Type.Kind.I64.value,
        Type.Kind.F32.value,
        Type.Kind.F64.value,
        Type.Kind.BOOL.value,
        Type.Kind.TYPETYPE.value,
        Type.Kind.REF.value,
        Type.Kind.METHOD.value,
        Type.Kind.PACKED.value,
    }
    return typ.kind.value not in NON_GC_POINTER_KINDS


def generate_globals(code: Bytecode) -> List[str]:
    """Generates C code for all global variables and their initialization."""
    res, indent = [], Indenter()

    def line(*args: Any) -> None:
        res.append(indent.current_indent + " ".join(str(arg) for arg in args))

    if not code.global_types:
        return res

    all_types = code.gather_types()
    line("// Global variables")
    for i, g_type_ptr in enumerate(code.global_types):
        g_type = g_type_ptr.resolve(code)
        c_type_str = ctype(code, g_type, all_types.index(g_type))
        line(f"{c_type_str} g${i} = 0;")

    for const in code.constants:
        obj = const._global.resolve(code).definition
        objIdx = const._global.partial_resolve(code).value
        assert isinstance(obj, Obj), (
            f"Expected global constant to be an Obj, got {type(obj).__name__}. This should never happen."
        )
        fields = obj.resolve_fields(code)
        const_fields: List[str] = []
        for i, field in enumerate(const.fields):
            typ = fields[i].type.resolve(code).definition
            name = fields[i].name.resolve(code)
            if isinstance(typ, (Obj, Struct)):
                raise MalformedBytecode("Global constants cannot contain other initialized Objs or Structs.")
            elif isinstance(typ, (I32, U8, U16, I64)):
                const_fields.append(str(code.ints[field.value].value))
            elif isinstance(typ, (F32, F64)):
                const_fields.append(str(code.floats[field.value].value))
            elif isinstance(typ, Bytes):
                val = code.strings.value[field.value]
                c_escaped_str = val.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
                const_fields.append(f'(vbyte*)USTR("{c_escaped_str}")')
        line(f"static struct _obj${objIdx} const_g${const._global.value} = {{&t${objIdx}, {', '.join(const_fields)}}};")

    line("\nvoid hl_init_roots() {")
    with indent:
        for const in code.constants:
            line(f"g${const._global.value} = &const_g${const._global.value};")
        for i, g_type_ptr in enumerate(code.global_types):
            g_type = g_type_ptr.resolve(code)
            if is_gc_ptr(g_type):
                line(f"hl_add_root((void**)&g${i});")
    line("}")
    return res


def generate_entry(code: Bytecode) -> List[str]:
    """Generates the C entry point for the HLC module."""
    res = []
    indent = Indenter()

    def line(*args: Any) -> None:
        res.append(indent.current_indent + " ".join(str(arg) for arg in args))

    line("void hl_entry_point() {")
    with indent:
        line("hl_module_context ctx;")
        line("hl_alloc_init(&ctx.alloc);")
        line("// ctx.functions_ptrs = hl_functions_ptrs;")  # TODO
        line("// ctx.functions_types = hl_functions_types;")
        line("hl_init_types(&ctx);")
        line("// hl_init_hashes();")
        line("hl_init_roots();")
        line(f"f${code.entrypoint.value}();")
    line("}")
    return res

unknown_ops = set()

def generate_functions(code: Bytecode) -> List[str]:
    global unknown_ops
    
    res = []
    indent = Indenter()

    def line(*args: Any) -> None:
        res.append(indent.current_indent + " ".join(str(arg) for arg in args))

    def opline(idx: int, *args: Any) -> None:
        res.append(indent.current_indent + f"Op_{idx}: " + " ".join(str(arg) for arg in args))
        
    def regstr(r: Reg) -> str:
        return f"r{r.value}"

    def rcast(reg: Reg, target_type: Type, function: Function) -> str:
        """Generates a C-style cast for a register if its type differs from the target."""
        reg_type = function.regs[reg.value].resolve(code)
        # This is a simplified check. A more robust one would use hl_safe_cast.
        if reg_type == target_type:
            return regstr(reg)
        # A full implementation would need the all_types map, but for now we use the raw index
        all_types = code.gather_types()
        type_map = {t: i for i, t in enumerate(all_types)}
        return f"({ctype(code, target_type, type_map[target_type])}){regstr(reg)}"

    def cast_fun(code: Bytecode, func_ptr_expr: str, ret_type: tIndex, args_types: List[tIndex]) -> str:
        """Generates a C cast for a function pointer."""
        ret_t_str = ctype(code, ret_type.resolve(code), ret_type.value)
        args_t_str = ", ".join(ctype(code, t.resolve(code), t.value) for t in args_types) or "void"
        return f"(({ret_t_str} (*)({args_t_str})){func_ptr_expr})"
    
    for function in code.functions:
        fun = function.type.resolve(code).definition
        assert isinstance(fun, Fun), (
            f"Expected function type to be Fun, got {type(fun).__name__}. This should never happen."
        )
        ret_t = ctype(code, fun.ret.resolve(code), fun.ret.value)
        args_t = [ctype(code, arg.resolve(code), arg.value) for arg in fun.args]
        args_with_names = [f"{t} r{i}" for i, t in enumerate(args_t)]
        args_str = ", ".join(args_with_names) if args_with_names else "void"
        line(f"{ret_t} f${function.findex.value}({args_str}) {{")
        closure_id = 0
        with indent:
            for i, reg in enumerate(function.regs[len(args_with_names) :]):
                reg_idx = i + len(args_with_names)
                if reg.resolve(code).kind.value == Type.Kind.VOID.value:
                    line(f"// void r{reg_idx}")
                    continue  # void is for explicit discard
                reg_type = ctype(code, reg.resolve(code), reg.value)
                line(f"{reg_type} r{reg_idx};")

            for i, op in enumerate(function.ops):
                # oh god, here we go
                df = op.df
                rhs = ""
                has_dst = "dst" in df

                match op.op:
                    case "Mov":
                        rhs = f"r{df['src']}"
                    case "Int":
                        rhs = f"{code.ints[df['ptr'].value].value}"
                    case "Float":
                        rhs = f"{code.floats[df['ptr'].value].value}"
                    case "Bool":
                        rhs = "true" if df["value"] else "false"
                    case "Bytes":
                        # TODO not sure this is right - might be bytes pool past v5?
                        rhs = f'(vbyte*)USTR("{code.strings.value[df["ptr"].value]}")'
                    case "String":
                        rhs = f'(vbyte*)USTR("{code.strings.value[df["ptr"].value]}")'
                    case "Null":
                        rhs = "NULL"
                    case "Add":
                        rhs = f"r{df['a']} + r{df['b']}"
                    case "Sub":
                        rhs = f"r{df['a']} - r{df['b']}"
                    case "Mul":
                        rhs = f"r{df['a']} * r{df['b']}"
                    case "SDiv":
                        rtype = function.regs[df["dst"].value].resolve(code).kind.value
                        if rtype in {Type.Kind.U8.value, Type.Kind.U16.value, Type.Kind.I32.value}:
                            rhs = f"(r{df['b']} == 0 || r{df['b']} == -1) ? r{df['a']} * r{df['b']} : r{df['a']} / r{df['b']}"
                        else:
                            rhs = f"r{df['a']} / r{df['b']}"
                    case "UDiv":
                        rhs = f"(r{df['b']} == 0) ? 0 : ((unsigned)r{df['a']}) / ((unsigned)r{df['b']})"
                    case "SMod":
                        rtype = function.regs[df["dst"].value].resolve(code).kind.value
                        if rtype in {Type.Kind.U8.value, Type.Kind.U16.value, Type.Kind.I32.value}:
                            rhs = f"(r{df['b']} == 0 || r{df['b']} == -1) ? 0 : r{df['a']} % r{df['b']}"
                        elif rtype == Type.Kind.F32.value:
                            rhs = f"fmodf(r{df['a']}, r{df['b']})"
                        elif rtype == Type.Kind.F64.value:
                            rhs = f"fmod(r{df['a']}, r{df['b']})"
                        else:
                            raise MalformedBytecode(f"Unsupported SMod type: {rtype} at op {i} in function {function.name.resolve(code)}")
                    case "UMod":
                        rhs = f"(r{df['b']} == 0) ? 0 : ((unsigned)r{df['a']}) % ((unsigned)r{df['b']})"
                    case "Shl":
                        rhs = f"r{df['a']} << r{df['b']}"
                    case "SShr":
                        rhs = f"r{df['a']} >> r{df['b']}"
                    case "UShr":
                        rtype = function.regs[df["dst"].value].resolve(code).kind.value
                        if rtype == Type.Kind.I64.value:
                            rhs = f"((uint64)r{df['a']}) >> r{df['b']}"
                        else:
                            rhs = f"((unsigned)r{df['a']}) >> r{df['b']}"
                    case "And":
                        rhs = f"r{df['a']} & r{df['b']}"
                    case "Or":
                        rhs = f"r{df['a']} | r{df['b']}"
                    case "Xor":
                        rhs = f"r{df['a']} ^ r{df['b']}"
                    case "Neg":
                        rhs = f"-r{df['src']}"
                    case "Not":
                        rhs = f"!r{df['src']}"
                    case "Incr":
                        rhs = f"++r{df['dst']}"
                        has_dst = False
                    case "Decr":
                        rhs = f"--r{df['dst']}"
                        has_dst = False
                    case "Call0" | "Call1" | "Call2" | "Call3" | "Call4":
                        nargs = int(op.op[4:])
                        args = [f"r{df[f'arg{i}']}" for i in range(nargs)]
                        if nargs == 0:
                            rhs = f"f${df['fun']}()"
                        else:
                            rhs = f"f${df['fun']}({', '.join(args)})"
                    case "CallN":
                        args = [f"r{arg}" for arg in df["args"].value]
                        rhs = f"f${df['fun']}({', '.join(args)})"
                    case "CallMethod" | "CallThis":
                        if op.op == "CallThis":
                            obj_reg = 0
                            arg_regs = df["args"].value
                        else:
                            obj_reg = df["args"].value[0].value
                            arg_regs = df["args"].value[1:]
                        obj_t = function.regs[obj_reg].resolve(code).definition
                        if isinstance(obj_t, (Obj, Struct)):
                            obj = f"r{obj_reg}"
                            fid = df["field"].value
                            func_ptr = f"{obj}->$type->vobj_proto[{fid}]"
                            dst_reg = df["dst"].value
                            ret_type = function.regs[dst_reg]
                            obj_type = function.regs[obj_reg]
                            arg_types = [obj_type] + [function.regs[r.value] for r in arg_regs]
                            casted_fun = cast_fun(code, func_ptr, ret_type, arg_types)
                            call_args_str = ", ".join([obj] + [f"r{r.value}" for r in arg_regs])
                            rhs = f"{casted_fun}({call_args_str})"
                        elif isinstance(obj_t, Virtual):
                            raise NotImplementedError(
                                f"CallMethod/CallThis on Virtual type not implemented at op {i} in function {function.name.resolve(code)}"
                            )
                        else:
                            raise MalformedBytecode(f"CallMethod/CallThis on non-Obj/Struct type: {obj_t} at op {i} in function {function.name.resolve(code)}")
                    case "CallClosure":
                        closure_reg = df['fun']
                        closure_reg_str = regstr(closure_reg)
                        closure_type = function.regs[closure_reg.value].resolve(code)
                        if closure_type.kind.value == Type.Kind.DYN.value:
                            unknown_ops.add("CallClosure_Dynamic")
                            opline(i, f"/* CallClosure on dynamic value r{closure_reg.value} not implemented */")
                            continue
                        if closure_type.kind.value != Type.Kind.FUN.value:
                             raise MalformedBytecode(f"CallClosure on an unexpected type: {closure_type}")
                        closure_type_def = closure_type.definition
                        assert isinstance(closure_type_def, Fun)
                        ret_type_idx = closure_type_def.ret
                        closure_arg_type_idxs = closure_type_def.args
                        call_arg_regs = df['args'].value
                        if len(call_arg_regs) != len(closure_arg_type_idxs):
                            raise MalformedBytecode(f"CallClosure argument count mismatch at op {i} in f{function.findex.value}. Expected {len(closure_arg_type_idxs)}, got {len(call_arg_regs)}")
                        casted_args_str_list = [rcast(reg, target_type_idx.resolve(code), function) for reg, target_type_idx in zip(call_arg_regs, closure_arg_type_idxs)]
                        static_fun_ptr = cast_fun(code, f"{closure_reg_str}->fun", ret_type_idx, closure_arg_type_idxs)
                        static_call = f"{static_fun_ptr}({', '.join(casted_args_str_list)})"
                        dyn_type_idx = code.find_prim_type(Type.Kind.DYN)
                        instance_arg_types = [dyn_type_idx] + closure_arg_type_idxs
                        instance_fun_ptr = cast_fun(code, f"{closure_reg_str}->fun", ret_type_idx, instance_arg_types)
                        instance_call = f"{instance_fun_ptr}({', '.join([f'(vdynamic*){closure_reg_str}->value'] + casted_args_str_list)})"
                        rhs = f"({closure_reg_str}->hasValue ? {instance_call} : {static_call})"
                    case "StaticClosure":
                        rhs = f"&cl${df['fun']}"
                        res.insert(1,
                                   f"static vclosure cl${closure_id} = {{ .... }}") # TODO FIXME whatever
                        closure_id += 1
                    case _:
                        print("Unknown operation:", op.op)
                        unknown_ops.add(op.op)
                        continue

                if has_dst:
                    dst_type = function.regs[df["dst"].value].resolve(code)
                    if dst_type.kind.value == Type.Kind.VOID.value:
                        opline(i, f"{rhs}; // void dst")
                    else:
                        opline(i, f"r{df['dst']} = {rhs};")
                else:
                    opline(i, f"{rhs};")
        line("}")

    return res


def code_to_c(code: Bytecode) -> str:
    """
    Translates a loaded Bytecode object into a single C source file.
    """
    res = []

    def line(*args: Any) -> None:
        res.append(" ".join(str(arg) for arg in args))

    sec: Callable[[str], None] = lambda section: res.append(f"\n\n/*---------- {section} ----------*/\n")

    line("// Generated by crashlink")
    line("#include <hlc.h>")

    sec("Natives & Abstracts Forward Declarations")
    res += generate_natives(code)

    sec("Structs")
    res += generate_structs(code)

    sec("Types")
    res += generate_types(code)

    sec("Globals & Strings")
    res += generate_globals(code)

    sec("Functions! Whoa!")
    res += generate_functions(code)

    sec("Entrypoint")
    res += generate_entry(code)
    
    if unknown_ops:
        print(f"Warning: {len(unknown_ops)} unknown operations encountered during function generation.")

    # TODO: Add generation for:
    # - Hash initialization (maybe we can live without it? i think it's just pre-caching for performance)
    # - Haxe functions

    return "\n".join(res)
