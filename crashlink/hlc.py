from __future__ import annotations

import enum
from typing import Any, Callable, List, Literal, Optional, Dict, Tuple

from crashlink.errors import MalformedBytecode
from tqdm import tqdm

from .core import *
from .core import USE_TQDM


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
    all_types = code.types
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
            args_with_names = ", ".join(
                f"{arg_type} r{i}" for i, arg_type in enumerate(arg_types)
            ) if arg_types else "void"
            line(f"{ret_type_str} f${native.findex.value}({args_with_names}){{")
            with indent:
                line(f"return {c_func_name}({', '.join(f'r{i}' for i in range(len(arg_types))) if arg_types else ''});") 
            line("}")                
    return res


def generate_structs(code: Bytecode) -> List[str]:
    """Generates C struct forward declarations and definitions for Haxe classes."""
    res = []
    indent = Indenter()

    def line(*args: Any) -> None:
        res.append(indent.current_indent + " ".join(str(arg) for arg in args))

    types = code.types
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
    for i, typ in tqdm(sorted(struct_map.items())) if USE_TQDM else sorted(struct_map.items()):
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

    types = code.types

    line("// Type shells")
    for i, typ in tqdm(enumerate(types)):
        line(f"hl_type t${i} = {{ {KIND_SHELLS[typ.kind.value]} }};")

    line("\n// Type data")
    for i, typ in tqdm(enumerate(types)):
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

    all_types = code.types
    line("// Global variables")
    for i, g_type_ptr in enumerate(code.global_types):
        g_type = g_type_ptr.resolve(code)
        c_type_str = ctype(code, g_type, all_types.index(g_type))
        line(f"{c_type_str} g${i} = 0;")

    for const in tqdm(code.constants):
        obj = const._global.resolve(code).definition
        objIdx = const._global.partial_resolve(code).value
        assert isinstance(obj, Obj), (
            f"Expected global constant to be an Obj, got {type(obj).__name__}. This should never happen."
        )
        fields = obj.resolve_fields(code)
        const_fields: List[str] = []
        for i, field in enumerate(const.fields):
            typd = fields[i].type.resolve(code).definition
            name = fields[i].name.resolve(code)
            if isinstance(typd, (Obj, Struct)):
                raise MalformedBytecode("Global constants cannot contain other initialized Objs or Structs.")
            elif isinstance(typd, (I32, U8, U16, I64)):
                const_fields.append(str(code.ints[field.value].value))
            elif isinstance(typd, (F32, F64)):
                const_fields.append(str(code.floats[field.value].value))
            elif isinstance(typd, Bytes):
                val = code.strings.value[field.value]
                c_escaped_str = val.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
                const_fields.append(f'(vbyte*)USTR("{c_escaped_str}")')
        line(f"static struct _obj${objIdx} const_g${const._global.value} = {{&t${objIdx}, {', '.join(const_fields)}}};")

    line("\n// Type initializer")
    line("void hl_init_types( hl_module_context *ctx ) {")
    with indent:
        for j, typ in enumerate(code.types):
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

    line("\nvoid hl_init_roots() {")
    with indent:
        for const in tqdm(code.constants):
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

def dyn_value_field(typ: Type) -> str:
    """
    Returns the name of the C union field used to store a value of a given type
    within a vdynamic struct.
    """
    dfn = typ.definition
    if isinstance(dfn, (U8, U16, I32)): return "i"
    if isinstance(dfn, I64): return "i64"
    if isinstance(dfn, F32): return "f"
    if isinstance(dfn, F64): return "d"
    if isinstance(dfn, Bool): return "b"
    # All other types (HBytes, HDyn, HFun, HObj, etc.) are pointers.
    return "ptr"

COMP_OP_MAP = {
    "JSLt": "<", "JSLte": "<=",
    "JSGt": ">", "JSGte": ">=",
    "JEq": "==", "JNotEq": "!=",
    "JULt": "<", "JUGte": ">=",
}

SWAP_OP_MAP = {
    "JSLt": "JSGt", "JSGt": "JSLt",
    "JSLte": "JSGte", "JSGte": "JSLte",
    "JEq": "JEq", "JNotEq": "JNotEq",
}

def is_ptr(kind: int) -> bool:
    return kind not in {
        Type.Kind.VOID.value,
        Type.Kind.U8.value,
        Type.Kind.U16.value,
        Type.Kind.I32.value,
        Type.Kind.I64.value,
        Type.Kind.F32.value,
        Type.Kind.F64.value,
        Type.Kind.BOOL.value,
    }

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

    def cast_fun(code: Bytecode, func_ptr_expr: str, ret_type: tIndex, args_types: List[tIndex]) -> str:
        """Generates a C cast for a function pointer."""
        ret_t_str = ctype(code, ret_type.resolve(code), ret_type.value)
        args_t_str = ", ".join(ctype(code, t.resolve(code), t.value) for t in args_types) or "void"
        return f"(({ret_t_str} (*)({args_t_str})){func_ptr_expr})"

    def rcast(code: Bytecode, reg: Reg, target_type_idx: tIndex, function: Function) -> str:
        """Generates a C-style cast for a register if its type differs from the target."""
        reg_type_idx = function.regs[reg.value]
        reg_type_def = reg_type_idx.resolve(code).definition
        target_type_def = target_type_idx.resolve(code).definition

        if reg_type_idx.value == target_type_idx.value:
            return regstr(reg)

        if isinstance(reg_type_def, Packed) and isinstance(target_type_def, Struct):
            target_ctype = ctype(code, target_type_idx.resolve(code), target_type_idx.value)
            return f"(*({target_ctype}*){regstr(reg)})"

        # Default cast
        target_ctype = ctype(code, target_type_idx.resolve(code), target_type_idx.value)
        return f"(({target_ctype}){regstr(reg)})"
    
    def compare_op(op_name: str, df: Dict[str, Any], function: Function, code: Bytecode, i: int) -> Tuple[bool, bool, str]:
        """
        Generates the C code for a comparison-based jump instruction.
        Replicates the logic of the `compare_op` function in the OCaml source.

        Returns:
            A tuple (has_dst, no_semi, C_code_string). For jumps, this is always (False, True, code).
        """
        try:
            comp_op_str = COMP_OP_MAP[op_name]
        except KeyError:
            raise NotImplementedError(f"Comparison operator for {op_name} not defined.")

        reg_a_idx, reg_b_idx = df['a'], df['b']
        reg_a, reg_b = regstr(reg_a_idx), regstr(reg_b_idx)
        label = f"Op_{df['offset'].value + i + 1}" # HL op offsets are relative to the *next* instruction

        regs = function.regs
        type_a_def = regs[reg_a_idx.value].resolve(code).definition
        type_b_def = regs[reg_b_idx.value].resolve(code).definition

        def phys_compare() -> str:
            """Generates a direct physical/pointer comparison in C."""
            target_type_idx = regs[reg_a_idx.value]
            casted_b = rcast(code, reg_b_idx, target_type_idx, function)
            return f"if ({reg_a} {comp_op_str} {casted_b}) goto {label};"

        # -- Primitive Types (Ints, Floats, Bools) --
        if isinstance(type_a_def, (U8, U16, I32, F32, F64, Bool, I64)) and \
        isinstance(type_b_def, (U8, U16, I32, F32, F64, Bool, I64)):
            return False, True, phys_compare()

        # -- Simple Pointer-based Types (Bytes, Arrays, Structs, etc.) --
        # These are compared by their memory address.
        if (isinstance(type_a_def, (Bytes, Array, Struct, Enum, DynObj, Abstract)) and type(type_a_def) == type(type_b_def)):
            return False, True, phys_compare()

        # -- HType --
        if isinstance(type_a_def, TypeType) and isinstance(type_b_def, TypeType):
            # hl_same_type returns 0 for equality.
            return False, True, f"if (hl_same_type({reg_a}, {reg_b}) {comp_op_str} 0) goto {label};"

        # -- HNull<T> --
        if isinstance(type_a_def, Null) and isinstance(type_b_def, Null):
            assert isinstance(type_a_def.type, tIndex)
            inner_type = type_a_def.type.resolve(code)
            field = dyn_value_field(inner_type)
            pcompare = f"({reg_a}->v.{field} {comp_op_str} {reg_b}->v.{field})"

            if op_name == "JEq":
                return False, True, f"if ({reg_a} == {reg_b} || ({reg_a} && {reg_b} && {pcompare})) goto {label};"
            if op_name == "JNotEq":
                return False, True, f"if ({reg_a} != {reg_b} && (!{reg_a} || !{reg_b} || {pcompare})) goto {label};"
            # For <, <=, >, >=, both must be non-null.
            return False, True, f"if ({reg_a} && {reg_b} && {pcompare}) goto {label};"

        # -- Dynamic or Function types --
        if isinstance(type_a_def, (Dyn, Fun)) or isinstance(type_b_def, (Dyn, Fun)):
            inv = "&& i != hl_invalid_comparison " if op_name in ("JSGt", "JSGte") else ""
            return False, True, f"{{ int i = hl_dyn_compare((vdynamic*){reg_a}, (vdynamic*){reg_b}); if (i {comp_op_str} 0 {inv}) goto {label}; }}"

        # -- HObj vs HObj --
        if isinstance(type_a_def, Obj) and isinstance(type_b_def, Obj):
            compare_fid = -1
            # Find the __compare function if it exists on the prototype of type A
            for proto in type_a_def.protos:
                if proto.name.resolve(code) == "__compare":
                    compare_fid = proto.findex.value
                    break

            if compare_fid == -1:
                return False, True, phys_compare()
            else:
                # Note: The OCaml code uses a global function table `funname fid`. We use `f${fid}`.
                compare_call = f"f${compare_fid}({reg_a}, (vdynamic*){reg_b})"
                if op_name == "JEq":
                    return False, True, f"if ({reg_a} == {reg_b} || ({reg_a} && {reg_b} && {compare_call} == 0)) goto {label};"
                if op_name == "JNotEq":
                    return False, True, f"if ({reg_a} != {reg_b} && (!{reg_a} || !{reg_b} || {compare_call} != 0)) goto {label};"
                return False, True, f"if ({reg_a} && {reg_b} && {compare_call} {comp_op_str} 0) goto {label};"

        # -- HVirtual vs HVirtual --
        if isinstance(type_a_def, Virtual) and isinstance(type_b_def, Virtual):
            if op_name == "JEq":
                return False, True, f"if ({reg_a} == {reg_b} || ({reg_a} && {reg_b} && {reg_a}->value && {reg_b}->value && {reg_a}->value == {reg_b}->value)) goto {label};"
            if op_name == "JNotEq":
                return False, True, f"if ({reg_a} != {reg_b} && (!{reg_a} || !{reg_b} || !{reg_a}->value || !{reg_b}->value || {reg_a}->value != {reg_b}->value)) goto {label};"
            # Other comparisons are not supported for Virtuals
            return False, True, f"/* JSLt/JSGt on Virtual not supported */"

        # -- HVirtual vs HObj --
        if isinstance(type_a_def, Virtual) and isinstance(type_b_def, Obj):
            if op_name == "JEq":
                return False, True, f"if ({reg_a} ? ({reg_b} && {reg_a}->value == (vdynamic*){reg_b}) : ({reg_b} == NULL)) goto {label};"
            if op_name == "JNotEq":
                return False, True, f"if ({reg_a} ? ({reg_b} == NULL || {reg_a}->value != (vdynamic*){reg_b}) : ({reg_b} != NULL)) goto {label};"
            return False, True, f"/* JSLt/JSGt on Virtual vs Obj not supported */"

        # -- HObj vs HVirtual (recursive call with swapped operands) --
        if isinstance(type_a_def, Obj) and isinstance(type_b_def, Virtual):
            swapped_op = SWAP_OP_MAP[op_name]
            swapped_df = df.copy()
            swapped_df['a'], swapped_df['b'] = df['b'], df['a']
            return compare_op(swapped_op, swapped_df, function, code, i)

        # Fallback for any unhandled combination
        return False, True, f"/* UNHANDLED COMPARISON: {type(type_a_def).__name__} vs {type(type_b_def).__name__} */\n{indent.current_indent}{phys_compare()}"

    def dyn_prefix(typ: Type) -> str:
        """
        Returns the one-char prefix for dynamic operations based on type.
        'i' for int-like, 'f' for f32, 'd' for f64, 'i64' for i64, 'p' for pointers.
        """
        kind = typ.kind.value
        if kind in {Type.Kind.U8.value, Type.Kind.U16.value, Type.Kind.I32.value, Type.Kind.BOOL.value}:
            return "i"
        if kind == Type.Kind.F32.value:
            return "f"
        if kind == Type.Kind.F64.value:
            return "d"
        if kind == Type.Kind.I64.value:
            return "i64"
        return "p"
    
          
    def enum_constr_type(code: Bytecode, e: Enum, cid: int) -> str:
        """
        Generates the C type name for a specific enum constructor struct.
        Example: my.pack.MyEnum constructor `MyValue(a:Int)` might become `my_pack_MyEnum_MyValue`.
        """
        constr = e.constructs[cid]
        if not constr.params:
            return "venum"

        enum_name_str = e.name.resolve(code)
        c_enum_name = sanitize_ident(enum_name_str.replace('.', '__'))
        
        constr_name_str = constr.name.resolve(code)
        c_constr_name = sanitize_ident(constr_name_str)

        if not enum_name_str:
            return f"Enum_{c_enum_name}"

        if not constr_name_str:
            return c_enum_name

        return f"{c_enum_name}_{c_constr_name}"

        
    for function in tqdm(code.functions):
        fun = function.type.resolve(code).definition
        assert isinstance(fun, Fun), (
            f"Expected function type to be Fun, got {type(fun).__name__}. This should never happen."
        )
        ret_t = ctype(code, fun.ret.resolve(code), fun.ret.value)
        args_t = [ctype(code, arg.resolve(code), arg.value) for arg in fun.args]
        args = [f"{t}" for t in args_t]
        args_str = ", ".join(args) if args else "void"
        line(f"{ret_t} f${function.findex.value}({args_str}); /* t${function.type.value} */")
    
    for function in tqdm(code.functions):
        fun = function.type.resolve(code).definition
        assert isinstance(fun, Fun), (
            f"Expected function type to be Fun, got {type(fun).__name__}. This should never happen."
        )
        ret_t = ctype(code, fun.ret.resolve(code), fun.ret.value)
        args_t = [ctype(code, arg.resolve(code), arg.value) for arg in fun.args]
        args = [f"{t} r{i}" for i, t in enumerate(args_t)]
        args_str = ", ".join(args) if args else "void"
        line(f"{ret_t} f${function.findex.value}({args_str}) {{")
        closure_id = 0
        trap_depth = 0
        max_trap_depth_seen = 0
        fn_start = len(res)
        with indent:
            for i, reg in enumerate(function.regs[len(args) :]):
                reg_idx = i + len(args)
                if reg.resolve(code).kind.value == Type.Kind.VOID.value:
                    line(f"// void r{reg_idx}")
                    continue  # void is for explicit discard
                reg_type = ctype(code, reg.resolve(code), reg.value)
                line(f"{reg_type} r{reg_idx}; ")

            for i, op in enumerate(function.ops):
                # oh god, here we go
                df = op.df
                rhs = ""
                has_dst = "dst" in df
                no_semi = False

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
                            raise MalformedBytecode(f"Unsupported SMod type: {rtype} at op {i} in function {function.findex}")
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
                                f"CallMethod/CallThis on Virtual type not implemented at op {i} in function {function.findex}"
                            )
                        else:
                            raise MalformedBytecode(f"CallMethod/CallThis on non-Obj/Struct type: {obj_t} at op {i} in function {function.findex}")
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
                        casted_args_str_list = [rcast(code, reg, target_type_idx, function) for reg, target_type_idx in zip(call_arg_regs, closure_arg_type_idxs)]
                        static_fun_ptr = cast_fun(code, f"{closure_reg_str}->fun", ret_type_idx, closure_arg_type_idxs)
                        static_call = f"{static_fun_ptr}({', '.join(casted_args_str_list)})"
                        dyn_type_idx = code.find_prim_type(Type.Kind.DYN)
                        instance_arg_types = [dyn_type_idx] + closure_arg_type_idxs
                        instance_fun_ptr = cast_fun(code, f"{closure_reg_str}->fun", ret_type_idx, instance_arg_types)
                        instance_call = f"{instance_fun_ptr}({', '.join([f'(vdynamic*){closure_reg_str}->value'] + casted_args_str_list)})"
                        rhs = f"({closure_reg_str}->hasValue ? {instance_call} : {static_call})"
                    case "StaticClosure":
                        rhs = f"&cl${closure_id}"
                        target_fun = df['fun'].resolve(code)
                        assert isinstance(target_fun, (Function, Native))
                        typ = target_fun.type.resolve(code)
                        assert isinstance(typ.definition, Fun), (
                            f"Expected function type to be Fun, got {type(typ.definition).__name__}. This should never happen."
                        )
                        res.insert(
                            fn_start,
                            f"    static vclosure cl${closure_id} = {{ &t${target_fun.type}, f${target_fun.findex}, 0 }};"
                        )
                        closure_id += 1
                    case "InstanceClosure":
                        target_fun = df['fun'].resolve(code)
                        assert isinstance(target_fun, (Function, Native))
                        typ = target_fun.type.resolve(code)
                        assert isinstance(typ.definition, Fun), (
                            f"Expected function type to be Fun, got {type(typ.definition).__name__}. This should never happen."
                        )
                        rhs = f"hl_alloc_closure_ptr(&t${target_fun.type.value}, f${target_fun.findex.value}, r{df['obj']})"
                    case "VirtualClosure":
                        obj_t = function.regs[df['obj'].value].resolve(code)
                        assert isinstance(obj_t, Type)
                        obj = obj_t.definition
                        assert isinstance(obj, (Obj, Struct)), (
                            f"VirtualClosure on non-Obj/Struct type: {obj} at op {i} in function {function.findex}"
                        )
                        fid = df["field"].value
                        func_ptr = f"r{df['obj']}->$type->vobj_proto[{fid}]"
                        fun_t = obj.virtuals[fid]
                        rhs = f"hl_alloc_closure_ptr(&t${fun_t}, {func_ptr}, r{df['obj']})"
                    case "GetGlobal":
                        dst_reg = df["dst"].value
                        dst = ctype(code, function.regs[dst_reg].resolve(code), function.regs[dst_reg])
                        rhs = f"({dst})g${df['global'].value}"
                    case "SetGlobal":
                        src_reg = df["src"].value
                        has_dst = False
                        rhs = f"g${df['global'].value} = r{src_reg}"
                    case "Ret":
                        has_dst = False
                        if fun.ret.resolve(code).kind.value == Type.Kind.VOID.value:
                            rhs = "return /* void */"
                        else:
                            dst_reg = df["ret"].value
                            rhs = f"return r{dst_reg}"
                    case "JTrue":
                        has_dst, no_semi = False, True
                        rhs = f"if (r{df['cond']}) goto Op_{df['offset'].value + i};"
                    case "JFalse":
                        has_dst, no_semi = False, True
                        rhs = f"if (!r{df['cond']}) goto Op_{df['offset'].value + i};"
                    case "JNull":
                        has_dst, no_semi = False, True
                        rhs = f"if (!r{df['reg']}) goto Op_{df['offset'].value + i};"
                    case "JNotNull":
                        has_dst, no_semi = False, True
                        rhs = f"if (r{df['reg']}) goto Op_{df['offset'].value + i};"
                    case "JSLt" | "JSGte" | "JSGt" | "JSLte" | "JEq" | "JNotEq":
                        has_dst, no_semi, rhs = compare_op(op.op, df, function, code, i)
                    case "JULt":
                        has_dst, no_semi = False, True
                        rhs = f"if( ((unsigned)r{df['a']}) < ((unsigned)r{df['b']}) ) goto Op_{df['offset'].value + i};"
                    case "JUGte":
                        has_dst, no_semi = False, True
                        rhs = f"if( ((unsigned)r{df['a']}) >= ((unsigned)r{df['b']}) ) goto Op_{df['offset'].value + i};"
                    case "JAlways":
                        has_dst, no_semi = False, True
                        rhs = f"goto Op_{df['offset'].value + i};"
                    case "Label" | "Nop":
                        has_dst = False
                        rhs = "dummycall_label();"
                    case "ToDyn":
                        if function.regs[df["src"].value].resolve(code).kind.value == Type.Kind.BOOL.value:
                            rhs = f"hl_alloc_dynbool(r{df['src']})"
                        else:
                            has_dst, no_semi = False, True
                            typ = function.regs[df["src"].value].resolve(code)
                            rhs = f"r{df['dst']} = hl_alloc_dynamic(&t${function.regs[df["src"].value]}); "
                            match typ.kind.value:
                                case Type.Kind.U8.value | Type.Kind.U16.value | Type.Kind.I32.value | Type.Kind.BOOL.value:
                                    rhs += f"r{df['dst']}->v.i = r{df['src']};"
                                case Type.Kind.I64.value:
                                    rhs += f"r{df['dst']}->v.i64 = r{df['src']};"
                                case Type.Kind.F32.value:
                                    rhs += f"r{df['dst']}->v.f = r{df['src']};"
                                case Type.Kind.F64.value:
                                    rhs += f"r{df['dst']}->v.d = r{df['src']};"
                                case _:
                                    rhs += f"r{df['dst']}->v.ptr = r{df['src']};"
                            if is_ptr(typ.kind.value):
                                rhs = f"if( r{df['src']} == NULL ) r{df['dst']} = NULL; else {{{rhs}}}"
                    case "ToSFloat":
                        has_dst = False
                        typ = function.regs[df["dst"].value].resolve(code)
                        rhs = f"r{df['dst']} = ({ctype(code, typ, function.regs[df["dst"].value].value)})r{df['src']}"
                    case "ToUFloat":
                        has_dst = False
                        typ = function.regs[df["dst"].value].resolve(code)
                        rhs = f"r{df['dst']} = ({ctype(code, typ, function.regs[df["dst"].value].value)})(unsigned)r{df['src']}"
                    case "ToInt":
                        rhs = f"(int)r{df['src']}"
                    case "New":
                        dst_reg = df["dst"].value
                        dst_t = function.regs[dst_reg]
                        dst_type = dst_t.resolve(code)
                        match dst_type.kind.value:
                            case Type.Kind.OBJ.value | Type.Kind.STRUCT.value:
                                tname = ctype(code, dst_type, dst_t.value)
                                rhs = f"({tname})hl_alloc_obj(&t${dst_t.value})"
                            case Type.Kind.DYNOBJ.value:
                                rhs = "hl_alloc_dynobj()"
                            case Type.Kind.VIRTUAL.value:
                                rhs = f"hl_alloc_virtual(&t${dst_t.value})"
                    case "Field" | "GetThis":
                        if op.op == "Field":
                            obj_reg = df["obj"].value
                        else:
                            obj_reg = 0
                        obj_tres = function.regs[obj_reg].resolve(code)
                        assert isinstance(obj_tres, Type), (
                            f"Expected obj type to be Type, got {type(obj_tres).__name__}. This should never happen."
                        )
                        field_idx: int = df["field"].value
                        match obj_tres.kind.value:
                            case Type.Kind.OBJ.value | Type.Kind.STRUCT.value:
                                dfn = obj_tres.definition
                                assert isinstance(dfn, (Obj, Struct)), (
                                    f"Expected obj type definition to be Obj or Struct, got {type(dfn).__name__}. This should never happen."
                                )
                                field_name = dfn.resolve_fields(code)[field_idx].name.resolve(code)
                                rhs = f"r{obj_reg}->{sanitize_ident(field_name)}"
                            case Type.Kind.VIRTUAL.value:
                                dfn = obj_tres.definition
                                assert isinstance(dfn, Virtual), "This check should pass."
                                field_info = dfn.fields[field_idx]
                                field_name = field_info.name.resolve(code)
                                field_hash = hl_hash_utf8(field_name)
                                field_type_idx = field_info.type
                                field_type = field_type_idx.resolve(code)
                                field_ctype = ctype(code, field_type, field_type_idx.value)
                                
                                prefix = dyn_prefix(field_type)
                                type_arg = ""
                                if field_type.kind.value not in {Type.Kind.F32.value, Type.Kind.F64.value, Type.Kind.I64.value}:
                                    type_arg = f", &t${field_type_idx.value}"
                                
                                dyn_get_call = f"(({field_ctype})hl_dyn_get{prefix}(r{obj_reg}->value, {field_hash}/*{field_name}*/{type_arg}))"
                                
                                direct_access = f"(*(({field_ctype}*)hl_vfields({obj_reg})[{field_idx}]))"
                                
                                rhs = f"(hl_vfields({obj_reg})[{field_idx}] ? {direct_access} : {dyn_get_call})"
                    case "SetField" | "SetThis":
                        if op.op == "SetField":
                            obj_reg_idx = df["obj"].value
                            val_reg_idx = df["src"].value
                        else:
                            obj_reg_idx = 0
                            val_reg_idx = df["src"].value
                        
                        obj_regs = f"r{obj_reg_idx}"
                        val_regs = f"r{val_reg_idx}"
                        obj_tres = function.regs[obj_reg_idx].resolve(code)
                        field_idx = df["field"].value
                        has_dst = False
                        
                        assert obj_tres is not None
                        match obj_tres.kind.value:
                            case Type.Kind.OBJ.value | Type.Kind.STRUCT.value:
                                dfn = obj_tres.definition
                                assert isinstance(dfn, (Obj, Struct)), "This check should pass."
                                
                                field = dfn.resolve_fields(code)[field_idx]
                                field_name = sanitize_ident(field.name.resolve(code))
                                field_type_idx = field.type
                                val_cast = rcast(code, Reg(val_reg_idx), field_type_idx, function)
                                
                                rhs = f"{obj_regs}->{field_name} = {val_cast}"

                            case Type.Kind.VIRTUAL.value:
                                dfn = obj_tres.definition
                                assert isinstance(dfn, Virtual), "This check should pass."
                                
                                field_info = dfn.fields[field_idx]
                                field_name = field_info.name.resolve(code)
                                field_hash = hl_hash_utf8(field_name)
                                field_type_idx = field_info.type
                                field_type = field_type_idx.resolve(code)
                                field_ctype = ctype(code, field_type, field_type_idx.value)

                                value_type = function.regs[val_reg_idx].resolve(code)

                                prefix = dyn_prefix(value_type)
                                type_arg = ""
                                if value_type.kind.value not in {Type.Kind.F32.value, Type.Kind.F64.value, Type.Kind.I64.value}:
                                    type_arg = f", &t${function.regs[val_reg_idx].value}"

                                dyn_set_call = f"hl_dyn_set{prefix}({obj_regs}->value, {field_hash}/*{field_name}*/{type_arg}, {val_regs})"
                                val_cast = f"({field_ctype}){val_regs}"
                                direct_set = f"*({field_ctype}*)(hl_vfields({obj_regs})[{field_idx}]) = {val_cast}"
                                rhs = f"if (hl_vfields({obj_regs})[{field_idx}]) {direct_set}; else {dyn_set_call}"
                            case _:
                                unknown_ops.add(f"SetField on {obj_tres.kind}")
                                continue
                    case "Throw" | "Rethrow":
                        # Opcodes: Throw: {"exc": Reg}, Rethrow: {"exc": Reg}
                        rhs = f"hl_{op.op.lower()}((vdynamic*)r{df['exc'].value})"
                        has_dst = False
                    case "GetUI8" | "GetI8":
                        # Opcode: GetI8: {"dst": Reg, "bytes": Reg, "index": Reg}
                        rhs = f"*(unsigned char*)(r{df['bytes'].value} + r{df['index'].value})"
                    case "GetUI16" | "GetI16":
                        # Opcode: GetI16: {"dst": Reg, "bytes": Reg, "index": Reg}
                        rhs = f"*(unsigned short*)(r{df['bytes'].value} + r{df['index'].value})"
                    case "GetMem":
                        # Opcode: GetMem: {"dst": Reg, "bytes": Reg, "index": Reg}
                        dst_type_idx = function.regs[df['dst'].value]
                        dst_ctype = ctype(code, dst_type_idx.resolve(code), dst_type_idx.value)
                        rhs = f"*({dst_ctype}*)(r{df['bytes'].value} + r{df['index'].value})"
                    case "GetArray":
                        # Opcode: GetArray: {"dst": Reg, "array": Reg, "index": Reg}
                        arr_type = function.regs[df['array'].value].resolve(code)
                        dst_type_idx = function.regs[df['dst'].value]
                        dst_ctype = ctype(code, dst_type_idx.resolve(code), dst_type_idx.value)

                        if isinstance(arr_type.definition, Abstract): # Raw pointer array (e.g. haxe.io.Bytes)
                            rhs = f"(({dst_ctype}*)r{df['array'].value})[r{df['index'].value}]"
                        else: # Standard `varray` with a header
                            rhs = f"(({dst_ctype}*)(r{df['array'].value} + 1))[r{df['index'].value}]"
                    case "SetUI8" | "SetI8":
                        # Opcode: SetI8: {"bytes": Reg, "index": Reg, "src": Reg}
                        rhs = f"*(unsigned char*)(r{df['bytes'].value} + r{df['index'].value}) = (unsigned char)r{df['src'].value}"
                        has_dst = False
                    case "SetUI16" | "SetI16":
                        # Opcode: SetI16: {"bytes": Reg, "index": Reg, "src": Reg}
                        rhs = f"*(unsigned short*)(r{df['bytes'].value} + r{df['index'].value}) = (unsigned short)r{df['src'].value}"
                        has_dst = False
                    case "SetMem":
                        # Opcode: SetMem: {"bytes": Reg, "index": Reg, "src": Reg}
                        val_type_idx = function.regs[df['src'].value]
                        val_ctype = ctype(code, val_type_idx.resolve(code), val_type_idx.value)
                        rhs = f"*({val_ctype}*)(r{df['bytes'].value} + r{df['index'].value}) = r{df['src'].value}"
                        has_dst = False
                    case "SetArray":
                        # Opcode: SetArray: {"array": Reg, "index": Reg, "src": Reg}
                        arr_type = function.regs[df['array'].value].resolve(code)
                        val_type_idx = function.regs[df['src'].value]
                        val_ctype = ctype(code, val_type_idx.resolve(code), val_type_idx.value)
                        
                        if isinstance(arr_type.definition, Abstract):
                            rhs = f"(({val_ctype}*)r{df['array'].value})[r{df['index'].value}] = r{df['src'].value}"
                        else:
                            rhs = f"(({val_ctype}*)(r{df['array'].value} + 1))[r{df['index'].value}] = r{df['src'].value}"
                        has_dst = False
                    case "SafeCast":
                        # Opcode: SafeCast: {"dst": Reg, "src": Reg}
                        src_reg, dst_reg = df["src"].value, df["dst"].value
                        src_type = function.regs[src_reg].resolve(code)
                        dst_type_idx = function.regs[dst_reg]
                        dst_type = dst_type_idx.resolve(code)
                        dst_ctype = ctype(code, dst_type, dst_type_idx.value)

                        if isinstance(src_type.definition, Null):
                            assert isinstance(src_type.definition.type, tIndex)
                            rhs = f"r{src_reg} ? r{src_reg}->v.{dyn_value_field(src_type.definition.type.resolve(code))} : 0"
                        else:
                            prefix = dyn_prefix(dst_type)
                            type_arg = ""
                            if dst_type.kind.value not in {Type.Kind.F32.value, Type.Kind.F64.value, Type.Kind.I64.value}:
                                type_arg = f", &t${dst_type_idx.value}"
                            
                            src_type_idx = function.regs[src_reg].value
                            rhs = f"({dst_ctype})hl_dyn_cast{prefix}((vdynamic*)r{src_reg}, &t${src_type_idx}{type_arg})"
                    case "UnsafeCast":
                        # Opcode: {"dst": Reg, "src": Reg}
                        # OCaml: sexpr "%s = (%s)%s" (reg r) (ctype (rtype r)) (reg v)
                        dst_type_idx = function.regs[df['dst'].value]
                        dst_ctype = ctype(code, dst_type_idx.resolve(code), dst_type_idx.value)
                        rhs = f"({dst_ctype})r{df['src'].value}"
                    case "ToVirtual":
                        # Opcode: {"dst": Reg, "src": "Reg"}
                        # OCaml: sexpr "%s = hl_to_virtual(%s,(vdynamic*)%s)" (reg r) (type_value ctx (rtype r)) (reg v)
                        dst_type_idx = function.regs[df['dst'].value]
                        rhs = f"hl_to_virtual(&t${dst_type_idx.value}, (vdynamic*)r{df['src'].value})"
                    case "ArraySize":
                        # Opcode: {"dst": Reg, "array": Reg}
                        # OCaml: sexpr "%s = %s->size" (reg r) (reg a)
                        rhs = f"r{df['array'].value}->size"
                    case "Type":
                        # Opcode: {"dst": Reg, "ty": RefType}
                        # OCaml: sexpr "%s = %s" (reg r) (type_value ctx t)
                        rhs = f"&t${df['ty'].value}"
                    case "GetType":
                        # Opcode: {"dst": Reg, "src": Reg}
                        # OCaml: sexpr "%s = %s ? ((vdynamic*)%s)->t : &hlt_void" (reg r) (reg v) (reg v)
                        rhs = f"r{df['src'].value} ? ((vdynamic*)r{df['src'].value})->t : &hlt_void"
                    case "GetTID":
                        # Opcode: {"dst": Reg, "src": Reg}
                        # OCaml: sexpr "%s = %s->kind" (reg r) (reg v)
                        rhs = f"r{df['src'].value}->kind"
                    case "DynGet":
                        # Opcode: {"dst": Reg, "obj": Reg, "field": RefString}
                        # OCaml: sexpr "%s = (%s)hl_dyn_get%s((vdynamic*)%s,%ld/*%s*/%s)" (reg r) (ctype t) (dyn_prefix t) (reg o) h code.strings.(sid) (type_value_opt t)
                        dst_type_idx = function.regs[df['dst'].value]
                        dst_type = dst_type_idx.resolve(code)
                        dst_ctype = ctype(code, dst_type, dst_type_idx.value)
                        
                        field_name = df['field'].resolve(code)
                        field_hash = hl_hash_utf8(field_name)
                        prefix = dyn_prefix(dst_type)
                        
                        type_arg = ""
                        if dst_type.kind.value not in {Type.Kind.F32.value, Type.Kind.F64.value, Type.Kind.I64.value}:
                            type_arg = f", &t${dst_type_idx.value}"
                        
                        rhs = f"({dst_ctype})hl_dyn_get{prefix}((vdynamic*)r{df['obj'].value}, {field_hash}/*{field_name}*/{type_arg})"
                    case "DynSet":
                        # Opcode: {"obj": Reg, "field": RefString, "src": Reg}
                        # OCaml: sexpr "hl_dyn_set%s((vdynamic*)%s,%ld/*%s*/%s,%s)" (dyn_prefix (rtype v)) (reg o) h code.strings.(sid) (type_value_opt (rtype v)) (reg v)
                        has_dst = False
                        src_reg = df['src'].value
                        src_type_idx = function.regs[src_reg]
                        src_type = src_type_idx.resolve(code)
                        
                        field_name = df['field'].resolve(code)
                        field_hash = hl_hash_utf8(field_name)
                        prefix = dyn_prefix(src_type)

                        type_arg = ""
                        if src_type.kind.value not in {Type.Kind.F32.value, Type.Kind.F64.value, Type.Kind.I64.value}:
                            type_arg = f", &t${src_type_idx.value}"
                        
                        rhs = f"hl_dyn_set{prefix}((vdynamic*)r{df['obj'].value}, {field_hash}/*{field_name}*/{type_arg}, r{src_reg})"
                    case "MakeEnum":
                        has_dst, no_semi = False, True

                        dst_reg_idx = df['dst'].value
                        cid = df['construct'].value
                        arg_regs = df['args'].value
                        param_reg_indices = [r.value for r in arg_regs]
                        need_tmp = dst_reg_idx in param_reg_indices

                        enum_def = function.regs[dst_reg_idx].resolve(code).definition
                        assert isinstance(enum_def, Enum)
                        
                        line(f"Op_{i}:")

                        with indent:
                            if need_tmp:
                                line("{")
                                with indent:
                                    line("venum *tmp;")
                                    target_var = "tmp"
                                    
                                    dst_type_tindex = function.regs[dst_reg_idx].value
                                    line(f"{target_var} = hl_alloc_enum(&t{dst_type_tindex}, {cid});")
                                    
                                    constr_ctype = enum_constr_type(code, enum_def, cid)
                                    param_types = enum_def.constructs[cid].params
                                    for idx, param_reg in enumerate(arg_regs):
                                        param_type_idx = param_types[idx]
                                        val_cast = rcast(code, param_reg, param_type_idx, function)
                                        line(f"(({constr_ctype}*){target_var})->p{idx} = {val_cast};")
                                    
                                    line(f"r{dst_reg_idx} = {target_var};")
                                line("}")
                            else:
                                target_var = f"r{dst_reg_idx}"
                                dst_type_tindex = function.regs[dst_reg_idx].value
                                line(f"{target_var} = hl_alloc_enum(&t{dst_type_tindex}, {cid});")
                                
                                constr_ctype = enum_constr_type(code, enum_def, cid)
                                param_types = enum_def.constructs[cid].params
                                for idx, param_reg in enumerate(arg_regs):
                                    param_type_idx = param_types[idx]
                                    val_cast = rcast(code, param_reg, param_type_idx, function)
                                    line(f"(({constr_ctype}*){target_var})->p{idx} = {val_cast};")
                        continue
                    case "EnumAlloc":
                        # Opcode: {"dst": Reg, "construct": RefEnumConstruct}
                        # OCaml: sexpr "%s = hl_alloc_enum(%s,%d)" (reg r) (type_value ctx (rtype r)) cid
                        dst_type_idx = function.regs[df['dst'].value]
                        cid = df['construct'].value
                        rhs = f"hl_alloc_enum(&t{dst_type_idx.value}, {cid})"
                    case "EnumIndex":
                        # Opcode: {"dst": Reg, "value": Reg}
                        # OCaml: sexpr "%s = HL__ENUM_INDEX__(%s)" (reg r) (reg v)
                        rhs = f"HL__ENUM_INDEX__(r{df['value'].value})"
                    case "EnumField":
                        # Opcode: {"dst": Reg, "value": Reg, "construct": RefEnumConstruct, "field": RefField}
                        # OCaml: sexpr "%s((%s*)%s)->p%d" (rassign r tl.(pid)) tname (reg e) pid
                        dst_reg_idx = df['dst'].value
                        enum_reg_idx = df['value'].value
                        cid = df['construct'].value
                        pid = df['field'].value
                        enum_type = function.regs[enum_reg_idx].resolve(code)
                        enum_def = enum_type.definition
                        assert isinstance(enum_def, Enum), "EnumField source must be an Enum type."
                        constr_ctype = enum_constr_type(code, enum_def, cid)
                        param_types = enum_def.constructs[cid].params
                        field_type_idx = param_types[pid]
                        
                        rhs = f"(({constr_ctype}*)r{enum_reg_idx})->p{pid}"
                        dst_type = function.regs[dst_reg_idx]
                        if field_type_idx.value != dst_type.value:
                           rhs = f"({ctype(code, dst_type.resolve(code), dst_type.value)})({rhs})"
                    case "SetEnumField":
                        # Opcode: {"value": Reg, "field": RefField, "src": Reg}
                        # OCaml: sexpr "((%s*)%s)->p%d = (%s)%s" tname (reg e) pid (ctype tl.(pid)) (reg r)
                        has_dst = False
                        enum_reg_idx = df['value'].value
                        pid = df['field'].value
                        src_reg_idx = df['src'].value

                        enum_type = function.regs[enum_reg_idx].resolve(code)
                        enum_def = enum_type.definition
                        assert isinstance(enum_def, Enum), "SetEnumField target must be an Enum type."
                        cid_for_type = -1
                        for i, constr in enumerate(enum_def.constructs):
                            if constr.params:
                                cid_for_type = i
                                break
                        if cid_for_type == -1:
                           raise MalformedBytecode(f"SetEnumField used on an enum with no parameters at op {i}")
                        
                        constr_ctype = enum_constr_type(code, enum_def, cid_for_type)
                        field_type_idx = enum_def.constructs[cid_for_type].params[pid]
                        
                        val_cast = rcast(code, Reg(src_reg_idx), field_type_idx, function)
                        rhs = f"(({constr_ctype}*)r{enum_reg_idx})->p{pid} = {val_cast}"
                    case "Switch":
                        has_dst, no_semi = False, True

                        reg_to_switch = df['reg'].value
                        offsets = df['offsets'].value
                        end_offset = df['end'].value
                        line(f"Op_{i}:")
                        with indent:
                            for case_idx, offset_varint in enumerate(offsets):
                                target_op_idx = i + 1 + offset_varint.value
                                line(f"if (r{reg_to_switch} == {case_idx}) goto Op_{target_op_idx};")
                            
                            default_target_op_idx = i + 1
                            line(f"goto Op_{default_target_op_idx}; // default")
                        continue
                    case "NullCheck":
                        has_dst = False
                        rhs = f"if( r{df['reg']} == NULL ) hl_null_access()"
                    case "Trap":
                        exc_reg = df["exc"].value
                        offset = df["offset"].value
                        target_label = f"Op_{i + 1 + offset}"
                        if trap_depth >= max_trap_depth_seen:
                            res.insert(fn_start, f"    hl_trap_ctx trap${trap_depth};")
                            max_trap_depth_seen += 1

                        rhs = f"hl_trap(&trap${trap_depth}, r{exc_reg}, {target_label})"
                        trap_depth += 1
                        has_dst = False
                    case "EndTrap":
                        rhs = f"hl_endtrap(&trap${(trap_depth := trap_depth - 1)})"
                        has_dst = False
                    case "Assert":
                        has_dst = False
                        rhs = "hl_assert()"
                    case "Ref":
                        rhs = f"&r{df['src']}"
                    case "Unref":
                        rhs = f"*r{df['src']}"
                    case "Setref":
                        has_dst = False
                        rhs = r"*r{df['dst']} = r{df['value']}"
                    case "RefData":
                        dst_reg = df['dst'].value
                        src_reg = df['src'].value
                        src_type = function.regs[src_reg.value].resolve(code)

                        if isinstance(src_type.definition, Array):
                            dst_type_idx = function.regs[dst_reg.value]
                            dst_ctype = ctype(code, dst_type_idx.resolve(code), dst_type_idx.value)
                            rhs = f"({dst_ctype})hl_aptr({regstr(src_reg)}, void*)"
                        else:
                            raise MalformedBytecode(f"RefData at op {i} in function {function.findex} expects an Array type in source register, but got {src_type.definition.__class__.__name__}")
                    case "RefOffset":
                        # Opcode: {"dst": "Reg", "reg": "Reg", "offset": "Reg"}
                        rhs = f"r{df['reg'].value} + r{df['offset'].value}"
                    case "Prefetch":
                        has_dst = False

                        obj_reg = df['value']
                        field_id = df['field'].value
                        mode = df['mode'].value

                        if not (0 <= mode <= 3):
                            raise MalformedBytecode(f"Invalid prefetch mode {mode} at op {i} in function {function.findex}")
                        
                        prefetch_expr = ""
                        if field_id == 0:
                            prefetch_expr = regstr(obj_reg)
                        else:
                            obj_type = function.regs[obj_reg.value].resolve(code)
                            obj_def = obj_type.definition

                            if isinstance(obj_def, (Obj, Struct)):
                                field_index = field_id - 1
                                try:
                                    resolved_fields = obj_def.resolve_fields(code)
                                    field = resolved_fields[field_index]
                                    field_c_name = sanitize_ident(field.name.resolve(code))
                                    prefetch_expr = f"&{regstr(obj_reg)}->{field_c_name}"
                                except IndexError:
                                    raise MalformedBytecode(f"Prefetch field index {field_id} is out of bounds for object {obj_def.name.resolve(code)} at op {i}")
                            else:
                                raise MalformedBytecode(f"Prefetch with non-zero field_id used on a non-object type ({obj_type.definition.__class__.__name__}) at op {i}")

                        rhs = f"__hl_prefetch_m{mode}({prefetch_expr})"
                    case "Asm":
                        raise MalformedBytecode("Asm is not supported by either the official HL/C compiler or crashlink. This is done intentionally for feature parity.")
                    case _:
                        unknown_ops.add(op.op if op.op else "unknown?????")
                        continue

                if has_dst:
                    dst_type = function.regs[df["dst"].value].resolve(code)
                    if dst_type.kind.value == Type.Kind.VOID.value:
                        opline(i, f"{rhs}; // void dst")
                    else:
                        opline(i, f"r{df['dst']} = {rhs};")
                elif no_semi:
                    opline(i, f"{rhs}")  # no semicolon for some ops
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
    line("// Compile with `-Wno-incompatible-pointer-types`!")
    line("#include <hlc.h>")

    sec("Natives & Abstracts Forward Declarations")
    res += generate_natives(code)

    sec("Structs")
    res += generate_structs(code)

    sec("Types")
    res += generate_types(code)

    sec("Globals & Strings")
    res += generate_globals(code)
    
    sec("Dummy label call")
    line("void dummycall_label() { /* dummy */ }")

    sec("Functions! Whoa!")
    res += generate_functions(code)

    sec("Entrypoint")
    res += generate_entry(code)
    
    if unknown_ops:
        print(f"Warning: {len(unknown_ops)} unknown operations encountered during function generation.")
        print(unknown_ops)

    return "\n".join(res)
