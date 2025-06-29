# type: ignore
# TODO: not typed yet because i suck at this
from __future__ import annotations

from typing import List, Optional, Dict, Tuple

from .core import *


def hl_hash_utf8(name: str) -> int:
    """Hash UTF-8 string until null terminator"""
    h = 0
    for char in name:
        char_val = ord(char)
        if char_val == 0:  # Stop at null terminator
            break
        h = 223 * h + char_val
        if h > 2147483647:  # 0x7FFFFFFF
            h = ((h + 2147483648) % 4294967296) - 2147483648
        elif h < -2147483648:  # -0x80000000
            h = ((h + 2147483648) % 4294967296) - 2147483648

    if h < 0:
        h = -((-h) % 0x1FFFFF7B)
        if h == 0:
            h = 0
    else:
        h = h % 0x1FFFFF7B

    return h


def hl_hash(name: bytes) -> int:
    """General hash function - processes until null terminator"""
    h = 0

    for byte_val in name:
        if byte_val == 0:  # Stop at null terminator
            break
        h = 223 * h + byte_val
        if h > 2147483647:  # 0x7FFFFFFF
            h = ((h + 2147483648) % 4294967296) - 2147483648
        elif h < -2147483648:  # -0x80000000
            h = ((h + 2147483648) % 4294967296) - 2147483648

    if h < 0:
        h = -((-h) % 0x1FFFFF7B)
        if h == 0:
            h = 0
    else:
        h = h % 0x1FFFFF7B

    return h


def hash_string(s: str) -> int:
    """Hash a string by encoding it as UTF-8 bytes"""
    return hl_hash(s.encode("utf-8"))


def _tname(haxe_name: str) -> str:
    """
    Sanitizes a Haxe type name (e.g., `my.pack.MyClass`) into a C-compatible
    identifier (e.g., `my__pack__MyClass`), mirroring hlc's `tname` function.
    """
    # String.concat "__" (ExtString.String.nsplit str ".")
    return haxe_name.replace(".", "__")


def _ctype_no_ptr(code: Bytecode, typ: Type) -> Tuple[str, int]:
    """
    Internal helper to get the base C type name and pointer level for a given crashlink.Type.
    Mirrors the logic of the OCaml `ctype_no_ptr` function.

    Returns:
        A tuple of (base_c_name: str, pointer_level: int).
    """
    defn = typ.definition
    if defn is None:
        raise ValueError(f"Type t@{typ.kind.value} has no definition, cannot determine C type.")

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
        haxe_name = defn.name.resolve(code)
        return _tname(haxe_name), 0

    if isinstance(defn, Abstract):
        c_name = defn.name.resolve(code)
        return c_name, 1

    if isinstance(defn, Ref):
        inner_type = defn.type.resolve(code)
        base_name, ptr_level = _ctype_no_ptr(code, inner_type)
        return base_name, ptr_level + 1

    if isinstance(defn, Packed):
        inner_type = defn.inner.resolve(code)
        base_name, ptr_level = _ctype_no_ptr(code, inner_type)
        return f"struct _{base_name}", ptr_level

    raise NotImplementedError(f"C type conversion not implemented for type definition: {type(defn).__name__}")


def ctype(code: Bytecode, typ: Type) -> str:
    """
    Converts a crashlink.Type object into a C type string representation,
    including pointers.

    For example:
    - A `Type` for I32 becomes "int".
    - A `Type` for a reference to I32 becomes "int*".
    - A `Type` for a Haxe class `my.MyClass` becomes "my__MyClass".
    """
    base_name, ptr_level = _ctype_no_ptr(code, typ)
    if ptr_level == 0:
        return base_name
    return base_name + ("*" * ptr_level)


def ctype_no_ptr(code: Bytecode, typ: Type) -> str:
    """
    Converts a crashlink.Type object into a C type string representation,
    excluding pointers.

    For example:
    - A `Type` for I32 becomes "int".
    - A `Type` for a reference to I32 becomes "int".
    - A `Type` for a Haxe class `my.MyClass` becomes "my__MyClass".
    """
    base_name, _ = _ctype_no_ptr(code, typ)
    return base_name


class Indenter:
    """
    A context manager for dynamically handling indentation levels.
    """

    def __init__(self, indent_char: str = "    "):
        """
        Initializes the indenter.

        Args:
            indent_char: The string to use for a single level of indentation.
        """
        self.indent_char = indent_char
        self.level = 0
        self.current_indent = ""

    def __enter__(self):
        """Called when entering a 'with' block. Increases indentation."""
        self.level += 1
        self.current_indent = self.indent_char * self.level
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Called when exiting a 'with' block. Decreases indentation."""
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


def generate_types(code: Bytecode) -> List[str]:
    res = []
    indent = Indenter()

    def line(*args):
        res.append(indent.current_indent + " ".join(str(arg) for arg in args))

    types = code.gather_types()

    line("// Shells")
    for i, typ in enumerate(types):
        line(f"hl_type t${i} = {{ {KIND_SHELLS[typ.kind.value]} }};")

    line("\n// Data")
    for i, typ in enumerate(types):
        df = typ.definition
        if df is None:
            raise ValueError(f"Type t@{typ.kind.value} has no definition, cannot generate C code.")
        if isinstance(df, Obj) or isinstance(df, Struct):
            if df.fields:
                vals = ", ".join(f"t${code.get_type_index(f.type)}" for f in df.fields)
                line(f"hl_obj_field fieldst${i}[] = {{{vals}}};")

    return res


def code_to_c(code: Bytecode) -> str:
    res = []
    indent = Indenter()

    def line(*args):
        res.append(indent.current_indent + " ".join(str(arg) for arg in args))

    sec = lambda section: res.append(f"\n/*---------- {section} ----------*/\n")

    line("// Generated by crashlink")
    line("#include <hlc.h>")

    sec("Types")
    res += generate_types(code)

    # TODO: res += generate_init_hashes(code)

    return "\n".join(res)
