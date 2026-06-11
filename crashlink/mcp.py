"""
MCP server for crashlink - exposes HashLink bytecode analysis tools via the Model Context Protocol.

Run as an stdio MCP server with: crashlink mcp [file]
"""

from __future__ import annotations

import io
import sys
from contextlib import redirect_stdout
from typing import Optional

from mcp.server.fastmcp import FastMCP

from . import decomp as _decomp
from . import disasm as _disasm
from .core import Bytecode, Function, Native, Obj, Enum, Fun, Virtual
from .hlc import code_to_c
from .opcodes import opcode_docs, opcodes
from .pseudo import pseudo

MAX_OUTPUT_CHARS = 8000
_TRUNCATION_NOTE = "\n\n[Output truncated to {kept} of {total} chars. Use pagination or a more specific query.]"

_code: Optional[Bytecode] = None

mcp = FastMCP(
    "crashlink",
    instructions=(
        "crashlink is a HashLink bytecode disassembler, decompiler, and analysis toolkit.\n"
        "Call load_bytecode first to load a .hl/.dat file before using other tools.\n"
        "\n"
        "Module maturity:\n"
        "  - disasm (disassemble_function, list_functions, get_type, etc.): STABLE\n"
        "  - decomp / pseudo (decompile_function, decompile_class, get_ir): EXPERIMENTAL — may crash or produce wrong output for complex functions\n"
        "  - hlc (to_hlc): VERY EXPERIMENTAL — generated C is not standard portable C and will likely not compile without extensive patching\n"
    ),
)


def _trim(text: str, max_chars: int = MAX_OUTPUT_CHARS) -> str:
    if len(text) <= max_chars:
        return text
    note = _TRUNCATION_NOTE.format(kept=max_chars, total=len(text))
    return text[:max_chars] + note


def _require_code() -> Bytecode:
    if _code is None:
        raise RuntimeError("No bytecode loaded. Call load_bytecode first.")
    return _code


@mcp.tool()
def load_bytecode(path: str, no_constants: bool = False) -> str:
    """
    Load a HashLink bytecode file (.hl or .dat) from disk.
    This must be called before any other analysis tool.
    Returns a summary of what was loaded.
    """
    global _code
    try:
        with open(path, "rb") as f:
            _code = Bytecode().deserialise(f, init_globals=not no_constants)
    except FileNotFoundError:
        raise RuntimeError(f"File not found: {path}")
    except Exception as e:
        raise RuntimeError(f"Failed to load bytecode: {e}")

    code = _code
    return (
        f"Loaded: {path}\n"
        f"Version: {code.version}\n"
        f"Has debug info: {code.has_debug_info}\n"
        f"Functions: {len(code.functions)}\n"
        f"Natives: {len(code.natives)}\n"
        f"Types: {len(code.types)}\n"
        f"Strings: {len(code.strings.value)}\n"
        f"Ints: {len(code.ints)}\n"
        f"Floats: {len(code.floats)}\n"
        f"Globals: {len(code.global_types)}\n"
    )


@mcp.tool()
def get_info() -> str:
    """Return a summary of the currently loaded bytecode."""
    code = _require_code()
    return (
        f"Version: {code.version}\n"
        f"Has debug info: {code.has_debug_info}\n"
        f"Functions: {len(code.functions)}\n"
        f"Natives: {len(code.natives)}\n"
        f"Types: {len(code.types)}\n"
        f"Strings: {len(code.strings.value)}\n"
        f"Ints: {len(code.ints)}\n"
        f"Floats: {len(code.floats)}\n"
        f"Globals: {len(code.global_types)}\n"
    )


@mcp.tool()
def list_functions(
    include_std: bool = False,
    include_natives: bool = True,
    offset: int = 0,
    limit: int = 200,
) -> str:
    """
    List functions in the loaded bytecode.

    Args:
        include_std: Include stdlib functions (default False — they are very numerous)
        include_natives: Include native function stubs (default True)
        offset: Start index for pagination
        limit: Max number of entries to return
    """
    code = _require_code()
    lines = []
    for func in code.functions:
        if _disasm.is_std(code, func) and not include_std:
            continue
        lines.append(_disasm.func_header(code, func))
    if include_natives:
        for native in code.natives:
            if _disasm.is_std(code, native) and not include_std:
                continue
            lines.append(_disasm.native_header(code, native))

    total = len(lines)
    page = lines[offset : offset + limit]
    result = "\n".join(page)
    if total > offset + limit:
        result += f"\n\n[Showing {offset}–{offset + len(page) - 1} of {total}. Use offset/limit to paginate.]"
    return _trim(result)


@mcp.tool()
def disassemble_function(findex: int) -> str:
    """
    Disassemble a function to annotated HashLink assembly (opcodes).
    STABLE — this is the most reliable output in crashlink.

    Args:
        findex: The function index (findex) to disassemble
    """
    code = _require_code()
    for func in code.functions:
        if func.findex.value == findex:
            return _trim(_disasm.func(code, func))
    for native in code.natives:
        if native.findex.value == findex:
            return _disasm.native_header(code, native)
    raise RuntimeError(f"Function f@{findex} not found.")


@mcp.tool()
def decompile_function(findex: int) -> str:
    """
    Decompile a function to pseudo-Haxe source code.

    ⚠ EXPERIMENTAL: The decompiler is a work in progress. Output may be wrong,
    incomplete, or this call may raise an exception for complex functions.
    Use disassemble_function for reliable output.

    Args:
        findex: The function index to decompile
    """
    code = _require_code()
    for func in code.functions:
        if func.findex.value == findex:
            try:
                ir = _decomp.IRFunction(code, func)
                result = pseudo(ir)
                return _trim(result)
            except Exception as e:
                raise RuntimeError(
                    f"Decompilation failed for f@{findex}: {e}\nTry disassemble_function for a more reliable view."
                )
    raise RuntimeError(f"Function f@{findex} not found (only non-native functions can be decompiled).")


@mcp.tool()
def decompile_class(tindex: int) -> str:
    """
    Decompile an entire class (Obj type) to pseudo-Haxe source.

    ⚠ EXPERIMENTAL: Same caveats as decompile_function — output may be wrong
    or incomplete. The class decompiler calls decompile_function for each method.

    Args:
        tindex: The type index (tIndex) of the class
    """
    code = _require_code()
    try:
        typ = code.types[tindex]
    except IndexError:
        raise RuntimeError(f"Type t@{tindex} not found.")
    if not isinstance(typ.definition, Obj):
        raise RuntimeError(f"Type t@{tindex} is not an Obj/class.")
    try:
        ir_class = _decomp.IRClass(code, typ.definition)
        result = ir_class.pseudo()
        return _trim(result)
    except Exception as e:
        raise RuntimeError(
            f"Class decompilation failed for t@{tindex}: {e}\n"
            "Try get_obj for a structural overview, or decompile individual methods with decompile_function."
        )


@mcp.tool()
def get_ir(findex: int) -> str:
    """
    Return the internal IR representation of a function in object-notation.
    Useful for debugging the decompiler or understanding control flow.

    ⚠ EXPERIMENTAL: IR structure may change between crashlink versions.

    Args:
        findex: The function index
    """
    code = _require_code()
    for func in code.functions:
        if func.findex.value == findex:
            try:
                ir = _decomp.IRFunction(code, func)
                buf = io.StringIO()
                with redirect_stdout(buf):
                    ir.print()
                return _trim(buf.getvalue())
            except Exception as e:
                raise RuntimeError(f"IR generation failed: {e}")
    raise RuntimeError(f"Function f@{findex} not found.")


@mcp.tool()
def list_types(
    kind_filter: Optional[str] = None,
    offset: int = 0,
    limit: int = 200,
) -> str:
    """
    List all types in the bytecode.

    Args:
        kind_filter: Optional type kind to filter by (e.g. 'Obj', 'Fun', 'Enum', 'Virtual')
        offset: Start index for pagination
        limit: Max number of entries to return
    """
    code = _require_code()
    lines = []
    for i, typ in enumerate(code.types):
        defn = typ.definition
        kind_name = type(defn).__name__
        if kind_filter and kind_name.lower() != kind_filter.lower():
            continue
        if isinstance(defn, Obj):
            label = f"Obj {defn.name.resolve(code)}"
        elif isinstance(defn, Fun):
            label = f"Fun {defn.str_resolve(code)}"
        elif isinstance(defn, Enum):
            label = f"Enum {defn.name.resolve(code)}"
        else:
            label = kind_name
        lines.append(f"t@{i}: {label}")

    total = len(lines)
    page = lines[offset : offset + limit]
    result = "\n".join(page)
    if total > offset + limit:
        result += f"\n\n[Showing {offset}–{offset + len(page) - 1} of {total}. Use offset/limit to paginate.]"
    return _trim(result)


@mcp.tool()
def get_type(tindex: int) -> str:
    """
    Get detailed information about a type by its tIndex.

    Args:
        tindex: The type index
    """
    code = _require_code()
    try:
        typ = code.types[tindex]
    except IndexError:
        raise RuntimeError(f"Type t@{tindex} not found.")

    from .core import Type as _Type

    lines = [f"Type t@{tindex}:"]
    try:
        kind_name = _Type.Kind(typ.kind.value).name
    except (ValueError, AttributeError):
        kind_name = str(typ.kind.value)
    lines.append(f"  Kind: {typ.kind.value} ({kind_name})")

    defn = typ.definition
    lines.append(f"  Definition: {type(defn).__name__}")

    if isinstance(defn, Fun):
        args = []
        for a in defn.args:
            try:
                args.append(_disasm.type_name(code, a.resolve(code)))
            except Exception:
                args.append(f"t@{a.value}")
        try:
            ret = _disasm.type_name(code, defn.ret.resolve(code))
        except Exception:
            ret = f"t@{defn.ret.value}"
        lines.append(f"  Signature: ({', '.join(args)}) -> {ret}")

    elif isinstance(defn, Obj):
        lines.append(f"  Name: {defn.name.resolve(code)}")
        lines.append(f"  Fields: {defn.nfields.value}")
        lines.append(f"  Protos: {defn.nprotos.value}")
        if defn.super and defn.super.value is not None:
            try:
                super_name = _disasm.type_name(code, defn.super.resolve(code))
            except Exception:
                super_name = f"t@{defn.super.value}"
            lines.append(f"  Super: {super_name}")

    elif isinstance(defn, Enum):
        lines.append(f"  Name: {defn.name.resolve(code)}")
        lines.append(f"  Constructs: {defn.nconstructs.value}")

    elif isinstance(defn, Virtual):
        field_names = [f.name.resolve(code) for f in defn.fields]
        lines.append(f"  Fields: {', '.join(field_names)}")

    return "\n".join(lines)


@mcp.tool()
def get_obj(tindex: int) -> str:
    """
    Get a structural overview of a class (Obj type): fields, protos, and bindings.

    Args:
        tindex: The type index of the class
    """
    code = _require_code()
    try:
        typ = code.types[tindex]
    except IndexError:
        raise RuntimeError(f"Type t@{tindex} not found.")
    if not isinstance(typ.definition, Obj):
        raise RuntimeError(f"Type t@{tindex} is not an Obj/class.")

    obj_def: Obj = typ.definition
    class_name = obj_def.name.resolve(code)
    lines = [f"--- {class_name} (t@{tindex}) ---"]

    if obj_def.super and obj_def.super.value is not None:
        try:
            super_name = _disasm.type_name(code, obj_def.super.resolve(code))
        except Exception:
            super_name = f"t@{obj_def.super.value}"
        lines.append(f"Inherits from: {super_name}")

    lines.append("\nFields:")
    for field in obj_def.fields or []:
        fname = field.name.resolve(code)
        ftype = _disasm.type_name(code, field.type.resolve(code))
        lines.append(f"  {fname}: {ftype}")
    if not obj_def.fields:
        lines.append("  (none)")

    lines.append("\nProtos (instance methods):")
    for proto in obj_def.protos or []:
        try:
            header = _disasm.func_header(code, proto.findex.resolve(code))
            lines.append(f"  {header}")
        except Exception:
            lines.append(f"  f@{proto.findex.value} (error resolving)")
    if not obj_def.protos:
        lines.append("  (none)")

    lines.append("\nBindings (static methods):")
    for binding in obj_def.bindings or []:
        try:
            header = _disasm.func_header(code, binding.findex.resolve(code))
            lines.append(f"  {header}")
        except Exception:
            lines.append(f"  f@{binding.findex.value} (error resolving)")
    if not obj_def.bindings:
        lines.append("  (none)")

    return _trim("\n".join(lines))


@mcp.tool()
def search_strings(query: str, offset: int = 0, limit: int = 100) -> str:
    """
    Search for strings in the bytecode by substring (case-insensitive).

    Args:
        query: Substring to search for
        offset: Start index for pagination
        limit: Max number of results to return
    """
    code = _require_code()
    matches = [(i, s) for i, s in enumerate(code.strings.value) if query.lower() in s.lower()]
    total = len(matches)
    page = matches[offset : offset + limit]
    lines = [f"s@{i}: {s}" for i, s in page]
    result = "\n".join(lines) if lines else f'No strings matching "{query}".'
    if total > offset + limit:
        result += f"\n\n[Showing {offset}–{offset + len(page) - 1} of {total} matches. Use offset/limit to paginate.]"
    return _trim(result)


@mcp.tool()
def list_strings(offset: int = 0, limit: int = 200) -> str:
    """
    List strings from the string table with pagination.

    Args:
        offset: Start index
        limit: Max number of strings to return
    """
    code = _require_code()
    strings = code.strings.value
    total = len(strings)
    page = strings[offset : offset + limit]
    lines = [f"s@{offset + i}: {s}" for i, s in enumerate(page)]
    result = "\n".join(lines)
    if total > offset + limit:
        result += f"\n\n[Showing {offset}–{offset + len(page) - 1} of {total}. Use offset/limit to paginate.]"
    return _trim(result)


@mcp.tool()
def get_string(index: int) -> str:
    """
    Get a string by its index in the string table.

    Args:
        index: String table index
    """
    code = _require_code()
    try:
        return code.strings.value[index]
    except IndexError:
        raise RuntimeError(f"String s@{index} not found.")


@mcp.tool()
def get_global(gindex: int) -> str:
    """
    Get information about a global variable by its gIndex.

    Args:
        gindex: Global variable index
    """
    code = _require_code()
    if not (0 <= gindex < len(code.global_types)):
        raise RuntimeError(f"Global g@{gindex} not found.")

    try:
        global_type_obj = code.global_types[gindex].resolve(code)
        type_str = _disasm.type_name(code, global_type_obj)
    except Exception:
        type_str = "Unknown"

    init_data = code.initialized_globals.get(gindex)
    if init_data is not None:
        if isinstance(init_data, dict):
            fields = "\n".join(f"  {k}: {v!r}" for k, v in init_data.items()) or "  (empty)"
        else:
            fields = f"  {init_data!r}"
        return f"g@{gindex} (Type: {type_str}):\n{fields}"
    return f"g@{gindex} (Type: {type_str}): no initialized constant values."


@mcp.tool()
def list_globals(offset: int = 0, limit: int = 200) -> str:
    """
    List global variables with their types.

    Args:
        offset: Start index for pagination
        limit: Max number of entries to return
    """
    code = _require_code()
    lines = []
    for i, gt in enumerate(code.global_types):
        try:
            type_str = _disasm.type_name(code, gt.resolve(code))
        except Exception:
            type_str = "?"
        lines.append(f"g@{i}: {type_str}")

    total = len(lines)
    page = lines[offset : offset + limit]
    result = "\n".join(page)
    if total > offset + limit:
        result += f"\n\n[Showing {offset}–{offset + len(page) - 1} of {total}. Use offset/limit to paginate.]"
    return _trim(result)


@mcp.tool()
def get_xrefs(findex: int) -> str:
    """
    Find all functions that call the given function (cross-references).

    Args:
        findex: The function index to find callers of
    """
    code = _require_code()
    target: Optional[Function | Native] = None
    for func in code.functions:
        if func.findex.value == findex:
            target = func
            break
    if target is None:
        for native in code.natives:
            if native.findex.value == findex:
                target = native
                break
    if target is None:
        raise RuntimeError(f"Function f@{findex} not found.")

    xrefs = target.called_by(code)
    if not xrefs:
        return f"No callers found for f@{findex}."

    lines = [f"Callers of f@{findex} ({code.full_func_name(target)}):"]
    for i, caller_findex in enumerate(xrefs):
        try:
            caller = caller_findex.resolve(code)
            lines.append(f"  {i}. {_disasm.func_header(code, caller)}")
        except Exception:
            lines.append(f"  {i}. f@{caller_findex.value} (error resolving)")
    return _trim("\n".join(lines))


@mcp.tool()
def get_opcode_doc(opcode: str) -> str:
    """
    Get documentation for a specific HashLink opcode, or search for opcodes by name.

    Args:
        opcode: Exact or partial opcode name (case-insensitive)
    """
    query = opcode.lower()
    if query in {k.lower(): k for k in opcode_docs}:
        exact_key = {k.lower(): k for k in opcode_docs}[query]
        args_str = ", ".join(f"{k}: {v}" for k, v in opcodes[exact_key].items())
        return f"{exact_key}\nArgs: {args_str}\nDesc: {opcode_docs[exact_key]}"

    matches = [k for k in opcode_docs if query in k.lower()]
    if not matches:
        return f"No opcodes matching '{opcode}'."
    if len(matches) == 1:
        k = matches[0]
        args_str = ", ".join(f"{n}: {v}" for n, v in opcodes[k].items())
        return f"{k}\nArgs: {args_str}\nDesc: {opcode_docs[k]}"
    return "Matching opcodes:\n" + "\n".join(f"  {m}" for m in matches) + "\nUse the exact name for details."


@mcp.tool()
def get_entry() -> str:
    """Return the entrypoint function of the bytecode."""
    code = _require_code()
    entry = code.entrypoint.resolve(code)
    if isinstance(entry, Native):
        return f"Entrypoint: Native {entry.name.resolve(code)}"
    return f"Entrypoint: {_disasm.func_header(code, entry)}"


@mcp.tool()
def find_function_by_name(name: str) -> str:
    """
    Find functions whose full name matches or contains the given string.

    Args:
        name: Substring to search for in function names (case-insensitive)
    """
    code = _require_code()
    results = []
    query = name.lower()
    for func in code.functions:
        full_name = code.full_func_name(func)
        if query in full_name.lower():
            results.append(_disasm.func_header(code, func))
    for native in code.natives:
        full_name = code.full_func_name(native)
        if query in full_name.lower():
            results.append(_disasm.native_header(code, native))

    if not results:
        return f"No functions matching '{name}'."
    return _trim(f"Found {len(results)} match(es):\n" + "\n".join(results))


@mcp.tool()
def get_native_libs() -> str:
    """List all unique native dynamic libraries referenced by the bytecode."""
    code = _require_code()
    libs = sorted({n.lib.resolve(code).lstrip("?") for n in code.natives if n.lib.resolve(code).lstrip("?")})
    if not libs:
        return "No native libraries found."
    return "Native libraries:\n" + "\n".join(f"  - {lib}" for lib in libs)


@mcp.tool()
def to_hlc() -> str:
    """
    Transpile the loaded bytecode to cHL/C source code.

    ⚠ VERY EXPERIMENTAL: The generated C targets the HashLink C runtime (hlc) and is
    not standard portable C. Expect missing symbols, broken control flow, and compiler
    errors without patching. Use as a rough reference only — not production output.

    Returns the first MAX_OUTPUT_CHARS characters of the generated C. For large
    bytecode files the output will be truncated — save to a file via the CLI instead.
    """
    code = _require_code()
    try:
        result = code_to_c(code)
        return _trim(result)
    except Exception as e:
        raise RuntimeError(f"cHL/C transpilation failed: {e}")


@mcp.tool()
def list_debug_files(offset: int = 0, limit: int = 200) -> str:
    """
    List debug source file names embedded in the bytecode (requires debug info).

    Args:
        offset: Start index for pagination
        limit: Max entries to return
    """
    code = _require_code()
    if not code.has_debug_info or not code.debugfiles:
        return "No debug information in bytecode."
    files = code.debugfiles.value
    total = len(files)
    page = files[offset : offset + limit]
    lines = [f"{offset + i}: {f}" for i, f in enumerate(page)]
    result = "\n".join(lines)
    if total > offset + limit:
        result += f"\n\n[Showing {offset}–{offset + len(page) - 1} of {total}. Use offset/limit to paginate.]"
    return _trim(result)


@mcp.tool()
def functions_in_file(filename: str) -> str:
    """
    Find all functions defined in a given source file (requires debug info).

    Args:
        filename: The source file name (as it appears in list_debug_files output)
    """
    code = _require_code()
    if not code.has_debug_info:
        return "No debug information in bytecode."
    results = [_disasm.func_header(code, func) for func in code.functions if func.resolve_file(code) == filename]
    if not results:
        return f"No functions found in file '{filename}'."
    return _trim(f"Functions in {filename}:\n" + "\n".join(results))


@mcp.tool()
def verify_bytecode() -> str:
    """Run basic sanity checks on the loaded bytecode and report results."""
    code = _require_code()
    ok = code.is_ok()
    return "Bytecode verification succeeded." if ok else "Bytecode verification FAILED."


def run_mcp_server(preload_path: Optional[str] = None) -> None:
    """Start the crashlink MCP stdio server."""
    global _code
    if preload_path:
        try:
            with open(preload_path, "rb") as f:
                _code = Bytecode().deserialise(f)
            print(f"[crashlink-mcp] Preloaded: {preload_path}", file=sys.stderr)
        except Exception as e:
            print(f"[crashlink-mcp] Warning: failed to preload {preload_path}: {e}", file=sys.stderr)

    mcp.run(transport="stdio")
