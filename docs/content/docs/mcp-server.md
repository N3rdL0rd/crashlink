---
slug: /mcp-server
title: The MCP Server
---

crashlink ships an MCP (Model Context Protocol) server in `crashlink.mcp`. It exposes bytecode introspection as a set of tools an MCP-aware assistant (Claude Code, Claude Desktop, or anything else that speaks MCP) can call directly, instead of you copy-pasting CLI output into a chat window.

## When to reach for it

The CLI and the Python API are for you, driving crashlink yourself, one command or script at a time. The MCP server is for handing crashlink to an assistant that's doing the exploring: pointing an agent at an unfamiliar `.hl` file and asking it to find where a bug lives, trace who calls a given function, or write a report on a class's structure, all without you relaying every intermediate result by hand. If you already know exactly which function you want to look at, `crashlink fn <findex>` is faster. If you want an agent to search, cross-reference, and decompile on its own across a large binary, the MCP server gives it the tools to do that directly.

## Launching it

```bash
crashlink mcp [file]
```

This runs `crashlink` as a stdio MCP server (`mcp_main` in `crashlink/__main__.py`). The `file` argument is optional and preloads a `.hl`/`.dat` file at startup; if you omit it, call the `load_bytecode` tool once the server is up. The `mcp` extra needs to be installed for this to work (`pip install crashlink[extras]`) since it pulls in the `mcp` package itself.

A loaded `Bytecode` instance is kept in module-level state for the life of the server process, so all tool calls in a session operate on whatever was last loaded with `load_bytecode`.

## Module maturity

The server reports this up front in its own instructions, and it's worth keeping in mind when interpreting tool output:

- `disasm` tools (`disassemble_function`, `list_functions`, `get_type`, etc.): **STABLE**
- `decomp`/`pseudo` tools (`decompile_function`, `decompile_class`, `get_ir`): **INCOMPLETE**, usually functional, but some complex functions may decompile imperfectly or raise
- `to_hlc`: **STABLE**, the generated C compiles and links against the real HashLink C runtime, and has been validated against a full commercial game's boot bytecode (37k+ functions)

## Tools

- **`load_bytecode(path, no_constants=False)`**: Load a HashLink bytecode file (.hl or .dat) from disk. This must be called before any other analysis tool. Returns a summary of what was loaded.
- **`get_info()`**: Return a summary of the currently loaded bytecode.
- **`list_functions(include_std=False, include_natives=True, offset=0, limit=200)`**: List functions in the loaded bytecode.
- **`disassemble_function(findex)`**: Disassemble a function to annotated HashLink assembly (opcodes). STABLE, this is the most reliable output in crashlink.
- **`decompile_function(findex)`**: Decompile a function to pseudo-Haxe source code. Falls back to suggesting `disassemble_function` if decompilation fails.
- **`decompile_class(tindex)`**: Decompile an entire class (Obj type) to pseudo-Haxe source. Calls `decompile_function` internally for each method.
- **`get_ir(findex)`**: Return the internal IR representation of a function in object-notation. Useful for debugging the decompiler or understanding control flow. Experimental, IR structure may change between crashlink versions.
- **`list_types(kind_filter=None, offset=0, limit=200)`**: List all types in the bytecode, optionally filtered by kind (`Obj`, `Fun`, `Enum`, `Virtual`, ...).
- **`get_type(tindex)`**: Get detailed information about a type by its tIndex: kind, fields, methods, enum constructs, or vtable slots as applicable. For `Fun` types, also lists every function/native/field/global that declares that signature (its "users").
- **`get_obj(tindex)`**: Get a structural overview of a class (Obj type): fields, protos, and bindings.
- **`search_strings(query, offset=0, limit=100)`**: Search for strings in the bytecode by substring (case-insensitive).
- **`list_strings(offset=0, limit=200)`**: List strings from the string table with pagination.
- **`get_string(index)`**: Get a string by its index in the string table.
- **`get_global(gindex)`**: Get information about a global variable by its gIndex.
- **`list_globals(offset=0, limit=200)`**: List global variables with their types.
- **`get_xrefs(findex)`**: Find all cross-references to a function: callers (direct calls, virtual calls, and closures), plus structural references (proto/binding declarations in type definitions).
- **`get_opcode_doc(opcode)`**: Get documentation for a specific HashLink opcode, or search for opcodes by name.
- **`get_entry()`**: Return the entrypoint function of the bytecode.
- **`find_function_by_name(name)`**: Find functions whose full name matches or contains the given string.
- **`get_native_libs()`**: List all unique native dynamic libraries referenced by the bytecode.
- **`to_hlc()`**: Transpile the loaded bytecode to cHL/C source code. Returns the first 8000 characters; for large bytecode files the output will be truncated, save to a file via the CLI instead.
- **`list_debug_files(offset=0, limit=200)`**: List debug source file names embedded in the bytecode (requires debug info).
- **`functions_in_file(filename)`**: Find all functions defined in a given source file (requires debug info).
- **`verify_bytecode()`**: Run basic sanity checks on the loaded bytecode and report results.

All paginated tools (`list_functions`, `list_types`, `search_strings`, `list_strings`, `list_globals`, `list_debug_files`) accept `offset`/`limit` and note how many results were omitted so an agent can page through large binaries without blowing its context window. Every tool's output is also capped at 8000 characters and truncated with a note if it runs over.

## Connecting a client

Any MCP-aware assistant that can launch a stdio server works. The exact config shape is client-specific, but the general form (illustrated here, check your client's docs for the authoritative format) looks like this:

```json
{
  "mcpServers": {
    "crashlink": {
      "command": "crashlink",
      "args": ["mcp", "path/to/file.hl"]
    }
  }
}
```

Drop the `path/to/file.hl` argument if you'd rather load the file yourself with the `load_bytecode` tool once the assistant is connected.
