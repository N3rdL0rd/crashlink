---
slug: /scripting
title: Scripting crashlink
---

crashlink isn't just a REPL, it's a Python library with zero core dependencies. Everything the CLI does (parsing, disassembly, decompilation, reserialisation) is exposed as plain functions and classes under the `crashlink` package, so you can drive it from a script, a Jupyter notebook, or IDAPython.

## Loading bytecode

`Bytecode` is the entry point for everything. Load a `.hl` file from disk with `from_path`, or from an in-memory buffer with `from_bytes`:

```py
from crashlink import *

code = Bytecode.from_path("path/to/file.hl")
```

Both classmethods take an optional `progress_cb` if you want a progress bar while parsing large files (see the `[extras]` install for a ready-made one), and `from_path` also records a sha256 of the source file on `code.sha256` for later comparison.

Once loaded, the interesting bits live as plain lists and blocks on the `Bytecode` instance:

- `code.functions`: `List[Function]`, every compiled function body
- `code.natives`: `List[Native]`, native function stubs
- `code.types`: `List[Type]`, the type pool (`Obj`, `Enum`, `Fun`, `Virtual`, etc.)
- `code.strings.value`: `List[str]`, the string pool
- `code.ints`, `code.floats`: the constant pools
- `code.global_types`: types of global variables, with `code.initialized_globals` holding their constant values where known

## Finding functions

Iterate `code.functions` directly, or use `code.fn(findex)` to look one up by index (it also matches natives unless you pass `native=False`):

```py
for func in code.functions:
    print(disasm.func_header(code, func))

main = code.fn(code.entrypoint.value)
```

`code.entrypoint` is a `fIndex` pointing at the function HashLink calls to start execution; resolve it with `.resolve(code)` or just pass `.value` to `code.fn()`. For name-based lookup, `code.search_index()` builds (and caches) a `SearchIndex` over full and partial function names, source files, and owning types - this is the same index the MCP server's `find_function_by_name` uses under the hood.

## Disassembly

`crashlink.disasm` turns a `Function` or `Native` into the same annotated assembly text the CLI's `fn` command prints:

```py
print(disasm.func(code, code.fn(22)))
```

That's a plain string, so it's fine to grep, diff, or write straight to a file. `disasm.func_header(code, func)` gives just the one-line signature (`f@22 static Clazz.main () -> Void (from Clazz.hx)`) if you don't need the full opcode listing.

## Decompilation

The decompiler lives in `crashlink.decomp` and `crashlink.pseudo`. Build an `IRFunction` from a `Function`, then render it with `pseudo.pseudo`:

```py
from crashlink.decomp import IRFunction
from crashlink.pseudo import pseudo

ir = IRFunction(code, code.fn(22))
print(pseudo(ir))
```

`IRClass(code, obj_def)` does the same for a whole class (all protos and bindings at once) and exposes a `.pseudo()` method that returns the full class source. The decompiler is marked INCOMPLETE in the maturity list: it's usually functional, but a sufficiently unusual function can raise partway through. Disassembly is the STABLE fallback when that happens - wrap decompilation in a `try/except` if you're batch-processing a whole binary.

## Cross-references

`code.xref_index()` builds (and caches) an `XrefIndex` over every function, so you don't have to scan opcodes by hand to answer "who calls this?":

```py
xi = code.xref_index()
for ref in xi.callers_of(22):
    caller = code.fn(ref.source_index)
    print(disasm.func_header(code, caller), "at op", ref.opcode_index)
```

`XrefIndex` also has `callees_of`, `field_reads`/`field_writes`, `allocators_of`, `subtypes_of`, `global_reads`/`global_writes`, `string_uses`, and more - it's the same index the MCP server's `get_xrefs` tool queries.

## Mutating and writing bytecode back out

`Bytecode` objects are mutable: functions, opcodes, strings, and types are just Python objects sitting in the lists above. `crashlink.disasm.from_asm` can turn edited assembly text back into a list of `Opcode`s if you'd rather patch in text form than poke at opcode fields directly. Once you're happy with the changes, `code.serialise()` produces the bytes to write back out:

```py
with open("patched.hl", "wb") as f:
    f.write(code.serialise())
```

The round-trip guarantee that matters here: for an *unmodified* file, `Bytecode().deserialise(f).serialise()` must reproduce the original bytes exactly, byte for byte. This is enforced directly in `tests/test_basic.py::test_reser_basic`, which parses every sample under `tests/haxe/*.hl` and asserts the reserialised output matches the file on disk (down to reporting the exact offset and section of the first mismatching byte if it doesn't). If your patched file fails to load in HashLink after a mutation, this is the property to check first: does an untouched copy of the same file still round-trip before your edit is applied?

```py
from crashlink import *

code = Bytecode.create_empty()
assert Bytecode.from_bytes(code.serialise()).serialise() == code.serialise()
```

`Bytecode.create_empty()` builds a minimal valid bytecode file from scratch (used by `test_create_empty` for exactly this kind of round-trip check), which is also the starting point if you want to assemble a `.hl` file programmatically rather than patch an existing one.

## Putting it together

A small script that loads a file, finds a function by name, and prints both its disassembly and its decompiled form:

```py
from crashlink import *
from crashlink.decomp import IRFunction
from crashlink.pseudo import pseudo

code = Bytecode.from_path("path/to/file.hl")

for func in code.functions:
    if "main" in code.full_func_name(func).lower():
        print(disasm.func(code, func))
        try:
            print(pseudo(IRFunction(code, func)))
        except Exception as e:
            print(f"decompilation failed: {e}")
        break
```

From here, the `crashlink.mcp` module (see [The MCP Server](/mcp-server)) is built entirely on top of this same public API, so it's a good second reference for realistic call patterns once you outgrow these snippets.
