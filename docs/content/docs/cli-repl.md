---
slug: /cli-repl
title: CLI and REPL
---

crashlink is invoked as `crashlink <file>`, either directly or via `python -m crashlink`. With no subcommand it opens `file` and drops you into the interactive REPL. Everything else, one-shot subcommands, top-level flags, and REPL commands, is covered below.

## Top-level flags

These apply to the base invocation, `crashlink <file> [flags]`:

- `-N` / `--no-constants`: skip constant resolution on deserialisation. Useful for malformed or unusually large files.
- `-a` / `--assemble`: treat `file` as crashlink assembly and assemble it to bytecode instead of opening it.
- `-o` / `--output`: output path for `--assemble` or `--patch`.
- `-p` / `--patch`: apply a patch module (a file of patch definitions) to `file`.
- `-c` / `--command`: run a single REPL command on startup instead of dropping into the interactive prompt (`-c ''` opens the REPL as usual).
- `-t` / `--traceback`: print full Python tracebacks on error instead of a short message.
- `-d` / `--debug`: enable extra debug output.
- `-D` / `--no-debug`: force debug output off, overriding anything that turned it on implicitly.
- `-C` / `--dehlc`: extract debug info from a compiled HL/C binary (needs PDB on PE, DWARF on ELF).
- `--help-all`: print the top-level help plus every subcommand's own `-h` output in one go.

## One-shot subcommands

For anything that doesn't need a live session, there are subcommands that run once and exit. Each has its own `-h`:

| Subcommand | Does |
|---|---|
| `funcs` | List functions in a bytecode file |
| `disasm` | Disassemble a function |
| `decompile` | Decompile a function or class to pseudo-Haxe (decompiler is incomplete, usually functional) |
| `info` | Summary info: version, counts, etc. |
| `search` | Search strings by substring |
| `db` | Inspect a `.cldb` debug-info database (`db info`, `db check`, `db renames`, `db comments`) |
| `hlc` | Transpile bytecode to C, optionally build it (`--build`) |
| `mcp` | Run crashlink as an MCP server |
| `gui` | Launch the graphical bytecode inspector |

```txt
$ crashlink funcs game.hl              # list functions
$ crashlink disasm game.hl 42          # disassemble f@42
$ crashlink decompile game.hl 42       # decompile f@42 to pseudo-Haxe
$ crashlink info game.hl               # summary info (version, counts, etc.)
$ crashlink search game.hl "password"  # search strings by substring
$ crashlink db info game.cldb          # inspect a .cldb debug-info database
$ crashlink hlc game.hl --build        # transpile to C and compile it
$ crashlink mcp                        # run as an MCP server
```

## The REPL

Running `crashlink game.hl` with no subcommand loads the file and starts an interactive prompt. Bytecode objects are addressed by index throughout: `f@<findex>` for functions and natives, `t@<tIndex>` for types, `g@<gIndex>` for globals, `s@<index>` for strings. Command history persists across sessions in `~/.crashlink_history` (up/down arrows to browse it), and Tab completes command names. `help` lists every command with its aliases; `help <command>` shows a command's usage string and full description.

### Command reference

This isn't exhaustive (there are 60+ commands; run `help` in a live session for the full current list), but it covers what you'll reach for most:

| Command | Aliases | Does |
|---|---|---|
| `funcs [std]` | `fns` | List functions; pass `std` to include stdlib |
| `fn <idx>` | `f` | Disassemble a function to opcodes |
| `cfg <idx>` | | Render a control flow graph and open it in the default image viewer |
| `ir <idx>` | | Print a function's IR in object notation |
| `decomp <idx>` | `decompile`, `dec`, `pseudo`, `d` | Decompile a function to pseudo-Haxe |
| `decompfile <file>` | `df` | Decompile every function in a debug source file, grouped by class |
| `stub <file>` | `stubfile` | Emit a compilable stub of a file (signatures kept, bodies stubbed) |
| `autostub <folder>` | | Stub every file in the debug database to a folder |
| `findfunc <query>` | `ff` | Search functions by name substring, or list functions in a source file |
| `fnn <name>` | | Print a function by exact name |
| `patch <idx>` | `edit` | Patch a function's raw opcodes |
| `save <path>` | | Write the modified bytecode out to `path` |
| `xref <kind> <index> [aux]` | | Cross-references: `func`, `type`, `field`, `global`, `string`, or `enum` |
| `locals <findex>` | | List a function's IR locals with their rename keys |
| `rename <findex> <reg> <def_op\|_> <name>` | | Rename an IR local |
| `unrename <findex> <reg> <def_op\|_>` | | Clear a local rename |
| `addcomment <findex> <op_idx> <text>` | | Attach a comment to a statement |
| `rmcomment <findex> <op_idx>` | | Remove a comment from a statement |
| `entry` | | Print the bytecode's entrypoint |
| `types` | | List all types |
| `objs` | | List all `Obj` types |
| `obj <tIndex>` | `object` | Overview of a class's fields, protos, and bindings |
| `type <tIndex>` | `t` | Detailed info on a type by index |
| `virt <idx>` | | Print a `Virtual` type by index |
| `enum <idx>` | | Print an enum type by index |
| `tn <name>` | | Find a type by name |
| `global <gIndex>` | `g` | Show a global's initialised values |
| `strings` | `strs` | List all strings |
| `floats` | | List all floats |
| `nativelibs` | `libs` | List native dynlibs used by the bytecode |
| `infile <file>` | | Find all functions from a given source file |
| `debugfiles` | | List all debug files |
| `source <...>` | | Debug-file/line lookup, in either direction |
| `op <opcode>` | | Print documentation for an opcode |
| `hlc <output path>` | | Transpile the loaded bytecode to C |
| `class <tIndex>` | `cls`, `c` | Decompile an entire class by type index |
| `apidocs <path>` | | Generate API documentation for the bytecode's classes |
| `mkdocs <path> [name]` | `mkdoc` | Generate a MkDocs + Material site for the bytecode's API |
| `shader [name]` | `shaders` | Recover hxsl shaders embedded in the bytecode |
| `run` | | Run the bytecode in crashlink's integrated interpreter |
| `pyrepl` | | Drop into a Python REPL with direct access to the `Bytecode` object |
| `copy <command> [args...]` | `cp` | Run a command and copy its plain-text output to the clipboard |
| `check` | | Run basic sanity checks on the loaded bytecode |
| `sha256` | | Print the SHA-256 of the loaded bytecode image |
| `plugins` | | List discovered plugin optimizers and whether they apply |
| `offset <hex>` | | Print the bytecode section at a given file offset |
| `history [count]` | `hist` | Show recently run REPL commands |
| `clear` | | Clear the terminal |
| `wiki` | | Open the HashLink bytecode wiki page in your browser |
| `exit` | | Exit the REPL |

### A worked session

```txt
$ crashlink game.hl
crashlink> funcs
f@22 static Clazz.main () -> Void (from Clazz.hx)
f@23 Clazz.method (Clazz) -> I32 (from Clazz.hx)
crashlink> findfunc method
f@23 Clazz.method (Clazz) -> I32 (from Clazz.hx)
crashlink> fn 23
f@23 Clazz.method (Clazz) -> I32 (from Clazz.hx)
Reg types:
  0. Clazz
  1. I32

Ops:
  0. Ret             {'ret': 1}                                       return
crashlink> decomp 23
function method(this: Clazz): Int {
    return 0;
}
crashlink> cfg 23
crashlink> xref func 23
f@22 static Clazz.main () -> Void (from Clazz.hx)
crashlink> rename 23 0 _ localName
crashlink> save game_patched.hl
crashlink> exit
```

`cfg` renders the graph with Graphviz and opens it in your system image viewer, so there's no meaningful text output to show. See [Getting Started](/getting-started) for installing Graphviz if that command errors out.
