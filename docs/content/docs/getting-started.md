---
slug: /getting-started
title: Getting Started
---

crashlink is a pure-Python toolkit for HashLink bytecode: disassembly, decompilation, patching, and reserialisation. This page gets you from nothing installed to poking around a `.hl` file. For the full CLI/REPL command reference, see [CLI and REPL](/cli-repl).

## Installing

The core package has zero dependencies, so a plain install is enough to disassemble and patch bytecode:

```bash
pip install crashlink
```

If you use [uv](https://docs.astral.sh/uv/), you can run it without installing anything into a project at all:

```bash
uvx crashlink game.hl
```

or install it as a standalone tool:

```bash
uv tool install crashlink
```

### The `[extras]` group

A handful of features are gated behind an optional dependency group, so the base install stays dependency-free. Install it with:

```bash
pip install crashlink[extras]
# or
uv tool install crashlink[extras]
```

`[extras]` pulls in:

- `tqdm`, for progress bars during load/save of large bytecode files
- `IPython`, for a nicer `pyrepl` drop-in Python shell
- `pygments`, for syntax-highlighted pseudocode output
- `lief` and `capstone`, for the HL/C binary-inspection and disassembly tooling
- `mcp`, to run crashlink as an MCP server
- `PySide6` and `graphviz` (Python bindings), for the GUI
- `keystone-engine`, for inline x86 assembly

There's also a smaller `[gui]` group (`PySide6` + `graphviz`) if all you want is the graphical inspector without the rest.

None of this is required to use the CLI or the library for basic disassembly and patching. Without `tqdm` installed, load/save just falls back to plain status lines on stderr instead of a progress bar.

### Graphviz (system dependency)

Rendering control flow graphs (the `cfg` REPL command, or the embedded CFG viewer in the GUI) needs the actual Graphviz binaries on your `PATH`, not just the Python bindings pulled in by `[extras]`. Install it with your platform's package manager:

- Windows: `choco install graphviz`
- macOS: `brew install graphviz`
- Debian/Ubuntu: `sudo apt install graphviz`
- Arch: `sudo pacman -S graphviz`
- Fedora: `sudo dnf install graphviz`

If you don't need CFG diagrams, you can skip this entirely.

## Your first five minutes

Point crashlink at a bytecode file with no subcommand and it opens the interactive REPL:

```txt
$ crashlink game.hl
crashlink> funcs
f@22 static Clazz.main () -> Void (from Clazz.hx)
f@23 Clazz.method (Clazz) -> I32 (from Clazz.hx)
crashlink> fn 22
f@22 static Clazz.main () -> Void (from Clazz.hx)
Reg types:
  0. Void

Ops:
  0. Ret             {'ret': 0}                                       return
```

`funcs` lists every function and native in the file (stdlib functions are hidden by default). `fn <findex>` disassembles one to its raw opcode listing. Functions, types, globals, and strings are all addressed by index throughout crashlink: `f@<findex>`, `t@<tIndex>`, `g@<gIndex>`, `s@<index>`.

If you'd rather script against it, the same load-and-inspect flow works from Python:

```py
from crashlink import *

code = Bytecode.from_path("game.hl")
func = code.fn(22)  # 22 and 240 are typical compiler-generated entry points
if func:
    print(disasm.func(code, func))
```

From here, `decomp <findex>` in the REPL gives you a pseudo-Haxe decompilation instead of raw opcodes, and `cfg <findex>` renders a control flow graph if Graphviz is installed. The full command list, CLI flags, and a longer worked session live on the [CLI and REPL](/cli-repl) page. For how the pieces underneath these commands fit together, see the [architecture overview](/architecture-overview).
