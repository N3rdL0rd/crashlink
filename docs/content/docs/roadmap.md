---
slug: /roadmap
title: Roadmap
---

# Roadmap

Where crashlink stands, feature by feature. Checked items are done; unchecked items are planned or in progress.

- [x] Bytecode parsing
- [x] Opcode disassembly
  - [x] Local resolution and naming
- [x] IR lifter (layer 0)
  - [x] If statements
  - [x] Loops
  - [x] Switch opcode statements
  - [x] Function calls
    - [x] CallClosure
  - [x] Closures, lambdas
- [ ] IR optimization layers
  - [x] Resolve locals from assigns block
  - [x] Trace optimization
  - [x] Nested if/else/if/else -> switch
  - [ ] More to address issues as they arise!
- [x] Haxe pseudocode
- [x] Cross-reference index
- [x] GUI prerequisites
  - [x] Workspace/project abstraction (wraps `Bytecode` with cached analysis state)
  - [x] Incremental/async analysis API (background decompile, progress callbacks)
  - [ ] Patch buffer (in-memory edits, dirty tracking, re-serialisation)
  - [x] Function search index (by name, file, type)
  - [x] Source location API (debug file + line → function/opcode, and reverse)
- [ ] GUI (probably qt6 at this point)
  - [x] Graphical disassembler
  - [x] Embedded CFG viewer through some Graphviz bindings
  - [x] Decompiler
  - [x] Basic local name patching
  - [ ] Other direct patching
  - [ ] Rename other symbols
  - [ ] Persistent patching/export modified bytecode
  - [ ] IR layer viewer
- [ ] Partial recompilation (against stubs of other functions)
