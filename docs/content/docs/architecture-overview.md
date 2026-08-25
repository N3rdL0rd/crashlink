---
slug: /architecture-overview
title: Architecture Overview
---

This page is a map of how a `.hl` file becomes readable output in crashlink, not a tour of any one stage. For the decompiler's internals specifically, see [Decompiler Internals](/decompiler-internals).

![Architecture](/flow.svg)

## Parsing: `Bytecode.deserialise`

Everything starts with `Bytecode.deserialise`, which reads the raw HashLink bytecode format (a HashLink-versioned binary layout of types, functions, natives, globals, and constants) into a `Bytecode` object. This is a straight parse, no interpretation of what the opcodes mean. `Bytecode` is also what gets reserialised back to disk when you patch or assemble, so it's the shared in-memory model everything else in the library works against.

## Disassembly: `disasm`

The `disasm` module turns a `Function`'s raw opcode list into a human-readable listing: register types, one line per opcode with its arguments resolved (jump targets, string refs, type refs) and a plain-English gloss. This is the `fn`/`disasm` output you see in the REPL and CLI. It doesn't build any higher-level structure, it's a direct, mechanical translation of what's already in the bytecode.

## Decompilation: `decomp`

The `decomp` package is where structure gets recovered. It builds a `CFGraph` (control flow graph) from a function's opcodes, then lifts that into IR (intermediate representation): an object model of statements and expressions instead of flat opcodes and jump targets. A series of IR optimizer passes then run over that IR, resolving locals, folding traces, turning nested if/else chains into switches, and so on, to get closer to what a human would have written. The decompiler is under active development: most functions decompile cleanly, but some complex control flow can still come out imperfect or raise. See [Decompiler Internals](/decompiler-internals) for how the passes are structured.

## Pseudocode: `pseudo`

The `pseudo` module walks the optimized IR and emits pseudo-Haxe source text, since HashLink bytecode is very close in shape to Haxe (the language it's normally compiled from). This is the `decomp`/`pseudo` REPL output and what `decompile`/`decompfile`/`class` produce on the CLI.

## Adjacent subsystems

Two other pieces sit next to this pipeline rather than in it:

- **Patching and assembly** (`hlrun`, the `-p`/`-a` CLI flags, and the in-REPL `patch`/`save` commands): editing bytecode in place or assembling it from crashlink assembly text, then reserialising. See [Patching](/patching).
- **`crashtest`**: a regression suite that scores the decompiler's pseudocode output against known-good source, used to track decompiler correctness over time. See [crashtest](/crashtest).
