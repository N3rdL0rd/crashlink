---
slug: /bytecode-primer
title: HashLink Bytecode Primer
---

# HashLink Bytecode Primer

For the byte-level file format, the actual section layout, offsets, and encoding of every field, see [ModDocCE's hlboot reference](https://n3rdl0rd.github.io/ModDocCE/files/hlboot/). This page does not repeat that material. Instead, it's about the mental model you need before poking at a `.hl` file with crashlink: how the pieces of a HashLink program actually reference each other, and why the format is shaped the way it is.

## Registers are typed slots, not stack cells

If you're coming from bytecode formats like the JVM or CPython's, the instinct is to think of a function's data as a stack that opcodes push to and pop from. HashLink doesn't work that way. Each `Function` (see `crashlink.core.Function`) owns a flat list of registers (`Function.regs`, a `List[tIndex]`), and every register has a fixed type for the lifetime of the function. An opcode like `Add` doesn't push a result onto anything, it writes into a specific numbered register, and that register can only ever hold the one type it was declared with.

This matters when you're reading disassembly: a register index isn't a scratch slot the compiler reused for anything convenient, it's closer to a statically-typed local variable that happens to be numbered instead of named. `crashlink/core.py`'s `Reg` class reflects this directly, `Reg.resolve(code)` doesn't look anything up in the function, it just resolves through `code.types[self.value]` because a `Reg` reference embedded in an opcode's operands is itself typed by which type index it targets... but the register's own declared type comes from `Function.regs[reg_index]`, one `tIndex` per register, set once when the function is defined. There's no register renaming or retyping mid-function.

## The type table is a shared pool, not embedded data

`Bytecode.types` is a single `List[Type]` for the whole file. Nothing else in the format stores a full type inline, everywhere a `Function`, `Obj`, `Field`, `Native`, or register needs a type, it stores a `tIndex`, a lightweight index into that shared list, and calls `.resolve(code)` to get the actual `Type` object back. This is why so much of `core.py` is index classes (`tIndex`, `fIndex`, `gIndex`, `strRef`, and so on) built on `ResolvableVarInt`, each with its own `resolve()` that knows which table it points into.

The payoff is that a type like a class definition (`Obj`) is described once, and every place that uses it, a field's type, a function's return type, a register's type, just references the same entry. Two functions that both return `String` share one `tIndex` pointing at one `Type` in `code.types`, they don't each carry their own copy of what a `String` is. This also means you can't meaningfully interpret an index in isolation, `resolve()` always needs the owning `Bytecode` instance to look it up in.

`Obj` (a class definition) follows the same pattern one level deeper: its fields don't carry types directly usable without a `code` reference, and its `super` is a `tIndex` rather than an embedded parent definition, so walking a class hierarchy means repeatedly resolving through the shared type table rather than following inline pointers.

## Functions reference their own signature the same way

A `Function` doesn't carry a name or a parameter list as such. It has a `type: tIndex` pointing at a `Fun` type definition in the shared table, and `resolve_fun(code)` walks that reference to get the actual signature (argument types and return type). `resolve_nargs(code)` similarly goes through `type.resolve(code).definition` rather than storing an argument count directly on the function. So "what does this function take and return" is always a lookup through the type table, never a field you can read off `Function` itself. A function's *identity* (its `findex`, an `fIndex`) is separate from its *signature* (its `type`), and both are just indices.

## Natives are declarations, not code

`Bytecode.natives` is a separate `List[Native]` alongside `Bytecode.functions`. A `Native` has a `lib` and `name` (both string references), a `type` (a `tIndex`, same signature mechanism as a regular function), and a `findex`. What it does *not* have is a body: no `regs`, no `ops`. It's a stub that says "this findex resolves to a function implemented outside the bytecode, in the named native library, with this signature." Call sites don't care whether the `fIndex` they're calling resolves to a `Function` or a `Native`, `fIndex.resolve(code)` returns `Function | Native` and the caller only needs the signature to know how to set up the call. This is how HashLink bridges into the C runtime and host libraries: the interpreter looks up the native symbol by lib/name at load time, but from the bytecode's perspective it's just another callable findex.

## Strings, ints, and floats are pooled, not inlined

Rather than embedding a string literal or a numeric constant at every point it's used, the bytecode stores three flat pools on `Bytecode`: `strings` (a `StringsBlock`), `ints` (`List[SerialisableInt]`), and `floats` (`List[SerialisableF64]`). Anywhere an opcode needs one of these values, it stores an index (`strRef`, `intRef`, `floatRef`) rather than the value itself. `Obj.name`, `Field.name`, debug file names, all of these are `strRef`s into the same pool. If a hundred functions all reference the string `"toString"`, that's a hundred small integer indices pointing at one entry, not a hundred copies of the string.

`Bytecode.constants` is a related but separate mechanism, used for statically-initialized globals (`Constant` ties a `gIndex` to a list of field values pulled from the int/float/string pools). It's how HashLink pre-populates static fields without needing bytecode to run at startup for the simple cases.

## Debug info rides alongside, but isn't load-bearing

A `Function` optionally carries `debuginfo` (a per-opcode file/line reference) and, in newer bytecode versions, `assigns`, a list of `(strRef, VarInt)` pairs mapping variable names to the opcode index where they're assigned. Both are gated behind `has_debug` and are genuinely optional: strip them and the bytecode still executes identically, because opcodes reference registers by number and functions by index regardless of whether any of it has a human-readable name attached.

What `assigns` gives you, when present, is a way to recover local variable names for a register that would otherwise just be "register 7". `Function.resolve_file(code)` and the debuginfo block are how disassembly and decompilation attach source file/line context to each opcode. crashlink's disassembler and decompiler lean on this heavily when it's available (that's most of what makes disassembly output read as `Reg7` versus something named), but nothing about opcode execution or type resolution depends on it, which is why release builds that strip debug info still run fine, they're just much harder to read after the fact.

## Putting it together

When you load a `Bytecode` with crashlink, what you actually get is a handful of flat, shared pools (`types`, `strings`, `ints`, `floats`, `natives`, `functions`, `constants`) and a large number of small index objects wiring them together. A `Function` is really just: an `fIndex` identity, a `tIndex` pointing at its signature, a list of `tIndex`s for its registers, and a list of opcodes whose operands are themselves more indices into the same pools. Understanding the format is mostly a matter of remembering which pool an index resolves into, and that `resolve(code)` is always how you get from "a small integer" to "the thing it actually means."
