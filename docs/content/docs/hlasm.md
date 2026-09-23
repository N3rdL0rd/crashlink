---
slug: /hlasm
title: Writing HashLink Bytecode by Hand
---

# Writing HashLink Bytecode by Hand

crashlink has its own text notation for HashLink bytecode: `.hlasm`. You can
write programs in it from scratch, and it can also express every part of a
real bytecode image: pools, every type kind, globals, constants, natives,
debug positions and variable assignments. This page covers the notation. For
the `Asm` opcode specifically (emitting raw x86 into a function body), see
[The Asm Opcode and Inline x86](/asm-x86); that feature is layered on top of
the same assembler.

Assemble a `.hlasm` file with:

```bash
crashlink path/to/file.hlasm -a -o path/to/file.hl
```

Write any bytecode image out as `.hlasm` with:

```bash
crashlink hlasm game.hl -o game.hlasm
```

Assembling that output gives back the original file byte for byte, so you can
edit a game's bytecode as text and assemble it again. From Python, the same
two steps are `crashlink.asm.to_hlasm(code)` and
`crashlink.asm.AsmFile(text).assemble()`.

To change one function of a loaded file, use `patch <findex>` in the REPL or
Edit › Edit Function as .hlasm (Ctrl+E) in the GUI. Both show the function as a
single `.f@N` block and apply your edit when you're done. From Python, that's
`crashlink.asm.function_to_hlasm(code, func)` and
`crashlink.asm.edit_function(code, text).apply(code)`. New strings and numbers
in the edited text are added to the file's pools.

Three runnable examples live in `examples/hlasm/` in the repo, and all three
run on the real HashLink runtime.

Loading and saving bytecode validates opcode operand schemas, register and pool
references, function/type references, and branch targets. Truncated tables and
invalid counts are rejected with `MalformedBytecode`; invalid opcode schemas
raise `InvalidOpCode`. `Bytecode.is_ok()` also checks these structural invariants;
it is not a complete verifier of runtime type compatibility. Mistakes in the
`.hlasm` source itself raise `crashlink.asm.AsmError` with the line number.

## A minimal program

`examples/hlasm/hello.hlasm`:

```text
.version 5

.types
    Bytes
    Fun (t@1) -> t@0

.natives
    f@1 (t@2) std.sys_print

.f@0
    .returns t@0
    .regs
        t@0
        t@1
    .ops
        String reg1, "Hello, World!\n"
        Call1 reg0, f@1, reg1
        Ret reg0

.entrypoint f@0
```

A few things to note about the shape:

- `.types` is a flat, ordered list. Types are referred to elsewhere by
  position, one-indexed with `t@0` reserved for `Void`: the first entry here
  is `t@1`, the second `t@2`. Get the order wrong and every later type
  reference is wrong too.
- `.natives` declares external functions the runtime provides. `f@1 (t@2)
  std.sys_print` means native function index 1, typed as `t@2` (the `Fun`
  declared above), named `sys_print` from the `std` library.
- Each `.f@N` block is one function: `.returns` and `.args` describe its
  signature, `.regs` lists the type of every register it uses (`reg0`,
  `reg1`, ... in declaration order), and `.ops` is the actual opcode list.
- `.entrypoint` picks which function runs first.

Assembling this and running it with crashlink's own toy interpreter (`crashlink
file.hl -c run`, useful for small sanity checks without needing a real HL
runtime) prints `Hello, World!`.

## Branching

HashLink's conditional jumps take a target *offset*, not a label, and the
offset is relative to the instruction *after* the jump: for a jump at index
`i`, the target index is `i + offset + 1`. This is the same convention
crashlink's own CFG builder assumes when reading bytecode back
(`crashlink/decomp/cfg.py`), so getting it backwards here produces bytecode
that disassembles fine but decompiles into nonsense, or crashes a real
runtime outright.

`examples/hlasm/branch.hlasm` compares two ints and prints one of two
strings:

```text
.ops
    Int reg1, 5              # 0: a = 5
    Int reg2, 7               # 1: b = 7
    JSLt reg1, reg2, 2        # 2: if a < b, jump to op 5
    String reg3, "a is not less than b\n"  # 3: else arm
    JAlways 1                 # 4: skip the if-arm
    String reg3, "a is less than b\n"      # 5: if-arm
    Call1 reg0, f@1, reg3     # 6: print
    Ret reg0                  # 7
```

`JSLt` jumps *to* its target when the comparison holds, so the arm right
after the `JSLt` (op 3) is the *else* case, and the jump target (op 5) is the
*if* case. This inversion is exactly what the Decompilation Notes page
describes when reconstructing `if` statements from bytecode: it's not an
artifact of hand-writing this, it's how the Haxe compiler itself emits every
`if`. Decompiling this file reproduces the intended `if (a < b) { ... } else
{ ... }` shape correctly, which is a decent sanity check that the offset
arithmetic is right.

Counting offsets by hand gets error-prone quickly, so jump operands can name
a label instead. `.label <name>` on its own line in `.ops` names the index of
the next opcode, and the assembler works out the offset:

```text
.ops
    Int reg1, 5
    Int reg2, 7
    JSLt reg1, reg2, less
    String reg3, "a is not less than b\n"
    JAlways print
    .label less
    String reg3, "a is less than b\n"
    .label print
    Call1 reg0, f@1, reg3
    Ret reg0
```

Labels work for every jump operand, including `Trap` and the case list and
end of a `Switch`. Plain numeric offsets still work too.

## Loops

Every loop in HashLink bytecode opens with a `Label` opcode at the head of
the back-edge. It's not just a readability marker: the JIT's register
allocator caches vreg values in CPU registers while emitting code linearly,
and `Label` forces it to reload from the register's actual stack slot rather
than trusting whatever a previous iteration left cached. Skip it in
hand-written bytecode and the loop can silently run with stale values from a
prior iteration; see the Decompilation Notes page for the full explanation.

`examples/hlasm/loop.hlasm` prints `tick` three times:

```text
.ops
    Int reg2, 3          # 0: counter = 3
    Int reg3, 1          # 1: constant 1
    Int reg4, 0          # 2: constant 0
    Label                # 3: loop head
    String reg1, "tick\n" # 4
    Call1 reg0, f@1, reg1 # 5: print
    Sub reg2, reg2, reg3  # 6: counter -= 1
    JSLt reg4, reg2, -5   # 7: if 0 < counter, jump back to op 3 (Label)
    Ret reg0               # 8
```

Negative offsets are normal for back-edges: op 7 targets `7 + (-5) + 1 = 3`,
which is the `Label`. One easy-to-miss detail if you write a loop like this
yourself: the decompiler's loop-to-`while` conversion expects a `Bool` type
to exist somewhere in the file's `.types` table (it synthesizes boolean
conditions when rebuilding the loop), so if nothing else in your bytecode
already declares one, add a bare `Bool` entry even if no opcode here
references it directly. Without it, decompiling a hand-written loop like this
one raises a `DecompError` instead of falling back to something readable.

## Reference

A file is a list of sections. A section starts with a line beginning with `.`
and holds the indented lines under it; nesting is by indentation, one tab or
four spaces per level. Anything after `#` outside a string literal is a
comment. Sections can come in any order, but each top-level section appears
once. Tokens are separated by spaces or commas.

### Operand notation

| Written as | Means |
|---|---|
| `regN` | register N of the current function |
| `[regA, regB]` | a register list (the arguments of `CallN`, `CallMethod`, `MakeEnum`, ...) |
| `f@N`, `t@N`, `g@N` | function, type and global index |
| `s@N`, `i@N`, `d@N`, `b@N` | index into the string, int, float and bytes pools |
| `"text"` | a string, added to the string pool if it isn't there yet |
| `x"de ad be ef"` | bytes as hex, added to the bytes pool (version 5) |
| `42`, `-1`, `0x2a` | an integer; for `Int`, added to the int pool |
| `1.5`, `-0.0`, `inf`, `nan`, `f64:0x7ff0000000000001` | a float; the last form gives the exact bits. For `Float`, added to the float pool |
| `true`, `false` | the `Bool` opcode's value |
| a label name, or `[a, b]` | jump targets (see above) |

Field operands (`Field`, `SetField`, `CallMethod`, ...) are the field's index
in the object, as a plain number. Integers accept signed 32-bit values and raw
unsigned 32-bit words; the pool keeps the raw bit pattern, so `-1` reads back
as `0xffffffff`.

String literals take the escapes `\n`, `\r`, `\t`, `\0`, `\\`, `\"`,
`\u{e9}` (a Unicode code point) and `\xNN` (a raw byte: `\x41` is `A`, and
bytes from `\x80` up are kept as raw bytes, for strings that aren't valid
UTF-8). Other characters, including non-ASCII text, can be written directly.

### Top-level sections

| Section | Contents |
|---|---|
| `.version N` | bytecode version (required). The bytes pool needs 5, constants need 4, assigns need 3 |
| `.debugfiles` | debug file names, one string per line. Its presence turns debug info on |
| `.strings`, `.ints`, `.floats`, `.bytes` | pool entries in order, one per line. Optional: literals used elsewhere are added after these |
| `.types` | the type table, see below |
| `.globals` | the type of each global in order, `t@N` per line (`g@0` first) |
| `.natives` | `f@N (t@T) lib.name`, or `f@N (t@T) "lib" "name"` |
| `.f@N` | one function, see below. Functions are stored in the order they appear |
| `.constants` | `g@N` followed by one pool index per field of that global's object: into ints, floats or strings depending on the field's type (`i@N`, `d@N`, `s@N` or a string literal also work) |
| `.entrypoint f@N` | the function that runs first (required) |

### Types

`t@0` is always `Void` and isn't listed, so the first line of `.types` is
`t@1`. Write `.types novoid` to list `t@0` yourself as the first line.

One-line types:

- `Void`, `U8`, `U16`, `I32`, `I64`, `F32`, `F64`, `Bool`, `Bytes`, `Dyn`,
  `Array`, `Type`, `DynObj`, `GUID`
- `Fun (t@1, t@2) -> t@0` and `Method (...) -> t@0`
- `Ref t@N`, `Null t@N`, `Packed t@N`
- `Abstract "name"`

Classes, structs, enums and virtuals are blocks:

```text
.types
    I32                        # t@1
    .obj "Point"               # t@2 (.struct for a struct)
        .super t@5             # optional
        .global g@0            # optional: the global holding the class object
        .fields
            "x" t@1
            "y" t@1
        .protos                # methods: name, function, virtual slot (-1 if none)
            "length" f@4 -1
        .bindings              # field index bound to a function
            0 f@7
    .enum "Mode"               # t@3
        .global g@1            # optional
        "Off"
        "On" (t@1)             # a construct with parameters
    .virtual                   # t@4
        "x" t@1
```

### Functions

```text
.f@3
    .type t@6                  # the function's Fun type
    .regs t@1 t@1 t@2          # register types, reg0 first; one per line also works
    .assigns                   # optional (debug info): variable name, opcode index
        "sum" 2
    .ops
        Add reg2, reg0, reg1  @0:12
        Ret reg2
```

Instead of `.type`, a function can give `.returns t@N` and `.args N` (how many
leading registers are parameters); the assembler then finds or adds the
matching `Fun` type.

With debug info on, `@F:L` at the end of an opcode sets its source position:
debug file index `F` (or a quoted file name) and line `L`. The position
carries over to the following opcodes until the next `@`.

`crashlink hlasm` output uses all of this, and is the best reference for how a
real compiler's output looks in `.hlasm`.

## A note on testing hand-written bytecode

crashlink ships a small interpreter (`crashlink/interp`) that can run simple
bytecode without a real HashLink install, useful for quick checks like the
`hello.hlasm` example above. It's genuinely partial, though: it implements
`Mov`, `Ret`, `Call*`, `GetGlobal`/`SetGlobal`, `String`, `NullCheck`/`JNull`,
and a handful of others, but not `Int`, `Sub`, or comparison jumps like
`JSLt`. Anything using arithmetic or numeric branching will assemble and run
without error but silently skip those opcodes rather than execute them, which
looks like success and isn't. For bytecode past the `Mov`/`Call`/`String`
level, decompiling it back and checking the reconstructed control flow (as
above) is the more reliable check available without a full `hl` runtime.
