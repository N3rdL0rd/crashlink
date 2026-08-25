---
slug: /hlasm
title: Writing HashLink Bytecode by Hand
---

# Writing HashLink Bytecode by Hand

crashlink has its own text notation for HashLink bytecode: `.hlasm`. It's not
a decompiler output format, it's an assembler input format, meant for writing
bytecode directly rather than compiling it from Haxe. This page covers the
plain notation: types, natives, functions, and ordinary control flow. For the
`Asm` opcode specifically (emitting raw x86 into a function body), see
[The Asm Opcode and Inline x86](/asm-x86); that's a different, much more
niche feature layered on top of the same assembler.

Assemble a `.hlasm` file with:

```bash
crashlink path/to/file.hlasm -a -o path/to/file.hl
```

Three runnable examples live in `examples/hlasm/` in the repo. Each was
assembled and checked, both by disassembling the result to confirm the op
sequence matches what was intended and by running it through crashlink's own
decompiler to confirm the control flow reconstructs correctly.

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
