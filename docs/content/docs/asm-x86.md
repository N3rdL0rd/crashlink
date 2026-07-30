---
slug: /asm-x86
title: The Asm Opcode and Inline x86
---

# The `Asm` Opcode and Inline x86

HashLink bytecode has an opcode that almost no compiler output contains: **`Asm`**
(opcode 100). It lets a `.hl` function emit *raw x86 machine code* directly into the
JIT's instruction stream. HashLink has no bytecode verifier and JITs everything into
**RWX memory**, so this is a fully supported arbitrary-native-code primitive that no
HL-level decompiler (including crashlink) can see through: it disassembles as an
opaque list of `Asm` ops.

`Asm` has three operands: `Asm mode, value, reg`. The mode decides what the JIT does
with it (see `src/jit.c` in the hashlink repo):

| Mode | Name | Effect |
|---|---|---|
| 0 | byte output | Emit `value` as one raw byte into the code buffer at the current position. |
| 1 | scratch CPU reg | Mark CPU register `value` as clobbered in the JIT's register allocator. |
| 2 | read VM reg | Copy VM register `reg - 1`'s value **into** CPU register `value` (reads args). |
| 3 | write VM reg | Copy CPU register `value` **into** VM register `reg - 1` (writes results). |
| 4 | naked | **Reset the code buffer back to the function's entry point**, erasing the prologue the JIT already emitted. Must be the *first* opcode, and the function must have *no local variables* (args included, unless they arrive on the stack). |

## Naked functions

The useful combination is **mode 4 followed by mode-0 bytes**: the function's whole
body becomes your raw machine code.

Rules (enforced by `hl_fatal` at JIT time):

- The `Asm` mode-4 op must be the first opcode of the function.
- `totalRegsSize` must be 0, so declare **no `.regs`** and give the function **no
  register-passed arguments**. On Linux/macOS (SysV AMD64) HL passes up to 6
  integer args in `RDI, RSI, RDX, RCX, R8, R9` and floats in `XMM0..5`, so any
  argument lands in the local frame and trips the check; on Windows x64 all args
  arrive on the stack and don't count against `totalRegsSize`.
- There is no prologue/epilogue. You are entered with a bare return address on the
  stack. Don't touch `RSP`/`RBP` unless you know what you're doing, keep the stack
  balanced, and end with a `ret` (0xC3) you emitted yourself.
- Return values follow the C ABI: integers/pointers in `RAX`, floats in `XMM0`.
  `Bytes`/`String`/objects are just pointers, so returning `RAX` works for them.
- All caller-saved registers are yours to clobber (the JIT assumes calls clobber
  them). Avoid `RBX`, `R12`-`R15` unless you save/restore them.

Because JIT pages are mapped `PROT_READ | PROT_WRITE | PROT_EXEC` (`src/gc.c`),
the emitted code can **modify itself at runtime**, e.g. keep state in bytes that
follow the `ret`, increment immediates in its own instructions, or decrypt a later
part of the function on first entry.

## Writing `Asm` code in `.hlasm`

crashlink's assembler has three pseudo-ops plus a mnemonic layer (requires the
optional `keystone-engine` dependency: `pip install crashlink[extras]`):

```text
.f@1
    .returns t@1        # Bytes
    .regs               # MUST be empty for a naked function
    .ops
        AsmNaked        # Asm mode 4: erase the prologue, we're naked now
        X86 lea rcx, [rip+cnt]
        X86 inc dword [rcx]
        X86 mov eax, [rcx]
        X86 ret
cnt:
        X86 dd 0        # data: 4 zero bytes living in the code stream

        AsmByte 0x90    # raw byte, if you want to be explicit
        Asm 0, 144, reg0  # ...which is exactly equivalent to this
```

- `AsmNaked`: emits `Asm 4, 0, reg0`.
- `AsmByte <v>`: emits a single raw byte (`Asm 0, <v>, reg0`).
- `X86 <line>`: one line of x86-64 assembly, assembled with
  [keystone-engine](https://www.keystone-engine.org/) (Intel syntax). Consecutive
  `X86` lines form one block.
- `name:` a label inside an `X86` block. Labels work in branches
  (`jnz my_loop`) and in RIP-relative operands (`[rip+my_data]`), including simple
  arithmetic (`[rip+buf+24]`). Branches and displacements are resolved for you.
- Data directives inside an `X86` block: `db 1, 2, 3`, `dd 0`, `dq 0x1122`,
  `times 26 db 0`. Data placed after a `ret` is never executed but lives in the
  same RWX page, which is perfect for self-modifying state.
- Anything keystone accepts works, with two syntax notes: write operand sizes as
  `dword [rcx]` or `dword ptr [rcx]` (both fine), and keystone 0.9.2 rejects the
  NASM directives `dd`/`times`, which is why crashlink implements those itself.

Under the hood every assembled byte becomes one `Asm 0, <byte>, reg0` opcode, so
the resulting `.hl` file is 100% valid HashLink bytecode that any stock `hl`
runtime will execute.

## Worked example: a self-modifying counter

`examples/asm/counter.hlasm` (build with `crashlink examples/asm/counter.hlasm -a -o counter.hl`)
defines a naked `counter() -> Bytes` that:

1. increments a `dd` counter stored in its own code page,
2. converts the value to a NUL-terminated UTF-16 decimal string in a static
   buffer that also lives in the code page (HL strings are UTF-16, which is what
   `std.sys_print` expects),
3. returns a pointer to the string in `RAX`.

Calling it three times prints `1`, `2`, `3`. The state persists between calls
*because the code modifies itself*. Disassembling the file shows only:

```text
f@1: 91 ops
    0: Asm {mode: 4, ...}
    1: Asm {mode: 0, value: 72}     # 0x48
    2: Asm {mode: 0, value: 141}    # 0x8D
  ...
```

## Caveats

- The JIT target is x86/x86-64 only, so `Asm` bytecode is inherently
  architecture-specific (as is the rest of the `hl` JIT).
- A malformed naked function won't be rejected at load time: it crashes or
  corrupts the process at JIT or run time. There is no safety net.
- `hl --version` matters little here, but the surrounding file format does:
  `Asm` exists in all bytecode versions crashlink supports.

## Hybrid functions (register bridge)

Mode 4 isn't the only option. Without it, the function keeps its normal JIT
prologue and can take arguments. Modes 2/3 then bridge the HL register file
and the CPU registers, and a real `Ret` opcode provides the epilogue:

```text
.f@1
    .returns t@2        # I32
    .args 2
    .regs
        t@2             # reg0: a
        t@2             # reg1: b
        t@2             # reg2: result
    .ops
        Asm 2, 0, reg1  # RAX = reg0 (a)      (mode 2: cpu <- vreg p3-1)
        Asm 2, 1, reg2  # RCX = reg1 (b)
        X86 add eax, ecx
        Asm 3, 0, reg3  # reg2 = RAX          (mode 3: vreg p3-1 <- cpu)
        Ret reg2
```

CPU register numbering (the `CpuReg` enum in `src/jit.c`):
`RAX=0 RCX=1 RDX=2 RBX=3 RSP=4 RBP=5 RSI=6 RDI=7 R8=8 ... R15=15`.
The `reg` operand is one-based: `reg1` refers to vreg 0. Reads/writes go through
the vreg's *stack slot*, which the prologue fills for register-passed args.
Read args before touching anything and you'll be fine. Avoid callee-saved
registers (`RBX`, `R12`-`R15`) in your x86; the JIT's epilogue only restores
what the prologue saved.

Two layout rules for inline data:

- RIP-relative labels only resolve within **one contiguous run of `X86` lines**.
  A non-`X86` op (like `Ret`) in the middle splits the block, because the JIT
  emits code for it, and the assembler can't know how many bytes.
- Therefore data must live *inside* the block, guarded from execution with a
  jump: `X86 jmp over` / `data:` / `X86 dd 0` / `over:` / `X86 nop`, with the
  `Asm`/`Ret` glue after it. And keep writes inside the declared data bytes:
  whatever follows your block in memory is live JIT code.

`examples/asm/add.hlasm` is the full version of the snippet above, with the
itos-style print helper wired in so you can build and run it end to end.
