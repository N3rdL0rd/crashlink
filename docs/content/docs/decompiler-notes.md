---
slug: /decompiler
title: Decompilation Notes
---

# Decompilation Notes

## Introduction

This document contains notes on what code patterns compile to in the HashLink bytecode. It is intended to be a reference both for the implementation of the crashlink decompiler and for anyone interested in reading and understanding HL opcodes.

## Registers

A register is a strictly typed single slot for data at runtime. Every function has a list of registers that it uses to store data - they store every value that is used in the function as a local. Register names can be inferred by the `assigns` debug field, which stores opcode indexes that correspond to assigning a variable. Sometimes, `assigns` will contain negative opcode indices - this means that the variable names being referred to are arguments. If a function is not static, then the first argument will always be `this`, and there will be no corresponding assignment for it.

## If Statements

Sample: `tests/haxe/If.hx`

In the case of an empty if statement:

```hx
var a = 500;
if (a > 400) {
    
}
```

The following is generated:

![Empty If Statement](/img/decompiler/empty_if.png)

Presumably to avoid implementing additional logic for empty if statements, the result of the condition is always stored in a register, even if it is not used. This only applies to if statements with empty bodies. Note that `reg2` is `Void` here, just discarding the result.

As for any other programming language's control flow graphs, if statements make a sort of "diamond" shape in the bytecode - the conditional jump splits the flow into two paths, and at some point they merge back together to one node. crashlink uses a simple approach of following the two control flow paths and finding where they merge to generate IR if conditional blocks.

## Loops

Sample: `tests/haxe/LoopWhile.hx`

This sample is a simple while loop. Its control-flow graph shows the shape crashlink actually looks for: a `Label` node with a back edge from later in the function, forming a cycle that dominates itself.

![CFG for LoopWhile.main](/img/decompiler/cfg_loopwhile.svg)

Notably, all loops in HashLink start with a `Label` opcode. It's not entirely known why this is the case, but it's incredibly useful to us as it allows us to easily identify loops, since the `Label` opcode is only used at the beginning of a loop and is not generated anywhere else by the Haxe compiler.

:::note
The reason for `Label` is now understood: it's a **JIT requirement**, not (just) a compiler convenience. The JIT's register allocator caches vreg values in CPU registers while emitting code linearly; a back-edge into a loop head would use those stale cached registers for the next iteration. `OLabel` calls `discard_regs(ctx, false)`, forcing the allocator to reload vregs from their stack slots. A hand-written loop with a back-edge and no `Label` at its head is **silently miscompiled**: loop variables keep values clobbered by the previous iteration's body. If you emit loops in hand-written bytecode, always put a `Label` at the loop head.
:::

:::warning
Although HashLink is a Haxe-only bytecode target and the Haxe compiler is the only compiler that generates HashLink bytecode, it is not guaranteed that the `Label` opcode will always be at the beginning of a loop - and if other languages start targeting HashLink, this assumption may no longer hold true. Long-term, it would always be best to use the CFG to identify loops more robustly.
:::

See that warning right above this sentence? crashlink ignores it (YOLO)! crashlink handles loops by following these simple steps:

- Look for `Label` opcodes
- Once one is encountered, perform an isolated abstract lift to IR for the current block (the condition)
- Find all other paths down the CFG that will jump back up to this Label
- Lift all nodes in these paths to IR

And just like that, we can handle a basic loop with no optimizations!

```txt
crashlink> ir 22
<IRBlock:
[<IRAssign: <IRLocal: b I32> = <IRConst: 69> (I32)>,
        <IRBlock:
        [<IRPrimitiveLoop: cond -> <IRBlock:
                [<IRAssign: <IRLocal: reg3 I32> = <IRConst: 5> (I32)>,
                        <IRPrimitiveJump: <Opcode: JSGte {'a': 3, 'b': 0, 'offset': 4}>>]>
                 body -> <IRBlock:
                [<IRAssign: <IRLocal: reg3 I32> = <IRConst: 2> (I32)>,
                        <IRAssign: <IRLocal: b I32> = <IRArithmetic: <IRLocal: b I32> - <IRLocal: reg3 I32>> (I32)>,
                        <IRAssign: <IRLocal: b I32> = <IRLocal: b I32> (I32)>,
                        <IRBlock>]>>]>]>
```

## Array Literals

Sample: `tests/haxe/ArrayAccezz.hx`

```hx
static function array() {
    return [1, 2, 3];
}
```

A fixed-size `Array<Int>` literal like this one doesn't compile to any single "make array" opcode. Instead the Haxe compiler lowers it to a raw byte buffer: an `alloc_bytes` native call sized to `element_count * element_size`, followed by one store per element (each index pre-shifted, e.g. `<< 2` for `I32`/`F32`, `<< 3` for `F64`, `<< 1` for `UI16`), followed by a call to a typed-array allocator native (`allocI32`, `allocF32`, `allocF64`, or `allocUI16`) that wraps the bytes into an `hl.types.ArrayBase` subtype.

`IRArrayPatternOptimizer` in `crashlink/decomp/opt/arrays.py` reverses this: it walks forward from the `alloc_bytes` assignment, matches a run of `bytes[idx << shift] = value; idx++` stores (accepting a handful of equivalent shapes, since the compiler sometimes hoists the shifted index or the store value into their own temporaries first), and once the store count and the following `alloc*` call agree, replaces the whole run with a single `IRArrayLiteral`. The shift amount doubles as a type tag - `_ALLOC_SHIFTS` maps each `alloc*` name back to the expected shift, so a mismatched shift (wrong element size) blocks the fold rather than misreading the buffer.

Object-element arrays like `[new TestClass(), new TestClass()]` take a different route entirely: `alloc_array(type, size)` allocates a boxed `Array`, individual `arr[i] = expr` stores populate it (optionally preceded by the element's own constructor call as a separate statement), and the whole thing is wrapped by `ArrayObj.anon(arr)`. `IRArrayPatternOptimizer._try_array_obj_literal` looks for exactly this alloc/store/wrap sequence and, when it finds it, also inlines a preceding single-use `var9 = new TestClass()` into the literal slot itself so element construction order survives the fold.

## String Concatenation

Sample: `tests/haxe/StringConcat.hx`

```hx
var a = "hello" + "world";
var c = 3;
var b = "number : " + c;
```

Every `+` between strings (or a string and a value that needs stringifying) compiles to a call to `String.__add__`, not an opcode of its own - `"a" + "b" + "c"` becomes nested `__add__(__add__("a", "b"), "c")` calls, which after temp-elimination usually show up as a straight-line chain: `temp = "a"; temp = __add__(temp, "b"); temp = __add__(temp, "c");`. `IRStringConcatFolder` in `crashlink/decomp/opt/strings.py` walks that chain and collapses it back into one nested `__add__` expression at the use site so pseudo can print it with Haxe's `+` operator instead of a chain of temp assignments.

Concatenating a non-string value (`"number : " + c` where `c` is an `Int`) goes through an extra step first: HashLink calls `itos(value, ref(value))` (or `ftos` for floats) to render the number into a byte buffer and get its length back through the ref argument, then wraps that buffer with `String.__alloc__(bytes, length)` before it ever reaches `__add__`. `IRStringIntConcatOptimizer` recognizes `__alloc__(itos(x, &x), x)` - matching the ref argument back to the same local used as the value - and collapses the whole thing down to the bare integer local, so the fold above sees a normal `__add__(str, intLocal)` instead of the conversion plumbing.

## Switch Statements

Sample: `tests/haxe/Switch.hx`

```hx
var a = 3;
var b = switch (a) {
    case 0: a * 2;
    case 3: a - 1;
    default: a << 2;
}
```

An integer switch with a small dense range of cases lowers to HashLink's native `Switch` opcode (a jump table), which crashlink lifts directly to `IRSwitch`. The CFG shows why this case is easy: `Switch` is a genuine N-way branch, one edge per case plus a default, all converging on the same successor.

![CFG for Switch.main](/img/decompiler/cfg_switch.svg)

But a sparse or negative-valued case set - not dense enough to justify a table - compiles instead to a chain of nested `if (x != c1) { if (x != c2) { ... } else {...} } else {...}` equality checks. `IRIntSwitchOptimizer` in `crashlink/decomp/opt/switches.py` walks that conditional chain, and as long as every link compares the same local against a distinct integer constant, re-raises it into a single `IRSwitch` with the original cases and the innermost unmatched branch as `default`.

String switches lower even further from the source shape: HashLink first null-checks the scrutinee, then guards on `s.length` before ever comparing content, then chains `std.string_compare(s.bytes, "case", len) == 0` calls for each case, falling through to the next comparison on a nonzero result. `IRStringSwitchOptimizer` matches that null-check/length-guard/compare-chain shape and rebuilds an `IRSwitch` keyed by the literal case strings, stitching together cases that got split across sibling statements by the CFG lifter (a `string_compare` chain doesn't structurally nest the same way an int-switch's `if` chain does).

## Enum-Pattern Switches

Sample: `tests/haxe/Enums.hx`

```hx
enum Color {
  Red;
  Green;
  Blue;
  Rgb(r:Int, g:Int, b:Int);
}
...
switch (c) {
    case Red: trace("red");
    case Rgb(r, g, b): trace("Color had a red value of " + r);
    ...
}
```

Haxe enum values are HashLink `Enum` objects tagged with a constructor index; switching on one lowers to an `EnumIndex` opcode extracting that index, followed by an ordinary integer `Switch` on it. Without further processing this decompiles as `switch (enumIndex(c)) { case 0: ...; case 3: ...; }` - correct, but unreadable, since the case labels are bare integers instead of constructor names.

`IREnumSwitchOptimizer` in `crashlink/decomp/opt/switches.py` looks for exactly the `idx = EnumIndex(value); switch (idx) { ... }` pair, resolves the enum's `Type.definition` to get its `constructs` list, and rewrites each integer case constant to the matching constructor's name (`Red`, `Green`, `Rgb`, ...), producing `switch (c) { case Red: ...; case Rgb: ...; }`. Recovering the constructor's bound parameters (`Rgb(r, g, b)` rather than just `Rgb`) is a separate step: parameter reads lower to `r = value.param0` field-style accesses inside the case body, which pseudo recognizes and folds into the case pattern itself.

See also: [The Asm Opcode and Inline x86](/asm-x86) for `Asm`/inline-x86-machine-code opcodes, which crashlink cannot decompile past.
