---
slug: /equivalence
title: Behavioural Signatures
---

`crashlink.equivalence` reduces a function to a hash of what it does. **Equal signatures prove two functions behave the same. Different signatures prove nothing**: the hash is a canonical form, and two equivalent functions can still be written in ways it does not unify.

```python
from crashlink import Bytecode
from crashlink.equivalence import signature, equivalent

a, b = Bytecode.from_path("original.hl"), Bytecode.from_path("recompiled.hl")
sig = signature(a, a.fn(a.entrypoint.value))   # Signature(digest=...) or Signature(None, reason)
equivalent(a, fa, b, fb)                       # True only when proven
```

## What a signature ignores

Register numbers and reuse, `Mov` copies, the order of independent pure computations, dead pure values, where and how constants are materialised, integer arithmetic (reduced to `c + k1*x1 + ...` in wrapping arithmetic, so `(x + 1 + 1) - (x + 1)` is `1`) and float constant folding, jump layout and branch polarity (`JSLt` against `JSGte` with swapped targets), conditions decided by constants and `x == null` against a null test, the order objects are allocated and filled in before first use, writes to address-taken registers (held back until a reference can observe them; `itos`/`ftos` out-parameters are write-only), string concatenation chains (`"" + a + b`), and the numbering of types, functions, globals and fields (all replaced by names). A closure lifted into its own function (including the `__anon_N` functions decompiled output declares) is identified by its own signature, not its name. A virtual call to a method no class below the receiver overrides is the direct call, and calling a closure over a known function is calling that function.

## What it keeps

In order: every call, store, allocation and every check that can throw (null dereference, checked cast). Loads depend on the effects before them, so they never move across a store. `strict=False` drops the checks that can throw and proves equality for runs in which none fails. `ignore_positions` (on by default) makes the source file and line stored in `haxe.PosInfos` irrelevant, because recompiling always moves them; pass `ignore_positions=False` to keep them.

## How it works

1. `lift` rebuilds the control-flow graph: jump-only blocks are threaded, straight-line blocks merged, each conditional is rewritten onto one of a complementary pair of predicates with its successors ordered by it, and blocks are numbered by a depth-first walk in that order.
2. `build` runs the function symbolically into a value graph. Registers become SSA values (Braun et al.), memory becomes a single chain of effects, pure values are shared by structure.
3. `digest` hashes the graph. Values that depend on themselves around a loop (phis) are hashed by colour refinement, which for ordered, labelled graphs is exactly bisimulation: equal digests mean the values unfold to the same infinite term.

## Exceptions

A handler starts from "one of the histories the protected block can have when something is raised". A register the block writes and the handler reads is the value written last before that point: it is hashed as the set of (history, value) pairs, so moving a write across a call that may throw changes the signature.

## Limits

A function is given no signature (and never compares equal) when it uses inline assembly, has irreducible control flow, when a block can run both inside and outside one `try`, when a catch handler has several entries, or when something it refers to has no stable name. A function's own type is part of its signature. Calls are compared by callee name, so the callees' own signatures have to be compared as well. Integer division by zero is treated as defined. Unrelated mutations that alias (two names for one object) are ordered conservatively, which only costs completeness.

`python -m pytest tests/test_equivalence.py` checks both directions on compiled Haxe: pairs that differ only in names, temporaries, folding, operand order or branch layout must match; pairs that differ in a constant, operator, call order, a dropped store or a changed loop bound must not.
