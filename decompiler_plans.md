# Decompiler weakness plan

Last crashtest run: `20260616211014` — Major failures (21.6%).
This file records the concrete weaknesses exposed by the new test cases and
proposes optimizer-level fixes.

## What just got fixed

- `IRForEachLoopOptimizer` now:
  - removes the index temporary's `idx = 0` initializer even when it is
    separated from the loop by array-expression temporaries;
  - inlines single-use array temporaries into the `for (...)` header;
  - only converts loops whose index temporary is compiler-generated.
- `pseudo.py` no longer pre-declares `for`-each element locals, so loops render
  as `for (i in expr)` instead of with a spurious `var i = 0`.
- `LoopForEach` now recompiles with opcode similarity `1.0`.

## New test cases

| Case | Purpose | Status in latest run |
|------|---------|----------------------|
| `ArrayBoundsConst` | Constant-index reads (`a[0]`, `a[2]`) through HashLink's length guard. | sim `0.932`, passed |
| `ArrayBoundsVar` | Variable-index read (`a[i]`). | sim `1.0`, passed |
| `ArrayBoundsWrite` | Constant-index writes (`a[0] = 99`, `a[2] = a[1]`). | sim `0.740`, **failed** |
| `ForEachValues` | `for (v in [1,2,3,4])` over an array literal. | sim `0.893`, **failed** |

## Planned fixes

### 1. Recover constant indexes in bounds-checked array reads

**Seen in:** `ArrayBoundsConst`, `ArrayAccezz`

HashLink lowers `a[C]` as:

```text
idx_reg = C
if (idx_reg >= a.length) {
    value = 0
} else {
    value = a.bytes[??? << 2]
}
```

The catch is that the compiler often loads the constant `C` into the *same*
register that will hold the result, then reuses that register as the index
scratchpad in the `else` branch.  After our SSA-like local splitting the index
and the result become two different `IRLocal` objects, so the current
`IRArrayPatternOptimizer._try_array_access` cannot tell that the index is a
constant and emits `value = a[value]`.

**Plan:**
1. Store the original register index on every `IRLocal` (set in `_lift` and
   preserved across `_split_local`).
2. In `IRArrayPatternOptimizer`, when `_try_array_access` sees a bounds check,
   look for an immediately preceding `idx_temp = const` that targets the same
   register as the array-access index expression (or as the result value if the
   compiler reused the result register).
3. Replace the conditional with a direct `value = a[const]` using the recovered
   constant.

### 2. Recognise array literals built with temp-loaded elements

**Seen in:** `ArrayBoundsWrite`

`IRArrayPatternOptimizer._try_array_literal` already matches:

```text
bytes = alloc_bytes(N * 4)
idx = 0
bytes[idx << 2] = value0
idx++
bytes[idx << 2] = value1
idx++
...
arr = allocI32(bytes, count)
```

but the Haxe compiler currently emits an extra `elem_temp = value` immediately
before each store:

```text
bytes[idx << 2] = 10
idx++
elem_temp = 20
bytes[idx << 2] = elem_temp
idx++
...
```

The matcher stops at the extra assignment and the literal is not recovered.

**Plan:** relax `_try_array_literal` so that each store may be preceded by a
single `elem_temp = expr` assignment, and treat `expr` (or `elem_temp`) as the
element value.

### 3. Simplify write bounds checks (`__expand`)

**Seen in:** `ArrayBoundsWrite`

HashLink inserts an explicit `__expand` call before an out-of-bounds write:

```text
if (C >= a.length) {
    a.__expand(C)
}
a[C] = value
```

We already emit a high-level `a[C] = value` for the store itself; the
conditional `__expand` block is dead weight that makes the output unreadable and
hurts recompile similarity.

**Plan:** add an `IRArrayWriteBoundsOptimizer` (or extend
`IRArrayPatternOptimizer`) that recognises the above pattern around a
high-level array-store assignment and deletes the conditional guard.  For
constant `C` this is always safe because `a[C] = value` semantically implies the
same expansion.  Variable indexes need the same treatment but with care to keep
side-effect ordering.

### 4. Re-roll unrolled loops over array literals

**Seen in:** `ForEachValues`

When the iterable is a constant array literal, Haxe unrolls the `for`-each loop
at compile time:

```text
v = 1; sum += v;
v = 2; sum += v;
v = 3; sum += v;
v = 4; sum += v;
```

**Plan:** add an `IRUnrolledLoopOptimizer` that looks for a sequence of
statements repeating the same body with a loop variable assigned successive
elements of an `IRArrayLiteral`.  Rewrite it as a single `IRForEachLoop` over
that literal.  This is lower priority because the unrolled form is semantically
correct and often recompiles to similar bytecode; the main value is readability.

### 5. Existing failing cases to revisit

| Case | Likely cause | Plan |
|------|--------------|------|
| `Branch`, `BranchNested`, `Random`, `SimpleIf` | Short-circuit / ternary expression lowering (`a && b`, `a || b`, `cond ? x : y`) | Lift `IRConditional` used as an expression back into expression form where all branches assign to the same temp. |
| `StringInterp` | String concatenation lowered to `StringBuf`/multiple appends | Extend `IRStringConcatFolder` to recognise `StringBuf` patterns, or lift trace-formatting calls. |
| `LoopNested` | `break`/`continue` lower to primitive jumps | Improve `IRPrimitiveJumpLifter` / loop structure recovery. |
| `VirtualClosure` | Virtual dispatch and explicit type annotations | Revisit type inference in `pseudo.py`; avoid explicit types when the original source omitted them. |

## Suggested implementation order

1. Add register-index tracking to `IRLocal` (needed by #1).
2. Extend `IRArrayPatternOptimizer` for constant-index reads (#1).
3. Extend `IRArrayPatternOptimizer` for temp-loaded array literals (#2) and
   write bounds guards (#3).
4. Add `IRUnrolledLoopOptimizer` (#4).
5. Tackle the remaining control-flow / string / closure cases (#5).

After each step, rebuild the test samples with `just build-tests`, run
`crashtest auto`, and update this plan with what actually changed.
