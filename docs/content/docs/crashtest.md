---
slug: /crashtest
title: The crashtest Regression Suite
---

crashtest is crashlink's regression suite for the decompiler. Rather than asserting against hand-written expected output, it checks a stronger property: that decompiling a piece of bytecode and recompiling the result gets you something semantically equivalent to what you started with.

## What it measures

For each test case, crashtest decompiles the original HashLink bytecode to Haxe, then hands that generated Haxe to the real `haxe` compiler and recompiles it back to bytecode. It then compares the two bytecode files method by method, scoring opcode-level similarity between the original and the recompiled version (see `_fmt_operand` and the comparison logic in `crashtest/run.py`). A method that decompiled and recompiled cleanly should produce nearly identical opcodes; drift shows where the decompiler folded, reordered, or misrepresented control flow.

The pass/fail line is `SIMILARITY_THRESHOLD = 0.90` in `crashtest/models.py`. Any case whose overall opcode similarity comes in under 90% is marked a failure (`Run.avg_similarity()` in the same file aggregates this across all cases in a run). The result types (`Run`, `TestCase`, `OpcodeComparison`, `MethodComparison`) also carry the original source, decompiled source, IR, and per-method disassembly, so a failing case can be inspected down to the actual opcode diff rather than just a pass/fail bit.

## Running it

From the repo root:

```sh
crashtest auto
# or
python -m crashtest auto
```

This must be run from the repo root, not from inside `crashtest/`, since it locates test fixtures relative to it. `just test` runs crashtest as part of the full test suite alongside pytest.

## Reading the results

Every run is saved with its git commit, timestamp, and status, and published to the [crashtest results](/results) page on this site. That page lists every run with its commit, pass/fail status, and average similarity score; click into one to see per-case original source, decompiled output, IR, and the opcode diff for any method that didn't recompile cleanly. It's usually the fastest way to see whether a change regressed the decompiler, and where.
