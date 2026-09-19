---
slug: /crashtest
title: The crashtest Regression Suite
---

crashtest recompiles decompiled Haxe and executes both bytecode images on the real HashLink runtime. It checks the observable behavior of deterministic corpus paths, not equivalence of every possible execution.

## What it measures

Each case is decompiled and recompiled with `haxe`. Both `.hl` files run twice in fresh working directories, with closed stdin and bounded execution time/output. A passing case requires successful, repeatable, matching stdout, stderr and exit status. Fixtures expose return values, mutations and caught exceptions through output. Missing tools, compilation errors, uncaught exceptions, timeouts and nondeterminism fail the case rather than producing a success without evidence.

Opcode-name similarity remains a diagnostic: changing constants or operands can leave that score at 100%. It no longer controls pass/fail. Reports retain original/recompiled execution observations alongside source, IR and disassembly. Only the current module's Haxe `trace` line prefixes are normalized; other output differences are preserved.

The shipped `Random` and `Closure` fixtures are explicitly exempt from behavioral execution because they print random values or process-dependent function identities. Reports show **EXEMPT**, not PASS, with a reason. Decompilation, recompilation, and opcode comparison still run, and their failures still fail the case. Exemptions apply only to the resolved files under `tests/haxe`, not arbitrary same-named programs. Other nondeterministic executions continue to fail closed.

## Running it

Install `haxe` and the HashLink runtime (`hl` on PATH, or an absolute executable path in `HL_RUNTIME`). This does not require the deprecated `pyhl` bridge. From the repo root:

```sh
crashtest auto
# or
python -m crashtest auto
```

`python -m crashtest run Arithmetic --no-decompiled` runs a single case; an explicit `.hx` path with a sibling `.hl` artifact is also accepted. The CLI exits nonzero when a case fails. `just test` runs pytest; use the commands above to run the full crashtest corpus.

## Reproducible quality corpus

`tests/quality/` contains a small self-contained behavioral corpus and a native recovery fixture. Build them with:

```sh
python tests/quality/build.py --out /tmp/crashlink-quality --native \
  --hl-source /path/to/hashlink --hl-library-dir /path/to/libhl-directory
HL_RUNTIME=/path/to/hl CRASHLINK_QUALITY_DIR=/tmp/crashlink-quality \
  CRASHLINK_REQUIRE_QUALITY=1 pytest -q tests/test_crashtest_behavior.py tests/test_dehlc_native_corpus.py
```

Native coverage uses unstripped x86-64 Linux ELF at `-O0` and `-O2`. Tests compare the original native executable with bytecode execution and check recovered signatures, operation families and machine addresses. They do not claim faithful executable reconstruction, or coverage of stripped images, PE or aarch64. CI builds this corpus and requires it; no gitignored helpers are needed. The larger optional local lifting-accuracy corpus remains useful for broader measurement.

These executions use temporary working directories, not a security sandbox. Run only trusted fixtures.

## Reading the results

Every run is saved with its git commit, timestamp, and status, and published to the [crashtest results](/results) page on this site. That page lists every run with its commit, pass/fail status, and average similarity score; click into one to see per-case original source, decompiled output, IR, and the opcode diff for any method that didn't recompile cleanly. It's usually the fastest way to see whether a change regressed the decompiler, and where.
