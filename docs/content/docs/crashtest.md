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

## hxsmith: random-program fuzzing

`hxsmith` generates random, deterministic, terminating Haxe programs that print their own state, then pushes each through the decompiler and places it on a quality ladder. It finds decompiler bugs without anyone writing the test, and measures progress as a distribution instead of a pass/fail.

```sh
HL_RUNTIME=/path/to/hl python -m crashtest hxsmith run 200 -j 8     # fuzz seeds 0..199
python -m crashtest hxsmith check 17                                  # one seed, with artifacts
python -m crashtest hxsmith gen 17                                    # print the program for a seed
python -m crashtest hxsmith lint 400                                  # are the generated programs valid tests? (no decompiling)
python -m crashtest hxsmith features                                  # list the language features
python -m crashtest hxsmith coverage                                  # which Haxe AST constructors are generated
```

`--features a,b` restricts a run to some features and `--exclude a,b` drops some; the same seed and feature set always give the same program. `--swarm 0.3` enables each feature per seed with that probability (swarm testing): programs stay small, and the per-feature table in the report becomes meaningful, because a feature absent from every failing program is not the cause. With all features in every program (the default), each program hits some bug and the histogram is flat.

### The ladder

Each program lands on the highest rung it reaches:

| Rung | Meaning |
|---|---|
| 0 `CRASH` | the decompiler raised, hung, ran out of memory, or emitted a `decompilation failed` stub |
| 1 `UNLIFTED` | the output contains `UNLIFTED OPCODE` markers |
| 2 `NO_COMPILE` | the decompiled project does not compile with Haxe |
| 3 `DIVERGES` | it compiles but the real runtime shows different stdout, stderr or exit status |
| 4 `BEHAVES` | same observable behaviour |
| 5 `IDENTICAL` | same behaviour and every user function recompiles to the same opcode sequence |

The report shows the histogram, failures clustered by a normalised signature (biggest first, with example seeds), and the failure rate per feature. A program the generator got wrong (does not compile, is nondeterministic, does not terminate) is reported as *invalid* and never counted against the decompiler. Artifacts for every program below `--keep` (default `behaves`) stay under `crashtest/hxsmith-runs/<time>/seed<N>/`: the source, the decompiled project and `result.json`.

The whole image is decompiled with `crashlink project`, so classes, enums, abstracts and closures are exercised together, not just the main class.

### Extending it

A language feature is one module in `crashtest/hxsmith/features/` with a class decorated `@register` that contributes types, expressions, statements and printing through the `Gen` API (see `feature.py`). Features never import each other, so any subset can be enabled. Its `covers` names Haxe `ast.ml` constructors; `hxsmith coverage` reads `ast.ml` from a Haxe checkout (`~/code/haxe` by default) and lists what nobody generates yet. After adding a feature, `hxsmith lint 400 --features yours` must report 0 invalid programs before its fuzz results mean anything.

## hxcorpus: the Haxe compiler's own tests

`python -m crashtest hxcorpus run -j 14` runs the same pipeline over every test class in `~/code/haxe/tests/unit/src/unit` (including `unit/issues`, about 1200 classes). Each class gets a small generated harness that constructs it and calls its `test*` methods; assertions print through a deterministic stand-in for utest (`crashtest/hxcorpus/shim/`), so output has no positions and is comparable. A class that does not build standalone is reported as invalid, not as a decompiler failure. `hxcorpus lint` shows which build, `hxcorpus list` the classes.

Haxe reports every compile error in a program, so a program has a set of error kinds, not one. `crashtest hxsmith report <run folder>` re-renders a saved run and prints the compile errors in **fix order**: greedily, the kind whose fix makes the most programs compile-clean given the kinds already chosen, so the first entry is the fix that unblocks the most programs rather than merely the most common message.
