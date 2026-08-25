---
slug: /decompiler-internals
title: Decompiler Internals Walkthrough
---

This page walks through how crashlink actually turns HashLink bytecode into readable Haxe-like pseudocode, stage by stage, grounded in the real pipeline code in `crashlink/decomp/`. It's not a bytecode format reference: for the opcode/type-format spec, see [ModDocCE's hlboot docs](https://n3rdl0rd.github.io/ModDocCE/files/hlboot/). This page is about crashlink's own machinery: how a `Function`'s raw ops become a control-flow graph, how that graph gets lifted into an IR tree, how roughly thirty optimizer passes rewrite that tree in a specific order, and how the result gets rendered as text.

If you're about to add an optimizer pass or change lifting behavior, this is the page to read first.

## Stage 1: control-flow graph construction

`CFGraph.build()` in `crashlink/decomp/cfg.py` (starting around line 126) turns `func.ops`, a flat list of opcodes, into a graph of basic blocks.

The algorithm is two passes. First it scans every op and records the set of instruction indices that are jump *targets*: for each conditional jump (`JTrue`, `JFalse`, `JSLt`, etc.), `JAlways`, and `Trap`, it computes `i + op.df["offset"].value + 1` and adds it to `jump_targets`; for `Switch` it adds a target for every entry in `offsets`. Second, it walks the ops again and splits into blocks wherever it hits one of those jump-target indices (starting a new block), or wherever the current op is itself a block terminator (`JTrue`/family, `Switch`, `Ret`, `Trap`, `EndTrap`), ending the current block right after that op. This is standard leader-based basic-block splitting, nothing exotic about it.

Once the blocks (as `CFNode`s) exist, `build()` wires up `branches` between them based on each block's terminating op. Conditional jumps get a `"true"` edge to the jump target and a `"false"` edge to the fall-through; note the HashLink convention here: the jump target is taken when the condition holds, and compilers emit the *negated* source condition, so the fall-through is the "then" arm (this convention resurfaces during lifting). `Switch` gets one `"switch: case: N"` edge per case plus a `"switch: default"` fall-through edge, `Trap`/`EndTrap` get `"trap"`/`"fall-through"`/`"endtrap"` edges, and anything else that isn't a `Ret` falls through unconditionally to the next block.

After the graph is built, `build()` runs two `CFOptimizer` passes if `do_optimize` is set: `CFJumpThreader`, which collapses blocks that are nothing but a single unconditional `JAlways` by redirecting their predecessors straight to the target, and `CFDeadCodeEliminator`, a simple reachability sweep from `self.entry` that drops unreachable nodes. Both operate purely on the graph shape, before any IR exists.

Finally `analyze()` computes the structural facts the lifter depends on: predecessors, dominators and post-dominators (iterative fixed-point algorithms, `_find_dominators`/`_find_post_dominators`), natural loops via back-edge detection (`_find_loops`: an edge `u -> v` is a back edge if `v` dominates `u`, and the loop body is everything that can reach `u` without leaving `v`'s dominance), and immediate post-dominators (`_find_immediate_post_dominators`). The post-dominator info in particular is what later lets the IR lifter figure out where an `if`/`else`'s two branches reconverge.

### Worked example

`tests/haxe/If.hx`'s `main()` compiles (`f@222` in `If.hl`) to 15 ops with two `JSGte` conditionals and one `JAlways`. Running the disassembler shows the raw shape:

```
3. JSGte   {'a': 2, 'b': 0, 'offset': 2}   if reg2 >= reg0: jump to 6
4. Call0   {'dst': 1, 'fun': 27}           reg1 = f@27()
5. JAlways {'offset': 1}                   jump to 7
6. Call0   {'dst': 1, 'fun': 220}          reg1 = f@220()
7. Call0   {'dst': 1, 'fun': 221}          reg1 = f@221()
```

`CFGraph.build()` sees op 3 (`JSGte`) as a block terminator and op 6 as a jump target, so it splits into a block ending at op 3, a block `{4, 5}` (ending at the `JAlways`), a block starting at 6, and so on. The `JSGte` node gets a `"true"` edge to node 6 and a `"false"` edge to node 4; node 4/5's `JAlways` gets an `"unconditional"` edge to node 7. `CFJumpThreader` would collapse the `{4,5}` block if it were *only* the `JAlways`, but it also has the `Call0`, so it survives untouched here.

This is the actual graph `CFGraph.build()` produces for `f@222`, rendered with `IRFunction.to_dot()` (the same DOT output the GUI's CFG viewer uses):

![CFG for If.main](/img/decompiler/cfg_if.svg)

`If.main()` actually runs two separate if-statements from the source one after another, and the shape shows it: `BB0`'s `JSGte` is a clean diamond (`BB1`/`BB2` converging at `BB3`), but the second if reuses part of its own condition logic across two blocks (`BB3` and `BB4`) before both of *their* branches converge on `BB6`, then `BB7`'s `Ret`. Green edges are the `"true"` branch (jump taken), red are `"false"` (fall-through), blue are unconditional. This is exactly the "diamond" shape `_find_convergence_node` has to detect and stop recursing at for each conditional, twice over, in one function.

## Stage 2: IR lifting

`IRFunction.__init__` (`crashlink/decomp/function.py`, ~line 217) is the entry point. For a `Native` function it skips all of this and just wraps an `IRNativeStub` (no CFG, no ops to lift). For a real function it builds the `CFGraph`, then calls `self._lift(no_lift=no_lift)`.

`_lift()` first creates one `IRLocal` per register in `func.regs` (`var0`, `var1`, ...), then calls `_build_assign_map()` and `_name_locals()` before doing any tree construction. `_build_assign_map()` reads `func.assigns` (debug info mapping op index -> variable name) and builds `_op_assigns`: which op index introduces which named local for which register. This matters because HashLink aggressively reuses registers: the same register slot can hold a loop counter, then get recycled as an anonymous temp, then get reused for something else entirely. crashlink handles this with what the code calls an "SSA-esque" split (`_split_local`, `_check_assign`): whenever a register's debug name changes, or a named register gets silently overwritten by something that clearly isn't a continuation of its own value (checked by `_has_untracked_reuse`/`_is_continuation_write`, which special-cases patterns like `i++` and `i = i + 1` as *not* a fresh variable), the lifter creates a brand-new `IRLocal` for that slot rather than reusing the old one. Without this, an unrelated `.length` read stored back into a loop counter's old register would print as if it were still the loop variable.

The actual tree construction happens in `_lift_block()` (~line 1691), called first as `self._lift_block(self.cfg.entry, set())`. This is a recursive descent over the CFG: it takes a `CFNode`, a `visited` set (cycle guard), an optional `stop_at` node (the convergence point where the current recursive branch should stop), and an optional `loop_ctx`. Ops in a block that aren't the trailing control-flow op get lifted one at a time by `_lift_ops_into_block` into `IRAssign`/`IRCall`/etc. statements; the trailing op (a conditional jump, `Switch`, `Ret`, `Trap`, ...) decides how the *next* IRBlock(s) get attached.

For a conditional jump specifically, `_lift_block` inverts the jump's condition (`cond_expr.invert()`) because, as noted above, HashLink's jump-on-true-to-target convention means the fall-through is actually the source's "then" branch. It then has to figure out where the two branches converge again so it knows where to stop recursing into each one; this is `_find_convergence_node`, backed up by the CFG's precomputed immediate post-dominators when the heuristic search doesn't find an unambiguous answer. There's a chunk of gnarly special-casing here worth knowing about if you touch it: the convergence heuristic can pick a branch target as its own convergence point when that target is *also* reachable via one of the other branch's internal sub-paths (not on every path, just one), which would wrongly treat an inner conditional's shared call as the outer merge point. The code detects this specifically with real post-dominance rather than blanket-overriding every self-referential pick, because the "if with no else" shape *legitimately* wants the branch target as its own convergence and forcing the post-dominator there would incorrectly pull trailing code into the conditional.

Loops get a separate path: if the target node heads a natural loop (`node in cfg.loops`), `_lift_block` defers to `_lift_loop` instead of the generic conditional handling, which builds an `IRWhileLoop`/`IRPrimitiveLoop` and a `_LoopContext` used to translate loop-exiting branches into `IRBreak`/`IRContinue` rather than raw jumps.

`tests/haxe/LoopWhile.hx`'s `main()` (`f@22` in `LoopWhile.hl`) is a natural loop in graph form:

![CFG for LoopWhile.main](/img/decompiler/cfg_loopwhile.svg)

The back edge is what `_find_loops` is looking for: an edge into a node that dominates the block the edge comes from. Everything reachable from the loop head without leaving that dominance is the loop body, which is exactly the region `_lift_loop` has to lift into the `IRWhileLoop`'s body rather than treating it as one more `if`/convergence pair.

One more thing worth knowing before touching this code: `_lift_block` memoizes on `(node, stop_at, id(loop_ctx))` in `self._lift_cache`. The comment on this (around line 1726) explains why it's necessary: CFGs where many branches funnel into a shared continuation point would otherwise cause the same region to be re-lifted independently from every branch that reaches it, which is exponential in nesting depth. Cached results are still handed back as clones (`self._clone_ir`), not the shared instance, because nothing downstream expects an IR node to be reachable from multiple parents. Treating the IR as a real DAG would just move the same exponential blowup into every consumer that walks it.

### Opcode-to-IR shape

The opcode-to-IR mapping in `_lift_ops_into_block` (~line 901) is mostly a big `if/elif` matched on `op.op`. A few representative cases: arithmetic ops (`Add`, `Sub`, `Mul`, ...) become `IRAssign(dst, IRArithmetic(lhs, rhs, type))`; constant-loading ops (`Int`, `Float`, `Bool`, `Bytes`, `String`, `Null`) become `IRAssign(dst, IRConst(...))`; `CallMethod`/`CallThis` resolve the callee through `_resolve_method_field` and become `IRAssign(dst, IRCall(METHOD, field_expr, args))`, or fall back to an `IRUnliftedOpcode` wrapper if the field can't be resolved. One subtlety in `_lift_ops_into_block`: it snapshots `source_locals = self.locals.copy()` *before* checking for a debug-name split on this op's destination, and operands read from that snapshot while the destination write reads from `self.locals` after the split. This exists because HashLink frequently reuses a register as both source and destination in the same op (`reg0 = String.__add__(reg0, reg1)`); splitting the destination local first would make the source operand pick up the freshly-split (empty) local instead of the value actually being read.

## Stage 3: the optimizer pipeline

Once lifting produces the raw IR tree, `IRFunction.__init__` builds `self.optimizers`, a list of roughly 40 optimizer instances (some pass classes appear more than once with different flags), and runs them in `_optimize()` (~line 544) by iterating the list, calling `o.should_run()` first (a cheap early-exit gate many passes implement to skip themselves when their target opcodes/patterns don't appear at all) and then `o.optimize()`.

This list, defined inline in `__init__` (~line 251-315), is not sorted alphabetically or by class name; it's an intentionally ordered pipeline, and a few of the orderings are load-bearing enough that the source comments call them out explicitly. Grouping the ~40 entries conceptually:

**Control-flow restructuring first.** `IRBlockFlattener` and later `IRElseFlattener` clean up nesting artifacts from lifting (an `else` branch that's itself just a single nested `if` collapsing into an `else if`, for instance). `IRConstructorFolder` and `IRPrimitiveJumpLifter` run early too, before anything downstream has a chance to obscure the raw shapes they're matching.

**Condition and jump simplification.** `IRGlobalStringOptimizer`, `IRStringIntConcatOptimizer`, `IRConditionInliner`, `IRArrayGrowGuardEliminator`, `IRLoopConditionOptimizer`, `IRSelfAssignOptimizer`, `IRRedundantContinueEliminator` clean up how conditions and jumps got lowered before the bulkier copy-propagation and inlining passes run.

**Copy propagation and temp inlining.** `IRCopyPropOptimizer` runs first, then later `IRTempAssignmentInliner` runs *twice*, once conservative (`aggressive=False`) then once aggressive (`aggressive=True`). The class docstring spells out the difference: conservative mode only inlines `temp = expr` into the *immediately following* statement's use of `temp`; aggressive mode inlines "safe" expressions (constants and similar) into *all* subsequent uses as long as the temp isn't redefined in between. Running conservative first and aggressive second lets the cheap, narrowly-safe fold happen without accidentally being blocked by the aggressive pass's broader substitution reach, then the aggressive pass mops up what's left. The pass never touches a variable that has an explicit debug name from the source; it only targets compiler-generated temporaries.

**Dead code and dead temp elimination.** `IRStringAllocOptimizer`, `IRSequentialTempFolder`, `IRDeadTempEliminator`, `IRDeadCodeEliminator` run after the first inlining round to clean up assignments that inlining just made unreachable or unused.

**Array/collection pattern recognizers, deliberately positioned after temp inlining.** `IRArrayPatternOptimizer`, `IRNativeArrayAllocOptimizer`, `IRArrayObjWrapperOptimizer`, `IRNativeMapAllocOptimizer`, `IRBytesAllocOptimizer` run only once the earlier inlining passes have collapsed multi-register lowering sequences into a single expression shape these optimizers can pattern-match. `IRArrayPatternOptimizer`'s own docstring says as much: it recognizes low-level patterns like "fixed-size integer array literal built with alloc_bytes + stores + allocI32" or "`temp = arr.bytes; ...; x = temp[idx << 2]` -> `x = arr[idx]`", and that second pattern only exists as a matchable shape once `temp` has actually been folded away by the inliner.

There's then a second, later round of `IRTempAssignmentInliner` calls (`aggressive=True, past_kills=True` immediately followed by `aggressive=False`), with a comment explaining they run "only after the pattern optimizers" because those optimizers match raw lowering shapes that an earlier inlining pass would have already disturbed. `past_kills=True` here means a later redefinition of the temp bounds the substitution range instead of blocking inlining outright, a looser rule than the first round used.

Right after that, `IRArrayObjBoundsCheckCollapser` runs, and its own comment is explicit about why it has to come here: "only after temp inlining has folded the register chain into a single `this.field.array[idx]` shape for it to match." The same pass runs *again* much later in the list (this is the "late second pass" comment near the end), because in larger functions that `this.field.array[idx]` shape doesn't fully materialize until after loop/switch restructuring and the cleanup passes that come after the first pass have had a chance to run. This double placement is the kind of thing that looks redundant until you trace through why a single placement isn't enough: the shape genuinely doesn't exist yet the first time some functions reach that point in the pipeline.

Another explicit ordering comment sits around `IRTempAssignmentInliner(self, aggressive=False)`, re-run right after `IRTraceOptimizer`: the comment explains that `trace()`'s `DynObj` scaffolding collapsing brings a dead user-local-register reassignment adjacent to its sole use for the first time, so the inliner's user-local-reuse fold (in `_visit_block_conservative`) can now see and fold something it couldn't see before that collapse happened.

**Switch, loop, and higher-level reconstruction near the end.** `IRIntSwitchOptimizer`, `IRStringSwitchOptimizer`, `IREnumSwitchOptimizer` turn chains of equality-compare-and-jump into `IRSwitch` nodes; `IRLoopRerollOptimizer`, `IRForEachLoopOptimizer`, `IRIntRangeLoopOptimizer` recognize `while`-loop shapes that are actually a `for` loop or a `for..in` iteration and rewrite them into the more specific `IRForEachLoop`/`IRIntRangeLoop` nodes. These run late because they depend on the conditionals and temps around them already being in their cleaned-up final form.

**Final cleanup pass.** `IRDeadStoreEliminator`, `IRDeadAssignmentEliminator`, `IRGuardOrMerger`, `IRRedundantRecomputeEliminator`, `IREmptyConditionalNormalizer`, `IRTerminalValueInliner` (run twice), and the late `IRArrayObjBoundsCheckCollapser` mentioned above sweep up whatever the structural passes left behind.

After the built-in list, `__init__` splices in any plugin-registered optimizers (`crashlink.plugins.optimizers_for`), gated per-image and cached on the `Bytecode` object via `self.code._plugin_optimizer_classes` so the gating check only runs once no matter how many functions in the same image get decompiled.

If `capture_layers=True` was passed to `IRFunction`, `_optimize()` records a pretty-printed snapshot of the whole block after every single pass into `self.layer_snapshots`, tagged with whether the pass actually ran (`should_run()` can skip it). This is what backs any "show me the IR after pass N" tooling; it's plumbing for observability, not part of the transformation logic itself.

### Worked example: array pattern lowering

`tests/haxe/ArrayAccezz.hx`'s `main()` does `var a = ArrayAccezz.array(); var b = a[0];`. The raw disassembly (`f@22` in `ArrayAccezz.hl`) shows what a single `a[0]` read actually lowers to in HashLink bytecode: a null check, a bounds-guard comparing the index against `a.length`, and on the guarded path a `Field` load of the array's raw `.bytes`, a `Shl` to scale the index by the element size, and a `GetMem` to actually read the byte. That's six ops and a branch for one array read:

```
1. NullCheck {'reg': 0}                            if reg0 is null: error
2. Int       {'dst': 2, 'ptr': 0}                  reg2 = 0
3. Field     {'dst': 3, 'obj': 0, 'field': 0}      reg3 = reg0.length
4. JULt      {'a': 2, 'b': 3, 'offset': 2}         if reg2 < reg3: jump to 7
...
7. Field     {'dst': 4, 'obj': 0, 'field': 1}      reg4 = reg0.bytes
8. Int       {'dst': 3, 'ptr': 1}                  reg3 = 2
9. Shl       {'dst': 3, 'a': 2, 'b': 3}             reg3 = reg2 << reg3
10. GetMem   {'dst': 2, 'bytes': 4, 'index': 3}    reg2 = reg4[reg3]
```

By the time this reaches `IRArrayPatternOptimizer`, the earlier optimizer passes (copy prop, temp inlining, bounds-guard simplification via `IRArrayGrowGuardEliminator`) have already folded the intermediate registers down to something close to a single `this.bytes[idx << 2]`-shaped expression, which is exactly the "conditional `arr.bytes[idx << 2]` load with length guard" pattern the docstring describes. `IRArrayObjBoundsCheckCollapser` and `IRArrayPatternOptimizer` fold this whole shape back into a plain array index. The final pseudocode output is just:

```haxe
class ArrayAccezz {
    public static function main(): Void {
        var a: Array<Int> = ArrayAccezz.array();
        var b: Int = a[0];
    }
}
```

which is a good illustration of how much of the optimizer pipeline's job is un-lowering: most of these passes exist to recognize a multi-op, guard-and-index HashLink lowering and fold it back to the single high-level expression a Haxe programmer actually wrote.

### Worked example: conditional lifting

Going back to `If.hx`'s `main()` from the CFG example above: after lifting, the two `JSGte` conditionals become `IRConditional` nodes with inverted conditions (source `b < a` compiles to a `JSGte` that jumps to the else-block when `b >= a`, so the lifter inverts it back to `b < a` for the then-branch). The full pipeline output for this function:

```haxe
class If {
    public static function main(): Void {
        var a: Int = 500;
        var b: Int = 10;
        If.spacer();
        if (b < a) {
            If.other();
        } else {
            If.other2();
        }
        If.spacer();
        if (a > 400 && b < a) {
            If.other();
        } else {
            If.other2();
        }
    }
}
```

The second `if` is a case where `IRConditionInliner` (or a related boolean-merging pass) has folded two separate `JSGte` guards (`a > 400`, checked via a jump to the same else-target as `b < a`'s failure) into a single `&&` expression, since the raw disassembly shows those as two independent conditional jumps to the same target (op 9 and op 10 in the disassembly both jump to node 13) rather than one compound condition.

## Stage 4: pseudocode rendering

`crashlink/pseudo.py` is the last stage: it walks the final, fully-optimized IR tree and renders Haxe-like source text. The module docstring is one line: "Pseudocode generation routines to create a Haxe representation of the decompiled IR," and that's accurate, this module doesn't do any further semantic transformation, it's a renderer.

`pseudo(ir_func: IRFunction) -> str` (~line 1997) is the per-function entry point; it delegates to `pseudo_oplines()`, which does the actual rendering via `_generate_function_pseudo_mapped` and wraps the result in a synthetic `class { ... }` block for context (crashlink infers the class name from the function's proto/field registration, or falls back to the first argument's type if it looks like a `this` receiver). It also returns a body-relative opcode-to-line map for tooling that needs to point back from a rendered line to the originating opcode, noting explicitly that the map is partial since optimizer-created statements have no source op to point back to.

`class_pseudo(ir_class: "IRClass") -> str` (~line 3373) is the whole-class entry point, recursing over referenced classes so a single class can be pretty-printed as a standalone, plausibly-recompilable Haxe file. The real per-class rendering work happens in `_class_body`, which `class_pseudo` and the flat whole-file `decompile_file` path both call into; its docstring is explicit that this is "the single place class bodies are rendered" so the two call sites stay in sync rather than duplicating rendering logic.
