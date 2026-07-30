---
slug: /plugins
title: Plugin System
---

The core decompiler pipeline in crashlink is fixed and general: it applies the same set of `IRFunction.optimizers` to every function, regardless of what compiled the bytecode. Real HashLink games, though, tend to have their own compiler macros and idioms baked into their output, a logging macro that inlines source position info, a custom assert, entity-system boilerplate, that decompile correctly but verbosely. Cleaning that up only makes sense for the one game that produces it, so it doesn't belong in the general pipeline. `crashlink/plugins.py` exists for exactly this: it lets you register extra IR optimizer passes that only apply to specific bytecode, without touching core.

## What gates a plugin

A plugin registers an `IROptimizer` subclass along with a predicate deciding when it should run:

- `sha=`: matches a bytecode by SHA-256 of the loaded image. A plugin written against one game's `hlboot.dat` applies to that exact file and nothing else.
- `when=`: a custom predicate function over the `Bytecode` object, for matching by looser criteria than an exact hash (say, "has a function named `tool.log.LogUtils.logInformation`"), so the same pass can survive across builds of the same game.
- Neither given: the optimizer always applies, to every bytecode file.

Both can be combined; if both are given, the plugin only applies when both are satisfied.

Each registration also picks a `position` in the pipeline: `"end"` (the default) runs the pass after the built-in optimizers, which is what you want for cleanup passes operating on already-simplified IR. `"start"` runs before the built-ins, for passes that need to see the raw lowering before anything else has touched it.

## Writing one

Plugins are plain Python files, auto-discovered from, in order: every directory listed in `$CRASHLINK_PLUGINS` (`os.pathsep`-separated), `~/.crashlink/plugins/`, and `./.crashlink/plugins/` (project-local). Any `.py` file in one of those directories that doesn't start with `_` gets imported once per session. A plugin registers its optimizer at import time via the `@optimizer(...)` decorator (or `register_optimizer(...)` directly, which returns the class so it also works as a decorator).

A minimal example, `~/.crashlink/plugins/deadcells.py`:

```python
from crashlink.plugins import optimizer
from crashlink.decomp import TraversingIROptimizer

@optimizer(sha="7d1f...the image's sha...")
class StripLogPositions(TraversingIROptimizer):
    def visit_expression(self, expr):
        ...
```

Once this file sits in a discovery directory, any decompile of bytecode matching that SHA runs `StripLogPositions` after the built-in pipeline. The decompiler asks `optimizers_for(code, position)` for the applicable classes at each pipeline position, so registration is all a plugin file needs to do; there's no separate wiring step.

If a plugin file fails to import, or an optimizer inside it raises, `plugins.py` catches it, logs via `dbg_print`, and skips it. A broken plugin should never take down a decompile.

## When to use this instead of editing core

If a cleanup applies universally, and generalizes, it belongs in `IRFunction.optimizers` in `crashlink/decomp/function.py` as a normal built-in pass. The plugin mechanism exists for the opposite case: an optimization whose correctness depends on assumptions true of one game's compiled output and not of HashLink bytecode in general. Gating by `sha` in particular means the pass is scoped to a specific image rather than to "anything that looks like it might have this macro," so it can be as aggressive or as game-specific as it needs to be without risking a false match against unrelated bytecode. It also keeps that logic out of the versioned core pipeline and in a file (or directory) that travels with whatever project is reversing that particular game, rather than living in crashlink itself.
