---
slug: /patching
title: Patching Bytecode
---

crashlink ships `hlrun` (formerly `pyhl`), a small Python module for patching and hooking HashLink bytecode, in the spirit of [DCCM](https://github.com/dead-cells-core-modding/core). It lives in `hlrun/` and centers on one class: `Patch`.

## Two patch modes

A `Patch` supports two kinds of changes, applied through the same object.

**Static patches**, via `@patch.patch(fn)`, run before the game ever starts. Your decorated function receives the loaded `Bytecode` and the target `Function` directly and edits opcodes in place, using crashlink itself. This is the same API surface you'd use for any other bytecode-editing script: add ops, rewrite a register, splice in new locals.

**Runtime intercepts**, via `@patch.intercept(fn)`, hook a function call while the HL VM is actually running. Instead of touching opcodes, your handler receives an `Args` object and returns a (possibly modified) `Args`, letting you rewrite arguments to a call in flight. Under the hood this works through `HlValue`/`HlObj` proxies in `hlrun/core.py` and `hlrun/obj.py`, which wrap live HL values so Python code can read and write them without knowing the raw memory layout. Registering an intercept also injects a small native call at the top of the target function so it can call back into Python.

## Why there are two `Patch` classes

If you read `hlrun/patch.py`, you'll find `Patch` defined twice, gated by `is_runtime()`. One version does the real work described above and imports crashlink directly; the other is a stub with a matching API that does nothing except forward intercepts, so patch scripts can be `import`ed both by tooling (offline, with crashlink available) and by the embedded interpreter inside the running VM (where importing crashlink isn't practical). The source calls this out as a `HACK` in a comment: it's a pragmatic workaround for an import problem, not a design anyone is proud of.

## hlrun vs. hlmod

If you're doing serious modding work on a real HL game, use [hlmod](https://github.com/N3rdL0rd/hlmod), not hlrun.

hlmod is hlrun's successor, and says so directly in its own README: "the spiritual successor to pyhl." Where hlrun is a lightweight patch/intercept layer meant to be driven from a crashlink script, hlmod is a full C-embedded HL runtime: a fork of the actual `hl.exe` binary with an embedded Python interpreter built in, not a native extension called from outside. It's built to be a generic, game-agnostic modding framework in the way DCCM (which hlmod's own README notes is deliberately Dead Cells-specific) and hlrun are not: mod loading and dependency resolution, metadata, JIT hooking straight to Python, two-way HL/Python object casting through Obj wrappers and metaclasses, static Obj and global support, and stub generation for editor ergonomics. It also reuses crashlink's own classes and data structures for bytecode handling rather than reimplementing that layer.

Checking hlmod's README roadmap, a good chunk of this is already done (mod loading/metadata, JIT hooking, primitive and HNULL casting, Obj wrappers/metaclasses, static Obj/global support, name-based hook, stub generation), while some pieces are still open (HVIRTUAL/HABSTRACT types, better HENUM support, subclassing HL objects from Python, and broader packaging/documentation work). It's an active project, not a finished one, but it's already well past what hlrun was ever meant to do.

Treat hlrun as what it is: the thing crashlink ships for small scripted patches, and the proof-of-concept hlmod grew out of. For an actual mod, go use hlmod.
