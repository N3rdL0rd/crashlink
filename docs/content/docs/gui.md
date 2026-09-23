---
slug: /gui
title: The GUI
---

crashlink ships a PySide6-based GUI for browsing and decompiling bytecode interactively, instead of driving everything through the CLI or the MCP server. Screenshots of the interface aren't included on this page yet, but the panels below are described in enough detail to navigate by.

## Installing and launching

The GUI is an optional extra, since crashlink's core has no dependencies. Install it with:

```
pip install crashlink[gui]
```

This pulls in `PySide6` for the interface and `graphviz` for the CFG viewer (the `dot` executable also needs to be on your `PATH` for the CFG viewer to actually render anything; if it's missing, the panel just shows a message instead of crashing).

Launch it with:

```
crashlink gui [file]
```

The optional `file` argument opens a `.hl`/`.dat` bytecode file immediately on startup; otherwise you get a welcome page with your recent files, and can open one from the File menu, with Ctrl+O, or by dropping it onto the window. If `PySide6` isn't installed, `crashlink gui` prints the install hint above and exits rather than throwing an import error.

## Layout

The main window is a `QMainWindow` with a set of dockable panels arranged around a central tabbed area of open functions/classes. Docks can be dragged, resized, or closed like any Qt dock widget. The panels are:

- **Navigator** (left dock): the function list, with a package tree, a file tree, and flat search results (matching function and class names), built on top of `disasm.py`'s naming. Constructors are listed as `new`.
- **Log** (bottom dock): timestamped, coloured output for GUI events (errors, load progress, decompile failures), plus an embedded Python REPL for poking at the loaded `Bytecode` object directly. `!<cmd>` runs a crashlink CLI command in the background and streams its output in; the interactive commands (`repl`, `patch`, `exit`, `cfg`) are refused. The decompiler's internal debug messages only appear when **View › Decompiler Debug Output** is on.
- **Edit History**: an undo/redo view (`QUndoView`) over renames, comments, string edits and function edits made in the session.
- **CFG** (right dock, Space toggles it): the control-flow graph of the function in focus, rendered by Graphviz on a background thread. Large graphs open legible at the entry block; click a block to jump to its first opcode, and the block holding the opcode under the disassembly cursor is outlined. `0` fits the graph, `1` resets to 100%.
- **Decompiler Internals** (Window menu): for the function in focus, every optimizer pass, which ones changed the IR, a diff of each pass, the IR snapshot after it, and the final IR tree.

Opening a function or class from the Navigator adds a tab in the central area showing a **sync view**. Long-running work (loading, decompiling, exports) is shown in the status bar. Middle-clicking a tab, a docked panel's title bar, or a panel's tab (when panels are tabbed together) closes it.

## The sync view

Each open function/class tab is a `SyncView` pairing a disassembly pane and a decompiled pseudocode pane. It has three display modes, cycled with Tab: **Split** (both panes side by side), **Disassembly** only, and **Decompiled** only. The class pane starts with the class's field declarations, then the constructor, then the other methods.

The two panes are line-synchronized: crashlink tracks, per function, which opcode each disassembly line and each pseudocode line corresponds to, so moving the cursor in one pane can be traced back to the same logical position in the other rather than the two views scrolling independently. Both panes also do syntax highlighting matched to the active editor theme.

In the disassembly, call targets show their name (`f@439 h2d.Scene.over`), constant-string globals show their value, and the source location column only prints when it changes. Hovering an opcode name shows what the opcode does and its operands; hovering `f@`, `g@`, `t@` or `regN` shows the function signature, global value, type layout or register type. In the pseudocode, hovering a called method shows its signature.

Keys in a sync view (IDA-style; **Help › Keyboard Shortcuts** lists everything):

- **Double-click / Enter**: follow the function, type, global or local under the cursor.
- **Esc / Alt+Left** and **Ctrl+Enter / Alt+Right**: back and forward through your jumps.
- **G**: jump to a function by index (`f@123`) or name, with completion.
- **X**: cross-references to the word under the cursor, listed by site with the code at each one.
- **N**: rename a local; **/**: comment an opcode.
- **Ctrl+F**: find in the pane, with a match count.

## Other browsers

A few flat, table-style views are available alongside the Navigator for scanning the whole bytecode file at once:

- **Strings** (Shift+F12): every string constant with its length and reference count. Enter or X lists the references, F2 edits the string (undoable).
- **Globals**: every global with its type, constant initializer and reference count. Double-clicking a `g@N` in the code opens it here.
- **Types view**: every type in the bytecode (`Obj`, `Enum`, `Virtual`, `Abstract`, `Ref`, `Null`, `Packed`, `Fun`), with a detail pane showing its layout, including fields, methods, enum constructs, and vtable slots.
- **Natives view**: every native function in the bytecode, sortable by column.
- **File Info** (Ctrl+I): path, size, SHA-256, version, table sizes, native libraries, a link to the entry point, and the bytecode sanity checks.
- **Opcode Reference** (Help menu): every opcode with its operands and description.

## Lookups and exports

The Jump and Search menus cover the CLI's lookups: **Go to File Offset** (which section an offset falls in), **Go to Source Location** (`File.hx:120`, jumping to the opcodes compiled from that line), and **Cross-References** by kind and index (function, type, field, global, string, enum construct).

**Edit › Edit Function as .hlasm** (Ctrl+E) opens the focused function as [.hlasm](/hlasm) text. Apply assembles it against the loaded file, reports any error with its line, and swaps the function in as an undoable edit; new strings and numbers are added to the pools.

**File › Export** writes the (possibly edited) bytecode back out (as bytecode or as `.hlasm`), transpiles to HL/C, stubs one or all source files, generates API docs or a MkDocs site, recovers hxsl shaders, and saves a class together with every class it references. Exports run in the background and report the output path when done.

## Errors and stability

The decompiler is still marked experimental, so the GUI installs a global exception hook that routes uncaught exceptions (a bad CFG render, a failed xref resolution, a broken REPL command) into the Log panel with a full traceback, instead of letting an unhandled exception take the whole window down.

Background loads and decompilation results belong to a specific document generation.
Switching files cancels pending work and ignores late results from the old document;
closing waits for owned analysis threads to finish. Cached analysis is scoped by
document identity, and invalidating it prevents an in-flight result from restoring
the old cache entry.

If saving an analysis database fails, choosing **Save** in the unsaved-changes
dialog does not close or replace the document. Its annotations remain dirty so you
can retry saving or explicitly choose **Discard**.

## Native image inspection

HL/C binaries open in inspection-only mode. The **Asm** view shows original
machine code; **Lift** and the right-hand pane show heuristic opcode families,
native addresses, and `?` for operands whose values or dataflow were not recovered.
Raw lift events remain visible even when they have no HL opcode representation.

These views do not populate executable function bodies or consume cached Haxe
pseudocode. Faithful Haxe/IR/CFG generation and executable bytecode/C export are
unavailable for native recovery; use the original assembly to inspect behavior.
