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

The optional `file` argument opens a `.hl`/`.dat` bytecode file immediately on startup; otherwise you get an empty window and can open one from the File menu. If `PySide6` isn't installed, `crashlink gui` prints the install hint above and exits rather than throwing an import error.

## Layout

The main window is a `QMainWindow` with a set of dockable panels arranged around a central tabbed area of open functions/classes. Docks can be dragged, resized, or closed like any Qt dock widget. The panels are:

- **Navigator** (left dock): the function list, with a package tree, a file tree, and flat search results, built on top of `disasm.py`'s naming. This is the primary way to find a function or class to open.
- **Log** (bottom dock): timestamped, coloured output for GUI events (errors, load progress, decompile failures), plus an embedded Python REPL for poking at the loaded `Bytecode` object directly.
- **Edit History**: an undo/redo view (`QUndoView`) over renames, comments, and string edits made in the session.
- **CFG** (right dock): the control-flow-graph viewer for the function currently in focus, rendered via Graphviz.

Opening a function or class from the Navigator adds a tab in the central area showing a **sync view**.

## The sync view

Each open function/class tab is a `SyncView` pairing a disassembly pane and a decompiled pseudocode pane. It has three display modes, cycled with Tab: **Split** (both panes side by side), **Disassembly** only, and **Decompiled** only.

The two panes are line-synchronized: crashlink tracks, per function, which opcode each disassembly line and each pseudocode line corresponds to, so moving the cursor in one pane can be traced back to the same logical position in the other rather than the two views scrolling independently. Both panes also do syntax highlighting matched to the active editor theme.

Related panels that key off the function/class currently open in a sync view:

- **Locals panel**: the current function's locals, with inline rename support.
- **xref resolution**: placing the cursor on a function, type, field, enum construct, or string reference and triggering an xref lookup pops up a list of every site that references it, grouped by target, with jump-to-source on Enter.

## Other browsers

A few flat, table-style views are available alongside the Navigator for scanning the whole bytecode file at once:

- **Types view**: every type in the bytecode (`Obj`, `Enum`, `Virtual`, `Abstract`, `Ref`, `Null`, `Packed`, `Fun`), with a detail pane showing its layout, including fields, methods, enum constructs, and vtable slots.
- **Natives view**: every native function in the bytecode, sortable by column.

## Errors and stability

The decompiler is still marked experimental, so the GUI installs a global exception hook that routes uncaught exceptions (a bad CFG render, a failed xref resolution, a broken REPL command) into the Log panel with a full traceback, instead of letting an unhandled exception take the whole window down.
