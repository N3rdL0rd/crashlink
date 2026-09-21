"""airspeed velocity (asv) benchmark suite for crashlink.

Benchmarks exercise the four stages a real decompile pass goes through -
bytecode parsing, disassembly, IR lifting, and pseudocode/C rendering - plus
a couple of control-flow shapes that have historically been superlinear
(see `control_flow.py`). Fixtures are prebuilt `.hl` images compiled from
`tests/haxe/*.hx`; build them with `haxe -hl <Name>.hl -main <Name>` (or run
the project's test suite once) before invoking `asv run`.
"""
