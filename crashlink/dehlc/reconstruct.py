"""
Top-level reconstruction pipeline: binary image -> bytecode.
"""

from __future__ import annotations

from typing import Callable, Optional

from ..core import (
    Bytecode,
    Obj,
    VarInt,
    fIndex,
    tIndex,
)

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: F401
    from capstone.x86 import X86_OP_MEM, X86_REG_RIP, X86_OP_IMM, X86_OP_REG, X86_REG_RDI, X86_REG_EDI  # noqa: F401
    from capstone.arm64 import (  # noqa: F401
        ARM64_OP_IMM,
        ARM64_OP_REG,
        ARM64_OP_MEM,
        ARM64_REG_X0,
        ARM64_REG_X17,
    )
    import lief  # noqa: F401
except ImportError:
    raise NotImplementedError(
        "Cannot run dehl without lief and capstone installed. Try `pip install crashlink[extras]` or `pip install lief capstone`."
    )
from .binary import HLCBinary, _resolve_plt_targets
from .context import DehlcContext
from .functions import _recover_functions, _recover_native_names
from .globals import _recover_globals
from .init_analysis import analyse_init_types
from .pools import _recover_constant_pools
from .strings import _dwarf_local_names, _recover_hash_names, _recover_strings
from .types import _parse_type, recover_type_order


def code_from_bin(
    path: str | None = None,
    data: bytes | None = None,
    verbose: bool = False,
    progress_cb: Optional[Callable[[str], None]] = None,
) -> Bytecode:
    """
    Dumps extracted information from the HL/C binary located on the filesystem at `path`
    or from the bytes in `data` to a new Bytecode instance. When `progress_cb` is
    given it receives a short status line per pipeline pass (used by the GUI loader).

    The returned bytecode carries `.hlc_binary` - the parsed native image it was
    reconstructed from - so callers can inspect original machine code (`nasm`).
    """

    def report(msg: str) -> None:
        if progress_cb is not None:
            try:
                progress_cb(msg)
            except Exception:
                pass

    bin_view = HLCBinary(path=path, data=data)
    ctx = DehlcContext(bin_view, verbose=verbose)
    code = Bytecode.create_empty(no_extra_types=True)

    # ------------------------------------------------------------------
    # Pass 1: types
    # ------------------------------------------------------------------
    report("Analysing hl_init_types…")
    ctx.log("Pass 1: analysing hl_init_types...")
    init_analysis = analyse_init_types(bin_view)
    ctx.log(
        f"  {len(init_analysis.type_order)} complex types ordered, "
        f"{len(init_analysis.global_links)} global links, {len(init_analysis.param_links)} param links"
    )

    ctx.log("Pass 1.2: recovering type order...")
    report("Recovering type order…")
    type_names, order_confident = recover_type_order(bin_view, init_analysis)
    ctx.log(f"  {len(type_names)} types (order {'confirmed' if order_confident else 'hybrid'})")
    for i, name in enumerate(type_names):
        ctx.name_to_tindex[name] = tIndex(i)
        sym = bin_view.symbol(name)
        if sym is not None:
            ctx.ptr_to_tindex[sym.value] = tIndex(i)

    ctx.log("Pass 1.3: reading type data...")
    types = [_parse_type(ctx, name, init_analysis) for name in type_names]
    code.ntypes.value = len(types)
    code.types = types

    # ------------------------------------------------------------------
    # Pass 2: strings
    # ------------------------------------------------------------------
    ctx.log("Pass 2: recovering strings...")
    report("Recovering strings…")
    _recover_strings(ctx)
    _recover_hash_names(ctx, _resolve_plt_targets(bin_view))
    for name in _dwarf_local_names(bin_view):
        if name and not name.startswith("$"):
            ctx.add_str(name)
    code.strings.value = ctx.strs
    code.strings.lengths = [VarInt(len(s.encode("utf-8", errors="surrogateescape"))) for s in ctx.strs]
    code.nstrings = VarInt(len(ctx.strs))
    ctx.log(f"  {len(ctx.strs)} strings")

    # ------------------------------------------------------------------
    # Pass 3: functions & natives
    # ------------------------------------------------------------------
    ctx.log("Pass 3: recovering functions & natives...")
    report("Recovering functions & natives…")
    functions, natives, entrypoint = _recover_functions(ctx)
    _recover_native_names(ctx, natives, code.types)

    code.functions = functions
    code.natives = natives
    code.nfunctions = VarInt(len(functions))
    code.nnatives = VarInt(len(natives))
    code.entrypoint = entrypoint if entrypoint is not None else fIndex(-1)
    ctx.log(f"  {len(functions)} functions, {len(natives)} natives, entrypoint={code.entrypoint.value}")

    # Locate the String obj type for string-global typing.
    string_type_ti: Optional[tIndex] = None
    for i, t in enumerate(code.types):
        d = t.definition
        if isinstance(d, Obj) and d.name.resolve(code) == "String":
            string_type_ti = tIndex(i)
            break

    # ------------------------------------------------------------------
    # Pass 4: globals
    # ------------------------------------------------------------------
    ctx.log("Pass 4: recovering globals...")
    report("Recovering globals…")
    global_types = _recover_globals(ctx, code, init_analysis, string_type_ti)
    code.nglobals = VarInt(len(global_types))
    code.global_types = global_types
    ctx.log(f"  {len(global_types)} globals")

    # ------------------------------------------------------------------
    # Pass 3.5: constant pools (synthesised from function-body immediates).
    # ------------------------------------------------------------------
    ctx.log("Pass 3.5: synthesising int/float pools...")
    report("Synthesising constant pools…")
    rec_ints, rec_floats = _recover_constant_pools(ctx, bin_view)
    from ..core import SerialisableInt

    # The HL format stores every pool int as a fixed 4-byte little-endian word,
    # read back unsigned (truth binaries keep >int32 values this way); negative
    # values are stored as their two's-complement bit pattern.
    code.ints = []
    for v in rec_ints:
        si = SerialisableInt()
        si.value = v & 0xFFFFFFFF
        si.signed = False
        si.length = 4
        code.ints.append(si)
    code.nints = VarInt(len(code.ints))
    from ..core import SerialisableF64

    code.floats = []
    for v in rec_floats:
        sf = SerialisableF64()
        sf.value = v
        code.floats.append(sf)
    code.nfloats = VarInt(len(code.floats))
    ctx.log(f"  {len(rec_ints)} ints, {len(rec_floats)} floats")
    code.bytes = None
    code.nbytes = None
    code.has_debug_info = False
    code.flags = VarInt(0)

    # Post-processing parity with normal deserialisation: build virtual tables and
    # pair static/dynamic class variants so downstream tooling (decompiler, xrefs,
    # REPL) works on the reconstructed image.
    code.deserialised = True
    try:
        code._build_virtual_tables()
    except Exception as e:
        print(f"Warning: could not build virtual tables on the reconstructed image ({e}).")
    try:
        code.map_statics()
    except Exception as e:
        print(f"Warning: could not map statics on the reconstructed image ({e}).")
    code.invalidate_findex_cache()
    code.invalidate_proto_field_cache()

    # Final sync: later passes may have appended strings via ctx.add_str after
    # the strings block was first wired up; nstrings must match the block or
    # reserialisation produces a misaligned file.
    if code.strings.value is ctx.strs and len(ctx.strs) != code.nstrings.value:
        code.nstrings = VarInt(len(ctx.strs))

    # Keep the native image alongside the reconstruction so assembly views and
    # address lookups can see the code that actually runs.
    code.hlc_binary = bin_view

    return code
