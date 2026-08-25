"""
Translation of lifted operation streams into real HL opcodes.

Second stage of the lift pipeline (`lift` recovers events from machine code;
this module materialises them as `core.Opcode` objects). V1 semantics:

- fresh register per produced value (no reuse) - sequences align with truth,
  dataflow does not yet;
- call arity comes from the callee's recovered signature;
- branch offsets are fixed up in a second pass using per-opcode address
  provenance recorded during emission.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from ..core import (
    Bytecode,
    InlineBool,
    Opcode,
    Reg,
    Regs,
    SerialisableF64,
    SerialisableInt,
    VarInt,
    fIndex,
    fieldRef,
    floatRef,
    gIndex,
    intRef,
)
from .binary import HLCBinary, _resolve_plt_targets
from .lift import LiftedOp

# cc -> conditional opcode family (signed/unsigned branches map directly).
_CC_TO_OP = {
    "l": "JSLt",
    "ge": "JSGte",
    "g": "JSGt",
    "le": "JSLte",
    "b": "JULt",
    "ae": "JUGte",
    "e": "JEq",
    "ne": "JNotEq",
    "s": "JSLt",
    "ns": "JSGte",  # sign-flag branches approximate
}

_ARITH_OPS = {
    "Add": "Add",
    "Sub": "Sub",
    "Mul": "Mul",
    "Shl": "Shl",
    "SShr": "SShr",
    "UShr": "UShr",
    "And": "And",
    "Or": "Or",
    "SDiv": "SDiv",
    "UDiv": "UDiv",
}

# Cold-path libhl prims that HL bytecode represents implicitly (checks the
# compiler hoisted around accesses); emitting them would only desync streams.
_PRIM_NOISE = {"null_access", "invalid_cast"}

_FIELD_SIZES = {"i32": 4, "u32": 4, "f32": 4, "i16": 2, "u16": 2, "i8": 1, "u8": 1, "bool": 1}


class EmitContext:
    """Shared state for one image's emission pass."""

    def __init__(self, code: Bytecode, bin_view: HLCBinary):
        self.code = code
        self.bin_view = bin_view
        self.addr2findex: Dict[int, int] = {}
        ps = bin_view.symbol("hl_functions_ptrs")
        if ps is not None:
            n = ps.size // bin_view.PTR
            for k in range(n):
                p = bin_view.read_ptr(ps.value + bin_view.PTR * k)
                if p:
                    self.addr2findex[p] = k
        self._int_pool: Dict[int, int] = {int(i.value): k for k, i in enumerate(code.ints)}
        self._float_pool: Dict[float, int] = {}
        # libhl prim name (without the "hl_" prefix) -> native findex, so lifted
        # `Prim:*` events materialise as real calls into the natives table.
        # Recovered native names may or may not carry the prefix depending on
        # how the hdll symbol table was parsed; normalise it away.
        self.native_findex: Dict[str, int] = {}
        for nat in code.natives or []:
            try:
                nm = str(nat.name.resolve(code))
            except Exception:
                continue
            if nm.startswith("hl_"):
                nm = nm[len("hl_") :]
            if nm and nat.findex is not None:
                self.native_findex[nm] = nat.findex.value
        # Recovered global symbol names -> gindex (see globals.py).
        self.global_index: Dict[str, int] = dict(getattr(code, "hlc_global_index", None) or {})
        # findex -> position in code.natives, for arity lookups of native calls.
        self._native_pos_by_findex: Dict[int, int] = {
            nat.findex.value: k for k, nat in enumerate(code.natives or []) if nat.findex is not None
        }

    def int_ref(self, value: int) -> intRef:
        value &= 0xFFFFFFFF
        if value not in self._int_pool:
            si = SerialisableInt()
            si.value = value
            si.signed = False
            si.length = 4
            self.code.ints.append(si)
            self.code.nints = VarInt(len(self.code.ints))
            self._int_pool[value] = len(self.code.ints) - 1
        return intRef(self._int_pool[value])

    def float_ref(self, value: float) -> Optional[floatRef]:
        if value not in self._float_pool:
            sf = SerialisableF64()
            sf.value = value
            self.code.floats.append(sf)
            self.code.nfloats = VarInt(len(self.code.floats))
            self._float_pool[value] = len(self.code.floats) - 1
        return floatRef(self._float_pool[value])

    def arity_of(self, fidx: int) -> int:
        """Arity of a module function OR a native, by findex."""
        pos = self._native_pos_by_findex.get(fidx)
        if pos is not None:
            try:
                d = self.code.types[self.code.natives[pos].type.value].definition
                nargs = getattr(d, "nargs", None)
                return int(nargs.value) if nargs is not None else 0
            except (IndexError, AttributeError):
                return 0
        try:
            f = self.code.functions[fidx]
        except IndexError:
            return 0
        d = self.code.types[f.type.value].definition
        nargs = getattr(d, "nargs", None)
        return int(nargs.value) if nargs is not None else 0

    def fields_by_offset(self, tidx: int) -> Dict[int, int]:
        """Byte offset -> field index for one recovered type."""
        try:
            obj = self.code.types[tidx].definition
        except IndexError:
            return {}
        out: Dict[int, int] = {}
        off = 8  # hlobj header
        for i, fld in enumerate(getattr(obj, "fields", []) or []):
            out[off] = i
            ftname = str(fld.t.name) if getattr(fld, "t", None) is not None else ""
            size = _FIELD_SIZES.get(ftname, 8)
            off += size
        return out


def emit_function(ctx: EmitContext, ops: List[LiftedOp], max_regs: int = 512) -> List[Opcode]:
    """
    Materialise one lifted stream; branch offsets are patched here using the
    address provenance each LiftedOp carries.
    """
    out: List[Opcode] = []
    addr_index: Dict[int, int] = {}  # src_addr -> emitted index
    fixups: List[Tuple[int, int]] = []  # (emitted idx, branch target addr)
    reg = 0
    last_value = 0
    last_obj = 0
    last_type_fields: Optional[Dict[int, int]] = None

    def new_reg() -> int:
        nonlocal reg
        reg += 1
        if reg >= max_regs:
            reg = 1
        return reg

    def materialise_call(fidx: int) -> None:
        """Emit a Call0..4/N against findex `fidx`, arity from its signature."""
        nonlocal last_value
        dst = new_reg()
        nargs = ctx.arity_of(fidx)
        fun = fIndex(fidx)
        if nargs == 0:
            out.append(Opcode("Call0", {"dst": Reg(dst), "fun": fun}))
        else:
            names = ["arg0", "arg1", "arg2", "arg3"]
            df: dict = {"dst": Reg(dst), "fun": fun}
            for k in range(min(nargs, 4)):
                ar = new_reg()
                df[names[k]] = Reg(ar)
                last_value = ar
            if nargs > 4:
                rg = Regs()
                rg.value = [Reg(new_reg()) for _ in range(nargs - 4)]
                df["args"] = rg
                out.append(Opcode("CallN", df))
            else:
                out.append(Opcode(f"Call{nargs}", df))
        last_value = dst

    for lo in ops:
        if lo.src_addr:
            addr_index.setdefault(lo.src_addr, len(out))
        nm, a = lo.op, lo.args

        if nm == "Int":
            r = new_reg()
            out.append(Opcode("Int", {"dst": Reg(r), "ptr": ctx.int_ref(a.get("value", 0))}))
            last_value = r
        elif nm == "Float":
            r = new_reg()
            fr = ctx.float_ref(a.get("value", 0.0))
            if fr is None:
                continue
            out.append(Opcode("Float", {"dst": Reg(r), "ptr": fr}))
            last_value = r
        elif nm == "New":
            r = new_reg()
            out.append(Opcode("New", {"dst": Reg(r)}))
            last_obj = r
            last_type_fields = None
        elif nm in ("Call", "CallVirtual"):
            tgt = a.get("target_addr")
            fidx = ctx.addr2findex.get(tgt) if tgt is not None else None
            if fidx is not None:
                materialise_call(fidx)
        elif nm.startswith("Prim:"):
            prim = nm[len("Prim:") :]
            if prim == "throw":
                out.append(Opcode("Throw", {"exc": Reg(last_value or new_reg())}))
                last_value = 0
            elif prim in _PRIM_NOISE:
                pass
            else:
                nfidx = ctx.native_findex.get(prim)
                if nfidx is not None:
                    materialise_call(nfidx)
        elif nm == "GetGlobal":
            gi = ctx.global_index.get(str(a.get("gidx", "")))
            if gi is not None:
                r = new_reg()
                out.append(Opcode("GetGlobal", {"dst": Reg(r), "global": gIndex(gi)}))
                last_value = r
        elif nm == "SetGlobal":
            gi = ctx.global_index.get(str(a.get("gidx", "")))
            if gi is not None:
                src_v = last_value or new_reg()
                out.append(Opcode("SetGlobal", {"global": gIndex(gi), "src": Reg(src_v)}))
                # stores don't produce a value; keep last_value as-is
        elif nm == "StoreField":
            fi = last_type_fields.get(a.get("off", 0), 0) if last_type_fields else 0
            src_v = last_value or new_reg()
            out.append(Opcode("SetField", {"obj": Reg(last_obj), "field": fieldRef(fi), "src": Reg(src_v)}))
        elif nm == "LoadField":
            r = new_reg()
            fi = last_type_fields.get(a.get("off", 0), 0) if last_type_fields else 0
            out.append(Opcode("Field", {"dst": Reg(r), "obj": Reg(last_obj), "field": fieldRef(fi)}))
            last_value = r
        elif nm in ("JIfS", "JIfU"):
            op_name = _CC_TO_OP.get(a.get("cc", "ne"), "JNotEq")
            b = last_value or new_reg()
            fixups.append((len(out), a.get("target", 0)))
            out.append(Opcode(op_name, {"a": Reg(b), "b": Reg(new_reg()), "offset": VarInt(0)}))
        elif nm == "JAlways":
            fixups.append((len(out), a.get("target", 0)))
            out.append(Opcode("JAlways", {"offset": VarInt(0)}))
        elif nm == "Bool":
            r = new_reg()
            ib = InlineBool()
            ib.value = True
            out.append(Opcode("Bool", {"dst": Reg(r), "value": ib}))
            last_value = r
        elif nm == "Ret":
            out.append(Opcode("Ret", {"ret": Reg(last_value or 0)}))
        elif nm == "Throw":
            out.append(Opcode("Throw", {"exc": Reg(last_value or new_reg())}))
        elif nm == "Null":
            r = new_reg()
            out.append(Opcode("Null", {"dst": Reg(r)}))
            last_value = r
        elif nm in _ARITH_OPS:
            r = new_reg()
            out.append(
                Opcode(_ARITH_OPS[nm], {"dst": Reg(r), "a": Reg(last_value or 0), "b": Reg(new_reg())})
            )
            last_value = r
        # Convert / LeaSym / StringRef / Call? / unmapped prims: skipped in v1

    # Branch fixup: offsets are relative to the instruction after the branch.
    # A branch target frequently lands on machine instructions that produced no
    # lifted op (spill reloads, padding), so resolve to the FIRST EMITTED op at
    # or after the target address instead of requiring an exact match.
    import bisect as _bisect

    addrs = sorted(addr_index)
    for idx, tgt_addr in fixups:
        if not tgt_addr or not addrs:
            continue
        k = _bisect.bisect_left(addrs, tgt_addr)
        if k < len(addrs):
            out[idx].df["offset"].value = addr_index[addrs[k]] - (idx + 1)

    return out


def emit_image(code: Bytecode, bin_view: HLCBinary, lifter=None, verbose: bool = False) -> int:
    """Lift+emit bodies for every function-table entry that resolves to code."""
    from .lift import FunctionLifter

    plt = _resolve_plt_targets(bin_view)
    if lifter is None:
        lifter = FunctionLifter.for_binary(bin_view, plt)
    ctx = EmitContext(code, bin_view)
    count = 0
    for addr, fidx in sorted(ctx.addr2findex.items()):
        if not (0 <= fidx < len(code.functions)):
            continue
        if code.functions[fidx].ops:
            continue  # already populated
        try:
            stream = lifter.lift(addr)
        except Exception:
            continue
        if not stream:
            continue
        code.functions[fidx].ops = emit_function(ctx, stream)
        code.functions[fidx].nops = VarInt(len(code.functions[fidx].ops))
        count += 1
    if verbose:
        print(f"  emitted bodies for {count} functions")
    return count
